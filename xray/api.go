// Package xray provides integration with the Xray proxy core.
// It includes API client functionality, configuration management, traffic monitoring,
// and process control for Xray instances.
package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
	hysteriaAccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/mieru"
	"github.com/xtls/xray-core/proxy/openvpn"
	"github.com/xtls/xray-core/proxy/orbit"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// XrayAPI is a gRPC client for managing Xray core configuration, inbounds, outbounds, and statistics.
type XrayAPI struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	grpcClient           *grpc.ClientConn
	isConnected          bool
}

// Init connects to the Xray API server and initializes handler and stats service clients.
func (x *XrayAPI) Init(apiPort int) error {
	if apiPort <= 0 || apiPort > math.MaxUint16 {
		return fmt.Errorf("invalid Xray API port: %d", apiPort)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to Xray API: %w", err)
	}

	x.grpcClient = conn
	x.isConnected = true

	hsClient := command.NewHandlerServiceClient(conn)
	ssClient := statsService.NewStatsServiceClient(conn)

	x.HandlerServiceClient = &hsClient
	x.StatsServiceClient = &ssClient

	return nil
}

// Close closes the gRPC connection and resets the XrayAPI client state.
func (x *XrayAPI) Close() {
	if x.grpcClient != nil {
		x.grpcClient.Close()
	}
	x.HandlerServiceClient = nil
	x.StatsServiceClient = nil
	x.isConnected = false
}

// handlerClient fails explicitly when the managed core is stopped or API
// initialization failed; service callers can then schedule a safe reload.
func (x *XrayAPI) handlerClient() (command.HandlerServiceClient, error) {
	if x == nil || x.HandlerServiceClient == nil || *x.HandlerServiceClient == nil {
		return nil, fmt.Errorf("Xray handler API is not initialized")
	}
	return *x.HandlerServiceClient, nil
}

// AddInbound adds a new inbound configuration to the Xray core via gRPC.
func (x *XrayAPI) AddInbound(inbound []byte) error {
	client, err := x.handlerClient()
	if err != nil {
		return err
	}

	conf := new(conf.InboundDetourConfig)
	err = json.Unmarshal(inbound, conf)
	if err != nil {
		logger.Debug("Failed to unmarshal inbound:", err)
		return err
	}
	config, err := conf.Build()
	if err != nil {
		logger.Debug("Failed to build inbound Detur:", err)
		return err
	}
	inboundConfig := command.AddInboundRequest{Inbound: config}

	_, err = client.AddInbound(context.Background(), &inboundConfig)

	return err
}

// DelInbound removes an inbound configuration from the Xray core by tag.
func (x *XrayAPI) DelInbound(tag string) error {
	client, err := x.handlerClient()
	if err != nil {
		return err
	}
	_, err = client.RemoveInbound(context.Background(), &command.RemoveInboundRequest{
		Tag: tag,
	})
	return err
}

// ErrUserRestartRequired tells the inbound service that a dynamic user update
// cannot represent the protocol settings and a validated configuration reload
// is required. Unsupported protocols must never report a successful no-op.
var ErrUserRestartRequired = errors.New("inbound configuration reload required")

// apiUserAuthFields contains only core account fields. Panel metadata such as
// traffic quotas and export certificates must not enter a native account. JSON
// decoding validates booleans and unsigned levels without assertion panics and
// preserves integer precision when callers use json.Number.
type apiUserAuthFields struct {
	ID                  string          `json:"id"`
	Flow                string          `json:"flow"`
	Testseed            []uint32        `json:"testseed"`
	Testpre             uint32          `json:"testpre"`
	Password            string          `json:"password"`
	Cipher              string          `json:"cipher"`
	Auth                string          `json:"auth"`
	Email               string          `json:"email"`
	Level               uint32          `json:"level"`
	RawUUIDAuth         bool            `json:"rawUuidAuth"`
	UUIDHashPrefix      bool            `json:"uuidHashPrefix"`
	UUIDHashMiddle      bool            `json:"uuidHashMiddle"`
	UUIDMetadataTrailer bool            `json:"uuidMetadataTrailer"`
	UUIDIdentityKeys    bool            `json:"uuidIdentityKeys"`
	Username            string          `json:"username"`
	CommonName          string          `json:"commonName"`
	Key                 string          `json:"key"`
	ExpiresAt           int64           `json:"expiresAt"`
	ClientProof         json.RawMessage `json:"clientProof"`
}

// AddUser adds a user to an inbound in the Xray core using the specified protocol and user data.
func (x *XrayAPI) AddUser(Protocol string, inboundTag string, user map[string]any) error {
	// DNS tunnels and ShadowTLS may wrap VLESS or SOCKS. The account map
	// omits listener version/inner policy, so a full validated reload is needed
	// to update the actual credentials (including ShadowTLS v1/v2 inner users).
	if Protocol == "dns" || Protocol == "dnstt" || Protocol == "shadowtls" {
		return fmt.Errorf("%w: %s listener and inner user configuration", ErrUserRestartRequired, Protocol)
	}
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("invalid %s user fields", Protocol)
	}
	var fields apiUserAuthFields
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("invalid %s user fields: %w", Protocol, err)
	}
	var account *serial.TypedMessage
	switch Protocol {
	case "vmess":
		account = serial.ToTypedMessage(&vmess.Account{
			Id:          fields.ID,
			RawUuidAuth: fields.RawUUIDAuth,
		})
	case "vless":
		vlessAccount := &vless.Account{
			Id:   fields.ID,
			Flow: fields.Flow,
		}
		// Decode numeric fields through JSON too, so UseNumber callers retain
		// the same seeds instead of silently turning them into zeros.
		if len(fields.Testseed) >= 4 {
			vlessAccount.Testseed = fields.Testseed
		}
		vlessAccount.Testpre = fields.Testpre
		account = serial.ToTypedMessage(vlessAccount)
	case "trojan":
		account = serial.ToTypedMessage(&trojan.Account{
			Password:       fields.Password,
			UuidHashPrefix: fields.UUIDHashPrefix,
		})
	case "shadowsocks":
		if value, present := user["uuidIdentityKeys"]; present {
			raw, _ := json.Marshal(value)
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("uuidIdentityKeys must be a boolean")
			}
		}
		identity := fields.Password
		if fields.UUIDIdentityKeys {
			identity, err = conf.NormalizeSS2022IdentityKey(fields.Cipher, identity)
			if err != nil {
				return fmt.Errorf("invalid Shadowsocks2022 identity key: %w", err)
			}
		}
		var ssCipherType shadowsocks.CipherType
		switch fields.Cipher {
		case "aes-128-gcm":
			ssCipherType = shadowsocks.CipherType_AES_128_GCM
		case "aes-256-gcm":
			ssCipherType = shadowsocks.CipherType_AES_256_GCM
		case "chacha20-poly1305", "chacha20-ietf-poly1305":
			ssCipherType = shadowsocks.CipherType_CHACHA20_POLY1305
		case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
			ssCipherType = shadowsocks.CipherType_XCHACHA20_POLY1305
		default:
			ssCipherType = shadowsocks.CipherType_NONE
		}

		if ssCipherType != shadowsocks.CipherType_NONE {
			account = serial.ToTypedMessage(&shadowsocks.Account{
				Password:   fields.Password,
				CipherType: ssCipherType,
			})
		} else {
			account = serial.ToTypedMessage(&shadowsocks_2022.ServerConfig{
				Key:   identity,
				Email: fields.Email,
			})
		}
	case "hysteria":
		account = serial.ToTypedMessage(&hysteriaAccount.Account{
			Auth: fields.Auth,
		})
	case "orbit":
		account = serial.ToTypedMessage(&orbit.Account{Key: fields.Key, ExpiresAt: fields.ExpiresAt})
	case "anytls":
		account = serial.ToTypedMessage(&anytls.Account{Password: fields.Password, UuidHashMiddle: fields.UUIDHashMiddle})
	case "mieru":
		account = serial.ToTypedMessage(&mieru.Account{Username: fields.Username, Password: fields.Password, UuidMetadataTrailer: fields.UUIDMetadataTrailer})
	case "openvpn":
		client := openvpn.ServerUser{Email: fields.Email, Level: fields.Level, CommonName: fields.CommonName, Username: fields.Username, Password: fields.Password}
		if len(fields.ClientProof) != 0 && string(fields.ClientProof) != "null" {
			decoder := json.NewDecoder(bytes.NewReader(fields.ClientProof))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&client.ClientProof); err != nil {
				return fmt.Errorf("invalid OpenVPN clientProof fields")
			}
		}
		settings, err := json.Marshal(client)
		if err != nil {
			return fmt.Errorf("invalid OpenVPN user fields")
		}
		account = serial.ToTypedMessage(&openvpn.ServerAccount{Settings: settings})
	default:
		return fmt.Errorf("%w: unsupported dynamic user protocol %q", ErrUserRestartRequired, Protocol)
	}

	// Validate typed credentials locally before sending the operation. Account
	// conversion also preserves compatibility flags across the gRPC boundary.
	value, err := account.GetInstance()
	if err != nil {
		return fmt.Errorf("invalid %s account message", Protocol)
	}
	if a, ok := value.(protocol.AsAccount); ok {
		if _, err := a.AsAccount(); err != nil {
			return fmt.Errorf("invalid %s user account: %w", Protocol, err)
		}
	}
	client, err := x.handlerClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.AlterInbound(ctx, &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   fields.Email,
				Level:   fields.Level,
				Account: account,
			},
		}),
	})
	return err
}

// RemoveUser removes a user from an inbound in the Xray core by email.
func (x *XrayAPI) RemoveUser(inboundTag, email string) error {
	client, err := x.handlerClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op := &command.RemoveUserOperation{Email: email}
	req := &command.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	}

	_, err = client.AlterInbound(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}

	return nil
}

// GetTraffic queries traffic statistics from the Xray core, optionally resetting counters.
func (x *XrayAPI) GetTraffic(reset bool) ([]*Traffic, []*ClientTraffic, error) {
	if x.grpcClient == nil {
		return nil, nil, common.NewError("xray api is not initialized")
	}

	trafficRegex := regexp.MustCompile(`(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)`)
	clientTrafficRegex := regexp.MustCompile(`user>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if x.StatsServiceClient == nil {
		return nil, nil, common.NewError("xray StatusServiceClient is not initialized")
	}

	resp, err := (*x.StatsServiceClient).QueryStats(ctx, &statsService.QueryStatsRequest{Reset_: reset})
	if err != nil {
		logger.Debug("Failed to query Xray stats:", err)
		return nil, nil, err
	}

	tagTrafficMap := make(map[string]*Traffic)
	emailTrafficMap := make(map[string]*ClientTraffic)

	for _, stat := range resp.GetStat() {
		if matches := trafficRegex.FindStringSubmatch(stat.Name); len(matches) == 4 {
			processTraffic(matches, stat.Value, tagTrafficMap)
		} else if matches := clientTrafficRegex.FindStringSubmatch(stat.Name); len(matches) == 3 {
			processClientTraffic(matches, stat.Value, emailTrafficMap)
		}
	}
	return mapToSlice(tagTrafficMap), mapToSlice(emailTrafficMap), nil
}

// processTraffic aggregates a traffic stat into trafficMap using regex matches and value.
func processTraffic(matches []string, value int64, trafficMap map[string]*Traffic) {
	isInbound := matches[1] == "inbound"
	tag := matches[2]
	isDown := matches[3] == "downlink"

	if tag == "api" {
		return
	}

	traffic, ok := trafficMap[tag]
	if !ok {
		traffic = &Traffic{
			IsInbound:  isInbound,
			IsOutbound: !isInbound,
			Tag:        tag,
		}
		trafficMap[tag] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

// processClientTraffic updates clientTrafficMap with upload/download values for a client email.
func processClientTraffic(matches []string, value int64, clientTrafficMap map[string]*ClientTraffic) {
	email := matches[1]
	isDown := matches[2] == "downlink"

	traffic, ok := clientTrafficMap[email]
	if !ok {
		traffic = &ClientTraffic{Email: email}
		clientTrafficMap[email] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

// mapToSlice converts a map of pointers to a slice of pointers.
func mapToSlice[T any](m map[string]*T) []*T {
	result := make([]*T, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}
