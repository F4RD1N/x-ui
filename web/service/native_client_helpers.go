package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	coreconf "github.com/xtls/xray-core/infra/conf"
)

func isNativeClientProtocol(p model.Protocol) bool {
	switch p {
	case model.Orbit, model.DNSTT, model.DNS, model.OpenVPN, model.AnyTLS, model.ShadowTLS, model.Mieru:
		return true
	default:
		return false
	}
}

func currentInboundAPIPort() int {
	if p == nil {
		return 0
	}
	return p.GetAPIPort()
}

// Native account identities never place secret keys/passwords in URL paths.
// The email token is stable across credential edits and safe for Gin routes.
func inboundClientID(p model.Protocol, c model.Client) string {
	if isNativeClientProtocol(p) {
		if c.Email == "" {
			return ""
		}
		return "email:" + base64.RawURLEncoding.EncodeToString([]byte(c.Email))
	}
	switch p {
	case model.Trojan:
		return c.Password
	case model.Shadowsocks:
		return c.Email
	case model.Hysteria:
		return c.Auth
	default:
		return c.ID
	}
}

func validateInboundClient(p model.Protocol, settings string, c model.Client) error {
	if inboundClientID(p, c) == "" {
		return fmt.Errorf("empty client ID")
	}
	if !isNativeClientProtocol(p) {
		return nil
	}
	switch p {
	case model.Orbit:
		if c.Key == "" {
			return fmt.Errorf("Orbit client key is required")
		}
	case model.DNSTT, model.DNS:
		var s struct {
			Inner struct {
				Protocol string `json:"protocol"`
			} `json:"inner"`
		}
		if err := json.Unmarshal([]byte(settings), &s); err != nil {
			return fmt.Errorf("invalid DNSTT settings")
		}
		if strings.EqualFold(s.Inner.Protocol, "socks") {
			if c.Username == "" || c.Password == "" || c.ID != "" {
				return fmt.Errorf("DNSTT SOCKS client requires username and password only")
			}
			if (c.TotalGB > 0 || c.LimitIP > 0) && c.Username != c.Email {
				return fmt.Errorf("DNSTT SOCKS traffic and IP limits require username to match client email")
			}
		} else if c.ID == "" || c.Username != "" || c.Password != "" {
			return fmt.Errorf("DNSTT VLESS client requires id only")
		}
	case model.OpenVPN:
		if c.CommonName == "" {
			return fmt.Errorf("OpenVPN client commonName is required")
		}
	case model.ShadowTLS:
		var s struct {
			Version uint32 `json:"version"`
			Inner   struct {
				Protocol string `json:"protocol"`
			} `json:"inner"`
		}
		if json.Unmarshal([]byte(settings), &s) != nil {
			return fmt.Errorf("invalid ShadowTLS settings")
		}
		// An inner SOCKS account is exported by its innerUsername regardless of
		// the ShadowTLS version (v3 included), so require it for every version;
		// otherwise a saved v3 SOCKS client cannot be exported.
		if strings.EqualFold(s.Inner.Protocol, "socks") && c.InnerUsername == "" {
			return fmt.Errorf("ShadowTLS SOCKS client requires innerUsername export binding")
		}
		if s.Version == 1 || s.Version == 2 {
			// In v1/v2 the inner SOCKS account is the accounting identity, so a
			// per-client traffic or IP limit only works when it is the client.
			if strings.EqualFold(s.Inner.Protocol, "socks") && (c.TotalGB > 0 || c.LimitIP > 0) && c.InnerUsername != c.Email {
				return fmt.Errorf("ShadowTLS SOCKS traffic and IP limits require innerUsername to match client email")
			}
			return nil
		}
		// v3 accounts on the outer password, so the inner SOCKS identity may
		// differ from the client and limits are applied on the outer account.
		if c.Password == "" {
			return fmt.Errorf("ShadowTLS v3 client password is required")
		}
	case model.AnyTLS:
		if c.Password == "" {
			return fmt.Errorf("native TLS client password is required")
		}
	case model.Mieru:
		if c.Username == "" || c.Password == "" {
			return fmt.Errorf("Mieru client username and password are required")
		}
	}
	return nil
}

func nativeClientRemovalRequiresRestart(p model.Protocol) bool {
	// These listeners have account authorization inside another protocol;
	// outer metadata deletion must also revoke the inner account atomically.
	return p == model.ShadowTLS || p == model.DNSTT || p == model.DNS
}

func clientEnabledForLiveAPI(p model.Protocol, c model.Client) bool {
	if !c.Enable {
		return false
	}
	return !isNativeClientProtocol(p) || c.ExpiryTime <= 0 || c.ExpiryTime > time.Now().UnixMilli()
}

func clientAPIValues(c model.Client, cipher string) map[string]any {
	// Explicit defaults retain the legacy AddUser contract; marshalled native
	// fields preserve nested proofs and account flags without float precision loss.
	result := map[string]any{"email": c.Email, "id": c.ID, "auth": c.Auth, "security": c.Security, "flow": c.Flow, "password": c.Password, "cipher": cipher}
	b, err := json.Marshal(c)
	if err == nil {
		var fields map[string]any
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.UseNumber()
		if dec.Decode(&fields) == nil {
			for k, v := range fields {
				result[k] = v
			}
		}
	}
	delete(result, "certificate")
	delete(result, "privateKey")
	delete(result, "tlsCryptV2")
	delete(result, "innerUsername")
	return result
}

func clientAPIValuesForInbound(c model.Client, cipher string, inbound *model.Inbound) map[string]any {
	values := clientAPIValues(c, cipher)
	if inbound != nil && inbound.Protocol == model.Orbit && c.ExpiryTime > 0 {
		seconds := c.ExpiryTime / 1000
		if c.ExpiresAt <= 0 || seconds < c.ExpiresAt {
			values["expiresAt"] = json.Number(strconv.FormatInt(seconds, 10))
		}
	}
	if inbound == nil || inbound.Protocol != model.Shadowsocks {
		return values
	}
	var settings map[string]any
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
		return values
	}
	if enabled, _ := settings["uuidIdentityKeys"].(bool); !enabled {
		return values
	}
	rows, _ := settings["clients"].([]any)
	for _, row := range rows {
		raw, ok := row.(map[string]any)
		if !ok || raw["email"] != c.Email {
			continue
		}
		if explicit, present := raw["uuidIdentityKeys"]; present {
			values["uuidIdentityKeys"] = explicit
			return values
		}
	}
	values["uuidIdentityKeys"] = true
	return values
}

func settingsClientMaps(settings map[string]any) ([]any, error) {
	if settings == nil {
		return nil, fmt.Errorf("settings must be an object")
	}
	raw, exists := settings["clients"]
	if !exists {
		return nil, nil
	}
	clients, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("clients must be an array")
	}
	for _, raw := range clients {
		if _, ok := raw.(map[string]any); !ok {
			return nil, fmt.Errorf("each client must be an object")
		}
	}
	return clients, nil
}

// Validate native protocol objects before persisting them, including the exact
// auth/proof parser. An intentionally inactive listener remains stored for later
// edits but is omitted from the runtime configuration.
func validateNativeInboundSettings(inbound *model.Inbound) error {
	if inbound == nil || !isNativeClientProtocol(inbound.Protocol) {
		return nil
	}
	var clientList struct {
		Clients []model.Client `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &clientList); err != nil {
		return fmt.Errorf("invalid native clients")
	}
	for _, client := range clientList.Clients {
		if err := validateInboundClient(inbound.Protocol, inbound.Settings, client); err != nil {
			return err
		}
	}
	runtimeInbound := *inbound
	settings, err := coreInboundSettings(&runtimeInbound)
	if errors.Is(err, errNoActiveNativeClients) {
		return nil
	}
	if err != nil {
		return err
	}
	runtimeInbound.Settings = settings
	raw, err := json.Marshal(runtimeInbound.GenXrayInboundConfig())
	if err != nil {
		return err
	}
	var config coreconf.InboundDetourConfig
	if err = json.Unmarshal(raw, &config); err != nil {
		return fmt.Errorf("invalid native inbound: %w", err)
	}
	if _, err = config.Build(); err != nil {
		return fmt.Errorf("invalid native inbound: %w", err)
	}
	return nil
}
