package xray

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const nativeAPIUUID = "00112233-4455-6677-8899-aabbccddeeff"

type nativeAPIRecorder struct {
	command.HandlerServiceClient
	calls    int
	request  *command.AlterInboundRequest
	err      error
	deadline time.Time
}

func (r *nativeAPIRecorder) AlterInbound(ctx context.Context, req *command.AlterInboundRequest, _ ...grpc.CallOption) (*command.AlterInboundResponse, error) {
	r.calls++
	r.request = proto.Clone(req).(*command.AlterInboundRequest)
	r.deadline, _ = ctx.Deadline()
	return &command.AlterInboundResponse{}, r.err
}
func nativeAPIClient() (*XrayAPI, *nativeAPIRecorder) {
	r := &nativeAPIRecorder{}
	var handler command.HandlerServiceClient = r
	return &XrayAPI{HandlerServiceClient: &handler}, r
}
func nativeAPIAccount(t *testing.T, r *nativeAPIRecorder) (*protocol.User, proto.Message) {
	t.Helper()
	if r.calls != 1 || r.request == nil {
		t.Fatalf("expected one real API operation, got %d", r.calls)
	}
	if r.request.Tag != "test-inbound" {
		t.Fatal("wrong inbound tag")
	}
	if r.deadline.IsZero() || time.Until(r.deadline) > 5*time.Second {
		t.Fatal("API request has no bounded deadline")
	}
	operation, err := r.request.Operation.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	u := operation.(*command.AddUserOperation).User
	account, err := u.Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	return u, account
}
func nativeAPIKey() string {
	return "vck1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
}

func TestNativeProtocolAPIAddUser(t *testing.T) {
	proofKey := strings.Repeat("ab", 32)
	cases := []struct {
		name   string
		fields map[string]any
		check  func(*testing.T, proto.Message)
	}{
		{"vmess", map[string]any{"id": nativeAPIUUID, "rawUuidAuth": true}, func(t *testing.T, m proto.Message) {
			a := m.(*vmess.Account)
			if a.Id != nativeAPIUUID || !a.RawUuidAuth {
				t.Fatal("VMess auth flag lost")
			}
		}},
		{"trojan", map[string]any{"password": nativeAPIUUID, "uuidHashPrefix": true}, func(t *testing.T, m proto.Message) {
			a := m.(*trojan.Account)
			if a.Password != nativeAPIUUID || !a.UuidHashPrefix {
				t.Fatal("Trojan auth flag lost")
			}
		}},
		{"orbit", map[string]any{"key": nativeAPIKey(), "expiresAt": json.Number("9007199254740993")}, func(t *testing.T, m proto.Message) {
			a := m.(*orbit.Account)
			if a.Key != nativeAPIKey() || a.ExpiresAt != 9007199254740993 {
				t.Fatal("Orbit key or precise expiry lost")
			}
		}},
		{"anytls", map[string]any{"password": nativeAPIUUID, "uuidHashMiddle": true}, func(t *testing.T, m proto.Message) {
			a := m.(*anytls.Account)
			if a.Password != nativeAPIUUID || !a.UuidHashMiddle {
				t.Fatal("AnyTLS auth flag lost")
			}
		}},
		{"mieru", map[string]any{"username": nativeAPIUUID, "password": "synthetic-password", "uuidMetadataTrailer": true}, func(t *testing.T, m proto.Message) {
			a := m.(*mieru.Account)
			if a.Username != nativeAPIUUID || a.Password != "synthetic-password" || !a.UuidMetadataTrailer {
				t.Fatal("Mieru account lost")
			}
		}},
		{"openvpn", map[string]any{"commonName": "client-cn", "username": "client-username", "password": "synthetic-password", "clientProof": map[string]any{"keyId": "device-1", "key": proofKey}, "certificate": "export-only-cert", "privateKey": "export-only-key"}, func(t *testing.T, m proto.Message) {
			a := m.(*openvpn.ServerAccount)
			var u openvpn.ServerUser
			if err := json.Unmarshal(a.Settings, &u); err != nil {
				t.Fatal(err)
			}
			if u.Email != "client@example.invalid" || u.Level != 7 || u.CommonName != "client-cn" || u.Username != "client-username" || u.Password != "synthetic-password" || u.ClientProof == nil || u.ClientProof.KeyID != "device-1" || u.ClientProof.Key != proofKey {
				t.Fatal("OpenVPN identity/proof lost")
			}
			if bytes.Contains(a.Settings, []byte("export-only")) {
				t.Fatal("export material leaked into account")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api, r := nativeAPIClient()
			tc.fields["email"] = "client@example.invalid"
			tc.fields["level"] = json.Number("7")
			if err := api.AddUser(tc.name, "test-inbound", tc.fields); err != nil {
				t.Fatal(err)
			}
			u, a := nativeAPIAccount(t, r)
			if u.Email != "client@example.invalid" || u.Level != 7 {
				t.Fatal("user identity/level lost")
			}
			tc.check(t, a)
			if _, err := u.ToMemoryUser(); err != nil {
				t.Fatalf("core cannot convert native account: %v", err)
			}
		})
	}
}

func TestNativeProtocolAPIStandardFlags(t *testing.T) {
	cases := []struct {
		protocol, flag string
		fields         map[string]any
		value          func(proto.Message) bool
	}{
		{"vmess", "rawUuidAuth", map[string]any{"id": nativeAPIUUID}, func(a proto.Message) bool { return a.(*vmess.Account).RawUuidAuth }},
		{"trojan", "uuidHashPrefix", map[string]any{"password": "normal-password"}, func(a proto.Message) bool { return a.(*trojan.Account).UuidHashPrefix }},
		{"anytls", "uuidHashMiddle", map[string]any{"password": "normal-password"}, func(a proto.Message) bool { return a.(*anytls.Account).UuidHashMiddle }},
		{"mieru", "uuidMetadataTrailer", map[string]any{"username": "normal-user", "password": "normal-password"}, func(a proto.Message) bool { return a.(*mieru.Account).UuidMetadataTrailer }},
	}
	for _, tc := range cases {
		for _, mode := range []string{"absent", "false", "null"} {
			t.Run(tc.protocol+"/"+mode, func(t *testing.T) {
				api, r := nativeAPIClient()
				fields := map[string]any{"email": "client@example.invalid"}
				for k, v := range tc.fields {
					fields[k] = v
				}
				if mode == "false" {
					fields[tc.flag] = false
				} else if mode == "null" {
					fields[tc.flag] = nil
				}
				if err := api.AddUser(tc.protocol, "test-inbound", fields); err != nil {
					t.Fatal(err)
				}
				_, a := nativeAPIAccount(t, r)
				if tc.value(a) {
					t.Fatal("standard account enabled compatibility mode")
				}
			})
		}
	}
}

func TestNativeProtocolAPIRejectsBadFields(t *testing.T) {
	cases := []struct {
		protocol string
		fields   map[string]any
	}{
		{"vmess", map[string]any{"id": nativeAPIUUID, "rawUuidAuth": "true"}},
		{"trojan", map[string]any{"password": nativeAPIUUID, "uuidHashPrefix": 1}},
		{"anytls", map[string]any{"password": "normal-password", "uuidHashMiddle": "false"}},
		{"mieru", map[string]any{"username": nativeAPIUUID, "password": "normal-password", "uuidMetadataTrailer": map[string]any{}}},
		{"orbit", map[string]any{"key": "bad-key"}},
		{"orbit", map[string]any{"key": nativeAPIKey(), "expiresAt": -1}},
		{"mieru", map[string]any{"password": "normal-password"}},
		{"openvpn", map[string]any{"commonName": "cn", "clientProof": map[string]any{"keyId": "id", "key": "bad"}}},
		{"openvpn", map[string]any{"commonName": "cn", "clientProof": map[string]any{"keyId": "id", "key": strings.Repeat("ab", 32), "unexpected": true}}},
		{"openvpn", map[string]any{"commonName": "cn", "clientProof": true}},
		{"vmess", map[string]any{"id": nativeAPIUUID, "level": -1}},
		{"vmess", map[string]any{"id": nativeAPIUUID, "level": 1.2}},
		{"vmess", map[string]any{"id": nativeAPIUUID, "level": json.Number("4294967296")}},
		{"vmess", map[string]any{"id": 123}},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%s/%d", tc.protocol, i), func(t *testing.T) {
			api, r := nativeAPIClient()
			tc.fields["email"] = "client@example.invalid"
			if err := api.AddUser(tc.protocol, "test-inbound", tc.fields); err == nil {
				t.Fatal("invalid field accepted")
			}
			if r.calls != 0 {
				t.Fatal("invalid user reached gRPC")
			}
		})
	}
}

func TestNativeProtocolAPIRestartRequired(t *testing.T) {
	for _, name := range []string{"dns", "dnstt", "shadowtls", "unknown"} {
		t.Run(name, func(t *testing.T) {
			api, r := nativeAPIClient()
			err := api.AddUser(name, "test-inbound", map[string]any{"id": nativeAPIUUID, "password": nativeAPIUUID, "requireUuidSessionId": true})
			if !errors.Is(err, ErrUserRestartRequired) {
				t.Fatalf("expected explicit reload requirement, got %v", err)
			}
			if r.calls != 0 {
				t.Fatal("unsupported update sent to gRPC")
			}
		})
	}
}

func TestNativeProtocolAPILegacyMappings(t *testing.T) {
	api, r := nativeAPIClient()
	if err := api.AddUser("vless", "test-inbound", map[string]any{"id": nativeAPIUUID, "email": "legacy", "flow": "", "testseed": []any{json.Number("1"), json.Number("2"), json.Number("3"), json.Number("4294967295")}, "testpre": json.Number("4")}); err != nil {
		t.Fatal(err)
	}
	_, m := nativeAPIAccount(t, r)
	a := m.(*vless.Account)
	if a.Id != nativeAPIUUID || !reflect.DeepEqual(a.Testseed, []uint32{1, 2, 3, 4294967295}) || a.Testpre != 4 {
		t.Fatal("legacy VLESS numeric options lost")
	}
	for _, cipher := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		api, r = nativeAPIClient()
		if err := api.AddUser("shadowsocks", "test-inbound", map[string]any{"cipher": cipher, "password": "password", "email": "legacy"}); err != nil {
			t.Fatal(err)
		}
		_, m = nativeAPIAccount(t, r)
		if m.(*shadowsocks.Account).Password != "password" {
			t.Fatal("legacy SS password lost")
		}
	}
	api, r = nativeAPIClient()
	if err := api.AddUser("shadowsocks", "test-inbound", map[string]any{"cipher": "2022-blake3-aes-128-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), "email": "legacy"}); err != nil {
		t.Fatal(err)
	}
	_, m = nativeAPIAccount(t, r)
	if m.(*shadowsocks_2022.ServerConfig).Email != "legacy" {
		t.Fatal("SS2022 mapping lost")
	}
	api, r = nativeAPIClient()
	if err := api.AddUser("hysteria", "test-inbound", map[string]any{"auth": "synthetic-auth", "email": "legacy"}); err != nil {
		t.Fatal(err)
	}
	_, m = nativeAPIAccount(t, r)
	if m.(*hysteriaAccount.Account).Auth != "synthetic-auth" {
		t.Fatal("Hysteria mapping lost")
	}
}

func TestNativeProtocolAPIUninitializedAndServerFailure(t *testing.T) {
	fields := map[string]any{"id": nativeAPIUUID, "email": "client@example.invalid"}
	if err := new(XrayAPI).AddUser("vmess", "test-inbound", fields); err == nil {
		t.Fatal("uninitialized API succeeded")
	}
	api, r := nativeAPIClient()
	r.err = status.Error(codes.PermissionDenied, "test server rejected account")
	if err := api.AddUser("vmess", "test-inbound", fields); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("upstream error lost: %v", err)
	}
	if r.calls != 1 {
		t.Fatal("operation not sent")
	}
}

func TestNativeProtocolAPIDisconnectedMutations(t *testing.T) {
	var nilHandler command.HandlerServiceClient
	for _, api := range []*XrayAPI{nil, {}, {HandlerServiceClient: &nilHandler}} {
		if err := api.AddInbound([]byte(`{}`)); err == nil {
			t.Fatal("disconnected AddInbound succeeded")
		}
		if err := api.DelInbound("test-inbound"); err == nil {
			t.Fatal("disconnected DelInbound succeeded")
		}
		if err := api.RemoveUser("test-inbound", "client@example.invalid"); err == nil {
			t.Fatal("disconnected RemoveUser succeeded")
		}
		if err := api.AddUser("vmess", "test-inbound", map[string]any{"id": nativeAPIUUID, "email": "client@example.invalid"}); err == nil {
			t.Fatal("disconnected AddUser succeeded")
		}
	}
}

func TestNativeProtocolAPIOpenVPNWithoutProof(t *testing.T) {
	for _, value := range []any{nil, json.RawMessage("null")} {
		api, r := nativeAPIClient()
		if err := api.AddUser("openvpn", "test-inbound", map[string]any{"email": "client@example.invalid", "commonName": "client-cn", "clientProof": value}); err != nil {
			t.Fatal(err)
		}
		_, account := nativeAPIAccount(t, r)
		var user openvpn.ServerUser
		if err := json.Unmarshal(account.(*openvpn.ServerAccount).Settings, &user); err != nil {
			t.Fatal(err)
		}
		if user.ClientProof != nil || user.Username != "" || user.Password != "" {
			t.Fatal("standard certificate-only account unexpectedly enabled custom auth")
		}
	}
}

func TestNativeProtocolAPISS2022UUIDIdentity(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			key := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
			if method != "2022-blake3-aes-128-gcm" {
				key = append(key, key...)
			}
			for _, enabled := range []bool{false, true} {
				api, r := nativeAPIClient()
				if err := api.AddUser("shadowsocks", "test-inbound", map[string]any{"email": "identity@example.invalid", "password": nativeAPIUUID, "cipher": method, "uuidIdentityKeys": enabled}); err != nil {
					t.Fatal(err)
				}
				_, m := nativeAPIAccount(t, r)
				expected := nativeAPIUUID
				if enabled {
					expected = base64.StdEncoding.EncodeToString(key)
				}
				if m.(*shadowsocks_2022.ServerConfig).Key != expected {
					t.Fatal("identity conversion changed the configured auth mode")
				}
			}
			api, r := nativeAPIClient()
			password := base64.StdEncoding.EncodeToString(key)
			if err := api.AddUser("shadowsocks", "test-inbound", map[string]any{"email": "identity@example.invalid", "password": password, "cipher": method, "uuidIdentityKeys": true}); err != nil {
				t.Fatal(err)
			}
			_, m := nativeAPIAccount(t, r)
			if m.(*shadowsocks_2022.ServerConfig).Key != password {
				t.Fatal("existing PSK changed")
			}
		})
	}
	for _, flag := range []any{"true", 1, nil} {
		api, r := nativeAPIClient()
		if err := api.AddUser("shadowsocks", "test-inbound", map[string]any{"password": nativeAPIUUID, "cipher": "2022-blake3-aes-128-gcm", "uuidIdentityKeys": flag}); err == nil {
			t.Fatal("invalid identity flag accepted")
		}
		if r.calls != 0 {
			t.Fatal("invalid flag reached core")
		}
	}
	api, r := nativeAPIClient()
	if err := api.AddUser("shadowsocks", "test-inbound", map[string]any{"password": nativeAPIUUID, "cipher": "aes-128-gcm", "uuidIdentityKeys": true}); err == nil {
		t.Fatal("SS2022 option applied to legacy Shadowsocks")
	}
	if r.calls != 0 {
		t.Fatal("invalid method reached core")
	}
}
