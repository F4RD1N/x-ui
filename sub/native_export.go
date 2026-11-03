package sub

import (
	"bytes"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/xtls/xray-core/infra/conf"
)

var errNativeJSONSubscriptionRequired = errors.New("native protocols and custom authentication require the JSON subscription endpoint")
var errNativeExportUnavailable = errors.New("native JSON export unavailable")

// SS2022's UUID notation is an import convention. URI/Clash clients receive
// its canonical base64 identity key, while the separate server PSK is retained.
func ss2022ExportIdentity(inbound *model.Inbound, client model.Client) (string, error) {
	var settings map[string]any
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
		return "", errors.New("invalid Shadowsocks export settings")
	}
	enabled, _ := settings["uuidIdentityKeys"].(bool)
	if rows, ok := settings["clients"].([]any); ok {
		for _, item := range rows {
			row := exportObject(item)
			if exportString(row["email"]) == client.Email {
				if flag, present := row["uuidIdentityKeys"]; present {
					var ok bool
					enabled, ok = flag.(bool)
					if !ok {
						return "", errors.New("uuidIdentityKeys export flag must be boolean")
					}
				} else if client.UUIDIdentityKeys {
					enabled = true
				}
				break
			}
		}
	}
	if !enabled {
		return client.Password, nil
	}
	return conf.NormalizeSS2022IdentityKey(exportString(settings["method"]), client.Password)
}

func nativeSubscriptionProtocol(protocol model.Protocol) bool {
	switch protocol {
	case "orbit", "dnstt", "dns", "openvpn", "anytls", "shadowtls", "mieru":
		return true
	}
	return false
}

func nativeClientExportActive(inbound *model.Inbound, client model.Client) bool {
	if !client.Enable || (client.ExpiryTime > 0 && client.ExpiryTime <= time.Now().UnixMilli()) {
		return false
	}
	if inbound.Protocol == "orbit" && client.ExpiresAt > 0 && client.ExpiresAt <= time.Now().Unix() {
		return false
	}
	for _, stat := range inbound.ClientStats {
		if stat.Email == client.Email {
			return stat.Enable && (stat.ExpiryTime <= 0 || stat.ExpiryTime > time.Now().UnixMilli())
		}
	}
	return true
}

func exportObject(value any) map[string]any {
	v, _ := value.(map[string]any)
	return v
}
func exportString(value any) string { s, _ := value.(string); return s }
func exportCopy(to, from map[string]any, fields ...string) {
	for _, field := range fields {
		if value, present := from[field]; present {
			to[field] = value
		}
	}
}

// Exact matching is intentional. An absent or ambiguous binding must never
// export another subscriber's credentials as a convenient fallback.
func exportSelectedClient(settings map[string]any, collection, field, identity string) (map[string]any, error) {
	if identity == "" {
		return nil, errors.New("native export requires an explicit account identity")
	}
	rows, ok := settings[collection].([]any)
	if !ok {
		return nil, errors.New("native export account list is missing")
	}
	var found map[string]any
	for _, item := range rows {
		row := exportObject(item)
		if exportString(row[field]) != identity {
			continue
		}
		if found != nil {
			return nil, errors.New("native export account binding is ambiguous")
		}
		found = row
	}
	if found == nil {
		return nil, errors.New("native export account binding was not found")
	}
	if enabled, ok := found["enable"].(bool); ok && !enabled {
		return nil, errors.New("native export account is disabled")
	}
	if expiry, ok := found["expiryTime"].(float64); ok && expiry > 0 && expiry <= float64(time.Now().UnixMilli()) {
		return nil, errors.New("native export account has expired")
	}
	return found, nil
}

func exportServerAddress(inbound *model.Inbound, host string) (string, error) {
	address := strings.TrimSpace(inbound.Listen)
	if address == "" || address == "0.0.0.0" || address == "::" || address == "::0" {
		address = strings.TrimSpace(host)
	}
	address = strings.Trim(address, "[]")
	if address == "" || strings.HasPrefix(address, "@") || inbound.Port < 1 || inbound.Port > 65535 {
		return "", errors.New("native export requires a public endpoint and port")
	}
	return address, nil
}

func exportPublicKey(private string, isHex bool) (string, error) {
	var raw []byte
	var err error
	if isHex {
		raw, err = hex.DecodeString(private)
	} else {
		raw, err = base64.RawURLEncoding.Strict().DecodeString(private)
	}
	if err != nil || len(raw) != 32 {
		return "", errors.New("native export server key is invalid")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	clear(raw)
	if err != nil {
		return "", errors.New("native export server key is invalid")
	}
	if isHex {
		return hex.EncodeToString(key.PublicKey().Bytes()), nil
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// nativeClientOutbounds exports public server parameters and only the selected
// client's credentials. Inbound settings are never copied wholesale.
func nativeClientOutbounds(inbound *model.Inbound, client model.Client, host string) ([]map[string]any, error) {
	if inbound == nil || !nativeSubscriptionProtocol(inbound.Protocol) {
		return nil, errors.New("unsupported native subscription protocol")
	}
	address, err := exportServerAddress(inbound, host)
	if err != nil {
		return nil, err
	}
	var settings map[string]any
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil || settings == nil {
		return nil, errors.New("invalid native export settings")
	}
	u, err := exportSelectedClient(settings, "clients", "email", client.Email)
	if err != nil {
		return nil, err
	}
	meta := exportObject(settings["clientExport"])
	out := map[string]any{"tag": "proxy", "protocol": string(inbound.Protocol)}
	cfg := map[string]any{"address": address, "port": inbound.Port}
	out["settings"] = cfg
	switch inbound.Protocol {
	case "orbit":
		if exportString(u["key"]) == "" {
			return nil, errors.New("Orbit export requires a client connection key")
		}
		if expiry, ok := u["expiresAt"].(float64); ok && expiry > 0 && expiry <= float64(time.Now().Unix()) {
			return nil, errors.New("Orbit export account has expired")
		}
		exportCopy(cfg, u, "key")
		exportCopy(cfg, settings, "transport", "host", "path", "security", "handshakeTimeout")
		if peer := exportString(meta["serverName"]); peer != "" {
			cfg["peer"] = peer
		}
		if exportString(settings["security"]) == "reality" {
			r := exportObject(settings["reality"])
			public, err := exportPublicKey(exportString(r["privateKey"]), false)
			if err != nil {
				return nil, err
			}
			names, _ := r["serverNames"].([]any)
			ids, _ := r["shortIds"].([]any)
			if len(names) == 0 {
				return nil, errors.New("Orbit Reality export requires a server name")
			}
			rc := map[string]any{"serverName": names[0], "publicKey": public}
			if len(ids) > 0 {
				rc["shortId"] = ids[0]
			}
			exportCopy(rc, meta, "fingerprint")
			cfg["reality"] = rc
		}
	case "dnstt", "dns":
		public, err := exportPublicKey(exportString(settings["privateKey"]), true)
		if err != nil {
			return nil, err
		}
		tunnel := map[string]any{"domain": settings["domain"], "publicKey": public}
		exportCopy(tunnel, settings, "handshakeTimeout")
		if resolvers, ok := meta["resolvers"].([]any); ok && len(resolvers) > 0 {
			tunnel["resolvers"] = resolvers
		} else {
			resolver := exportString(meta["resolver"])
			if resolver == "" {
				resolver = net.JoinHostPort(address, strconv.Itoa(inbound.Port))
			}
			tunnel["resolvers"] = []any{map[string]any{"transport": "udp", "address": resolver}}
		}
		kind := exportString(exportObject(settings["inner"])["protocol"])
		if kind == "" {
			kind = "vless"
		}
		inner := map[string]any{"protocol": kind}
		switch kind {
		case "vless":
			inner["uuid"] = u["id"]
		case "socks":
			exportCopy(inner, u, "username", "password")
		default:
			return nil, errors.New("unsupported DNSTT inner export protocol")
		}
		tunnel["inner"] = inner
		out["protocol"], out["settings"] = "dns", map[string]any{"tunnel": tunnel}
	case "anytls":
		exportCopy(cfg, u, "password", "uuidHashMiddle")
		exportCopy(cfg, settings, "handshakeTimeout")
		var stream map[string]any
		_ = json.Unmarshal([]byte(inbound.StreamSettings), &stream)
		serverTLS := exportObject(stream["tlsSettings"])
		name := exportString(meta["serverName"])
		if name == "" {
			name = exportString(serverTLS["serverName"])
		}
		if name == "" {
			name = address
		}
		tlsSettings := map[string]any{"serverName": name}
		exportCopy(tlsSettings, serverTLS, "alpn")
		exportCopy(tlsSettings, meta, "fingerprint")
		if ca := exportString(meta["ca"]); ca != "" {
			tlsSettings["certificates"] = []any{map[string]any{"certificate": strings.Split(ca, "\n"), "usage": "verify"}}
		} else {
			trust, err := exportPublicCertificateTrust(serverTLS)
			if err != nil {
				return nil, err
			}
			if len(trust) > 0 {
				tlsSettings["certificates"] = trust
			}
		}
		cfg["tlsSettings"] = tlsSettings
	case "mieru":
		exportCopy(cfg, u, "username", "password", "uuidMetadataTrailer")
		exportCopy(cfg, settings, "transport", "handshakeTimeout")
	case "openvpn":
		cfg, err = exportOpenVPNClient(settings, u, address, inbound.Port)
		if err != nil {
			return nil, err
		}
		out["settings"] = cfg
	case "shadowtls":
		return exportShadowTLSClient(settings, meta, u, address, inbound.Port)
	}
	return []map[string]any{out}, nil
}

// Only public X.509 certificate blocks are copied. This permits a configured
// self-signed leaf to be trusted without changing hostname verification or
// accidentally shipping an inline/file-backed server private key.
func exportPublicCertificateTrust(serverTLS map[string]any) ([]any, error) {
	certificates, _ := serverTLS["certificates"].([]any)
	var trust []any
	for _, item := range certificates {
		cert := exportObject(item)
		if usage := exportString(cert["usage"]); usage == "verify" {
			continue
		}
		var text []byte
		if lines, ok := cert["certificate"].([]any); ok {
			for _, line := range lines {
				s, ok := line.(string)
				if !ok {
					return nil, errors.New("AnyTLS public certificate lines are invalid")
				}
				text = append(text, s...)
				text = append(text, '\n')
			}
		}
		if len(text) == 0 && exportString(cert["certificateFile"]) != "" {
			path := exportString(cert["certificateFile"])
			st, err := os.Stat(path)
			if err != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 {
				return nil, errors.New("AnyTLS public certificate file is unavailable")
			}
			file, err := os.Open(path)
			if err != nil {
				return nil, errors.New("AnyTLS public certificate file is unavailable")
			}
			current, statErr := file.Stat()
			if statErr != nil || !current.Mode().IsRegular() || current.Size() > 2<<20 {
				file.Close()
				return nil, errors.New("AnyTLS public certificate file is unavailable")
			}
			text, err = io.ReadAll(io.LimitReader(file, (2<<20)+1))
			file.Close()
			if err != nil || len(text) > 2<<20 {
				return nil, errors.New("AnyTLS public certificate file is unavailable")
			}
		}
		if len(text) == 0 {
			continue
		}
		var public []byte
		for len(text) > 0 {
			block, rest := pem.Decode(text)
			if block == nil {
				break
			}
			text = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, errors.New("AnyTLS public certificate is invalid")
			}
			public = append(public, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		}
		if len(public) == 0 {
			return nil, errors.New("AnyTLS public certificate is missing")
		}
		trust = append(trust, map[string]any{"certificate": strings.Split(string(public), "\n"), "usage": "verify"})
	}
	return trust, nil
}

func exportOpenVPNClient(settings, client map[string]any, address string, port int) (map[string]any, error) {
	serverCertificates := exportObject(settings["certificates"])
	cert, key := exportString(client["certificate"]), exportString(client["privateKey"])
	if cert == "" || key == "" {
		return nil, errors.New("OpenVPN JSON export requires this client's certificate and privateKey")
	}
	if key == exportString(serverCertificates["key"]) {
		return nil, errors.New("OpenVPN export cannot use the server private key")
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("OpenVPN export client certificate and key do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.Subject.CommonName != exportString(client["commonName"]) {
		return nil, errors.New("OpenVPN export certificate common name does not match the account")
	}
	// Compare key identity as well as PEM spelling: whitespace or another PEM
	// encoding must not make reusing the server private key exportable.
	if serverPair, err := tls.X509KeyPair([]byte(exportString(serverCertificates["cert"])), []byte(exportString(serverCertificates["key"]))); err == nil && len(serverPair.Certificate) > 0 {
		if serverLeaf, err := x509.ParseCertificate(serverPair.Certificate[0]); err == nil && bytes.Equal(serverLeaf.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
			return nil, errors.New("OpenVPN export cannot use the server private key")
		}
	}
	certificates := map[string]any{"ca": serverCertificates["ca"], "cert": cert, "key": key}
	if exportString(serverCertificates["tlsCryptV2"]) != "" {
		v2 := exportString(client["tlsCryptV2"])
		if v2 == "" || v2 == exportString(serverCertificates["tlsCryptV2"]) {
			return nil, errors.New("OpenVPN export requires this client's tlsCryptV2 key")
		}
		certificates["tlsCryptV2"] = v2
	} else {
		exportCopy(certificates, serverCertificates, "tlsCrypt", "tlsAuth")
		if _, tlsAuth := serverCertificates["tlsAuth"]; tlsAuth {
			if direction, ok := serverCertificates["keyDirection"].(float64); ok {
				if direction != 0 && direction != 1 {
					return nil, errors.New("OpenVPN server keyDirection is invalid")
				}
				certificates["keyDirection"] = 1 - int(direction)
			}
		}
	}
	network := exportString(settings["network"])
	if network == "" {
		network = "udp"
	}
	advanced := map[string]any{"dev": "tun", "nobind": true, "remoteCertTls": "server"}
	exportCopy(advanced, exportObject(settings["tunnel"]), "mtu")
	cfg := map[string]any{"server": map[string]any{"address": address, "port": port, "network": network}, "certificates": certificates, "advanced": advanced}
	crypto := make(map[string]any)
	exportCopy(crypto, exportObject(settings["crypto"]), "dataCiphers", "authHash")
	if len(crypto) > 0 {
		cfg["crypto"] = crypto
	}
	if username := exportString(client["username"]); username != "" {
		cfg["auth"] = map[string]any{"user": username, "pass": client["password"]}
	}
	if proof, exists := client["clientProof"]; exists {
		p := exportObject(proof)
		if exportString(p["keyId"]) == "" || exportString(p["key"]) == "" {
			return nil, errors.New("OpenVPN export clientProof is incomplete")
		}
		cfg["clientProof"] = map[string]any{"keyId": p["keyId"], "key": p["key"]}
	} else if required, _ := exportObject(settings["clientProof"])["required"].(bool); required {
		return nil, errors.New("OpenVPN export requires the client's proof key")
	}
	return cfg, nil
}

func exportShadowTLSClient(settings, meta, client map[string]any, address string, port int) ([]map[string]any, error) {
	version := 3
	if v, ok := settings["version"].(float64); ok && v != 0 {
		version = int(v)
	}
	name := exportString(meta["serverName"])
	if name == "" {
		name = exportString(exportObject(settings["handshake"])["address"])
	}
	carrier := map[string]any{"address": address, "port": port, "version": version, "serverName": name}
	exportCopy(carrier, settings, "strict", "handshakeTimeout")
	if version == 3 {
		carrier["password"] = client["password"]
		if flag, exists := client["requireUuidSessionId"]; exists {
			carrier["uuidSessionId"] = flag
		}
	} else {
		exportCopy(carrier, settings, "password")
	}
	if ca := exportString(meta["ca"]); ca != "" {
		carrier["caPem"] = ca
	}
	exportCopy(carrier, meta, "fingerprint")
	inner := exportObject(settings["inner"])
	innerSettings := exportObject(inner["settings"])
	protocol := exportString(inner["protocol"])
	proxy := map[string]any{"tag": "proxy", "protocol": protocol, "proxySettings": map[string]any{"tag": "native-shadowtls", "transportLayer": true}}
	switch protocol {
	case "vless":
		user, err := exportSelectedClient(innerSettings, "clients", "email", exportString(client["email"]))
		if err != nil {
			return nil, err
		}
		outUser := map[string]any{"id": user["id"], "encryption": "none"}
		exportCopy(outUser, user, "flow", "level")
		if dialects, ok := innerSettings["dialects"].([]any); ok && len(dialects) > 0 {
			outUser["dialect"] = dialects[0]
		}
		proxy["settings"] = map[string]any{"vnext": []any{map[string]any{"address": address, "port": port, "users": []any{outUser}}}}
	case "socks":
		account, err := exportSelectedClient(innerSettings, "accounts", "user", exportString(client["innerUsername"]))
		if err != nil {
			return nil, err
		}
		proxy["settings"] = map[string]any{"servers": []any{map[string]any{"address": address, "port": port, "users": []any{map[string]any{"user": account["user"], "pass": account["pass"]}}}}}
	case "shadowsocks":
		account, err := exportSelectedClient(innerSettings, "clients", "email", exportString(client["email"]))
		if err != nil {
			return nil, err
		}
		method := exportString(account["method"])
		if method == "" {
			method = exportString(innerSettings["method"])
		}
		identity := exportString(account["password"])
		if strings.HasPrefix(method, "2022-") {
			enabled, _ := innerSettings["uuidIdentityKeys"].(bool)
			if flag, present := account["uuidIdentityKeys"].(bool); present {
				enabled = flag
			}
			if enabled {
				identity, err = conf.NormalizeSS2022IdentityKey(method, identity)
				if err != nil {
					return nil, err
				}
			}
			serverKey := exportString(innerSettings["password"])
			if serverKey == "" {
				return nil, errors.New("ShadowTLS SS2022 export requires the server PSK")
			}
			identity = serverKey + ":" + identity
		}
		server := map[string]any{"address": address, "port": port, "method": method, "password": identity}
		if strings.HasPrefix(method, "2022-") {
			// ShadowTLS carries TCP. The current client core reads UoT only
			// from the selected SS2022 server, not the surrounding settings.
			server["uot"] = true
			server["uotVersion"] = 2
		}
		exportCopy(server, account, "level")
		proxy["settings"] = map[string]any{"servers": []any{server}}
	default:
		return nil, errors.New("ShadowTLS JSON export requires VLESS, authenticated SOCKS, or encrypted Shadowsocks inner protocol")
	}
	return []map[string]any{proxy, {"tag": "native-shadowtls", "protocol": "shadowtls", "settings": carrier}}, nil
}

func (s *SubJsonService) getNativeConfig(inbound *model.Inbound, client model.Client, host string) ([]json_util.RawMessage, error) {
	outbounds, err := nativeClientOutbounds(inbound, client, host)
	if err != nil {
		return nil, err
	}
	all := make([]json_util.RawMessage, 0, len(outbounds)+len(s.defaultOutbounds))
	for _, outbound := range outbounds {
		encoded, err := json.Marshal(outbound)
		if err != nil {
			return nil, errors.New("unable to encode native outbound")
		}
		all = append(all, encoded)
	}
	all = append(all, s.defaultOutbounds...)
	config := make(map[string]any, len(s.configJson)+2)
	maps.Copy(config, s.configJson)
	config["outbounds"] = all
	config["remarks"] = s.SubService.genRemark(inbound, client.Email, "")
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to encode native subscription: %w", err)
	}
	return []json_util.RawMessage{encoded}, nil
}
