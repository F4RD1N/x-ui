package native_client

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/xtls/xray-core/infra/conf"
)

var errEndpoint = errors.New("A valid server endpoint is required")

// Host validates an explicit endpoint without resolving or inferring addresses.
// It accepts private/loopback addresses for locally deployed listeners, but not
// unspecified, multicast, scoped, or syntactically ambiguous addresses.
func Host(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "/\\@?#%") {
		return "", errEndpoint
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
		if !strings.Contains(value, ":") {
			return "", errEndpoint
		}
	}
	if ip := net.ParseIP(value); ip != nil {
		if !ip.IsGlobalUnicast() && !ip.IsLoopback() {
			return "", errEndpoint
		}
		return ip.String(), nil
	}
	value = strings.TrimSuffix(value, ".")
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, ":[]") {
		return "", errEndpoint
	}
	allNumeric := true
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errEndpoint
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' {
				allNumeric = false
			} else if c < '0' || c > '9' {
				return "", errEndpoint
			}
		}
	}
	if allNumeric {
		return "", errEndpoint
	}
	return strings.ToLower(value), nil
}

// RequestHost parses only the HTTP Host authority. Forwarding/client-IP headers
// are intentionally not consulted by the authenticated copy endpoint.
func RequestHost(authority string) (string, error) {
	if authority == "" || authority != strings.TrimSpace(authority) {
		return "", errEndpoint
	}
	host := authority
	if name, port, err := net.SplitHostPort(authority); err == nil {
		if port == "" || strings.IndexFunc(port, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			return "", errEndpoint
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errEndpoint
		}
		host = name
	}
	return Host(host)
}

// FullConfig reuses the subscription serializer, but builds a standalone client
// template with a loopback SOCKS listener. It never copies server routing,
// listeners, management ports, issuer keys, or whole inbound settings.
func FullConfig(inbound *model.Inbound, client model.Client, fallbackHost string) (json.RawMessage, error) {
	if inbound == nil || !Supports(inbound.Protocol) {
		return nil, errors.New("This protocol does not support native client JSON")
	}
	host, err := Host(fallbackHost)
	if err != nil {
		return nil, err
	}
	var settings map[string]any
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil || settings == nil {
		return nil, errors.New("The saved client configuration is invalid")
	}
	address := strings.TrimSpace(inbound.Listen)
	if address == "" || address == "0.0.0.0" || address == "::" || address == "::0" {
		address = host
	}
	if inbound.Protocol == model.Orbit {
		if value, exists := exportObject(settings["clientExport"])["address"]; exists {
			text, ok := value.(string)
			if !ok {
				return nil, errEndpoint
			}
			address = strings.TrimSpace(text)
		}
	}
	address, err = Host(address)
	if err != nil {
		return nil, err
	}
	if inbound.Protocol == model.Orbit && net.ParseIP(address) == nil {
		return nil, errors.New("Configure a numeric Orbit client server address")
	}
	copyInbound := *inbound
	copyInbound.Listen = address
	outbounds, err := ClientOutbounds(&copyInbound, client, host)
	if err != nil {
		return nil, errors.New("The selected client is missing valid connection material")
	}
	outbounds = append(outbounds,
		map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}},
		map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
	)
	remarks := inbound.Remark
	if remarks == "" {
		remarks = string(inbound.Protocol)
	}
	if client.Email != "" {
		remarks += " - " + client.Email
	}
	config := map[string]any{
		"remarks": remarks,
		"log":     map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": outbounds,
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
		}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, errors.New("Unable to build the client configuration")
	}
	var typed conf.Config
	if json.Unmarshal(encoded, &typed) != nil {
		return nil, errors.New("The client configuration is invalid")
	}
	if _, err := typed.Build(); err != nil {
		// Builders can quote invalid private input. Never expose that error
		// through an HTTP response or the panel's error logging helper.
		return nil, errors.New("The selected client configuration cannot be used by this core")
	}
	return encoded, nil
}
