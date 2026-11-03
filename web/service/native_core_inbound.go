package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// A listener with no active native accounts is omitted from the next complete
// configuration. This avoids both accidental anonymous access and one expired
// listener preventing all unrelated listeners from starting.
var errNoActiveNativeClients = errors.New("native inbound has no active clients")

func isNativePanelProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "orbit", "dnstt", "dns", "openvpn", "anytls", "shadowtls", "mieru":
		return true
	}
	return false
}

// coreInboundSettings projects the panel's stored settings into the core's
// schema without modifying the stored model. In particular, client export
// certificates/keys are panel metadata; they must never become server keys.
func coreInboundSettings(inbound *model.Inbound) (string, error) {
	if inbound == nil {
		return "", errors.New("inbound is required")
	}
	return coreInboundSettingsAt(string(inbound.Protocol), inbound.Settings, inbound.ClientStats, time.Now().UnixMilli())
}

func coreInboundSettingsAt(protocol, input string, stats []xray.ClientTraffic, nowMillis int64) (string, error) {
	native := isNativePanelProtocol(protocol)
	if !native && strings.TrimSpace(input) == "" {
		return input, nil
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal([]byte(input), &settings) != nil || settings == nil {
		return "", errors.New("invalid inbound settings object")
	}
	changed := false
	var innerEmails, innerUsernames map[string]bool
	if native {
		if _, exists := settings["clientExport"]; exists {
			delete(settings, "clientExport")
			changed = true
		}
	}
	if raw, exists := settings["clients"]; exists && (native || !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))) {
		clients, err := projectCoreClients(protocol, raw, stats, nowMillis)
		if err != nil {
			return "", err
		}
		var method string
		_ = json.Unmarshal(settings["method"], &method)
		// An explicitly managed SS2022 client list must never collapse into
		// the core's single-user server-PSK mode after the last user expires.
		managedSS2022 := strings.EqualFold(protocol, "shadowsocks") && strings.HasPrefix(method, "2022-")
		if (native || managedSS2022) && len(clients) == 0 {
			return "", errNoActiveNativeClients
		}
		if strings.EqualFold(protocol, "shadowtls") && !nativeUsesOuterClients(protocol, settings) {
			// In v1/v2 these are panel subscription records, not outer auth.
			// Only the inner accounts referenced by active records may remain.
			innerEmails = make(map[string]bool, len(clients))
			innerUsernames = make(map[string]bool, len(clients))
			for _, client := range clients {
				var email string
				_ = json.Unmarshal(client["email"], &email)
				if email != "" {
					innerEmails[email] = true
				}
			}
			var panelClients []map[string]json.RawMessage
			_ = json.Unmarshal(raw, &panelClients)
			for _, client := range panelClients {
				var email, username string
				_ = json.Unmarshal(client["email"], &email)
				_ = json.Unmarshal(client["innerUsername"], &username)
				if innerEmails[email] && username != "" {
					innerUsernames[username] = true
				}
			}
			delete(settings, "clients")
		} else {
			settings["clients"], _ = json.Marshal(clients)
		}
		changed = true
	}
	// ShadowTLS carries a separate inner proxy. Its VLESS account metadata is
	// subject to the same panel filters as an ordinary VLESS listener.
	if strings.EqualFold(protocol, "shadowtls") {
		if innerRaw, exists := settings["inner"]; exists {
			var inner map[string]json.RawMessage
			if json.Unmarshal(innerRaw, &inner) != nil || inner == nil {
				return "", errors.New("invalid ShadowTLS inner settings")
			}
			var innerProtocol string
			_ = json.Unmarshal(inner["protocol"], &innerProtocol)
			if strings.EqualFold(innerProtocol, "vless") || strings.EqualFold(innerProtocol, "shadowsocks") {
				if innerEmails != nil {
					if err := validateShadowTLSInnerBindings(string(inner["settings"]), "clients", "email", innerEmails); err != nil {
						return "", err
					}
				}
				clean, err := coreInboundSettingsAt(strings.ToLower(innerProtocol), string(inner["settings"]), stats, nowMillis)
				if err != nil {
					return "", err
				}
				if innerEmails != nil {
					clean, err = bindShadowTLSInnerAccounts(clean, "clients", "email", innerEmails)
					if err != nil {
						return "", err
					}
				}
				inner["settings"] = json.RawMessage(clean)
				settings["inner"], _ = json.Marshal(inner)
				changed = true
			} else if strings.EqualFold(innerProtocol, "socks") && innerUsernames != nil {
				if err := validateShadowTLSInnerBindings(string(inner["settings"]), "accounts", "user", innerUsernames); err != nil {
					return "", err
				}
				clean, err := bindShadowTLSInnerAccounts(string(inner["settings"]), "accounts", "user", innerUsernames)
				if err != nil {
					return "", err
				}
				inner["settings"] = json.RawMessage(clean)
				settings["inner"], _ = json.Marshal(inner)
				changed = true
			}
		}
	}
	if !changed {
		return input, nil
	}
	result, err := json.MarshalIndent(settings, "", "  ")
	return string(result), err
}

// Check the persisted bindings before account expiry/enable filtering. A missing
// credential is a configuration error; a present but inactive one may safely
// disable the listener without invalidating unrelated listeners.
func validateShadowTLSInnerBindings(input, collection, identity string, allowed map[string]bool) error {
	var settings map[string]json.RawMessage
	if json.Unmarshal([]byte(input), &settings) != nil || settings == nil {
		return errors.New("invalid ShadowTLS inner account settings")
	}
	var accounts []map[string]json.RawMessage
	if json.Unmarshal(settings[collection], &accounts) != nil {
		return errors.New("invalid ShadowTLS inner account list")
	}
	matched := make(map[string]bool, len(allowed))
	for _, account := range accounts {
		var id string
		_ = json.Unmarshal(account[identity], &id)
		if id != "" && allowed[id] {
			matched[id] = true
		}
	}
	if len(allowed) == 0 || len(matched) != len(allowed) {
		return errors.New("active ShadowTLS client has no matching inner account")
	}
	return nil
}

func nativeUsesOuterClients(protocol string, settings map[string]json.RawMessage) bool {
	if !strings.EqualFold(protocol, "shadowtls") {
		return true
	}
	var version uint32
	_ = json.Unmarshal(settings["version"], &version)
	return version == 0 || version == 3
}

func coreClientFieldAllowed(protocol, field string) bool {
	// These fields existed in the original panel projection. Keep its ordinary
	// output unchanged and add only the typed account compatibility fields.
	switch strings.ToLower(protocol) {
	case "orbit":
		return field == "email" || field == "level" || field == "key" || field == "expiresAt"
	case "dnstt", "dns":
		return field == "email" || field == "level" || field == "id" || field == "username" || field == "password"
	case "openvpn":
		return field == "email" || field == "level" || field == "commonName" || field == "username" || field == "password" || field == "clientProof"
	case "anytls":
		return field == "email" || field == "level" || field == "password" || field == "uuidHashMiddle"
	case "shadowtls":
		return field == "email" || field == "level" || field == "password" || field == "requireUuidSessionId"
	case "mieru":
		return field == "email" || field == "level" || field == "username" || field == "password" || field == "uuidMetadataTrailer"
	case "vmess":
		if field == "rawUuidAuth" || field == "level" {
			return true
		}
	case "trojan":
		if field == "uuidHashPrefix" || field == "level" {
			return true
		}
	case "shadowsocks":
		if field == "uuidIdentityKeys" || field == "level" {
			return true
		}
	case "vless":
		if field == "level" {
			return true
		}
	}
	switch field {
	case "email", "id", "password", "flow", "method", "auth":
		return true
	}
	return false
}

func projectCoreClients(protocol string, raw json.RawMessage, stats []xray.ClientTraffic, nowMillis int64) ([]map[string]json.RawMessage, error) {
	var clients []json.RawMessage
	if json.Unmarshal(raw, &clients) != nil {
		return nil, errors.New("inbound clients must be an array")
	}
	active := make(map[string]bool, len(stats))
	for _, stat := range stats {
		active[stat.Email] = stat.Enable && (stat.ExpiryTime <= 0 || stat.ExpiryTime > nowMillis)
	}
	result := make([]map[string]json.RawMessage, 0, len(clients))
	for _, rawClient := range clients {
		var client map[string]json.RawMessage
		if json.Unmarshal(rawClient, &client) != nil || client == nil {
			if isNativePanelProtocol(protocol) {
				return nil, errors.New("native inbound client must be an object")
			}
			continue // Preserve the old projection for malformed legacy rows.
		}
		var email string
		_ = json.Unmarshal(client["email"], &email)
		if enabled, exists := active[email]; exists && !enabled {
			continue
		}
		if rawEnable, exists := client["enable"]; exists && !bytes.Equal(bytes.TrimSpace(rawEnable), []byte("null")) {
			var enabled bool
			if json.Unmarshal(rawEnable, &enabled) != nil {
				return nil, errors.New("client enable must be a boolean")
			}
			if !enabled {
				continue
			}
		}
		var expiry int64
		if rawExpiry, exists := client["expiryTime"]; exists {
			if json.Unmarshal(rawExpiry, &expiry) != nil {
				return nil, errors.New("client expiryTime must be an integer")
			}
			if expiry > 0 && expiry <= nowMillis {
				continue
			}
		}
		if strings.EqualFold(protocol, "orbit") {
			if raw, exists := client["expiresAt"]; exists {
				var explicit int64
				if json.Unmarshal(raw, &explicit) != nil {
					return nil, errors.New("Orbit expiresAt must be an integer")
				}
				if explicit > 0 && explicit <= nowMillis/1000 {
					continue
				}
			}
		}
		projected := make(map[string]json.RawMessage)
		for field, value := range client {
			if coreClientFieldAllowed(protocol, field) {
				projected[field] = value
			}
		}
		if strings.EqualFold(protocol, "orbit") && expiry > 0 {
			var explicit int64
			if raw, exists := projected["expiresAt"]; exists && json.Unmarshal(raw, &explicit) != nil {
				return nil, errors.New("Orbit expiresAt must be an integer")
			}
			if explicit <= 0 || explicit > expiry/1000 {
				projected["expiresAt"], _ = json.Marshal(expiry / 1000)
			}
		}
		var flow string
		if json.Unmarshal(projected["flow"], &flow) == nil && flow == "xtls-rprx-vision-udp443" {
			projected["flow"] = json.RawMessage(`"xtls-rprx-vision"`)
		}
		result = append(result, projected)
	}
	return result, nil
}

func coreInboundProjectionError(protocol string, err error) error {
	return fmt.Errorf("%s inbound: %w", protocol, err)
}

// bindShadowTLSInnerAccounts prevents disabled/deleted panel records from
// leaving an orphaned v1/v2 inner credential active after a restart.
func bindShadowTLSInnerAccounts(input, collection, identity string, allowed map[string]bool) (string, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal([]byte(input), &settings) != nil || settings == nil {
		return "", errors.New("invalid ShadowTLS inner account settings")
	}
	var accounts []map[string]json.RawMessage
	if json.Unmarshal(settings[collection], &accounts) != nil {
		return "", errors.New("invalid ShadowTLS inner account list")
	}
	active := make([]map[string]json.RawMessage, 0, len(accounts))
	for _, account := range accounts {
		var id string
		_ = json.Unmarshal(account[identity], &id)
		if id != "" && allowed[id] {
			active = append(active, account)
		}
	}
	if len(active) == 0 {
		return "", errNoActiveNativeClients
	}
	settings[collection], _ = json.Marshal(active)
	out, err := json.Marshal(settings)
	return string(out), err
}
