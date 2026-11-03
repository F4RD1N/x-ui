package service

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	coreconf "github.com/xtls/xray-core/infra/conf"
)

// appendNativeInnerClients merges only credentials for the outer accounts being
// added. It never accepts a replacement listener or an unrelated inner account
// from the client modal's potentially stale copy of the inbound.
func appendNativeInnerClients(protocol model.Protocol, stored, request map[string]any, added []any) (bool, error) {
	if protocol != model.ShadowTLS {
		return false, nil
	}
	for key, value := range request {
		if key != "clients" && key != "inner" {
			// Older callers may echo unchanged export metadata. It is ignored;
			// no stale or different listener-level value may be applied here.
			if old, exists := stored[key]; !exists || !reflect.DeepEqual(old, value) {
				return false, errors.New("ShadowTLS add client cannot change listener settings")
			}
		}
	}
	inner, ok := stored["inner"].(map[string]any)
	if !ok {
		if _, supplied := request["inner"]; supplied {
			return false, errors.New("ShadowTLS stored inner settings are missing")
		}
		// Preserve inactive legacy metadata. Normal inbound validation rejects
		// an active listener without an authenticated inner proxy.
		return false, nil
	}
	innerSettings, ok := inner["settings"].(map[string]any)
	if !ok {
		return false, errors.New("ShadowTLS stored inner settings are invalid")
	}
	name, _ := inner["protocol"].(string)
	collection, binding, outerBinding := "clients", "email", "email"
	allowed := map[string]bool{"email": true, "level": true}
	switch name {
	case "socks":
		collection, binding, outerBinding = "accounts", "user", "innerUsername"
		allowed = map[string]bool{"user": true, "pass": true}
	case "vless":
		for _, key := range []string{"id", "flow", "encryption"} {
			allowed[key] = true
		}
	case "shadowsocks":
		for _, key := range []string{"password", "method", "uuidIdentityKeys"} {
			allowed[key] = true
		}
	default:
		return false, errors.New("unsupported ShadowTLS inner protocol")
	}
	current, ok := innerSettings[collection].([]any)
	if !ok {
		return false, errors.New("ShadowTLS add client requires a managed inner account list")
	}
	existing := make(map[string]bool, len(current))
	credentials := make(map[string]bool, len(current))
	for _, raw := range current {
		row, ok := raw.(map[string]any)
		if !ok {
			return false, errors.New("invalid stored ShadowTLS inner account")
		}
		identity, _ := row[binding].(string)
		if identity == "" || existing[identity] {
			return false, errors.New("ambiguous stored ShadowTLS inner identity")
		}
		existing[identity] = true
		credential, err := nativeInnerAppendCredential(name, innerSettings, row)
		if err != nil {
			return false, err
		}
		if credential != "" {
			credentials[credential] = true
		}
	}
	wanted := make(map[string]bool, len(added))
	for _, raw := range added {
		row, ok := raw.(map[string]any)
		if !ok {
			return false, errors.New("invalid ShadowTLS outer account")
		}
		identity, _ := row[outerBinding].(string)
		if identity == "" || strings.TrimSpace(identity) != identity || wanted[identity] {
			return false, errors.New("ShadowTLS new accounts require unique exact inner bindings")
		}
		wanted[identity] = true
	}
	var incoming []any
	if raw, supplied := request["inner"]; supplied {
		extra, ok := raw.(map[string]any)
		if !ok || extra["protocol"] != name || len(extra) != 2 {
			return false, errors.New("ShadowTLS supplemental inner protocol must match the existing listener")
		}
		settings, ok := extra["settings"].(map[string]any)
		if !ok || len(settings) != 1 {
			return false, errors.New("ShadowTLS add client cannot change inner server settings")
		}
		incoming, ok = settings[collection].([]any)
		if !ok || len(incoming) == 0 {
			return false, errors.New("ShadowTLS supplemental inner accounts must be a nonempty array")
		}
	}
	seen := make(map[string]bool, len(incoming))
	for _, raw := range incoming {
		row, ok := raw.(map[string]any)
		if !ok {
			return false, errors.New("ShadowTLS supplemental inner account must be an object")
		}
		identity, _ := row[binding].(string)
		if !wanted[identity] || seen[identity] || existing[identity] {
			return false, errors.New("ShadowTLS supplemental inner account is unrelated, duplicate or already exists")
		}
		for key := range row {
			if !allowed[key] {
				return false, errors.New("unsupported ShadowTLS supplemental inner account field")
			}
		}
		credential, err := nativeInnerAppendCredential(name, innerSettings, row)
		if err != nil {
			return false, err
		}
		if credential != "" {
			if credentials[credential] {
				return false, errors.New("ShadowTLS new inner credential duplicates an existing account")
			}
			credentials[credential] = true
		}
		seen[identity] = true
	}
	for identity := range wanted {
		if !seen[identity] && !existing[identity] {
			return false, errors.New("ShadowTLS new client is missing its matching inner credential")
		}
	}
	if len(incoming) == 0 {
		return false, nil
	}
	// Validate the complete merged native inbound in AddInboundClient before
	// persisting it. Clone the collection so rejection cannot edit old rows.
	merged := make([]any, 0, len(current)+len(incoming))
	merged = append(merged, current...)
	merged = append(merged, incoming...)
	innerSettings[collection] = merged
	return true, nil
}

func nativeInnerAppendCredential(protocol string, settings, client map[string]any) (string, error) {
	if protocol == "socks" {
		return "", nil // SOCKS authenticates the already-unique username too.
	}
	field := "password"
	if protocol == "vless" {
		field = "id"
	}
	value, _ := client[field].(string)
	if value == "" {
		return "", errors.New("ShadowTLS inner credential is missing")
	}
	if protocol == "vless" {
		return strings.ToLower(value), nil
	}
	method, _ := settings["method"].(string)
	if strings.HasPrefix(method, "2022-") {
		enabled, _ := settings["uuidIdentityKeys"].(bool)
		if flag, exists := client["uuidIdentityKeys"]; exists {
			var ok bool
			enabled, ok = flag.(bool)
			if !ok {
				return "", errors.New("ShadowTLS UUID identity flag must be boolean")
			}
		}
		if enabled {
			var err error
			value, err = coreconf.NormalizeSS2022IdentityKey(method, value)
			if err != nil {
				return "", errors.New("invalid ShadowTLS SS2022 identity key")
			}
		}
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", errors.New("invalid ShadowTLS SS2022 identity encoding")
		}
		return string(key), nil
	}
	return value, nil
}

// renameNativeInnerClient keeps the export binding paired with an outer email
// edit. SOCKS uses its separate explicit username binding and is not renamed.
func renameNativeInnerClient(protocol model.Protocol, stored map[string]any, oldEmail, newEmail string) (bool, error) {
	if protocol != model.ShadowTLS || oldEmail == newEmail {
		return false, nil
	}
	inner, ok := stored["inner"].(map[string]any)
	if !ok {
		if _, exists := stored["inner"]; exists {
			return false, errors.New("invalid stored ShadowTLS inner settings")
		}
		return false, nil // Inactive legacy metadata has no runtime inner proxy.
	}
	name, _ := inner["protocol"].(string)
	if name == "socks" {
		return false, nil
	}
	if name != "vless" && name != "shadowsocks" {
		return false, errors.New("unsupported ShadowTLS inner protocol")
	}
	settings, ok := inner["settings"].(map[string]any)
	if !ok {
		return false, errors.New("invalid stored ShadowTLS inner settings")
	}
	rows, ok := settings["clients"].([]any)
	if !ok {
		return false, errors.New("ShadowTLS email edit requires a managed inner account list")
	}
	selected := -1
	for index, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return false, errors.New("invalid stored ShadowTLS inner account")
		}
		if row["email"] == newEmail {
			return false, errors.New("ShadowTLS target inner email already exists")
		}
		if row["email"] == oldEmail {
			if selected >= 0 {
				return false, errors.New("ShadowTLS source inner email is ambiguous")
			}
			selected = index
		}
	}
	if selected < 0 {
		return false, errors.New("ShadowTLS source inner identity is missing")
	}
	row := rows[selected].(map[string]any)
	renamed := make(map[string]any, len(row))
	for key, value := range row {
		renamed[key] = value
	}
	renamed["email"] = newEmail
	updated := append([]any(nil), rows...)
	updated[selected] = renamed
	settings["clients"] = updated
	return true, nil
}
