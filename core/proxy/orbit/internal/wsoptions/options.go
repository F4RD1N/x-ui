// Package wsoptions validates optional outer WebSocket handshake settings.
package wsoptions

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/xtls/xray-core/proxy/orbit/internal/strictjson"
)

const (
	MaxUserAgentBytes   = 512
	MaxHeaders          = 16
	MaxHeaderNameBytes  = 64
	MaxHeaderValueBytes = 1024
	MaxHeaderBytes      = 4096
)

var ErrOptions = errors.New("invalid WebSocket handshake options")

// ValidateBrowser accepts the default browser-style handshake or an explicit
// compatibility opt-out. Callers canonicalize "on" to the empty default.
func ValidateBrowser(browser string) error {
	switch browser {
	case "", "on", "off":
		return nil
	default:
		return ErrOptions
	}
}

// DecodeHeaders rejects duplicate object keys and null values rather than
// silently turning malformed input into an empty HTTP header.
func DecodeHeaders(data []byte) (map[string]string, error) {
	var raw map[string]json.RawMessage
	if err := strictjson.Decode(data, &raw); err != nil || raw == nil {
		return nil, ErrOptions
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		var text string
		if strings.TrimSpace(string(value)) == "null" || json.Unmarshal(value, &text) != nil {
			return nil, ErrOptions
		}
		out[key] = text
	}
	if Validate("", "", out, false) != nil {
		return nil, ErrOptions
	}
	return CanonicalHeaders(out), nil
}

// Validate never includes potentially private header contents in errors.
// Fingerprints describe the outer WSS TLS handshake, not the inner tunnel.
func Validate(fingerprint, userAgent string, headers map[string]string, secure bool) error {
	if fingerprint != "" && !secure {
		return ErrOptions
	}
	switch fingerprint {
	case "", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn", "unsafe":
	default:
		return ErrOptions
	}
	if len(userAgent) > MaxUserAgentBytes || !printable(userAgent) || len(headers) > MaxHeaders {
		return ErrOptions
	}
	seen := make(map[string]bool, len(headers))
	total := 0
	for name, value := range headers {
		lower := strings.ToLower(name)
		if len(name) == 0 || len(name) > MaxHeaderNameBytes || seen[lower] || len(value) > MaxHeaderValueBytes || !printable(value) {
			return ErrOptions
		}
		for _, ch := range name {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", ch) {
				return ErrOptions
			}
		}
		if strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "sec-websocket-") {
			return ErrOptions
		}
		switch lower {
		case "host", "user-agent", "connection", "upgrade", "content-length", "transfer-encoding", "te", "trailer", "origin":
			return ErrOptions
		}
		seen[lower] = true
		total += len(name) + len(value)
		if total > MaxHeaderBytes {
			return ErrOptions
		}
	}
	return nil
}

func printable(value string) bool {
	for i := range value {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}

// CanonicalHeaders clones an already validated map, preventing caller mutation
// and making URI identities independent of HTTP header name casing.
func CanonicalHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(headers))
	for name, value := range headers {
		result[http.CanonicalHeaderKey(name)] = value
	}
	return result
}
