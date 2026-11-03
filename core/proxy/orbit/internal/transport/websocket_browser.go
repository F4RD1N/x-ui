package transport

import (
	"net/http"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/proxy/orbit/internal/wsoptions"
)

// webSocketHeaders builds only HTTP handshake defaults. It neither schedules
// traffic nor modifies the encrypted native protocol or a saved connection URI.
// The owned Host, not the separately selected dial address, defines Origin.
func webSocketHeaders(o WebSocketDialOptions) (http.Header, error) {
	headers := make(http.Header, len(o.Headers)+5)
	for name, value := range wsoptions.CanonicalHeaders(o.Headers) {
		headers.Set(name, value)
	}
	if o.Browser != "off" {
		scheme := "http"
		if o.Secure {
			scheme = "https"
		}
		headers.Set("Origin", scheme+"://"+o.Host)
		for name, value := range map[string]string{
			"Cache-Control":   "no-cache",
			"Pragma":          "no-cache",
			"Accept-Language": "en-US,en;q=0.9",
		} {
			// Presence matters: an explicitly empty custom value is an override.
			if _, exists := headers[name]; !exists {
				headers.Set(name, value)
			}
		}
		if o.UserAgent == "" {
			agent, err := webSocketUserAgent(o.Fingerprint)
			if err != nil {
				return nil, err
			}
			headers.Set("User-Agent", agent)
		}
	}
	if o.UserAgent != "" {
		headers.Set("User-Agent", o.UserAgent)
	}
	return headers, nil
}

// These are versioned HTTP templates, not an assertion that a real browser is
// executing. Known browser versions track the pinned uTLS ClientHello IDs.
// Non-browser/randomized/legacy profiles get no claimed browser version.
func webSocketUserAgent(fingerprint string) (string, error) {
	if fingerprint == "" {
		fingerprint = "chrome" // WS has no TLS, but uses the same HTTP defaults.
	}
	if fingerprint == "unsafe" || fingerprint == "randomized" || fingerprint == "randomizednoalpn" {
		return "Mozilla/5.0", nil
	}
	id, err := fingerprintID(fingerprint)
	if err != nil {
		return "", err
	}
	switch id.Client {
	case utls.HelloChrome_Auto.Client:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + id.Version + ".0.0.0 Safari/537.36", nil
	case utls.HelloFirefox_Auto.Client:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + id.Version + ".0) Gecko/20100101 Firefox/" + id.Version + ".0", nil
	case utls.HelloSafari_Auto.Client:
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + id.Version + " Safari/605.1.15", nil
	case utls.HelloIOS_Auto.Client:
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + id.Version + ".0 Mobile/15E148 Safari/604.1", nil
	case utls.HelloEdge_Auto.Client:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + id.Version + ".0.0.0 Safari/537.36 Edg/" + id.Version + ".0.0.0", nil
	default:
		return "Mozilla/5.0", nil
	}
}
