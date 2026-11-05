package service

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func nativeAnyTLSCompatibilityCurves() []string {
	return []string{"X25519", "CurveP256", "CurveP384"}
}

// coreInboundStreamSettings projects only AnyTLS defaults. Some supported
// randomized ClientHello implementations advertise a hybrid group without a
// matching key share and cannot answer the server's hybrid HelloRetryRequest.
// Classical defaults keep those clients interoperable; an explicit nonempty
// curve preference remains the administrator's choice. Stored JSON is untouched.
func coreInboundStreamSettings(protocol model.Protocol, input string) (string, error) {
	if !strings.EqualFold(string(protocol), "anytls") || strings.TrimSpace(input) == "" {
		return input, nil
	}
	var stream map[string]json.RawMessage
	if json.Unmarshal([]byte(input), &stream) != nil || stream == nil {
		return "", errors.New("invalid AnyTLS stream settings")
	}
	var security string
	if json.Unmarshal(stream["security"], &security) != nil || !strings.EqualFold(security, "tls") {
		return input, nil // The normal inbound builder validates the required TLS layer.
	}
	tlsSettings := make(map[string]json.RawMessage)
	if raw, exists := stream["tlsSettings"]; exists {
		if json.Unmarshal(raw, &tlsSettings) != nil {
			return "", errors.New("invalid AnyTLS TLS settings")
		}
		if tlsSettings == nil {
			tlsSettings = make(map[string]json.RawMessage)
		}
	}
	if raw, exists := tlsSettings["curvePreferences"]; exists {
		var curves []json.RawMessage
		if json.Unmarshal(raw, &curves) != nil {
			// StringList also accepts a scalar. Only the empty scalar is a
			// default; preserve every nonempty explicit choice as supplied.
			var scalar string
			if json.Unmarshal(raw, &scalar) != nil || scalar != "" {
				return input, nil
			}
		} else if len(curves) > 0 {
			return input, nil
		}
	}
	tlsSettings["curvePreferences"], _ = json.Marshal(nativeAnyTLSCompatibilityCurves())
	stream["tlsSettings"], _ = json.Marshal(tlsSettings)
	raw, err := json.Marshal(stream)
	return string(raw), err
}
