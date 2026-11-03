package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"google.golang.org/protobuf/proto"
)

// buildDNSTunnel deliberately rejects unknown fields, including fields inside
// inner/resolvers, so misspelled carrier settings do not silently fall back to
// an unrelated DNS-query operation. Parsing errors never echo supplied values.
func buildDNSTunnel(raw json.RawMessage) (proto.Message, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errors.New("dns: tunnel settings must be a non-null JSON object")
	}
	var shape any
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, errors.New("dns: tunnel settings must contain one valid JSON object")
	}
	if dnsTunnelHasNull(shape) {
		return nil, errors.New("dns: tunnel settings must not contain null values")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config DNSTTConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, errors.New("dns: tunnel settings contain invalid or unknown fields")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("dns: tunnel settings must contain one JSON object")
	}
	return config.Build()
}

func dnsTunnelHasNull(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case map[string]any:
		for _, child := range v {
			if dnsTunnelHasNull(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if dnsTunnelHasNull(child) {
				return true
			}
		}
	}
	return false
}
