package xray

import (
	"bytes"
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v2/util/json_util"
)

// Config represents the complete Xray configuration structure.
// It contains all sections of an Xray config file including inbounds, outbounds, routing, etc.
type Config struct {
	LogConfig        json_util.RawMessage `json:"log"`
	RouterConfig     json_util.RawMessage `json:"routing"`
	DNSConfig        json_util.RawMessage `json:"dns"`
	InboundConfigs   []InboundConfig      `json:"inbounds"`
	OutboundConfigs  json_util.RawMessage `json:"outbounds"`
	Transport        json_util.RawMessage `json:"transport"`
	Policy           json_util.RawMessage `json:"policy"`
	API              json_util.RawMessage `json:"api"`
	Stats            json_util.RawMessage `json:"stats"`
	Reverse          json_util.RawMessage `json:"reverse"`
	FakeDNS          json_util.RawMessage `json:"fakedns"`
	Observatory      json_util.RawMessage `json:"observatory"`
	BurstObservatory json_util.RawMessage `json:"burstObservatory"`
	Metrics          json_util.RawMessage `json:"metrics"`
}

// Equals compares two Config instances for deep equality. Sections that
// differ only in layout are equal: a template re-indented by the Xray page
// is the same config, and must not restart a core.
func (c *Config) Equals(other *Config) bool {
	if len(c.InboundConfigs) != len(other.InboundConfigs) {
		return false
	}
	for i, inbound := range c.InboundConfigs {
		if !inbound.Equals(&other.InboundConfigs[i]) {
			return false
		}
	}
	if !SameJSON(c.LogConfig, other.LogConfig) {
		return false
	}
	if !SameJSON(c.RouterConfig, other.RouterConfig) {
		return false
	}
	if !SameJSON(c.DNSConfig, other.DNSConfig) {
		return false
	}
	if !SameJSON(c.OutboundConfigs, other.OutboundConfigs) {
		return false
	}
	if !SameJSON(c.Transport, other.Transport) {
		return false
	}
	if !SameJSON(c.Policy, other.Policy) {
		return false
	}
	if !SameJSON(c.API, other.API) {
		return false
	}
	if !SameJSON(c.Stats, other.Stats) {
		return false
	}
	if !SameJSON(c.Reverse, other.Reverse) {
		return false
	}
	if !SameJSON(c.FakeDNS, other.FakeDNS) {
		return false
	}
	if !SameJSON(c.Metrics, other.Metrics) {
		return false
	}
	return true
}

// SameJSON reports whether a and b are the same JSON text apart from
// insignificant whitespace.
func SameJSON(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}
