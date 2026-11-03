package wsoptions

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateBrowser(t *testing.T) {
	for _, value := range []string{"", "on", "off"} {
		if ValidateBrowser(value) != nil {
			t.Fatal("supported browser mode rejected")
		}
	}
	for _, value := range []string{"default", "ON", "OFF", "true", "false", " on", "off\r\n"} {
		if ValidateBrowser(value) != ErrOptions {
			t.Fatal("invalid browser mode accepted")
		}
	}
}

func TestHeaderBoundsAndReservedFields(t *testing.T) {
	for _, name := range []string{"Host", "USER-AGENT", "Connection", "Upgrade", "Content-Length", "Transfer-Encoding", "TE", "Trailer", "Origin", "Proxy-Authorization", "Proxy-Custom", "Sec-WebSocket-Key", "sec-websocket-accept", "", "X Test", "X:Test", "X-\xff"} {
		if Validate("", "", map[string]string{name: "value"}, false) == nil {
			t.Fatal("accepted reserved/invalid name", name)
		}
	}
	for _, value := range []string{"x\r\ny", "x\n", "x\t", "x\x7f", "é", strings.Repeat("x", MaxHeaderValueBytes+1)} {
		if Validate("", "", map[string]string{"X-Test": value}, false) == nil {
			t.Fatal("accepted invalid value")
		}
	}
	if Validate("", strings.Repeat("x", MaxUserAgentBytes), nil, true) != nil || Validate("", strings.Repeat("x", MaxUserAgentBytes+1), nil, true) == nil {
		t.Fatal("UA bounds")
	}
	if Validate("", "", map[string]string{strings.Repeat("X", MaxHeaderNameBytes): ""}, true) != nil || Validate("", "", map[string]string{strings.Repeat("X", MaxHeaderNameBytes+1): ""}, true) == nil {
		t.Fatal("name bounds")
	}
	m := map[string]string{}
	for i := 0; i < MaxHeaders; i++ {
		m[fmt.Sprintf("X-%d", i)] = ""
	}
	if Validate("", "", m, true) != nil {
		t.Fatal("header count at limit")
	}
	m["X-Extra"] = ""
	if Validate("", "", m, true) == nil {
		t.Fatal("header count over limit")
	}
	m = map[string]string{"X-A": strings.Repeat("x", 1021), "X-B": strings.Repeat("x", 1021), "X-C": strings.Repeat("x", 1021), "X-D": strings.Repeat("x", 1021)}
	if Validate("", "", m, true) != nil {
		t.Fatal("aggregate at limit")
	}
	m["X-E"] = ""
	if Validate("", "", m, true) == nil {
		t.Fatal("aggregate over limit")
	}
}

func TestDecodeAndCanonicalHeaders(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"X-A":null}`, `{"X-A":1}`, `{"X-A":"1","x-a":"2"}`, `{"X-A":"1","X-A":"2"}`} {
		if _, err := DecodeHeaders([]byte(raw)); err == nil {
			t.Fatal("malformed headers accepted")
		}
	}
	m, err := DecodeHeaders([]byte(`{"x-a":"value: extra","X-B":""}`))
	if err != nil || m["X-A"] != "value: extra" || len(m) != 2 {
		t.Fatal("valid headers changed", err)
	}
	copy := CanonicalHeaders(m)
	copy["X-A"] = "changed"
	if m["X-A"] != "value: extra" {
		t.Fatal("headers alias caller")
	}
}
