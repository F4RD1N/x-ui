package service

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type outboundProbeBody struct {
	reader io.Reader
	closed bool
}

func (b *outboundProbeBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *outboundProbeBody) Close() error {
	b.closed = true
	return nil
}

type outboundProbeErrorReader struct{ err error }

func (r outboundProbeErrorReader) Read([]byte) (int, error) { return 0, r.err }

type outboundProbeTransport struct {
	responses []*http.Response
	err       error
	calls     int
	closed    int
}

func (p *outboundProbeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	if p.calls > len(p.responses) {
		return nil, errors.New("unexpected extra probe request")
	}
	return p.responses[p.calls-1], nil
}

func (p *outboundProbeTransport) CloseIdleConnections() { p.closed++ }

func TestOutboundMeasurementDetectsIncompleteResponses(t *testing.T) {
	for _, failAt := range []int{0, 1} {
		name := []string{"warmup", "measured"}[failAt]
		t.Run(name, func(t *testing.T) {
			bodies := []*outboundProbeBody{
				{reader: strings.NewReader("warmup")},
				{reader: strings.NewReader("measurement")},
			}
			bodies[failAt].reader = io.MultiReader(strings.NewReader("partial"), outboundProbeErrorReader{io.ErrUnexpectedEOF})
			transport := &outboundProbeTransport{responses: []*http.Response{
				{StatusCode: 200, Body: bodies[0]},
				{StatusCode: 200, Body: bodies[1]},
			}}
			_, _, err := measureOutboundHTTP(&http.Client{Transport: transport}, "https://probe.example.test/")
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated %s response reported as success: %v", name, err)
			}
			if transport.calls != failAt+1 || transport.closed != 1 {
				t.Fatalf("probe cleanup or request count: calls=%d closed=%d", transport.calls, transport.closed)
			}
			for i := 0; i <= failAt; i++ {
				if !bodies[i].closed {
					t.Fatalf("response %d was not closed", i)
				}
			}
		})
	}
}

func TestOutboundMeasurementKeepsHTTPStatusReachability(t *testing.T) {
	for _, status := range []int{204, 200, 403, 503} {
		first := &outboundProbeBody{reader: strings.NewReader("warmup")}
		second := &outboundProbeBody{reader: strings.NewReader("complete response")}
		transport := &outboundProbeTransport{responses: []*http.Response{
			{StatusCode: status, Body: first}, {StatusCode: status, Body: second},
		}}
		delay, code, err := measureOutboundHTTP(&http.Client{Transport: transport}, "https://probe.example.test/")
		if err != nil || code != status || delay < 0 {
			t.Fatalf("HTTP status %d: delay=%d code=%d err=%v", status, delay, code, err)
		}
		if transport.calls != 2 || transport.closed != 1 || !first.closed || !second.closed {
			t.Fatalf("HTTP status %d: responses or idle connections were not closed", status)
		}
	}
}

func TestOutboundMeasurementClosesTransportOnRequestFailure(t *testing.T) {
	transport := &outboundProbeTransport{err: errors.New("connection refused")}
	_, _, err := measureOutboundHTTP(&http.Client{Transport: transport}, "https://probe.example.test/")
	if err == nil || transport.calls != 1 || transport.closed != 1 {
		t.Fatalf("request failure not propagated/cleaned: err=%v calls=%d closed=%d", err, transport.calls, transport.closed)
	}
}

func TestOutboundTestUsesSelectedConfiguration(t *testing.T) {
	selected := map[string]any{"tag": "proxy", "protocol": "anytls", "settings": map[string]any{"password": "new"}}
	stale := map[string]any{"tag": "proxy", "protocol": "anytls", "settings": map[string]any{"password": "old"}}
	direct := map[string]any{"tag": "direct", "protocol": "freedom"}
	dependencies := []any{stale, direct}
	tag, outbounds, err := prepareOutboundTest(selected, dependencies)
	if err != nil || tag != "proxy" || len(outbounds) != 2 || !reflect.DeepEqual(outbounds[0], selected) || !reflect.DeepEqual(outbounds[1], direct) {
		t.Fatalf("selected config not used: tag=%s outbounds=%v err=%v", tag, outbounds, err)
	}
	if !reflect.DeepEqual(dependencies[0], stale) {
		t.Fatal("dependency list was mutated")
	}
	_, appended, err := prepareOutboundTest(selected, []any{direct})
	if err != nil || len(appended) != 2 || !reflect.DeepEqual(appended[1], selected) {
		t.Fatalf("missing selected outbound was not included: %v %v", appended, err)
	}
	if _, _, err := prepareOutboundTest(selected, []any{stale, stale}); err == nil {
		t.Fatal("duplicate selected tag accepted")
	}
}

func TestShadowTLSOutboundTestRequiresUnambiguousInnerChain(t *testing.T) {
	carrier := map[string]any{"tag": "carrier", "protocol": "shadowtls", "settings": map[string]any{"password": "current"}}
	inner := func(tag, protocol string, transportLayer bool) map[string]any {
		return map[string]any{"tag": tag, "protocol": protocol, "proxySettings": map[string]any{"tag": "carrier", "transportLayer": transportLayer}}
	}
	for _, protocol := range []string{"vless", "socks", "shadowsocks"} {
		proxy := inner("proxy", protocol, true)
		tag, outbounds, err := prepareOutboundTest(carrier, []any{proxy, carrier})
		if err != nil || tag != "proxy" || len(outbounds) != 2 || !reflect.DeepEqual(outbounds[0], proxy) || !reflect.DeepEqual(outbounds[1], carrier) {
			t.Fatalf("%s chain changed or not selected: %s %v %v", protocol, tag, outbounds, err)
		}
	}
	for _, test := range []struct {
		name string
		deps []any
	}{
		{"missing", []any{carrier}},
		{"ambiguous", []any{inner("one", "vless", true), inner("two", "socks", true), carrier}},
		{"non-transport", []any{inner("proxy", "vless", false), carrier}},
		{"unencoded-traffic", []any{inner("proxy", "freedom", true), carrier}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := prepareOutboundTest(carrier, test.deps); err == nil {
				t.Fatal("invalid/ambiguous carrier test accepted")
			}
		})
	}
}
