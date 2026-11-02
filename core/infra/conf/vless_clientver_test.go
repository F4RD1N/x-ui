package conf_test

import (
	"bytes"
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless/inbound"
)

func TestVLessInboundClientVer(t *testing.T) {
	build := func(extra string) (*inbound.Config, error) {
		c := new(VLessInboundConfig)
		js := `{"clients":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b"}],"decryption":"none"` + extra + `}`
		if err := json.Unmarshal([]byte(js), c); err != nil {
			t.Fatal(err)
		}
		m, err := c.Build()
		if err != nil {
			return nil, err
		}
		return m.(*inbound.Config), nil
	}
	for _, c := range []struct {
		extra    string
		min, max []byte
	}{
		{``, nil, nil},
		{`,"minClientVer":"","maxClientVer":""`, nil, nil},
		{`,"minClientVer":"25.3.6"`, []byte{25, 3, 6}, nil},
		{`,"maxClientVer":"26.3.27"`, nil, []byte{26, 3, 27}},
		{`,"minClientVer":"25.9","maxClientVer":" 26 "`, []byte{25, 9, 0}, []byte{26, 0, 0}},
	} {
		cfg, err := build(c.extra)
		if err != nil {
			t.Fatalf("%s: %v", c.extra, err)
		}
		if !bytes.Equal(cfg.MinClientVer, c.min) || !bytes.Equal(cfg.MaxClientVer, c.max) {
			t.Errorf("%s: got %v %v, want %v %v", c.extra, cfg.MinClientVer, cfg.MaxClientVer, c.min, c.max)
		}
	}
	for _, bad := range []string{`,"minClientVer":"25.3.6.1"`, `,"minClientVer":"256.0.0"`, `,"maxClientVer":"a.b.c"`, `,"maxClientVer":"25..6"`} {
		if _, err := build(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}
