package conf_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openvpn"
	"google.golang.org/protobuf/proto"
)

const proofTestSecret = "4343434343434343434343434343434343434343434343434343434343434343"

func TestOpenVPNClientProofJSONForms(t *testing.T) {
	proof := `"clientProof":{"keyId":"test-key_1","key":"` + proofTestSecret + `"}`
	forms := []string{
		`{"ovpn":` + jsonString(testOVPN) + `,` + proof + `}`,
		`{"ovpnBase64":` + jsonString(base64.StdEncoding.EncodeToString([]byte(testOVPN))) + `,` + proof + `}`,
		`{"server":{"address":"192.0.2.10","port":1194,"network":"udp"},"certificates":{"ca":` + jsonString(testCA) + `},` + proof + `}`,
	}
	for i, raw := range forms {
		var c OpenVPNConfig
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("form %d: %v", i, err)
		}
		msg, err := c.Build()
		if err != nil {
			t.Fatalf("form %d: %v", i, err)
		}
		result := msg.(*openvpn.Config)
		if result.ClientProof == nil || result.ClientProof.KeyId != "test-key_1" || !bytes.Equal(result.ClientProof.Key, bytes.Repeat([]byte{0x43}, 32)) {
			t.Fatalf("form %d: proof lost", i)
		}
		rawProto, err := proto.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var decoded openvpn.Config
		if err := proto.Unmarshal(rawProto, &decoded); err != nil || !proto.Equal(result, &decoded) {
			t.Fatalf("protobuf round-trip: %v", err)
		}
		if _, err := decoded.ParseOptions(); err != nil {
			t.Fatal(err)
		}
	}
	var normal OpenVPNConfig
	if err := json.Unmarshal([]byte(`{"ovpn":`+jsonString(testOVPN)+`}`), &normal); err != nil {
		t.Fatal(err)
	}
	result, err := normal.Build()
	if err != nil || result.(*openvpn.Config).ClientProof != nil {
		t.Fatal("normal configuration acquired proof")
	}
}

func TestOpenVPNClientProofRejectsMalformedJSON(t *testing.T) {
	bad := []string{
		`null`, `false`, `"text"`, `[]`, `{}`,
		`{"keyId":"id"}`, `{"keyId":"id","key":""}`, `{"keyId":"id","key":null}`,
		`{"keyId":null,"key":"` + proofTestSecret + `"}`,
		`{"keyId":"id","key":"` + proofTestSecret + `","keyFile":null}`,
		`{"keyId":"id","key":"` + proofTestSecret + `","keyFile":"secret.file"}`,
		`{"keyId":"id","key":"` + proofTestSecret + `","unknown":"private-marker"}`,
		`{"keyId":"id","Key":"` + proofTestSecret + `"}`,
		`{"keyId":"id","key":"` + proofTestSecret + `","key":"` + proofTestSecret + `"}`,
		`{"keyId":"id","key":9}`, `{"keyId":"id","key":"00"}`,
		`{"keyId":"a.b","key":"` + proofTestSecret + `"}`,
		`{"keyId":"` + strings.Repeat("x", 65) + `","key":"` + proofTestSecret + `"}`,
		`{"keyId":"id","key":"` + strings.Repeat("g", 64) + `"}`,
	}
	for i, proof := range bad {
		var c OpenVPNConfig
		err := json.Unmarshal([]byte(`{"ovpn":`+jsonString(testOVPN)+`,"clientProof":`+proof+`}`), &c)
		if err == nil {
			_, err = c.Build()
		}
		if err == nil {
			t.Errorf("malformed case %d accepted", i)
		}
		if err != nil && (strings.Contains(err.Error(), proofTestSecret) || strings.Contains(err.Error(), "private-marker")) {
			t.Errorf("case %d error exposes private content", i)
		}
	}
	for _, field := range []string{"ClientProof", "clientproof", "CLIENTPROOF"} {
		var c OpenVPNConfig
		if err := json.Unmarshal([]byte(`{"ovpn":`+jsonString(testOVPN)+`,`+jsonString(field)+`:null}`), &c); err == nil {
			t.Errorf("ambiguous field spelling %s accepted", field)
		}
	}
	var c OpenVPNConfig
	if err := json.Unmarshal([]byte(`{"ovpn":`+jsonString(testOVPN)+`,"clientProof":{},"clientProof":{}}`), &c); err == nil {
		t.Fatal("duplicate top-level proof accepted")
	}
}

func TestOpenVPNClientProofKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proof.key")
	write := func(text string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	build := func() (*openvpn.Config, error) {
		var c OpenVPNConfig
		err := json.Unmarshal([]byte(`{"ovpn":`+jsonString(testOVPN)+`,"clientProof":{"keyId":"file-key","keyFile":`+jsonString(path)+`}}`), &c)
		if err != nil {
			return nil, err
		}
		msg, err := c.Build()
		if err != nil {
			return nil, err
		}
		return msg.(*openvpn.Config), nil
	}
	write(proofTestSecret+"\n", 0600)
	config, err := build()
	if err != nil || config.ClientProof == nil || len(config.ClientProof.Key) != 32 {
		t.Fatalf("private file rejected: %v", err)
	}
	// The config contains a snapshot, not a path that gets reread during retry.
	write(strings.Repeat("5", 64), 0600)
	if hex.EncodeToString(config.ClientProof.Key) != proofTestSecret {
		t.Fatal("loaded key changed after file rotation")
	}
	write(proofTestSecret+strings.Repeat(" ", 64), 0600)
	if _, err := build(); err != nil {
		t.Fatalf("128-byte file rejected: %v", err)
	}
	for _, text := range []string{"", proofTestSecret + strings.Repeat(" ", 65), "private-marker-invalid-key", strings.Repeat("g", 64)} {
		write(text, 0600)
		if _, err := build(); err == nil {
			t.Fatal("invalid key file accepted")
		} else if strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), proofTestSecret) {
			t.Fatal("file content in error")
		}
	}
	if runtime.GOOS != "windows" {
		write(proofTestSecret, 0644)
		if _, err := build(); err == nil {
			t.Fatal("publicly readable key file accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(dir, "real-private.key")
		if err := os.WriteFile(target, []byte(proofTestSecret), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := build(); err == nil {
			t.Fatal("symlink key file accepted")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := build(); err == nil {
		t.Fatal("missing key file accepted")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := build(); err == nil {
		t.Fatal("directory accepted as key file")
	}
}

func TestOpenVPNClientProofFormattingAndProtoValidation(t *testing.T) {
	var c OpenVPNConfig
	input := `{"ovpn":` + jsonString(testOVPN) + `,"clientProof":{"keyId":"id","key":"` + proofTestSecret + `"}}`
	if err := json.Unmarshal([]byte(input), &c); err != nil {
		t.Fatal(err)
	}
	msg, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	pc := msg.(*openvpn.Config)
	before := bytes.Clone(pc.ClientProof.Key)
	for _, value := range []any{c.ClientProof, *c.ClientProof, pc, pc.ClientProof} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			output := fmt.Sprintf(verb, value)
			if strings.Contains(output, proofTestSecret) || strings.Contains(output, strings.Repeat("C", 32)) || strings.Contains(output, strings.TrimRight(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)), "=")) {
				t.Errorf("proof key exposed using %s", verb)
			}
		}
	}
	for _, text := range []string{pc.String(), pc.ClientProof.String()} {
		if strings.Contains(text, strings.Repeat("C", 32)) || strings.Contains(text, proofTestSecret) {
			t.Fatal("String leaks key")
		}
	}
	if !bytes.Equal(before, pc.ClientProof.Key) {
		t.Fatal("diagnostic formatting altered the live key")
	}
	for _, bad := range []*openvpn.ClientProofConfig{{}, {KeyId: "bad.id", Key: make([]byte, 32)}, {KeyId: "id", Key: make([]byte, 31)}} {
		config := &openvpn.Config{Ovpn: testOVPN, ClientProof: bad}
		if _, err := config.ParseOptions(); err == nil {
			t.Fatal("malformed protobuf proof accepted")
		}
	}
}

func FuzzOpenVPNClientProofJSON(f *testing.F) {
	for _, raw := range []string{`null`, `{}`, `{"keyId":"id","key":"` + proofTestSecret + `"}`, `{"keyId":"id","keyFile":"not-opened-during-unmarshal"}`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		var c OpenVPNConfig
		err := json.Unmarshal([]byte(`{"ovpn":"not-parsed-here","clientProof":`+raw+`}`), &c)
		if err == nil && c.ClientProof == nil {
			t.Fatal("explicit proof silently disabled")
		}
	})
}

func TestOpenVPNNoProofDecoderCompatibility(t *testing.T) {
	// Alias removes the newly added UnmarshalJSON method, reproducing the
	// previous plain encoding/json behavior for normal configuration settings.
	type previous OpenVPNConfig
	forms := []string{
		`null`, `{}`, `{"username":"first","username":"last"}`,
		`{"Username":"first","USERNAME":"last"}`,
		`{"ovpn":"first","OVPN":"last"}`,
		`{"ovpn":["client","remote 192.0.2.1"]}`,
		`{"auth":{"user":"first"},"auth":{"user":"last"}}`,
		`{"unknown":true}`, `{"username":null}`,
		`{"ovpn":42}`, `[]`, `"text"`, `42`,
	}
	for _, input := range forms {
		actual := OpenVPNConfig{Username: "original", Password: "original-password"}
		old := previous{Username: "original", Password: "original-password"}
		err := json.Unmarshal([]byte(input), &actual)
		oldErr := json.Unmarshal([]byte(input), &old)
		if (err == nil) != (oldErr == nil) {
			t.Errorf("decode result differs for %s", input)
			continue
		}
		if err != nil {
			continue
		}
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(old)
		if string(a) != string(b) {
			t.Errorf("ordinary decoding changed for %s", input)
		}
	}
}
