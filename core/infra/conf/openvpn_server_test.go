package conf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openvpn"
)

func TestNativeOpenVPNFullConfigAliases(t *testing.T) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-server"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	cp := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kp := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	settings := map[string]any{"certificates": map[string]any{"ca": cp, "cert": cp, "key": kp}, "clients": []any{map[string]any{"email": "alias@test", "commonName": "client", "clientProof": map[string]any{"keyId": "client", "key": strings.Repeat("ab", 32)}}}, "clientProof": map[string]any{"required": true}}
	for _, name := range []string{"ov", "openvpn"} {
		t.Run(name, func(t *testing.T) {
			value := map[string]any{"inbounds": []any{map[string]any{"protocol": name, "port": 1194, "listen": "127.0.0.1", "settings": settings}}, "outbounds": []any{map[string]any{"protocol": name, "settings": map[string]any{"ovpn": testOVPN}}}}
			b, _ := json.Marshal(value)
			var c conf.Config
			if e = json.Unmarshal(b, &c); e != nil {
				t.Fatal(e)
			}
			built, e := c.Build()
			if e != nil {
				t.Fatal(e)
			}
			in, e := built.Inbound[0].ProxySettings.GetInstance()
			if e != nil {
				t.Fatal(e)
			}
			native, ok := in.(*openvpn.ServerConfig)
			if !ok {
				t.Fatalf("wrong inbound %T", in)
			}
			decoded, e := openvpn.ParseServerSettings(native.Settings)
			if e != nil || !decoded.ClientProof.Required || decoded.Clients[0].ClientProof.KeyID != "client" {
				t.Fatal("inbound proof lost", e)
			}
			out, e := built.Outbound[0].ProxySettings.GetInstance()
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := out.(*openvpn.Config); !ok {
				t.Fatalf("wrong outbound %T", out)
			}
		})
	}
}
