package service

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
)

func TestNativeCredentialGenerators(t *testing.T) {
	a, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "dnstt"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "dnstt"})
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, _ := hex.DecodeString(a["privateKey"])
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil || hex.EncodeToString(key.PublicKey().Bytes()) != a["publicKey"] || a["privateKey"] == b["privateKey"] {
		t.Fatal("invalid DNS key generation")
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, r := range []NativeCredentialRequest{{Kind: "orbit", RealityPublicKey: public}, {Kind: "orbit", RealityPrivateKey: base64.RawURLEncoding.EncodeToString(privateBytes)}} {
		v, err := GenerateNativeCredentials(r)
		if err != nil || !strings.HasPrefix(v["key"], "vck1_") || len(v["key"]) != 91 {
			t.Fatalf("Orbit key generation failed: %v", err)
		}
	}
	p, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "openvpn-proof"})
	if err != nil || len(p["key"]) != 64 || !strings.HasPrefix(p["keyId"], "proof-") {
		t.Fatal("invalid proof key")
	}
	s, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "openvpn-tls-crypt-v2-server"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "openvpn-tls-crypt-v2", ServerKey: s["serverKey"]})
	if err != nil {
		t.Fatal(err)
	}
	server, err := ctlwrap.ParseTLSCryptV2ServerKey([]byte(s["serverKey"]))
	if err != nil {
		t.Fatal(err)
	}
	client, wkc, err := ctlwrap.ParseTLSCryptV2ClientKey([]byte(c["clientKey"]))
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, _, err := ctlwrap.UnwrapTLSCryptV2ClientKey(server, wkc)
	if err != nil || client == nil || unwrapped == nil {
		t.Fatal("issued key cannot be unwrapped")
	}
	if bytes.Contains([]byte(c["clientKey"]), []byte("SERVER")) {
		t.Fatal("returned server key as client key")
	}
}

func TestNativeCredentialFailuresDoNotEchoMaterial(t *testing.T) {
	secret := "SENSITIVE-invalid-input"
	for _, request := range []NativeCredentialRequest{{Kind: secret}, {Kind: "orbit"}, {Kind: "orbit", Certificate: secret}, {Kind: "orbit", RealityPrivateKey: secret}, {Kind: "orbit", Certificate: secret, RealityPublicKey: secret}, {Kind: "openvpn-tls-crypt-v2", ServerKey: secret}} {
		_, err := GenerateNativeCredentials(request)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("invalid request accepted or secret echoed")
		}
	}
}

func TestNativeOrbitRealityCredentials(t *testing.T) {
	a, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "orbit-reality"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "orbit-reality"})
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := base64.RawURLEncoding.Strict().DecodeString(a["privateKey"])
	if err != nil || len(privateBytes) != 32 {
		t.Fatal("invalid Reality private key")
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil || base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != a["publicKey"] {
		t.Fatal("Reality key pair does not match")
	}
	short, err := hex.DecodeString(a["shortId"])
	if err != nil || len(short) != 8 || a["shortId"] == b["shortId"] || a["privateKey"] == b["privateKey"] {
		t.Fatal("Reality short ID or key reused")
	}
	connection, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(a["key"], "vck1_"))
	pin := sha256.Sum256(private.PublicKey().Bytes())
	if err != nil || len(connection) != 64 || !bytes.Equal(connection[32:], pin[:]) {
		t.Fatal("Reality connection identity does not match public key")
	}
	if a["target"] != "www.microsoft.com:443" || a["serverName"] != "www.microsoft.com" {
		t.Fatal("Reality default target and name diverged")
	}
}
