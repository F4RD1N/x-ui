package service

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/orbit"
)

// NativeCredentialRequest contains explicit, administrator-supplied material.
// Nothing is persisted or written to logs by this helper.
type NativeCredentialRequest struct {
	Kind                string `json:"kind"`
	Certificate         string `json:"certificate,omitempty"`
	RealityPublicKey    string `json:"realityPublicKey,omitempty"`
	RealityPrivateKey   string `json:"realityPrivateKey,omitempty"`
	ServerKey           string `json:"serverKey,omitempty"`
	Protocol            string `json:"protocol,omitempty"`
	ServerName          string `json:"serverName,omitempty"`
	ServerAddress       string `json:"serverAddress,omitempty"`
	Email               string `json:"email,omitempty"`
	Domain              string `json:"domain,omitempty"`
	HandshakeAddress    string `json:"handshakeAddress,omitempty"`
	Port                uint32 `json:"port,omitempty"`
	CACertificate       string `json:"caCertificate,omitempty"`
	IssuerPrivateKey    string `json:"issuerPrivateKey,omitempty"`
	ClientProofRequired bool   `json:"clientProofRequired,omitempty"`
}

func GenerateNativeCredentials(r NativeCredentialRequest) (map[string]string, error) {
	switch r.Kind {
	case "orbit-reality":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.New("Reality key generation failed")
		}
		shortID, err := nativeProfileRandom(8)
		if err != nil {
			return nil, err
		}
		public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		connection, err := orbit.GenerateRealityConnectionKey(public)
		if err != nil {
			return nil, errors.New("Reality connection key generation failed")
		}
		return map[string]string{
			"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "publicKey": public,
			"shortId": hex.EncodeToString(shortID), "key": connection,
			"target": "www.microsoft.com:443", "serverName": "www.microsoft.com",
		}, nil
	case "dnstt":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.New("key generation failed")
		}
		return map[string]string{"privateKey": hex.EncodeToString(key.Bytes()), "publicKey": hex.EncodeToString(key.PublicKey().Bytes())}, nil
	case "orbit":
		count := 0
		for _, v := range []string{r.Certificate, r.RealityPublicKey, r.RealityPrivateKey} {
			if v != "" {
				count++
			}
		}
		if count != 1 {
			return nil, errors.New("Orbit requires exactly one leaf certificate or Reality key")
		}
		var key string
		var err error
		if r.Certificate != "" {
			key, err = orbit.GenerateConnectionKey(r.Certificate)
		} else {
			public := r.RealityPublicKey
			if r.RealityPrivateKey != "" {
				b, e := base64.RawURLEncoding.Strict().DecodeString(r.RealityPrivateKey)
				if e != nil || len(b) != 32 {
					return nil, errors.New("invalid Reality private key")
				}
				private, e := ecdh.X25519().NewPrivateKey(b)
				if e != nil {
					return nil, errors.New("invalid Reality private key")
				}
				public = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
			}
			key, err = orbit.GenerateRealityConnectionKey(public)
		}
		if err != nil {
			return nil, errors.New("cannot generate Orbit key from supplied public identity")
		}
		return map[string]string{"key": key}, nil
	case "openvpn-proof":
		var secret [32]byte
		var id [8]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return nil, errors.New("key generation failed")
		}
		if _, err := rand.Read(id[:]); err != nil {
			return nil, errors.New("key generation failed")
		}
		return map[string]string{"keyId": "proof-" + hex.EncodeToString(id[:]), "key": hex.EncodeToString(secret[:])}, nil
	case "openvpn-tls-crypt-v2":
		server, err := ctlwrap.ParseTLSCryptV2ServerKey([]byte(r.ServerKey))
		if err != nil {
			return nil, errors.New("invalid TLS-crypt-v2 server key")
		}
		client, err := ctlwrap.IssueTLSCryptV2ClientKey(server, nil)
		if err != nil {
			return nil, errors.New("TLS-crypt-v2 client key generation failed")
		}
		return map[string]string{"clientKey": string(client)}, nil
	case "openvpn-tls-crypt-v2-server":
		key, err := ctlwrap.GenerateTLSCryptV2ServerKey()
		if err != nil {
			return nil, errors.New("TLS-crypt-v2 server key generation failed")
		}
		return map[string]string{"serverKey": string(key.MarshalPEM())}, nil
	default:
		return nil, errors.New("unsupported native credential kind")
	}
}
