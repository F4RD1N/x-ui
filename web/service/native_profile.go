package service

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/orbit"
)

type NativeProfileRequirement struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// NativeInboundProfile is proposed form material, not a persisted inbound.
// Client export metadata is removed by the existing core projection; the
// subscription exporter independently selects only public and client material.
type NativeInboundProfile struct {
	Protocol       string                     `json:"protocol"`
	Settings       map[string]any             `json:"settings"`
	StreamSettings map[string]any             `json:"streamSettings,omitempty"`
	PublicKey      string                     `json:"publicKey,omitempty"`
	Requirements   []NativeProfileRequirement `json:"requirements,omitempty"`
}

func GenerateNativeInboundProfile(r NativeCredentialRequest) (*NativeInboundProfile, error) {
	switch r.Protocol {
	case "orbit", "dnstt", "openvpn", "anytls", "shadowtls", "mieru":
	default:
		return nil, errors.New("unsupported native profile protocol")
	}
	if r.Port > 65535 {
		return nil, errors.New("invalid native profile port")
	}
	name := r.ServerName
	var err error
	if name != "" {
		name, err = nativeProfileHost(name)
		if err != nil {
			return nil, errors.New("serverName must be a DNS name or IP address")
		}
	}
	var serverIP net.IP
	if r.Protocol == "orbit" {
		address := r.ServerAddress
		if address == "" && net.ParseIP(name) != nil {
			address = name
		}
		if address != "" {
			serverIP = nativeProfileIP(address)
			if serverIP == nil || (!serverIP.IsGlobalUnicast() && !serverIP.IsLoopback()) {
				return nil, errors.New("Orbit requires a numeric unicast serverAddress")
			}
			if name == "" {
				name = serverIP.String()
			}
		}
	}
	email := strings.TrimSpace(r.Email)
	if len(email) > 255 || !utf8.ValidString(email) || strings.IndexFunc(email, unicode.IsControl) >= 0 {
		return nil, errors.New("invalid native client email")
	}
	id, err := nativeProfileUUID()
	if err != nil {
		return nil, err
	}
	if email == "" {
		email = "client-" + id
	}
	subID, err := nativeProfileRandom(16)
	if err != nil {
		return nil, err
	}
	client := map[string]any{"email": email, "level": 0, "enable": true, "subId": hex.EncodeToString(subID)}
	settings := map[string]any{"clients": []any{client}}
	result := &NativeInboundProfile{Protocol: r.Protocol, Settings: settings}
	switch r.Protocol {
	case "anytls", "orbit", "openvpn":
		if r.Protocol == "anytls" {
			client["password"] = id
			settings["handshakeTimeout"], settings["maxStreams"] = 10, 128
			if name == "" {
				result.StreamSettings = map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"minVersion": "1.2"}}
				result.Requirements = append(result.Requirements, NativeProfileRequirement{"serverName", "Enter the server DNS name or IP address before generating its certificate."})
				return result, nil
			}
		}
		if r.Protocol == "orbit" {
			settings["transport"], settings["handshakeTimeout"] = "tcp", 15
			settings["maxSessions"], settings["maxFlows"], settings["udpIdleTimeout"] = 1000, 128, 60
			if serverIP == nil {
				result.Requirements = append(result.Requirements, NativeProfileRequirement{"serverAddress", "Enter the server IP address before generating its certificate and client key."})
				return result, nil
			}
		}
		pki, err := newNativeProfilePKI(name, serverIP)
		if err != nil {
			return nil, err
		}
		switch r.Protocol {
		case "anytls":
			settings["clientExport"] = map[string]any{"serverName": name, "ca": pki.caPEM}
			result.StreamSettings = map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{
				"minVersion": "1.2", "certificates": []any{map[string]any{
					"certificate": nativeProfilePEMLines(pki.serverPEM + pki.caPEM), "key": nativeProfilePEMLines(pki.serverKeyPEM),
				}},
			}}
		case "orbit":
			key, err := orbit.GenerateConnectionKey(pki.serverPEM)
			if err != nil {
				return nil, errors.New("Orbit connection key generation failed")
			}
			client["key"] = key
			settings["tls"] = map[string]any{"certificate": nativeProfilePEMLines(pki.serverPEM), "key": nativeProfilePEMLines(pki.serverKeyPEM)}
			settings["clientExport"] = map[string]any{"address": serverIP.String()}
		case "openvpn":
			issuerKey, err := x509.MarshalPKCS8PrivateKey(pki.caKey)
			if err != nil {
				return nil, errors.New("OpenVPN issuer key encoding failed")
			}
			settings["clientExport"] = map[string]any{"issuerPrivateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerKey}))}
			commonName := "client-" + id
			cert, key, err := pki.issue(commonName, "", false)
			if err != nil {
				return nil, err
			}
			serverWrap, err := ctlwrap.GenerateTLSCryptV2ServerKey()
			if err != nil {
				return nil, errors.New("OpenVPN control key generation failed")
			}
			clientWrap, err := ctlwrap.IssueTLSCryptV2ClientKey(serverWrap, nil)
			if err != nil {
				return nil, errors.New("OpenVPN client control key generation failed")
			}
			client["commonName"], client["certificate"], client["privateKey"], client["tlsCryptV2"] = commonName, cert, key, string(clientWrap)
			settings["network"] = "udp"
			settings["certificates"] = map[string]any{"ca": pki.caPEM, "cert": pki.serverPEM, "key": pki.serverKeyPEM, "tlsCryptV2": string(serverWrap.MarshalPEM())}
			settings["crypto"] = map[string]any{"dataCiphers": []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}, "authHash": "SHA256"}
			settings["tunnel"] = map[string]any{"ipv4": "10.88.0.0/24", "dns": []string{}, "mtu": 1400}
			settings["limits"] = map[string]any{"maxSessions": 128, "maxSessionsPerIP": 16, "maxFlowsPerSession": 256, "handshakeSeconds": 15, "idleSeconds": 120}
			settings["renegotiationSeconds"] = 3600
		}
	case "mieru":
		password, err := nativeProfileUUID()
		if err != nil {
			return nil, err
		}
		client["username"], client["password"] = id, password
		settings["transport"], settings["handshakeTimeout"] = "tcp", 10
	case "dnstt":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.New("DNS tunnel key generation failed")
		}
		domain := ""
		if r.Domain != "" {
			domain, err = nativeProfileHost(r.Domain)
			if err != nil || net.ParseIP(domain) != nil {
				return nil, errors.New("domain must be a DNS tunnel name")
			}
		} else {
			result.Requirements = append(result.Requirements, NativeProfileRequirement{"domain", "Enter the DNS tunnel domain configured for this deployment."})
		}
		client["id"] = id
		settings["domain"], settings["privateKey"] = domain, hex.EncodeToString(key.Bytes())
		settings["inner"] = map[string]any{"protocol": "vless"}
		settings["mtu"], settings["handshakeTimeout"], settings["maxSessions"], settings["maxStreams"] = 1232, 30, 256, 128
		result.PublicKey = hex.EncodeToString(key.PublicKey().Bytes())
	case "shadowtls":
		address := ""
		if r.HandshakeAddress != "" {
			address, err = nativeProfileHost(r.HandshakeAddress)
			if err != nil {
				return nil, errors.New("handshakeAddress must be a TLS server DNS name or IP address")
			}
		} else {
			result.Requirements = append(result.Requirements, NativeProfileRequirement{"handshake.address", "Enter the TLS handshake target for this deployment."})
		}
		serverKey, err := nativeProfileRandom(32)
		if err != nil {
			return nil, err
		}
		userKey, err := nativeProfileRandom(32)
		if err != nil {
			return nil, err
		}
		client["password"] = id
		settings["version"], settings["strict"], settings["handshakeTimeout"] = 3, true, 10
		settings["handshake"] = map[string]any{"address": address, "port": 443}
		settings["inner"] = map[string]any{"protocol": "shadowsocks", "settings": map[string]any{
			"network": "tcp", "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(serverKey),
			"clients": []any{map[string]any{"email": email, "level": 0, "password": base64.StdEncoding.EncodeToString(userKey)}},
		}}
	}
	return result, nil
}

func nativeProfileRandom(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, errors.New("secure credential generation failed")
	}
	return b, nil
}

func nativeProfileUUID() (string, error) {
	b, err := nativeProfileRandom(16)
	if err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// nativeProfileIP normalizes an explicitly supplied IP without resolving or
// inferring an endpoint. Brackets are accepted only around an IPv6 literal.
func nativeProfileIP(input string) net.IP {
	address := strings.TrimSpace(input)
	if strings.HasPrefix(address, "[") || strings.HasSuffix(address, "]") {
		if !strings.HasPrefix(address, "[") || !strings.HasSuffix(address, "]") {
			return nil
		}
		address = address[1 : len(address)-1]
		if !strings.Contains(address, ":") {
			return nil
		}
	}
	return net.ParseIP(address)
}

func nativeProfileHost(input string) (string, error) {
	host := strings.TrimSpace(input)
	if ip := nativeProfileIP(host); ip != nil {
		return ip.String(), nil
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", errors.New("invalid host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid host")
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return "", errors.New("invalid host")
			}
		}
	}
	return strings.ToLower(host), nil
}

func nativeProfilePEMLines(value string) []string {
	return strings.Split(strings.TrimSpace(value), "\n")
}

type nativeProfilePKI struct {
	ca                             *x509.Certificate
	caKey                          crypto.Signer
	caPEM, serverPEM, serverKeyPEM string
}

func newNativeProfilePKI(name string, additionalIPs ...net.IP) (*nativeProfilePKI, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("certificate key generation failed")
	}
	serial, err := nativeProfileSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Native VPN CA " + serial.Text(16)},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, errors.New("CA certificate generation failed")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("CA certificate generation failed")
	}
	p := &nativeProfilePKI{ca: parsed, caKey: key, caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	commonName := name
	if commonName == "" {
		commonName = "Native VPN server " + serial.Text(16)
	}
	p.serverPEM, p.serverKeyPEM, err = p.issue(commonName, name, true, additionalIPs...)
	return p, err
}

func nativeProfileSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("certificate serial generation failed")
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func (p *nativeProfilePKI) issue(commonName, host string, server bool, additionalIPs ...net.IP) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", errors.New("certificate key generation failed")
	}
	serial, err := nativeProfileSerial()
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if cert.NotBefore.Before(p.ca.NotBefore) {
		cert.NotBefore = p.ca.NotBefore
	}
	if cert.NotAfter.After(p.ca.NotAfter) {
		cert.NotAfter = p.ca.NotAfter
	}
	if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = []net.IP{ip}
		} else if host != "" {
			cert.DNSNames = []string{host}
		}
		for _, additional := range additionalIPs {
			if additional == nil {
				continue
			}
			duplicate := false
			for _, existing := range cert.IPAddresses {
				if existing.Equal(additional) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				cert.IPAddresses = append(cert.IPAddresses, additional)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		return "", "", errors.New("leaf certificate generation failed")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", errors.New("private key encoding failed")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

// GenerateNativeOpenVPNClient signs only with the explicit administrator-supplied
// issuer. It never replaces an existing CA or persists material by itself.
func GenerateNativeOpenVPNClient(r NativeCredentialRequest) (map[string]any, error) {
	caBlock, caRest := pem.Decode([]byte(r.CACertificate))
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(caRest)) != 0 {
		return nil, errors.New("invalid CA certificate")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	now := time.Now()
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return nil, errors.New("issuer certificate must be a currently valid certificate-signing CA")
	}
	keyBlock, keyRest := pem.Decode([]byte(r.IssuerPrivateKey))
	if keyBlock == nil || len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, errors.New("invalid issuer private key")
	}
	var rawKey any
	switch keyBlock.Type {
	case "PRIVATE KEY":
		rawKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		rawKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		rawKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, errors.New("unsupported issuer private key encoding")
	}
	if err != nil {
		return nil, errors.New("invalid issuer private key")
	}
	key, ok := rawKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("issuer private key cannot sign certificates")
	}
	switch signer := key.(type) {
	case *ecdsa.PrivateKey:
		if signer.Curve.Params().BitSize < 256 {
			return nil, errors.New("issuer elliptic curve must be at least 256 bits")
		}
	case *rsa.PrivateKey:
		if signer.N.BitLen() < 2048 {
			return nil, errors.New("issuer RSA key must be at least 2048 bits")
		}
	case ed25519.PrivateKey:
	default:
		return nil, errors.New("unsupported issuer signing key algorithm")
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(public, ca.RawSubjectPublicKeyInfo) {
		return nil, errors.New("issuer private key does not match the CA certificate")
	}
	identity, err := nativeProfileUUID()
	if err != nil {
		return nil, err
	}
	commonName := "client-" + identity
	pki := &nativeProfilePKI{ca: ca, caKey: key}
	certificate, privateKey, err := pki.issue(commonName, "", false)
	if err != nil {
		return nil, err
	}
	client := map[string]any{"commonName": commonName, "certificate": certificate, "privateKey": privateKey}
	if r.ServerKey != "" {
		wrap, err := ctlwrap.ParseTLSCryptV2ServerKey([]byte(r.ServerKey))
		if err != nil {
			return nil, errors.New("invalid TLS-crypt-v2 server key")
		}
		wrapped, err := ctlwrap.IssueTLSCryptV2ClientKey(wrap, nil)
		if err != nil {
			return nil, errors.New("TLS-crypt-v2 client key generation failed")
		}
		client["tlsCryptV2"] = string(wrapped)
	}
	if r.ClientProofRequired {
		proof, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "openvpn-proof"})
		if err != nil {
			return nil, err
		}
		client["clientProof"] = proof
	}
	return map[string]any{"client": client}, nil
}
