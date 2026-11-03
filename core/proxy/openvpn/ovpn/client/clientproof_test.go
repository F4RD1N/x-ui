package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
)

func TestClientProofNormalPeerInfoUnchanged(t *testing.T) {
	c := &Client{d: &dialer{cfg: Config{Platform: "android"}, ciphers: []string{"AES-256-GCM", "AES-128-GCM"}}}
	const expected = "IV_VER=2.6.12\nIV_PLAT=android\nIV_PROTO=222\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:AES-128-GCM\nIV_MTU=1600\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_LZO=1\nIV_LZ4=1\nIV_LZ4v2=1\n"
	if got := c.peerInfo(true); got != expected {
		t.Fatalf("normal wire metadata changed: %q", got)
	}
}

func TestClientProofFreshOnRenegotiationAndAuthToken(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("tcp-%v-tls-%x", tcp, version), func(t *testing.T) {
				secret := bytes.Repeat([]byte{0x43}, 32)
				key, err := clientproof.New("client-test", secret)
				if err != nil {
					t.Fatal(err)
				}
				type observation struct {
					proof string
					err   error
				}
				seen := make(chan observation, 16)
				srv := startServer(t, srvConfig{tcp: tcp, cipher: "AES-256-GCM", ekm: true, tlsMin: version, tlsMax: version, authToken: "renewed-token", renegAfter: 180 * time.Millisecond, observePeerInfo: func(info string, cs tls.ConnectionState) {
					var proof string
					for _, line := range strings.Split(info, "\n") {
						if strings.HasPrefix(line, clientproof.PeerInfoKey+"=") {
							proof = strings.TrimPrefix(line, clientproof.PeerInfoKey+"=")
						}
					}
					exporter, err := cs.ExportKeyingMaterial(clientproof.ExporterLabel, nil, clientproof.ExporterLength)
					if err == nil {
						err = clientproof.Verify(proof, exporter, secret)
					}
					clear(exporter)
					seen <- observation{proof, err}
				}})
				c := mustDial(t, srv, sessionOpts{cfg: func(cfg *Config) {
					cfg.ClientProof = key
					cfg.DisableEKM = tcp
					cfg.Username = "alice"
					cfg.Password = "password"
				}})
				defer c.Close()
				var last string
				for i := 0; i < 2; i++ {
					select {
					case observation := <-seen:
						if observation.err != nil {
							t.Fatal(observation.err)
						}
						if observation.proof == last {
							t.Fatal("proof reused across TLS key states")
						}
						last = observation.proof
					case <-time.After(4 * time.Second):
						t.Fatal("no fresh proof at key exchange")
					}
				}
				st := srv.snapshot()
				if len(st.passwords) < 2 || st.passwords[0] != "password" || st.passwords[1] != "renewed-token" || st.usernames[1] != "alice" {
					t.Fatalf("ordinary auth/token path changed: %v %v", st.usernames, st.passwords)
				}
			})
		}
	}
}

func TestClientProofRejectsLegacyTLSWithoutDowngrade(t *testing.T) {
	srv := startServer(t, srvConfig{cipher: "AES-256-GCM", tlsMin: tls.VersionTLS11, tlsMax: tls.VersionTLS11})
	key, _ := clientproof.New("legacy-test", bytes.Repeat([]byte{0x21}, 32))
	_, err := dialServer(t, srv, sessionOpts{ovpn: "tls-version-min 1.1\n", cfg: func(c *Config) { c.ClientProof = key }, timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "TLS 1.2 or newer") {
		t.Fatalf("legacy TLS did not fail closed: %v", err)
	}
	if st := srv.snapshot(); st.exchanges != 0 {
		t.Fatal("custom mode sent key-method 2 without a proof")
	}
}
