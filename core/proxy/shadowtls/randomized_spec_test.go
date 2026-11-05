package shadowtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func randomizedFixtureID(name string, index int) utls.ClientHelloID {
	id := utls.HelloRandomizedALPN
	if name == "randomizednoalpn" {
		id = utls.HelloRandomizedNoALPN
	}
	seed := utls.PRNGSeed(sha256.Sum256([]byte(fmt.Sprintf("shadowtls-fixture-%s-%d", name, index))))
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	id.Seed, id.Weights = &seed, &weights
	return id
}

func randomizedSpecGroups(spec *utls.ClientHelloSpec) (groups, shares []utls.CurveID) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			groups = append(groups, e.Curves...)
		case *utls.KeyShareExtension:
			for _, share := range e.KeyShares {
				shares = append(shares, share.Group)
			}
		}
	}
	return
}

func containsCurve(curves []utls.CurveID, curve utls.CurveID) bool {
	for _, c := range curves {
		if c == curve {
			return true
		}
	}
	return false
}

func assertRandomizedSpec(t *testing.T, before, after *utls.ClientHelloSpec) {
	t.Helper()
	groups, shares := randomizedSpecGroups(after)
	originalGroups, originalShares := randomizedSpecGroups(before)
	if len(shares) == 0 {
		t.Fatal("normalization removed all initial key shares")
	}
	for _, share := range shares {
		if !containsCurve(groups, share) {
			t.Fatalf("key share %d is not advertised", share)
		}
	}
	for _, hybrid := range []utls.CurveID{utls.X25519MLKEM768, utls.X25519Kyber768Draft00} {
		if containsCurve(groups, hybrid) && !containsCurve(shares, hybrid) {
			t.Fatal("hybrid group would require an unsupported HelloRetryRequest")
		}
		if containsCurve(originalGroups, hybrid) && containsCurve(originalShares, hybrid) && (!containsCurve(groups, hybrid) || !containsCurve(shares, hybrid)) {
			t.Fatal("valid hybrid pair was removed")
		}
	}
	for _, classical := range []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521} {
		if containsCurve(originalGroups, classical) != containsCurve(groups, classical) {
			t.Fatal("classical supported group was changed")
		}
	}
	if !reflect.DeepEqual(before.CipherSuites, after.CipherSuites) || len(before.Extensions) != len(after.Extensions) {
		t.Fatal("unrelated randomized properties changed")
	}
	for i, ext := range before.Extensions {
		switch x := ext.(type) {
		case *utls.SupportedCurvesExtension, *utls.KeyShareExtension:
			continue
		case *utls.UtlsPaddingExtension:
			// Function values are not DeepEqual, even for the same function.
			y, ok := after.Extensions[i].(*utls.UtlsPaddingExtension)
			if !ok || x.PaddingLen != y.PaddingLen || x.WillPad != y.WillPad || reflect.ValueOf(x.GetPaddingLen).Pointer() != reflect.ValueOf(y.GetPaddingLen).Pointer() {
				t.Fatal("padding policy changed")
			}
			continue
		}
		if !reflect.DeepEqual(ext, after.Extensions[i]) {
			t.Fatalf("extension %T changed", ext)
		}
	}
}

// This intentionally exercises multiple deterministic process seeds: a single
// passing random seed cannot establish compatibility with strict TLS parsers.
func TestShadowTLSRandomizedSpecSeeds(t *testing.T) {
	for _, name := range []string{"randomized", "randomizednoalpn"} {
		for index := 0; index < 64; index++ {
			t.Run(fmt.Sprintf("%s/%d", name, index), func(t *testing.T) {
				id := randomizedFixtureID(name, index)
				before, err := utls.UTLSIdToSpec(id)
				if err != nil {
					t.Fatal(err)
				}
				after := versionCappedSpec(id, 3, false)
				if after == nil {
					t.Fatal("randomized non-strict spec was not materialized")
				}
				assertRandomizedSpec(t, &before, after)
				if versionCappedSpec(id, 2, false) == nil {
					t.Fatal("randomized v2 spec was not materialized")
				}
			})
		}
	}
}

func TestShadowTLSFixedFingerprintSpecUnchanged(t *testing.T) {
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloAndroid_11_OkHttp, utls.Hello360_Auto} {
		if versionCappedSpec(id, 2, false) != nil || versionCappedSpec(id, 3, false) != nil {
			t.Fatalf("fixed preset %s no longer uses the original non-strict path", id.Str())
		}
	}
}

func TestShadowTLSRandomizedGoTLSAndClassicalRetry(t *testing.T) {
	certificate := testCert(t)
	for _, name := range []string{"randomized", "randomizednoalpn"} {
		for index := 0; index < 64; index++ {
			t.Run(fmt.Sprintf("%s/%d", name, index), func(t *testing.T) {
				spec := versionCappedSpec(randomizedFixtureID(name, index), 3, true)
				randomizedPipeHandshake(t, spec, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
			})
		}
	}
	// P-256 remains advertised even if it has no initial share. Ordinary TLS
	// HelloRetryRequest must keep working; only unimplemented hybrid retries
	// are avoided by the normalization.
	for index := 0; index < 64; index++ {
		spec := versionCappedSpec(randomizedFixtureID("randomizednoalpn", index), 3, true)
		groups, shares := randomizedSpecGroups(spec)
		if containsCurve(groups, utls.CurveP256) && !containsCurve(shares, utls.CurveP256) {
			t.Run("classical-p256-hello-retry", func(t *testing.T) {
				randomizedPipeHandshake(t, spec, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tls.CurveP256}})
			})
			return
		}
	}
	t.Fatal("deterministic fixture set had no classical retry case")
}

func randomizedPipeHandshake(t *testing.T, spec *utls.ClientHelloSpec, config *tls.Config) {
	t.Helper()
	// Each relay direction contributes io.Copy's bounded buffer, like socket
	// buffers. A direct zero-buffer net.Pipe can deadlock when both TLS peers
	// write a compatibility ChangeCipherSpec during HelloRetryRequest.
	clientRaw, clientRelay := net.Pipe()
	serverRaw, serverRelay := net.Pipe()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(clientRelay, serverRelay); done <- struct{}{} }()
	go func() { _, _ = io.Copy(serverRelay, clientRelay); done <- struct{}{} }()
	defer func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
		_ = clientRelay.Close()
		_ = serverRelay.Close()
		<-done
		<-done
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_ = clientRaw.SetDeadline(deadline)
	_ = serverRaw.SetDeadline(deadline)
	server := tls.Server(serverRaw, config)
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.HandshakeContext(ctx) }()
	client := utls.UClient(clientRaw, &utls.Config{ServerName: "x", InsecureSkipVerify: true, MinVersion: utls.VersionTLS13}, utls.HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	clientErr := client.HandshakeContext(ctx)
	serverErr := <-serverResult
	if clientErr != nil || serverErr != nil {
		t.Fatalf("memory-pipe handshake: client=%v server=%v", clientErr, serverErr)
	}
}

// Optional local evidence export for OpenSSL MemoryBIO verification. This does
// not run external commands or use network sockets from the Go test suite.
func TestShadowTLSRandomizedOpenSSLFixture(t *testing.T) {
	path := os.Getenv("SHADOWTLS_RANDOMIZED_FIXTURE")
	if path == "" {
		t.Skip("set SHADOWTLS_RANDOMIZED_FIXTURE for deterministic TLS ClientHello evidence")
	}
	type row struct {
		Fingerprint string `json:"fingerprint"`
		Seed        int    `json:"seed"`
		Record      string `json:"record"`
	}
	rows := []row{}
	for _, name := range []string{"randomized", "randomizednoalpn"} {
		for index := 0; index < 64; index++ {
			spec := versionCappedSpec(randomizedFixtureID(name, index), 3, true)
			client := utls.UClient(nil, &utls.Config{ServerName: "e2e.test", InsecureSkipVerify: true, MinVersion: utls.VersionTLS13}, utls.HelloCustom)
			if err := client.ApplyPreset(spec); err != nil {
				t.Fatal(err)
			}
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			client.HandshakeState.Hello.SessionId = make([]byte, 32)
			if err := client.MarshalClientHello(); err != nil {
				t.Fatal(err)
			}
			body := client.HandshakeState.Hello.Raw
			record := append([]byte{22, 3, 1, byte(len(body) >> 8), byte(len(body))}, body...)
			rows = append(rows, row{Fingerprint: name, Seed: index, Record: base64.StdEncoding.EncodeToString(record)})
		}
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
