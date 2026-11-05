package tls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"google.golang.org/protobuf/proto"
)

func cacheMatrixCertificate(t *testing.T, name string, authority bool) *Certificate {
	t.Helper()
	options := []cert.Option{cert.CommonName(name), cert.DNSNames(name)}
	if authority {
		options = append(options, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	}
	generated, err := cert.Generate(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	entry := ParseCertificate(generated)
	if authority {
		entry.Usage = Certificate_AUTHORITY_ISSUE
	}
	return entry
}

func TestCertificateCacheImmutableOCSPPublication(t *testing.T) {
	entry := cacheMatrixCertificate(t, "cache.test", false)
	cache := (&Config{Certificate: []*Certificate{entry}}).buildCertificateCache(false)
	old := cache.snapshot()[0]
	selectCert := getNewGetCertificateFunc(cache.snapshot, false)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				got, err := selectCert(&tls.ClientHelloInfo{ServerName: "cache.test"})
				if err != nil || !bytes.Equal(got.Certificate[0], old.Certificate[0]) || got.Leaf.Subject.CommonName != "cache.test" {
					t.Errorf("invalid concurrent snapshot: %v", err)
					return
				}
				if len(got.OCSPStaple) > 0 && len(got.OCSPStaple) != 128 {
					t.Error("partial OCSP snapshot")
				}
				if len(old.OCSPStaple) != 0 {
					t.Error("previously returned certificate was mutated")
				}
			}
		}()
	}
	for i := range 500 {
		response := bytes.Repeat([]byte{byte(i)}, 128)
		current := cache.slots[0].Load()
		next := refreshCertificate(current, entry, false, true, func([][]byte) ([]byte, error) { return response, nil })
		cache.slots[0].Store(next)
		response[0] ^= 0xff
		if next.OCSPStaple[0] != byte(i) {
			t.Fatal("OCSP response aliases published memory")
		}
	}
	wg.Wait()
	if len(old.OCSPStaple) != 0 {
		t.Fatal("old certificate changed")
	}
	if got := refreshCertificate(old, entry, false, false, nil); got != old {
		t.Fatal("no-op refresh replaced certificate")
	}
}

func TestCertificateCacheReplacementKeepsLastGoodPair(t *testing.T) {
	first := cacheMatrixCertificate(t, "first.test", false)
	second := cacheMatrixCertificate(t, "second.test", false)
	current := parseKeyPair(first)
	for _, bad := range []*Certificate{
		{Certificate: []byte("invalid"), Key: second.Key},
		{Certificate: second.Certificate, Key: first.Key},
	} {
		if got := refreshCertificate(current, bad, true, false, nil); got != current {
			t.Fatal("invalid replacement discarded working certificate")
		}
	}
	next := refreshCertificate(current, second, true, false, nil)
	if next == current || next.Leaf.Subject.CommonName != "second.test" || current.Leaf.Subject.CommonName != "first.test" {
		t.Fatal("replacement did not publish a distinct valid pair")
	}
	if got := refreshCertificate(next, second, false, true, func([][]byte) ([]byte, error) { return nil, fmt.Errorf("synthetic OCSP unavailable") }); got != next {
		t.Fatal("OCSP error discarded working snapshot")
	}
}

func TestCertificateCacheSNISelection(t *testing.T) {
	first := cacheMatrixCertificate(t, "first.test", false)
	wildcard := cacheMatrixCertificate(t, "*.example.test", false)
	cache := (&Config{Certificate: []*Certificate{first, wildcard}}).buildCertificateCache(false)
	for _, reject := range []bool{false, true} {
		selectCert := getNewGetCertificateFunc(cache.snapshot, reject)
		for _, name := range []string{"first.test", "FIRST.TEST", "api.example.test"} {
			got, err := selectCert(&tls.ClientHelloInfo{ServerName: name})
			if err != nil {
				t.Fatal(err)
			}
			if name == "api.example.test" && got.Leaf.Subject.CommonName != "*.example.test" {
				t.Fatal("wildcard selected wrong certificate")
			}
		}
		for _, name := range []string{"", "unknown.test", "deep.api.example.test"} {
			got, err := selectCert(&tls.ClientHelloInfo{ServerName: name})
			if reject && err == nil {
				t.Fatal("unknown SNI accepted")
			}
			if !reject && (err != nil || got != cache.snapshot()[0]) {
				t.Fatal("fallback changed")
			}
		}
	}
}

func TestCertificateCacheFileReloadAndInputIsolation(t *testing.T) {
	first := cacheMatrixCertificate(t, "first.test", false)
	second := cacheMatrixCertificate(t, "second.test", false)
	dir := t.TempDir()
	first.CertificatePath = filepath.Join(dir, "certificate.pem")
	first.KeyPath = filepath.Join(dir, "key.pem")
	// A one-second poll keeps this fixture bounded; synthetic certificates have
	// no OCSP endpoint, so this never performs network I/O.
	first.OcspStapling = 1
	if err := os.WriteFile(first.CertificatePath, second.Certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.KeyPath, second.Key, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := &Config{Certificate: []*Certificate{first}}
	before := proto.Clone(configuration)
	var configurations []*tls.Config
	for range 4 {
		configurations = append(configurations, configuration.GetTLSConfig())
	}
	defer func() {
		os.Remove(first.CertificatePath)
		os.Remove(first.KeyPath)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for _, runtime := range configurations {
		for {
			got, err := runtime.GetCertificate(&tls.ClientHelloInfo{ServerName: "second.test"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Leaf.Subject.CommonName == "second.test" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("file replacement not published")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if !proto.Equal(configuration, before) {
		t.Fatal("runtime watchers mutated shared proto input")
	}
	// Snapshot and one-time APIs deliberately retain their initial material.
	if snapshot := configuration.BuildCertificates(); snapshot[0].Leaf.Subject.CommonName != "first.test" {
		t.Fatal("BuildCertificates is not a stable initial snapshot")
	}
	oneTime := proto.Clone(configuration).(*Config)
	oneTime.Certificate[0].OneTimeLoading = true
	got, err := oneTime.GetTLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || got.Leaf.Subject.CommonName != "first.test" {
		t.Fatal("oneTimeLoading ignored")
	}
}

func TestCertificateIssuerPrivateCacheConcurrent(t *testing.T) {
	ca := cacheMatrixCertificate(t, "issuer.test", true)
	configuration := &Config{Certificate: []*Certificate{ca}}
	before := proto.Clone(configuration)
	runtime := configuration.GetTLSConfig()
	initialCertificates := slices.Clone(runtime.Certificates)
	initialNames := len(runtime.NameToCertificate)
	var wg sync.WaitGroup
	for worker := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("host-%d.test", worker%3)
			var previous *tls.Certificate
			for range 10 {
				got, err := runtime.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
				if err != nil {
					t.Error(err)
					return
				}
				if previous != nil && previous != got {
					t.Error("concurrent cache issued duplicate certificate")
				}
				if err := got.Leaf.VerifyHostname(name); err != nil {
					t.Error(err)
				}
				previous = got
				// crypto/tls may read these fields concurrently with callbacks.
				if len(runtime.Certificates) != len(initialCertificates) || len(runtime.NameToCertificate) != initialNames {
					t.Error("published TLS config was mutated")
				}
			}
		}()
	}
	wg.Wait()
	if !proto.Equal(configuration, before) {
		t.Fatal("issuer changed caller proto")
	}
}

func TestCertificateIssuerReloadSnapshotAndChain(t *testing.T) {
	first := cacheMatrixCertificate(t, "first-ca.test", true)
	second := cacheMatrixCertificate(t, "second-ca.test", true)
	first.BuildChain, second.BuildChain = true, true
	first.OneTimeLoading, second.OneTimeLoading = true, true
	ca := (&Config{Certificate: []*Certificate{first}}).getCustomCA()
	original := ca[0].Load()
	for _, bad := range []*Certificate{
		{Certificate: []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"), Key: second.Key},
		{Certificate: second.Certificate, Key: first.Key},
	} {
		if got := refreshAuthority(original, bad); got != original {
			t.Fatal("invalid CA replacement discarded usable authority")
		}
	}
	published := refreshAuthority(original, second)
	if published == original || !bytes.Equal(published.Certificate, second.Certificate) {
		t.Fatal("valid CA replacement rejected")
	}
	ca[0].Store(published)
	second.Certificate[0] ^= 1
	if bytes.Equal(published.Certificate, second.Certificate) {
		t.Fatal("published CA aliases mutable watcher bytes")
	}
	get := getGetCertificateFunc(&tls.Config{}, ca)
	got, err := get(&tls.ClientHelloInfo{ServerName: "issued.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificate) != 2 {
		t.Fatal("buildChain lost issuer")
	}
	issuer, err := x509.ParseCertificate(got.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if issuer.Subject.CommonName != "second-ca.test" || got.Leaf.CheckSignatureFrom(issuer) != nil {
		t.Fatal("signer and emitted chain came from different snapshots")
	}
	if !bytes.Equal(original.Certificate, first.Certificate) {
		t.Fatal("old CA snapshot changed")
	}
}

func TestCertificateExpiryDoesNotMutateSnapshot(t *testing.T) {
	entry := cacheMatrixCertificate(t, "expiry.test", false)
	certificate := parseKeyPair(entry)
	certificate.Leaf = nil
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if isCertificateExpired(certificate) {
					t.Error("valid certificate marked expired")
				}
			}
		}()
	}
	wg.Wait()
	if certificate.Leaf != nil {
		t.Fatal("expiry check mutated shared certificate")
	}
}

func TestCertificateRefreshIntervalBoundaries(t *testing.T) {
	const maximum = uint64((1<<63 - 1) / time.Second)
	for _, tc := range []struct {
		seconds uint64
		want    time.Duration
	}{
		{0, time.Hour}, {1, time.Second}, {3600, time.Hour},
		{maximum, time.Duration(maximum) * time.Second}, {maximum + 1, time.Duration(maximum) * time.Second},
		{^uint64(0), time.Duration(maximum) * time.Second},
	} {
		if got := certificateRefreshInterval(tc.seconds); got != tc.want || got <= 0 {
			t.Fatalf("unsafe interval %d: %v", tc.seconds, got)
		}
	}
}

func TestCertificateIssuerRefreshesExpiringCachedLeaf(t *testing.T) {
	ca := cacheMatrixCertificate(t, "issuer.test", true)
	ca.OneTimeLoading = true
	generated, err := cert.Generate(nil, cert.CommonName("renew.test"), cert.DNSNames("renew.test"), cert.NotAfter(time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	old := parseKeyPair(ParseCertificate(generated))
	published := &tls.Config{Certificates: []tls.Certificate{*old}}
	get := getGetCertificateFunc(published, (&Config{Certificate: []*Certificate{ca}}).getCustomCA())
	fresh, err := get(&tls.ClientHelloInfo{ServerName: "renew.test"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fresh.Certificate[0], old.Certificate[0]) || isCertificateExpired(fresh) {
		t.Fatal("expiring cached leaf was reused")
	}
	again, err := get(&tls.ClientHelloInfo{ServerName: "renew.test"})
	if err != nil || again != fresh {
		t.Fatal("fresh issued leaf not cached")
	}
	if len(published.Certificates) != 1 || !bytes.Equal(published.Certificates[0].Certificate[0], old.Certificate[0]) {
		t.Fatal("published TLS config mutated during expiry")
	}
}

func TestCertificateCacheTLSHandshakeVersions(t *testing.T) {
	entry := cacheMatrixCertificate(t, "handshake.test", false)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(entry.Certificate) {
		t.Fatal("test trust anchor invalid")
	}
	for _, version := range []struct {
		name   string
		number uint16
	}{{"1.2", tls.VersionTLS12}, {"1.3", tls.VersionTLS13}} {
		t.Run(version.name, func(t *testing.T) {
			configuration := (&Config{Certificate: []*Certificate{entry}, MinVersion: version.name, MaxVersion: version.name}).GetTLSConfig()
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(3 * time.Second))
			right.SetDeadline(time.Now().Add(3 * time.Second))
			server := tls.Server(right, configuration)
			client := tls.Client(left, &tls.Config{ServerName: "handshake.test", RootCAs: roots, MinVersion: version.number, MaxVersion: version.number, NextProtos: []string{"h2"}})
			finished := make(chan error, 1)
			go func() { finished <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			state := client.ConnectionState()
			if state.Version != version.number || state.NegotiatedProtocol != "h2" || len(state.VerifiedChains) == 0 {
				t.Fatal("TLS policy or authentication changed")
			}
		})
	}
}
