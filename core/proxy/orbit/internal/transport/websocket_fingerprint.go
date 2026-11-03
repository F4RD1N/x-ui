package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"math/big"
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// A random browser choice and randomized-spec seed remain stable within this
// process. Each connection still gets new TLS keys, random bytes, and a fresh
// mutable ClientHelloSpec. Browser presets are supplied by the pinned uTLS
// dependency; only TLS's minimum version and HTTP/1.1 ALPN are constrained here.
var randomBrowser = sync.OnceValues(func() (utls.ClientHelloID, error) {
	ids := []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto,
		utls.HelloSafari_Auto, utls.HelloIOS_Auto, utls.HelloAndroid_11_OkHttp,
		utls.HelloEdge_Auto, utls.Hello360_Auto, utls.HelloQQ_Auto}
	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(ids))))
	if err != nil {
		return utls.ClientHelloID{}, err
	}
	return ids[i.Int64()], nil
})

var randomizedSeed = sync.OnceValues(utls.NewPRNGSeed)

func fingerprintID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "random":
		return randomBrowser()
	case "randomized", "randomizednoalpn":
		id := utls.HelloRandomized
		if name == "randomizednoalpn" {
			id = utls.HelloRandomizedNoALPN
		}
		seed, err := randomizedSeed()
		if err != nil {
			return utls.ClientHelloID{}, err
		}
		id.Seed = seed
		return id, nil
	default:
		return utls.ClientHelloID{}, errors.New("unknown WebSocket TLS fingerprint")
	}
}

func fingerprintDialer(name string, tc *tls.Config, dial func(context.Context, string, string) (net.Conn, error)) (func(context.Context, string, string) (net.Conn, error), error) {
	// A browser preset owns ciphers, curves, extensions and resumption shape.
	// Fail closed for unsupported embedding options instead of silently losing
	// an explicit client identity, ECH requirement or algorithm restriction.
	if tc.InsecureSkipVerify || len(tc.Certificates) != 0 || tc.GetClientCertificate != nil ||
		len(tc.CipherSuites) != 0 || len(tc.CurvePreferences) != 0 || tc.ClientSessionCache != nil ||
		len(tc.EncryptedClientHelloConfigList) != 0 || tc.EncryptedClientHelloRejectionVerify != nil ||
		tc.Renegotiation != tls.RenegotiateNever {
		return nil, errors.New("TLS embedding options are incompatible with a WebSocket browser fingerprint")
	}
	id, err := fingerprintID(name)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		spec, err := fingerprintSpec(id, name, tc)
		if err != nil {
			return nil, err
		}
		uc := &utls.Config{
			Rand: tc.Rand, Time: tc.Time, RootCAs: tc.RootCAs, ServerName: tc.ServerName,
			MinVersion: spec.TLSVersMin, MaxVersion: spec.TLSVersMax,
			NextProtos: []string{"http/1.1"}, VerifyPeerCertificate: tc.VerifyPeerCertificate,
			SessionTicketsDisabled:      tc.SessionTicketsDisabled,
			DynamicRecordSizingDisabled: tc.DynamicRecordSizingDisabled, KeyLogWriter: tc.KeyLogWriter,
		}
		if tc.VerifyConnection != nil {
			uc.VerifyConnection = func(s utls.ConnectionState) error {
				// Preserve the embedding's additional certificate/TLS checks after
				// uTLS performs mandatory normal hostname/chain verification. Go's
				// private exporter state and newer implementation-only fields are
				// not transferable between the two TLS implementations.
				return tc.VerifyConnection(tls.ConnectionState{
					Version: s.Version, HandshakeComplete: s.HandshakeComplete, DidResume: s.DidResume,
					CipherSuite: s.CipherSuite, NegotiatedProtocol: s.NegotiatedProtocol,
					NegotiatedProtocolIsMutual: s.NegotiatedProtocolIsMutual, ServerName: s.ServerName,
					PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains,
					SignedCertificateTimestamps: s.SignedCertificateTimestamps, OCSPResponse: s.OCSPResponse,
					TLSUnique: s.TLSUnique, ECHAccepted: s.ECHAccepted,
				})
			}
		}
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		client := utls.UClient(raw, uc, utls.HelloCustom)
		if err = client.ApplyPreset(&spec); err == nil {
			err = client.HandshakeContext(ctx)
		}
		if err != nil {
			raw.Close()
			return nil, err
		}
		return client, nil
	}, nil
}

func fingerprintSpec(id utls.ClientHelloID, name string, tc *tls.Config) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return spec, err
	}
	if name == "randomized" || name == "randomizednoalpn" {
		completeRandomizedShares(&spec)
	}
	// ApplyPreset replaces uTLS Config's bounds with those in the spec. Derive
	// the preset's original range before intersecting with the caller's bounds.
	minVersion, maxVersion := spec.TLSVersMin, spec.TLSVersMax
	for _, extension := range spec.Extensions {
		if versions, ok := extension.(*utls.SupportedVersionsExtension); ok {
			for _, version := range versions.Versions {
				if version < tls.VersionTLS10 || version > tls.VersionTLS13 {
					continue // GREASE
				}
				if minVersion == 0 || version < minVersion {
					minVersion = version
				}
				maxVersion = max(maxVersion, version)
			}
		}
	}
	if maxVersion == 0 {
		maxVersion = tls.VersionTLS12
	}
	minVersion = max(minVersion, tls.VersionTLS12, tc.MinVersion)
	if tc.MaxVersion != 0 {
		maxVersion = min(maxVersion, tc.MaxVersion)
	}
	if minVersion > maxVersion || maxVersion > tls.VersionTLS13 {
		return spec, errors.New("WebSocket fingerprint has no compatible TLS version")
	}
	spec.TLSVersMin, spec.TLSVersMax = minVersion, maxVersion
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	hasALPN := false
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.ALPNExtension:
			ext.AlpnProtocols = []string{"http/1.1"}
			hasALPN = true
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			continue // H2 ALPS cannot accompany an HTTP/1.1-only upgrade.
		case *utls.SupportedVersionsExtension:
			versions := ext.Versions[:0]
			for _, version := range ext.Versions {
				if version >= minVersion && version <= maxVersion || version&0x0f0f == 0x0a0a {
					versions = append(versions, version)
				}
			}
			ext.Versions = versions
		}
		extensions = append(extensions, extension)
	}
	if !hasALPN && name != "randomizednoalpn" {
		extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	spec.Extensions = extensions
	return spec, nil
}

func completeRandomizedShares(spec *utls.ClientHelloSpec) {
	// uTLS randomizes supported groups independently of initial key shares.
	// Its TLS13 retry path cannot generate a hybrid share after an HRR, so an
	// advertised hybrid group must have an initial share. Conversely, a share
	// must also be in supported_groups (RFC8446 4.2.8). Keep the hybrid exchange
	// whenever either random choice enabled it; named browser presets are not
	// modified by this compatibility repair.
	var curves *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = ext
		case *utls.KeyShareExtension:
			shares = ext
		}
	}
	if curves == nil || shares == nil {
		return // TLS12 has no key_share extension.
	}
	// This uTLS version keeps one classical private key, even when its
	// randomizer emits two classical shares. Keep the first initial classical
	// share, leaving other groups advertised: a server selecting another group
	// uses the fully supported classical HelloRetryRequest path instead.
	initialShares := shares.KeyShares[:0]
	classical := false
	for _, share := range shares.KeyShares {
		switch share.Group {
		case utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521:
			if classical {
				continue
			}
			classical = true
		}
		initialShares = append(initialShares, share)
	}
	shares.KeyShares = initialShares
	hasGroup, hasShare := false, false
	for _, group := range curves.Curves {
		hasGroup = hasGroup || group == utls.X25519MLKEM768
	}
	for _, share := range shares.KeyShares {
		hasShare = hasShare || share.Group == utls.X25519MLKEM768
	}
	if hasGroup && !hasShare {
		shares.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, shares.KeyShares...)
	}
	if hasShare && !hasGroup {
		curves.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, curves.Curves...)
	}
}
