package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	utls "github.com/refraction-networking/utls"
)

var errNativeTLSConfig = errors.New("transport: TLS configuration is incompatible with the native TCP profile")

// nativeTLSSpec reproduces the captured ARM64 BoringSSL profile with AES CPU
// support. It never lowers the caller's TLS version floor. Owned profiles
// (every orbit link: pki.ClientTLS sets MinVersion 1.3) use TLS13; only the
// explicit native provider policy of the custom outbound sets a 1.2 floor and
// also offers the recovered TLS12 (VPN-Core 0.12). There is no ALPN, GREASE or
// browser padding.
func nativeTLSSpec(tc *tls.Config) (utls.ClientHelloSpec, error) {
	if tc == nil || tc.InsecureSkipVerify && tc.VerifyConnection == nil ||
		len(tc.Certificates) != 0 || tc.GetClientCertificate != nil ||
		len(tc.CipherSuites) != 0 || len(tc.CurvePreferences) != 0 ||
		tc.ClientSessionCache != nil || len(tc.NextProtos) != 0 ||
		tc.SessionTicketsDisabled || tc.Renegotiation != tls.RenegotiateNever ||
		len(tc.EncryptedClientHelloConfigList) != 0 || tc.EncryptedClientHelloRejectionVerify != nil {
		return utls.ClientHelloSpec{}, errNativeTLSConfig
	}
	// The caller owns the version policy: an unset floor stays at 1.3.
	minimum, maximum := uint16(tls.VersionTLS13), uint16(tls.VersionTLS13)
	if tc.MinVersion != 0 {
		minimum = max(tls.VersionTLS12, tc.MinVersion)
	}
	if tc.MaxVersion != 0 {
		maximum = min(maximum, tc.MaxVersion)
	}
	if minimum > maximum {
		return utls.ClientHelloSpec{}, errNativeTLSConfig
	}
	versions := []uint16{}
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		if version >= minimum && version <= maximum {
			versions = append(versions, version)
		}
	}
	return utls.ClientHelloSpec{
		TLSVersMin: minimum, TLSVersMax: maximum,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
			&utls.SupportedVersionsExtension{Versions: versions},
		},
	}, nil
}

func nativeTLSClient(ctx context.Context, raw net.Conn, tc *tls.Config) (net.Conn, error) {
	spec, err := nativeTLSSpec(tc)
	if err != nil {
		return nil, err
	}
	uc := &utls.Config{
		Rand: tc.Rand, Time: tc.Time, RootCAs: tc.RootCAs, ServerName: tc.ServerName,
		MinVersion: spec.TLSVersMin, MaxVersion: spec.TLSVersMax,
		InsecureSkipVerify: tc.InsecureSkipVerify, VerifyPeerCertificate: tc.VerifyPeerCertificate,
		DynamicRecordSizingDisabled: tc.DynamicRecordSizingDisabled, KeyLogWriter: tc.KeyLogWriter,
	}
	if tc.VerifyConnection != nil {
		uc.VerifyConnection = func(s utls.ConnectionState) error {
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
	client := utls.UClient(raw, uc, utls.HelloCustom)
	if err = client.ApplyPreset(&spec); err == nil {
		err = client.HandshakeContext(ctx)
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}
