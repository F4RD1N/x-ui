package tls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

var globalSessionCache = tls.NewLRUClientSessionCache(128)

// ParseCertificate converts a cert.Certificate to Certificate.
func ParseCertificate(c *cert.Certificate) *Certificate {
	if c != nil {
		certPEM, keyPEM := c.ToPEM()
		return &Certificate{
			Certificate: certPEM,
			Key:         keyPEM,
		}
	}
	return nil
}

func (c *Config) loadSelfCertPool() (*x509.CertPool, error) {
	root := x509.NewCertPool()
	for _, cert := range c.Certificate {
		if !root.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("failed to append cert").AtWarning()
		}
	}
	return root, nil
}

// certificateCache publishes immutable certificates. A handshake can retain a
// returned pointer while the watcher prepares and publishes a newer snapshot.
type certificateCache struct {
	slots []*atomic.Pointer[tls.Certificate]
}

func (c *certificateCache) snapshot() []*tls.Certificate {
	certs := make([]*tls.Certificate, len(c.slots))
	for i, slot := range c.slots {
		certs[i] = slot.Load()
	}
	return certs
}

func parseKeyPair(entry *Certificate) *tls.Certificate {
	keyPair, err := tls.X509KeyPair(entry.Certificate, entry.Key)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid X509 key pair")
		return nil
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid certificate")
		return nil
	}
	return &keyPair
}

// refreshCertificate never modifies current, which may already be in use by
// crypto/tls. A bad replacement pair leaves the last working snapshot intact.
func refreshCertificate(current *tls.Certificate, entry *Certificate, reloaded, stapling bool, fetchOCSP func([][]byte) ([]byte, error)) *tls.Certificate {
	next := current
	if reloaded {
		next = parseKeyPair(entry)
		if next == nil {
			return current
		}
	}
	if stapling {
		if data, err := fetchOCSP(next.Certificate); err != nil {
			errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
		} else if !bytes.Equal(data, next.OCSPStaple) {
			copy := *next
			copy.OCSPStaple = slices.Clone(data)
			next = &copy
		}
	}
	return next
}

func (c *Config) buildCertificateCache(watch bool) *certificateCache {
	cache := &certificateCache{}
	for _, configured := range c.Certificate {
		if configured == nil || configured.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		// The watcher owns these bytes. In particular, creating two runtime
		// configs from one proto must not let either watcher rewrite its input.
		entry := proto.Clone(configured).(*Certificate)
		keyPair := parseKeyPair(entry)
		if keyPair == nil {
			continue
		}
		slot := new(atomic.Pointer[tls.Certificate])
		slot.Store(keyPair)
		cache.slots = append(cache.slots, slot)
		if watch {
			setupOcspTicker(entry, func(reloaded, stapling bool) {
				current := slot.Load()
				if next := refreshCertificate(current, entry, reloaded, stapling, ocsp.GetOCSPForCert); next != current {
					slot.Store(next)
				}
			})
		}
	}
	return cache
}

// BuildCertificates builds an immutable snapshot from the proto definition.
// Runtime certificate reloads are published through GetTLSConfig's callback;
// a returned slice is never modified by a background watcher.
func (c *Config) BuildCertificates() []*tls.Certificate {
	return c.buildCertificateCache(false).snapshot()
}

func certificateRefreshInterval(seconds uint64) time.Duration {
	const maximum = uint64((1<<63 - 1) / time.Second)
	if seconds == 0 {
		return time.Hour
	}
	if seconds > maximum {
		// JSON configuration rejects this value. Keep programmatically built
		// protobuf configurations from overflowing into a ticker panic too.
		errors.LogWarning(context.Background(), "certificate refresh interval exceeds timer range; clamping")
		seconds = maximum
	}
	return time.Duration(seconds) * time.Second
}

func setupOcspTicker(entry *Certificate, callback func(isReloaded, isOcspstapling bool)) {
	if entry.OneTimeLoading || ((entry.CertificatePath == "" || entry.KeyPath == "") && entry.OcspStapling == 0) {
		return
	}
	go func() {
		var isOcspstapling bool
		hotReloadCertInterval := uint64(3600)
		if entry.OcspStapling != 0 {
			hotReloadCertInterval = entry.OcspStapling
			isOcspstapling = true
		}
		t := time.NewTicker(certificateRefreshInterval(hotReloadCertInterval))
		defer t.Stop()
		for {
			var isReloaded bool
			if entry.CertificatePath != "" && entry.KeyPath != "" {
				newCert, err := filesystem.ReadCert(entry.CertificatePath)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "failed to parse certificate")
					return
				}
				newKey, err := filesystem.ReadCert(entry.KeyPath)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "failed to parse key")
					return
				}
				if string(newCert) != string(entry.Certificate) || string(newKey) != string(entry.Key) {
					entry.Certificate = newCert
					entry.Key = newKey
					isReloaded = true
				}
			}
			callback(isReloaded, isOcspstapling)
			<-t.C
		}
	}()
}

func isCertificateExpired(c *tls.Certificate) bool {
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return leaf != nil && leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
}

func issueCertificate(rawCA *Certificate, domain string) (*tls.Certificate, error) {
	parent, err := cert.ParseCertificate(rawCA.Certificate, rawCA.Key)
	if err != nil {
		return nil, errors.New("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, errors.New("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	if rawCA.BuildChain {
		newCertPEM = bytes.Join([][]byte{newCertPEM, rawCA.Certificate}, []byte("\n"))
	}
	cert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	return &cert, err
}

func (c *Config) getCustomCA() []*atomic.Pointer[Certificate] {
	certs := make([]*atomic.Pointer[Certificate], 0, len(c.Certificate))
	for _, configured := range c.Certificate {
		if configured == nil || configured.Usage != Certificate_AUTHORITY_ISSUE {
			continue
		}
		entry := proto.Clone(configured).(*Certificate)
		slot := new(atomic.Pointer[Certificate])
		slot.Store(proto.Clone(entry).(*Certificate))
		certs = append(certs, slot)
		setupOcspTicker(entry, func(reloaded, _ bool) {
			if !reloaded {
				return
			}
			current := slot.Load()
			if next := refreshAuthority(current, entry); next != current {
				slot.Store(next)
			}
		})
	}
	return certs
}

func refreshAuthority(current, replacement *Certificate) *Certificate {
	if parseKeyPair(replacement) == nil {
		return current
	}
	return proto.Clone(replacement).(*Certificate)
}

func getGetCertificateFunc(c *tls.Config, ca []*atomic.Pointer[Certificate]) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.Mutex
	// crypto/tls reads its Config without our lock. Keep issued certificates in
	// a private cache instead of appending to the already published Config.
	initial := &tls.Config{Certificates: slices.Clone(c.Certificates)}
	initial.BuildNameToCertificate()
	certificates := initial.NameToCertificate
	for name, certificate := range c.NameToCertificate {
		certificates[name] = certificate
	}

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		access.Lock()
		defer access.Unlock()
		domain := hello.ServerName
		if certificate := certificates[domain]; certificate != nil {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			for name, cached := range certificates {
				if isCertificateExpired(cached) {
					delete(certificates, name)
				}
			}
		}

		for _, slot := range ca {
			rawCert := slot.Load()
			newCert, err := issueCertificate(rawCert, domain)
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to issue new certificate for ", domain)
				continue
			}
			parsed, err := x509.ParseCertificate(newCert.Certificate[0])
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to parse new certificate for ", domain)
			} else {
				newCert.Leaf = parsed
				expTime := parsed.NotAfter.Format(time.RFC3339)
				errors.LogInfo(context.Background(), "new certificate for ", domain, " (expire on ", expTime, ") issued")
			}
			certificates[domain] = newCert
			return newCert, nil
		}
		return nil, errors.New("failed to create a new certificate for ", domain)
	}
}

func getNewGetCertificateFunc(loadCertificates func() []*tls.Certificate, rejectUnknownSNI bool) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certs := loadCertificates()
		if len(certs) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
		if !rejectUnknownSNI && (len(certs) == 1 || sni == "") {
			return certs[0], nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, keyPair := range certs {
			if keyPair.Leaf.Subject.CommonName == sni || keyPair.Leaf.Subject.CommonName == gsni {
				return keyPair, nil
			}
			for _, name := range keyPair.Leaf.DNSNames {
				if name == sni || name == gsni {
					return keyPair, nil
				}
			}
		}
		if rejectUnknownSNI {
			return nil, errNoCertificates
		}
		return certs[0], nil
	}
}

func (c *Config) parseServerName() string {
	if IsFromMitm(c.ServerName) {
		return ""
	}
	return c.ServerName
}

func (r *RandCarrier) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
	// extract x509 certificates from rawCerts (verifiedChains will be nil if InsecureSkipVerify is true)
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		certs[i], _ = x509.ParseCertificate(asn1Data)
	}
	if len(certs) == 0 {
		return errors.New("unexpected certs")
	}

	// directly return success if pinned cert is leaf
	// or replace RootCAs if pinned cert is CA (and can be used in VerifyPeerCertByName)
	CAs := r.RootCAs
	var verifyResult verifyResult
	var verifiedCert *x509.Certificate
	if r.PinnedPeerCertSha256 != nil {
		verifyResult, verifiedCert = verifyChain(certs, r.PinnedPeerCertSha256)
		switch verifyResult {
		case certNotFound:
			return errors.New("peer cert is unrecognized (against pinnedPeerCertSha256)")
		case foundLeaf:
			return nil
		case foundCA:
			CAs = x509.NewCertPool()
			CAs.AddCert(verifiedCert)
		default:
			panic("impossible pinnedPeerCertSha256 verify result")
		}
	}

	if r.VerifyPeerCertByName != nil { // RAW's Dial() may make it empty but not nil
		opts := x509.VerifyOptions{
			Roots:         CAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		for _, opts.DNSName = range r.VerifyPeerCertByName {
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}
		}
		if verifyResult == foundCA {
			errors.New("peer cert is invalid (against pinned CA and verifyPeerCertByName)")
		}
		return errors.New("peer cert is invalid (against root CAs and verifyPeerCertByName)")
	}

	if verifyResult == foundCA { // if found CA, we need to verify here
		opts := x509.VerifyOptions{
			Roots:         CAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			DNSName:       r.Config.ServerName,
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := certs[0].Verify(opts); err == nil {
			return nil
		}
		return errors.New("peer cert is invalid (against pinned CA and serverName)")
	}

	return nil // r.PinnedPeerCertSha256==nil && r.verifyPeerCertByName==nil
}

type RandCarrier struct {
	Config               *tls.Config
	RootCAs              *x509.CertPool
	VerifyPeerCertByName []string
	PinnedPeerCertSha256 [][]byte
}

func (r *RandCarrier) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// GetTLSConfig converts this Config into tls.Config.
func (c *Config) GetTLSConfig(opts ...Option) *tls.Config {
	root, err := c.getCertPool()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to load system root certificate")
	}

	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			SessionTicketsDisabled: true,
		}
	}

	randCarrier := &RandCarrier{
		RootCAs:              root,
		VerifyPeerCertByName: slices.Clone(c.VerifyPeerCertByName),
		PinnedPeerCertSha256: c.PinnedPeerCertSha256,
	}
	config := &tls.Config{
		InsecureSkipVerify:     c.AllowInsecure,
		Rand:                   randCarrier,
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		NextProtos:             slices.Clone(c.NextProtocol),
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyPeerCertificate:  randCarrier.verifyPeerCert,
	}
	randCarrier.Config = config
	if len(c.VerifyPeerCertByName) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.VerifyPeerCertByName = nil
	}
	if len(c.PinnedPeerCertSha256) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.PinnedPeerCertSha256 = nil
	}

	for _, opt := range opts {
		opt(config)
	}

	caCerts := c.getCustomCA()
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts)
	} else {
		config.GetCertificate = getNewGetCertificateFunc(c.buildCertificateCache(true).snapshot, c.RejectUnknownSni)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(c.CurvePreferences) > 0 {
		config.CurvePreferences = ParseCurveName(c.CurvePreferences)
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	switch c.MinVersion {
	case "1.0":
		config.MinVersion = tls.VersionTLS10
	case "1.1":
		config.MinVersion = tls.VersionTLS11
	case "1.2":
		config.MinVersion = tls.VersionTLS12
	case "1.3":
		config.MinVersion = tls.VersionTLS13
	}

	switch c.MaxVersion {
	case "1.0":
		config.MaxVersion = tls.VersionTLS10
	case "1.1":
		config.MaxVersion = tls.VersionTLS11
	case "1.2":
		config.MaxVersion = tls.VersionTLS12
	case "1.3":
		config.MaxVersion = tls.VersionTLS13
	}

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range tls.CipherSuites() {
			id[s.Name] = s.ID
		}
		for _, n := range strings.Split(c.CipherSuites, ":") {
			if id[n] != 0 {
				config.CipherSuites = append(config.CipherSuites, id[n])
			}
		}
	}

	if len(c.MasterKeyLog) > 0 && c.MasterKeyLog != "none" {
		writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
		} else {
			config.KeyLogWriter = writer
		}
	}
	if len(c.EchConfigList) > 0 || len(c.EchServerKeys) > 0 {
		err := ApplyECH(c, config)
		if err != nil {
			if c.EchForceQuery == "full" {
				errors.LogError(context.Background(), err)
			} else {
				errors.LogInfo(context.Background(), err)
			}
		}
	}

	return config
}

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
// Due to the incorrect structure of GetTLSConfig(), the config.ServerName will always be empty.
// So the real logic for SNI is:
// set it to dest -> overwrite it with servername(if it's len>0).
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if config.ServerName == "" {
			config.ServerName = dest.Address.String()
		}
	}
}

func WithOverrideName(serverName string) Option {
	return func(config *tls.Config) {
		config.ServerName = serverName
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}

// ConfigFromStreamSettings fetches Config from stream settings. Nil if not found.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

func ParseCurveName(curveNames []string) []tls.CurveID {
	curveMap := map[string]tls.CurveID{
		"curvep256":          tls.CurveP256,
		"curvep384":          tls.CurveP384,
		"curvep521":          tls.CurveP521,
		"x25519":             tls.X25519,
		"x25519mlkem768":     tls.X25519MLKEM768,
		"secp256r1mlkem768":  tls.SecP256r1MLKEM768,
		"secp384r1mlkem1024": tls.SecP384r1MLKEM1024,
	}

	var curveIDs []tls.CurveID
	for _, name := range curveNames {
		if curveID, ok := curveMap[strings.ToLower(name)]; ok {
			curveIDs = append(curveIDs, curveID)
		} else {
			errors.LogWarning(context.Background(), "unsupported curve name: "+name)
		}
	}
	return curveIDs
}

func IsFromMitm(str string) bool {
	return strings.ToLower(str) == "frommitm"
}

type verifyResult int

const (
	certNotFound verifyResult = iota
	foundLeaf
	foundCA
)

func verifyChain(certs []*x509.Certificate, pinnedPeerCertSha256 [][]byte) (verifyResult, *x509.Certificate) {
	leafHash := GenerateCertHash(certs[0])
	for _, c := range pinnedPeerCertSha256 {
		if hmac.Equal(leafHash, c) {
			return foundLeaf, nil
		}
	}
	certs = certs[1:] // skip leaf
	for _, cert := range certs {
		certHash := GenerateCertHash(cert)
		for _, c := range pinnedPeerCertSha256 {
			if hmac.Equal(certHash, c) {
				if cert.IsCA {
					return foundCA, cert
				}
			}
		}
	}
	return certNotFound, nil
}
