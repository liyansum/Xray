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

type certificateSnapshot struct {
	certificate []byte
	key         []byte
	keyPair     *tls.Certificate
}

// managedCertificate publishes immutable certificate snapshots. Refreshes are
// demand-driven so an unused or closed listener doesn't retain a ticker
// goroutine for the lifetime of the process.
type managedCertificate struct {
	certificatePath string
	keyPath         string
	usage           Certificate_Usage
	buildChain      bool
	refreshInterval time.Duration
	ocspStapling    bool

	current     atomic.Pointer[certificateSnapshot]
	nextRefresh atomic.Int64
	refreshing  atomic.Bool
}

func newManagedCertificate(entry *Certificate) *managedCertificate {
	m := &managedCertificate{
		certificatePath: entry.CertificatePath,
		keyPath:         entry.KeyPath,
		usage:           entry.Usage,
		buildChain:      entry.BuildChain,
		ocspStapling:    entry.OcspStapling != 0,
	}
	snapshot, err := m.buildSnapshot(bytes.Clone(entry.Certificate), bytes.Clone(entry.Key), nil)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid X509 key pair")
		return nil
	}
	m.current.Store(snapshot)

	if !entry.OneTimeLoading && (m.certificatePath != "" && m.keyPath != "" || m.ocspStapling) {
		interval := entry.OcspStapling
		if interval == 0 {
			interval = 3600
		}
		m.refreshInterval = time.Duration(interval) * time.Second
		// Preserve the previous behavior of attempting OCSP immediately. The
		// initial certificate remains available while the bounded refresh runs.
		if m.ocspStapling {
			m.nextRefresh.Store(time.Now().UnixNano())
		} else {
			m.nextRefresh.Store(time.Now().Add(m.refreshInterval).UnixNano())
		}
	}
	return m
}

func (m *managedCertificate) buildSnapshot(certificate, key []byte, previous *certificateSnapshot) (*certificateSnapshot, error) {
	snapshot := &certificateSnapshot{
		certificate: bytes.Clone(certificate),
		key:         bytes.Clone(key),
	}
	if m.usage != Certificate_ENCIPHERMENT {
		return snapshot, nil
	}

	keyPair, err := tls.X509KeyPair(snapshot.certificate, snapshot.key)
	if err != nil {
		return nil, err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.keyPair != nil &&
		bytes.Equal(previous.keyPair.Certificate[0], keyPair.Certificate[0]) {
		keyPair.OCSPStaple = bytes.Clone(previous.keyPair.OCSPStaple)
	}
	snapshot.keyPair = &keyPair
	return snapshot, nil
}

func (m *managedCertificate) snapshot() *certificateSnapshot {
	snapshot := m.current.Load()
	m.maybeRefresh()
	return snapshot
}

func (m *managedCertificate) maybeRefresh() {
	if m.refreshInterval == 0 || time.Now().UnixNano() < m.nextRefresh.Load() || !m.refreshing.CompareAndSwap(false, true) {
		return
	}
	m.nextRefresh.Store(time.Now().Add(m.refreshInterval).UnixNano())
	go m.refresh()
}

func (m *managedCertificate) refresh() {
	defer m.refreshing.Store(false)

	previous := m.current.Load()
	if previous == nil {
		return
	}
	certificate, key := previous.certificate, previous.key
	if m.certificatePath != "" && m.keyPath != "" {
		var err error
		certificate, err = filesystem.ReadCert(m.certificatePath)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to read certificate")
			return
		}
		key, err = filesystem.ReadCert(m.keyPath)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to read key")
			return
		}
	}

	next, err := m.buildSnapshot(certificate, key, previous)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid refreshed X509 key pair")
		return
	}
	if m.ocspStapling && next.keyPair != nil {
		ocspData, err := ocsp.GetOCSPForCert(next.keyPair.Certificate)
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
		} else {
			next.keyPair.OCSPStaple = bytes.Clone(ocspData)
		}
	}
	m.current.Store(next)
}

func (c *Config) buildManagedCertificates(usage Certificate_Usage) []*managedCertificate {
	certs := make([]*managedCertificate, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != usage {
			continue
		}
		if managed := newManagedCertificate(entry); managed != nil {
			certs = append(certs, managed)
		}
	}
	return certs
}

// BuildCertificates builds a list of TLS certificates from proto definition.
func (c *Config) BuildCertificates() []*tls.Certificate {
	managed := c.buildManagedCertificates(Certificate_ENCIPHERMENT)
	certs := make([]*tls.Certificate, 0, len(managed))
	for _, certificate := range managed {
		if snapshot := certificate.current.Load(); snapshot != nil && snapshot.keyPair != nil {
			certs = append(certs, snapshot.keyPair)
		}
	}
	return certs
}

func isCertificateExpired(c *tls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
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

func (c *Config) getCustomCA() []*managedCertificate {
	return c.buildManagedCertificates(Certificate_AUTHORITY_ISSUE)
}

func getGetCertificateFunc(c *tls.Config, ca []*managedCertificate) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := hello.ServerName
		certExpired := false

		access.RLock()
		certificate, found := c.NameToCertificate[domain]
		access.RUnlock()

		if found {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			certExpired = true
		}

		if certExpired {
			newCerts := make([]tls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				if !isCertificateExpired(&certificate) {
					newCerts = append(newCerts, certificate)
				} else if certificate.Leaf != nil {
					expTime := certificate.Leaf.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "old certificate for ", domain, " (expire on ", expTime, ") discarded")
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *tls.Certificate

		// Create a new certificate from existing CA if possible
		for _, managedCA := range ca {
			if snapshot := managedCA.snapshot(); snapshot != nil {
				rawCert := &Certificate{
					Certificate: snapshot.certificate,
					Key:         snapshot.key,
					Usage:       Certificate_AUTHORITY_ISSUE,
					BuildChain:  managedCA.buildChain,
				}
				newCert, err := issueCertificate(rawCert, domain)
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to issue new certificate for ", domain)
					continue
				}
				parsed, err := x509.ParseCertificate(newCert.Certificate[0])
				if err == nil {
					newCert.Leaf = parsed
					expTime := parsed.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "new certificate for ", domain, " (expire on ", expTime, ") issued")
				} else {
					errors.LogInfoInner(context.Background(), err, "failed to parse new certificate for ", domain)
				}

				access.Lock()
				c.Certificates = append(c.Certificates, *newCert)
				issuedCertificate = &c.Certificates[len(c.Certificates)-1]
				access.Unlock()
				break
			}
		}

		if issuedCertificate == nil {
			return nil, errors.New("failed to create a new certificate for ", domain)
		}

		access.Lock()
		c.BuildNameToCertificate()
		access.Unlock()

		return issuedCertificate, nil
	}
}

func getNewGetCertificateFunc(certs []*managedCertificate, rejectUnknownSNI bool) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(certs) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
		first := certs[0].snapshot()
		if first == nil || first.keyPair == nil {
			return nil, errNoCertificates
		}
		if !rejectUnknownSNI && (len(certs) == 1 || sni == "") {
			return first.keyPair, nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, certificate := range certs {
			snapshot := certificate.snapshot()
			if snapshot == nil || snapshot.keyPair == nil {
				continue
			}
			keyPair := snapshot.keyPair
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
		return first.keyPair, nil
	}
}

func (c *Config) parseServerName() string {
	if IsFromMitm(c.ServerName) {
		return ""
	}
	return c.ServerName
}

func (r *RandCarrier) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
	// With no custom policy, leave verification entirely to crypto/tls. This
	// also permits the server side of an ordinary TLS connection, where the
	// client usually does not present a certificate.
	if r.PinnedPeerCertSha256 == nil && r.VerifyPeerCertByName == nil {
		return nil
	}
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
		if len(r.Config.ServerName) == 0 {
			return errors.New("Pinning CA needs a valid ServerName")
		}
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

	return nil
}

// verifyConnection runs for full and resumed handshakes. In contrast,
// VerifyPeerCertificate is skipped when a client resumes a session, which can
// bypass certificate pinning or VerifyPeerCertByName after policy changes.
func (r *RandCarrier) verifyConnection(state tls.ConnectionState) error {
	rawCerts := make([][]byte, len(state.PeerCertificates))
	for index, certificate := range state.PeerCertificates {
		rawCerts[index] = certificate.Raw
	}
	return r.verifyPeerCert(rawCerts, state.VerifiedChains)
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
		Rand:                   randCarrier,
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		NextProtos:             slices.Clone(c.NextProtocol),
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyConnection:       randCarrier.verifyConnection,
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
		config.GetCertificate = getNewGetCertificateFunc(c.buildManagedCertificates(Certificate_ENCIPHERMENT), c.RejectUnknownSni)
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
		for _, s := range tls.InsecureCipherSuites() {
			id[s.Name] = s.ID
		}
		for n := range strings.SplitSeq(c.CipherSuites, ":") {
			n = strings.TrimSpace(n)
			if v, ok := id[n]; ok {
				config.CipherSuites = append(config.CipherSuites, v)
			}
		}
	} else if len(c.Certificate) > 0 {
		// Keep the existing ECDSA AEAD suites while excluding Go's two
		// ECDHE-ECDSA CBC defaults. TLS 1.3 cipher suites are unaffected.
		config.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	}

	if len(c.MasterKeyLog) > 0 && c.MasterKeyLog != "none" {
		writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
		} else {
			config.KeyLogWriter = writer
		}
	}
	if len(c.EchConfigList) > 0 || len(c.EchServerKeys) > 0 {
		err := ApplyECH(c, config)
		if err != nil {
			errors.LogError(context.Background(), err)
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
