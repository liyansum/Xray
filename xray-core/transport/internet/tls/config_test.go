package tls_test

import (
	gotls "crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func TestCertificateIssuing(t *testing.T) {
	ct, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	xrayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.example.com",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(xrayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestExpiredCertificate(t *testing.T) {
	caCert, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	expiredCert, _ := cert.MustGenerate(caCert, cert.NotAfter(time.Now().Add(time.Minute*-2)), cert.CommonName("www.example.com"), cert.DNSNames("www.example.com"))

	certificate := ParseCertificate(caCert)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	certificate2 := ParseCertificate(expiredCert)

	c := &Config{
		Certificate: []*Certificate{
			certificate,
			certificate2,
		},
	}

	tlsConfig := c.GetTLSConfig()
	xrayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.example.com",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(xrayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestInsecureCertificates(t *testing.T) {
	c := &Config{}

	tlsConfig := c.GetTLSConfig()
	if len(tlsConfig.CipherSuites) > 0 {
		t.Fatal("Unexpected tls cipher suites list: ", tlsConfig.CipherSuites)
	}
}

func TestServerCertificateCipherSuitesUseForwardSecretAEAD(t *testing.T) {
	tlsConfig := (&Config{Certificate: []*Certificate{{}}}).GetTLSConfig()
	want := map[uint16]bool{
		gotls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       true,
		gotls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       true,
		gotls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
		gotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         true,
		gotls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         true,
		gotls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
	}
	for _, suite := range tlsConfig.CipherSuites {
		if !want[suite] {
			t.Fatalf("unexpected default TLS 1.2 cipher suite 0x%04x", suite)
		}
		delete(want, suite)
	}
	if len(want) != 0 {
		t.Fatalf("missing forward-secret AEAD cipher suites: %v", want)
	}
}

func TestMasterKeyLogIsCreatedPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls.keys")
	tlsConfig := (&Config{MasterKeyLog: path}).GetTLSConfig()
	if closer, ok := tlsConfig.KeyLogWriter.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("master key log permissions are %o, want 600", permissions)
	}
}

func BenchmarkCertificateIssuing(b *testing.B) {
	ct, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	lenCerts := len(tlsConfig.Certificates)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
			ServerName: "www.example.com",
		})
		delete(tlsConfig.NameToCertificate, "www.example.com")
		tlsConfig.Certificates = tlsConfig.Certificates[:lenCerts]
	}
}
