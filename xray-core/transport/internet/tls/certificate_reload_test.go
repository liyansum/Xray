package tls

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestManagedCertificateConcurrentRefresh(t *testing.T) {
	first, _ := cert.MustGenerate(nil, cert.CommonName("first.example"), cert.DNSNames("first.example"))
	second, _ := cert.MustGenerate(nil, cert.CommonName("second.example"), cert.DNSNames("second.example"))
	entry := ParseCertificate(first)
	originalCertificate := bytes.Clone(entry.Certificate)
	originalKey := bytes.Clone(entry.Key)
	directory := t.TempDir()
	entry.CertificatePath = filepath.Join(directory, "certificate.pem")
	entry.KeyPath = filepath.Join(directory, "key.pem")
	if err := os.WriteFile(entry.CertificatePath, entry.Certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.KeyPath, entry.Key, 0o600); err != nil {
		t.Fatal(err)
	}

	managed := newManagedCertificate(entry)
	if managed == nil {
		t.Fatal("failed to build initial certificate")
	}
	// The test drives refresh directly; readers must only observe complete,
	// immutable snapshots while the backing files are replaced.
	managed.refreshInterval = 0

	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 1000 {
				snapshot := managed.snapshot()
				if snapshot == nil || snapshot.keyPair == nil || snapshot.keyPair.Leaf == nil {
					t.Error("observed incomplete certificate snapshot")
					return
				}
			}
		})
	}
	for i := range 100 {
		current := ParseCertificate(first)
		if i%2 != 0 {
			current = ParseCertificate(second)
		}
		if err := os.WriteFile(entry.CertificatePath, current.Certificate, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry.KeyPath, current.Key, 0o600); err != nil {
			t.Fatal(err)
		}
		managed.refresh()
	}
	readers.Wait()

	if !bytes.Equal(entry.Certificate, originalCertificate) || !bytes.Equal(entry.Key, originalKey) {
		t.Fatal("certificate refresh mutated the source configuration")
	}
}
