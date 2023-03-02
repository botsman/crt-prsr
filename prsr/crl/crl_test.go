package crl

import (
	"io"
	"os"
	"testing"
)

func TestNewCRL(t *testing.T) {
	file, err := os.Open("../testdata/TCA3.crl")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCRL(content)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCRL_GetRevokedCertificates(t *testing.T) {
	file, err := os.Open("../testdata/TCA3.crl")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := NewCRL(content)
	if err != nil {
		t.Fatal(err)
	}
	certs := crl.GetRevokedCertificates()
	if len(certs) == 0 || certs == nil {
		t.Fatal("No revoked certificates")
	}
}
