package crl

import (
	"github.com/botsman/crt-prsr/prsr/crt"
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

func TestCertificateLoader_LoadCRL(t *testing.T) {
	certs, err := crt.LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	crl, err := LoadCRL(certs[0])
	if err != nil {
		t.Fatal(err)
	}
	if crl == nil {
		t.Fatal("crl should not be nil")
	}
}

func TestLoadCRLFromUri(t *testing.T) {
	crl, err := LoadCRLFromUri("http://qtlsca2018-crl1.e-szigno.hu/qtlsca2018.crl")
	if err != nil {
		t.Fatal(err)
	}
	if crl == nil {
		t.Fatal("CRL is nil")
	}
}

func Test_IsRevoked(t *testing.T) {
	crl, err := LoadCRLFromUri("http://qtlsca2018-crl1.e-szigno.hu/qtlsca2018.crl")
	if err != nil {
		t.Fatal(err)
	}
	if crl == nil {
		t.Fatal("CRL is nil")
	}
	serialNumber := crl.GetRevokedCertificates()[0].SerialNumber
	if !crl.IsRevoked(serialNumber) {
		t.Fatal("Serial number not revoked")
	}
}
