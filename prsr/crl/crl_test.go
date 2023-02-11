package crl

import "testing"

func TestLoadCRLFromUri(t *testing.T) {
	crl, err := LoadCRLFromUri("http://qtlsca2018-crl1.e-szigno.hu/qtlsca2018.crl")
	if err != nil {
		t.Fatal(err)
	}
	if crl == nil {
		t.Fatal("CRL is nil")
	}
}

func TestCRL_IsRevoked(t *testing.T) {
	crl, err := LoadCRLFromUri("http://qtlsca2018-crl1.e-szigno.hu/qtlsca2018.crl")
	if err != nil {
		t.Fatal(err)
	}
	if crl == nil {
		t.Fatal("CRL is nil")
	}
	serialNumber := crl.GetRevokedCertificates()[0].SerialNumber
	if !crl.IsRevoked(*serialNumber) {
		t.Fatal("Serial number not revoked")
	}
}
