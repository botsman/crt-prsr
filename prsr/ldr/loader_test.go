package ldr

import (
	"github.com/botsman/crt-prsr/prsr/crt"
	"testing"
)

func TestNewCertificateLoader(t *testing.T) {
	NewCertificateLoader()
}

func TestCertificateLoader_Load(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
	}
	loader := NewCertificateLoader()
	loader.Load(certs)
}

func Test_loadParentCertificate(t *testing.T) {
	cert, err := crt.LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := LoadParentCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		t.Fatal("parent should not be nil")
	}
	if parent.GetSha256() != "07f6606a521ad4e8d463c4e5656382e2baa110b9a753c27b5497bf9875d7c0e5" {
		t.Fatalf("Unexpected sha256: %s", parent.GetSha256())
	}
}

func Test_loadRootCertificate(t *testing.T) {
	cert, err := crt.LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	root, err := LoadRootCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if root == nil {
		t.Fatal("root should not be nil")
	}
	if root.GetSha256() != "d42df70b62f315415ceb8791638a563966d69078c127204832b2f4fabeaf2830" {
		t.Fatalf("Unexpected sha256: %s", root.GetSha256())
	}
}

func TestCertificateLoader_LoadCRL(t *testing.T) {
	cert, err := crt.LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	crl, err := LoadCRL(cert)
	if err != nil {
		t.Fatal(err)
	}
	if crl == nil {
		t.Fatal("crl should not be nil")
	}
}

func TestIsRevoked(t *testing.T) {
	cert, err := crt.LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := IsRevoked(cert)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("cert should not be revoked")
	}
}
