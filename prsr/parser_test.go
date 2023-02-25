package prsr

import (
	"github.com/botsman/crt-prsr/prsr/crt"
	"testing"
)

func TestNewCertificateParser(t *testing.T) {
	parser := NewParser([]crt.Id{}, nil)
	if parser == nil {
		t.Fatal("parser should not be nil")
	}
}

func TestCertificateParser_IsTrusted(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
	}
	parser := NewParser(certs, nil)
	cert, err := crt.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	isTrusted := parser.IsTrusted(cert)
	if !isTrusted {
		t.Fatal("certificate should be trusted")
	}
}

func TestCertificateParser_IsTrustedRoot(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "d42df70b62f315415ceb8791638a563966d69078c127204832b2f4fabeaf2830",
			IdType: crt.Sha256,
		},
	}
	parser := NewParser(certs, nil)
	cert, err := crt.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	isTrusted := parser.IsTrusted(cert)
	if !isTrusted {
		t.Fatal("certificate should be trusted")
	}
}

func TestCertificateParser_Parse(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
	}
	parser := NewParser(certs, nil)
	cert, err := crt.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.Parse(cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)
}

func TestCertificateParser_Json(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
	}
	parser := NewParser(certs, nil)
	cert, err := crt.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.Json(cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(result))
}
