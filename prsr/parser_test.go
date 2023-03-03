package prsr

import (
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
	"testing"
)

func TestNewCertificateParser(t *testing.T) {
	parser := NewParser([]crt.Id{}, nil, nil)
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
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	cert, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	isTrusted, err := parser.IsTrusted(cert)
	if err != nil {
		t.Fatal(err)
	}
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
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	cert, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	isTrusted, err := parser.IsTrusted(cert)
	if err != nil {
		t.Fatal(err)
	}
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
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	cert, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.Parse(cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)
}

func TestCertificateParser_ParseAndValidate(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
	}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	cert, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.ParseAndValidate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsValid {
		t.Fatal("certificate should be valid")
	}
}

func TestCertificateParser_Json(t *testing.T) {
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
	}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	cert, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.ParseAndValidate(cert)
	if err != nil {
		t.Fatal(err)
	}
	resultJson, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(resultJson))
}
