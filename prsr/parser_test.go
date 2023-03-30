package prsr

import (
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr/ldr"
	"testing"
)

func TestNewCertificateParser(t *testing.T) {
	parser := NewParser([]string{}, nil, nil)
	if parser == nil {
		t.Fatal("parser should not be nil")
	}
}

func TestCertificateParser_AddTrustedCertificates(t *testing.T) {
	parser := NewParser([]string{}, nil, nil)
	if parser == nil {
		t.Fatal("parser should not be nil")
	}
	certs := []string{"de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565"}
	parser.AddTrustedCertificates(certs...)
	if len(parser.TrustedCertificates) != 1 {
		t.Fatal("TrustedCertificates should have 1 item")
	}
	moreCerts := []string{"d42df70b62f315415ceb8791638a563966d69078c127204832b2f4fabeaf2830"}
	parser.AddTrustedCertificates(moreCerts...)
	if len(parser.TrustedCertificates) != 2 {
		t.Fatal("TrustedCertificates should have 2 items")
	}
}

func TestCertificateParser_IsTrusted(t *testing.T) {
	certs := []string{"de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565"}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	crts, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert := crts[0]
	isTrusted, err := parser.IsTrusted(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !isTrusted {
		t.Fatal("certificate should be trusted")
	}
}

func TestCertificateParser_IsTrustedRoot(t *testing.T) {
	certs := []string{"d42df70b62f315415ceb8791638a563966d69078c127204832b2f4fabeaf2830"}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	crts, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert := crts[0]
	isTrusted, err := parser.IsTrusted(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !isTrusted {
		t.Fatal("certificate should be trusted")
	}
}

func TestCertificateParser_Parse(t *testing.T) {
	certs := []string{"de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565"}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	crts, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert := crts[0]
	result, err := parser.Parse(cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)
}

func TestCertificateParser_ParseAndValidate(t *testing.T) {
	certs := []string{"de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565"}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	crts, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert := crts[0]
	result, err := parser.ParseAndValidate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsValid {
		t.Fatal("certificate should be valid")
	}
}

func TestCertificateParser_Json(t *testing.T) {
	certs := []string{"de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565"}
	loader := ldr.NewCertificateLoader()
	parser := NewParser(certs, loader, nil)
	crts, err := loader.LoadCertFromPath("testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert := crts[0]
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
