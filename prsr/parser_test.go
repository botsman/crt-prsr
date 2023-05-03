package prsr

import (
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
	"testing"
)

type TestLoader struct {
	ldr.Loader
}

func (l TestLoader) LoadRootCerts() ([][]byte, error) {
	return [][]byte{
		[]byte(`-----BEGIN CERTIFICATE-----
MIIF1DCCBLygAwIBAgIJAN8Yo9jSJfnYMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNV
BAYTAkhVMREwDwYDVQQHEwhCdWRhcGVzdDEWMBQGA1UEChMNTWljcm9zZWMgTHRk
LjEUMBIGA1UECxMLZS1Temlnbm8gQ0ExLDAqBgNVBAMTI01pY3Jvc2VjIGUtU3pp
Z25vIFRlc3QgUm9vdCBDQSAyMDA4MB4XDTA4MDkyNTEwMDAxMFoXDTM3MDkyNTEw
MDAxMFowfDELMAkGA1UEBhMCSFUxETAPBgNVBAcTCEJ1ZGFwZXN0MRYwFAYDVQQK
Ew1NaWNyb3NlYyBMdGQuMRQwEgYDVQQLEwtlLVN6aWdubyBDQTEsMCoGA1UEAxMj
TWljcm9zZWMgZS1Temlnbm8gVGVzdCBSb290IENBIDIwMDgwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDgXsFvG/ez5z2GiJakv7wOwohcyWUY1J14DcSI
axvFPubuh3mACx76lQQFuwdGkthGj8MT5k05zghKnnh7p7kWnIEsqyKwNBBPnwaK
6Re+gGS3mU7J/VkliIHDXVkLzsE9mKcQP71EQgiQNR/l+p/WcuzwgehYZSDQhuqh
7oSvFfpr1zu16aeUo4ap6n3U9AWspuqBXYyjZqdUJMnEuFoQhBtvbjsextDmJtoS
N5cDb6ktzBrrxYVfQ+hmmEDsmD8KWcnNqaQE2EPVILLm61mCQ0tti58PCold1kZ2
nMwffDoD6vaLe18WdDN6e+mz6Io1F6lGbKJoko7Dtlsy6TwdAgMBAAGjggJXMIIC
UzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS1LwbSm6uxc1CbUsO/2oGgG95q
OTAfBgNVHSMEGDAWgBS1LwbSm6uxc1CbUsO/2oGgG95qOTAOBgNVHQ8BAf8EBAMC
AQYwggGoBgNVHSAEggGfMIIBmzCCAZcGDCsGAQQBgagYAgEBCTCCAYUwJwYIKwYB
BQUHAgEWG2h0dHA6Ly93d3cuZS1zemlnbm8uaHUvVEhSLzCCAVgGCCsGAQUFBwIC
MIIBSh6CAUYAVABlAHMAegB0AGUAbADpAHMAaQAgAGMA6QBsAHIAYQAgAGsAaQBh
AGQAbwB0AHQAIABUAEUAUwBaAFQAIAB0AGEAbgD6AHMA7QB0AHYA4QBuAHkALgAg
AEEAIABoAGEAcwB6AG4A4QBsAGEAdADhAHYAYQBsACAAawBhAHAAYwBzAG8AbABh
AHQAbwBzAGEAbgAgAGYAZQBsAG0AZQByAPwAbAFRACAAawDhAHIAbwBrAOkAcgB0
ACAAYQB6ACAAZQAtAFMAegBpAGcAbgDzACAASABpAHQAZQBsAGUAcwDtAHQA6QBz
ACAAUwB6AG8AbABnAOEAbAB0AGEAdADzACAAcwBlAG0AbQBpAGwAeQBlAG4AIABm
AGUAbABlAGwBUQBzAHMA6QBnAGUAdAAgAG4AZQBtACAAdgDhAGwAbABhAGwAITBE
BggrBgEFBQcBAQQ4MDYwNAYIKwYBBQUHMAKGKGh0dHA6Ly90ZXN6dC5lLXN6aWdu
by5odS9UUm9vdENBMjAwOC5jcnQwDQYJKoZIhvcNAQELBQADggEBAJ/LJyWKHkGa
BZPu8lduw8/tzIu9FUWcjyI7YVyhcuVGEgpIKRexIyknhnhsO8Bdsx6jhT9BNPvL
irOceAAT+qtkb12h+wD4Gv0CgELBImtRE7vKLdVhaoex1G5Ihr9YgaTVA5tsK56i
kYzZWCh7hHZWneuOsQtLXhEQoAEJQZ3fC4YSaiupm3x71n/iH4Q+7vRO2ZJ+7B03
uonbwlvtRw967pWUm2vqYTFuJ0hnqkRvg+1IzcMTP+LRIYtJhbPgeA6xltDNl1Ps
tRJbfLgi0GA7699rK8cbxmIpO7sVdUEJA5qtsGntp5QbT3mMbhbU/87CHa0xBChh
VUDPvt4WHto=
-----END CERTIFICATE-----`),
	}, nil
}

func TestNewCertificateParser(t *testing.T) {
	parser := NewParser(nil, TestLoader{}, nil)
	if parser == nil {
		t.Fatal("parser should not be nil")
	}
}

func TestCertificateParser_IsTrusted(t *testing.T) {
	parser := NewParser(nil, TestLoader{}, nil)
	crts, err := crt.LoadCertFromPath("testdata/qwac.crt")
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
	parser := NewParser(nil, nil, nil)
	crts, err := crt.LoadCertFromPath("testdata/qwac.crt")
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
	parser := NewParser(nil, TestLoader{}, nil)
	crts, err := crt.LoadCertFromPath("testdata/qwac.crt")
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
	parser := NewParser(nil, nil, nil)
	crts, err := crt.LoadCertFromPath("testdata/qwac.crt")
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
