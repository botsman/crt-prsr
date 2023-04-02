package crt

import (
	"io"
	"net/http"
	"testing"
)

const certString = `-----BEGIN CERTIFICATE-----
MIIJvzCCCKegAwIBAgINfFpB/JRgotxghHiHCjANBgkqhkiG9w0BAQsFADBqMQsw
CQYDVQQGEwJIVTERMA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2Vj
IEx0ZC4xFDASBgNVBAsMC2UtU3ppZ25vIENBMRowGAYDVQQDDBFlLVN6aWdubyBU
ZXN0IENBMzAeFw0yMzAyMDYwNzMxNDVaFw0yNDAyMDYwNzMxNDVaMIG/MRMwEQYL
KwYBBAGCNzwCAQMTAkZJMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjES
MBAGA1UEBRMJMTIzNDU2Ny04MQswCQYDVQQGEwJGSTERMA8GA1UEBwwISGVsc2lu
a2kxHTAbBgNVBAoMFENlcnRpZmljYXRlIFZlcmlmaWVyMR8wHQYDVQRhDBZQU0RG
SS1GSU5GU0EtMTIzNDU2Ny04MRUwEwYDVQQDDAxjcnQtcHJzci5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdRDAHdBDp7grHigwUEJ1Gl/2JGhAr
rrNdXoPP05L9zFJ6sPIN6Jn5LP1a+beyCsyoFXtxm1G0zibYXB8BILDCC3eWiqrq
JT/BChXNAzztUrRb13Fycga12NjukTGllc/k08yjQ0g6v2fghufvMIxwpZ6jrrK/
Uex3jnpVXgqT+InZHAWmAIRXCODWgQMV9JPXqCgsHKiWFiry9HAS6VM36D9PJlvy
arWr4Cd5jb+oOfaJCLREKMxasa+yY+Zjk+k53CqrAfs/dC9+YwNAacVWZK9tKpf8
0bdGpSE9rmJB+DtvE4hsJp/xBMTB7DqYh3uRc4R1e8oolFs/8chv9I1TAgMBAAGj
ggYMMIIGCDAOBgNVHQ8BAf8EBAMCBaAwgYkGCisGAQQB1nkCBAIEewR5AHcAdQCq
HngEP4BkgivlTLXBysLjLuRQ5nMwKki8JpcLmywIHQAAAYYlo1BCAAAEAwBGMEQC
IAuRFsANiqXaiHXiR4syLp2q+lAHL4PPOEOsaWT70udpAiBq/bfSzFSKa/p2gE/p
UHVUaZItzK0eWht7bjhswLlE4TAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwggMkBgNVHSAEggMbMIIDFzCCAxMGDCsGAQQBgagYAgEBZDCCAwEwJgYIKwYB
BQUHAgEWGmh0dHA6Ly9jcC5lLXN6aWduby5odS9xY3BzMIG/BggrBgEFBQcCAjCB
sgyBr1Rlc3QgcXVhbGlmaWVkIGNlcnRpZmljYXRlIGZvciB3ZWJzaXRlIGF1dGhl
bnRpY2F0aW9uIGFuZCBjbGllbnQgYXV0aGVudGljYXRpb24uIFRoZSBwcm92aWRl
ciBwcmVzZXJ2ZXMgcmVnaXN0cmF0aW9uIGRhdGEgZm9yIDEwIHllYXJzIGFmdGVy
IHRoZSBleHBpcmF0aW9uIG9mIHRoZSBjZXJ0aWZpY2F0ZS4wgZUGCCsGAQUFBwIC
MIGIDIGFVEVTVCBjZXJ0aWZpY2F0ZSBpc3N1ZWQgb25seSBmb3IgdGVzdGluZyBw
dXJwb3Nlcy4gVGhlIGlzc3VlciBpcyBub3QgbGlhYmxlIGZvciBhbnkgZGFtYWdl
cyBhcmlzaW5nIGZyb20gdGhlIHVzZSBvZiB0aGlzIGNlcnRpZmljYXRlITCBzAYI
KwYBBQUHAgIwgb8MgbxUZXN6dCBtaW7FkXPDrXRldHQgd2Vib2xkYWwtaGl0ZWxl
c8OtdMWRIMOpcyDDvGd5ZsOpbC1oaXRlbGVzw610xZEgdGFuw7pzw610dsOhbnku
IEEgcmVnaXN6dHLDoWNpw7NzIGFkYXRva2F0IGEgc3pvbGfDoWx0YXTDsyBhIHRh
bsO6c8OtdHbDoW55IGxlasOhcnTDoXTDs2wgc3rDoW3DrXRvdHQgMTAgw6l2aWcg
xZFyemkgbWVnLjCBrQYIKwYBBQUHAgIwgaAMgZ1UZXN6dGVsw6lzaSBjw6lscmEg
a2lhZG90dCBURVNaVCB0YW7DunPDrXR2w6FueS4gQSBoYXN6bsOhbGF0w6F2YWwg
a2FwY3NvbGF0b3NhbiBmZWxtZXLDvGzFkSBrw6Fyb2vDqXJ0IGEgU3pvbGfDoWx0
YXTDsyBzZW1taWx5ZW4gZmVsZWzFkXNzw6lnZXQgbmVtIHbDoWxsYWwhMB0GA1Ud
DgQWBBSgu/AIb8+f8rJsuoicGeMJ6wA17DAfBgNVHSMEGDAWgBTc5gIo7zcwj4k+
oK0gVfPvNujwzTAXBgNVHREEEDAOggxjcnQtcHJzci5jb20wMgYDVR0fBCswKTAn
oCWgI4YhaHR0cDovL3Rlc3p0LmUtc3ppZ25vLmh1L1RDQTMuY3JsMG8GCCsGAQUF
BwEBBGMwYTAwBggrBgEFBQcwAYYkaHR0cDovL3Rlc3p0LmUtc3ppZ25vLmh1L3Rl
c3RjYTNvY3NwMC0GCCsGAQUFBzAChiFodHRwOi8vdGVzenQuZS1zemlnbm8uaHUv
VENBMy5jcnQwggEjBggrBgEFBQcBAwSCARUwggERMAgGBgQAjkYBATALBgYEAI5G
AQMCAQowUwYGBACORgEFMEkwJBYeaHR0cHM6Ly9jcC5lLXN6aWduby5odS9xY3Bz
X2VuEwJFTjAhFhtodHRwczovL2NwLmUtc3ppZ25vLmh1L3FjcHMTAkhVMBMGBgQA
jkYBBjAJBgcEAI5GAQYDMIGNBgYEAIGYJwIwgYIwTDARBgcEAIGYJwEBDAZQU1Bf
QVMwEQYHBACBmCcBAgwGUFNQX1BJMBEGBwQAgZgnAQMMBlBTUF9BSTARBgcEAIGY
JwEEDAZQU1BfSUMMJ0Zpbm5pc2ggRmluYW5jaWFsIFN1cGVydmlzb3J5IEF1dGhv
cml0eQwJRkktRklORlNBMA0GCSqGSIb3DQEBCwUAA4IBAQAvl68baP2tiG35tdpv
fJkg0o+Y+xSwtCLuAaVrZDw3HCixGu2Y3f/UfyjBDiRYHMqjzzPKkrqI2NiogGu9
byPLNQcaCrh35uSfSPRy1TkPSxj3dihI9pmUru0j/Ik1RAcm4gPDu9vy+7WbuvzU
JQecL67NdCDwuFUzFn1PdF3kppKjCIycje1XFPzFqs1tMK3CEf0PHlQE+xlWPIRs
s+M0KVUHyePg4oAItm+dKnWClUBPtqfMZbCTYYY49jmb9DshzAAXHBuPkeOualk8
x35wT6cuCGm5EnH+r/0imXjrG+Sy6JYjgXvBi9aypcV/+xOIeTjNojgbKOdt8Z7U
mOaW
-----END CERTIFICATE-----
`

func TestCertificate_GetIssuer(t *testing.T) {
	certs, err := LoadCertFromBytes([]byte(certString), "")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	issuer := cert.GetIssuer()
	if issuer.String() != "CN=e-Szigno Test CA3,OU=e-Szigno CA,O=Microsec Ltd.,L=Budapest,C=HU" {
		t.Fatalf("Unexpected issuer: %s", cert.GetIssuer())
	}
	if issuer.Country[0] != "HU" {
		t.Fatalf("Unexpected country: %s", issuer.Country)
	}
	if issuer.Organization[0] != "Microsec Ltd." {
		t.Fatalf("Unexpected organization: %s", issuer.Organization[0])
	}
	if issuer.CommonName != "e-Szigno Test CA3" {
		t.Fatalf("Unexpected common name: %s", issuer.CommonName)
	}
}

func TestCertificate_GetParentLink(t *testing.T) {
	certs, err := LoadCertFromBytes([]byte(certString), "")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	parentLinks := cert.GetParentLinks()
	parentLink := parentLinks[0]
	if parentLink != "http://teszt.e-szigno.hu/TCA3.crt" {
		t.Fatalf("Unexpected parent link: %s", parentLink)
	}
}

func TestCertificate_GetCrlLink(t *testing.T) {
	certs, err := LoadCertFromBytes([]byte(certString), "")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	crlLinks := cert.GetCrlLinks()
	if crlLinks[0] != "http://teszt.e-szigno.hu/TCA3.crl" {
		t.Fatalf("Unexpected crl link: %s", crlLinks[0])
	}
}

func TestCertificate_GetKeyUsage(t *testing.T) {
	certs, err := LoadCertFromBytes([]byte(certString), "")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	keyUsage := cert.GetKeyUsage()
	if len(keyUsage) != 2 {
		t.Fatalf("Unexpected key usage: %v", keyUsage)
	}
}

func Test_loadParentCertificate(t *testing.T) {
	cert, err := LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := cert[0].LoadParentCertificate()
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
	certs, err := LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	root, err := certs[0].LoadRootCertificate()
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

func TestLoadCertFromPath(t *testing.T) {
	certs, err := LoadCertFromPath("../testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	if cert.GetSha256() != "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565" {
		t.Fatalf("Unexpected sha256: %s", cert.GetSha256())
	}
}

func TestLoadCertFromUri(t *testing.T) {
	certs, err := LoadCertFromUri("https://pki.goog/repo/certs/gts1c3.der")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	if cert.GetSha256() != "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522" {
		t.Fatalf("Unexpected sha256: %s", cert.GetSha256())
	}
}

func TestLoadCertFromString(t *testing.T) {
	certs, err := LoadCertFromBytes([]byte(certString), "")
	if err != nil {
		t.Fatal(err)
	}
	cert := certs[0]
	if cert.GetSha256() != "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565" {
		t.Fatalf("Unexpected sha256: %s", cert.GetSha256())
	}
}

func TestLoadCertFromUriWithInvalidUri(t *testing.T) {
	_, err := LoadCertFromUri("https://pki.goog/repo/certs/gts1c3.der/")
	if err == nil {
		t.Fatal("Expected error")
	}
}

func TestLoadCert_p7cFormat(t *testing.T) {
	const uri = "http://aia.entrust.net/esqseal1-g4.p7c"
	content, err := http.Get(uri)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(content.Body)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertFromBytes(body, uri)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("cert should not be nil")
	}
	if len(cert) != 2 {
		t.Fatalf("Unexpected cert count: %d", len(cert))
	}
}
