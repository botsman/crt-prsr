package crt

import (
	"encoding/pem"
	"errors"
	"fmt"
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

func LoadCertFromString(content string) (*Certificate, error) {
	certDERBlock, _ := pem.Decode([]byte(content))
	if certDERBlock == nil {
		return nil, errors.New("invalid crt content")
	}
	if certDERBlock.Type != "CERTIFICATE" {
		return nil, errors.New(fmt.Sprintf("Only public certificates supported. Got: %s", certDERBlock.Type))
	}
	return NewCertificate(certDERBlock.Bytes, "")
}

func TestCertificate_GetIssuer(t *testing.T) {
	cert, err := LoadCertFromString(certString)
	if err != nil {
		t.Fatal(err)
	}
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
	cert, err := LoadCertFromString(certString)
	if err != nil {
		t.Fatal(err)
	}
	parentLinks := cert.GetParentLinks()
	parentLink := parentLinks[0]
	if parentLink != "http://teszt.e-szigno.hu/TCA3.crt" {
		t.Fatalf("Unexpected parent link: %s", parentLink)
	}
}

func TestCertificate_GetCrlLink(t *testing.T) {
	cert, err := LoadCertFromString(certString)
	if err != nil {
		t.Fatal(err)
	}
	crlLink := cert.GetCrlLink()
	if crlLink != "http://teszt.e-szigno.hu/TCA3.crl" {
		t.Fatalf("Unexpected crl link: %s", crlLink)
	}
}

func TestCertificate_GetKeyUsage(t *testing.T) {
	cert, err := LoadCertFromString(certString)
	if err != nil {
		t.Fatal(err)
	}
	keyUsage := cert.GetKeyUsage()
	if len(keyUsage) != 2 {
		t.Fatalf("Unexpected key usage: %v", keyUsage)
	}
}
