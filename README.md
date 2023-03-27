# Certificate parser

Project is at the very beginning of development. It is not ready for use.

This parser is intended to be used for parsing certificates in both PEM and DER formats.   
Parser itself provides only basic functionality for parsing certificates.  
If you want to use it for some specific purpose, you need to implement your own plugin (see `/plugin`)

## Loader 
Existing Loader is implemented mostly for reference and testing purposes.
In real world you probably want to preserve loaded data (certificates, CRLs) in some database/cache.

## Usage

```go
package main

import (
	"fmt"
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr"
	"github.com/botsman/crt-prsr/prsr/crt"
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

func main() {
	// Initialize parser with a set of trusted certificates
	certs := []string{"de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565"}
	parser := prsr.NewParser(certs, nil, nil)
	cert, err := prsr.LoadCertFromBytes([]byte(certString))
	if err != nil {
		panic(err)
	}
	parsed, err := parser.Parse(cert)
	if err != nil {
		panic(err)
	}
	parsedJson, err := json.Marshal(parsed)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(parsedJson))
    // Output:
    // {
    //    "sha256": "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
    //    "issuer": {
    //        "country": "HU",
    //        "organization": "Microsec Ltd.",
    //        "organizational_unit": "",
    //        "locality": "",
    //        "province": "",
    //        "street_address": "",
    //        "postal_code": "",
    //        "serial_number": "",
    //        "common_name": "",
    //        "unit": "e-Szigno CA"
    //    },
    //    "subject": {
    //        "country": "FI",
    //        "organization": "Certificate Verifier",
    //        "organizational_unit": "",
    //        "locality": "",
    //        "province": "",
    //        "street_address": "",
    //        "postal_code": "",
    //        "serial_number": "",
    //        "common_name": "",
    //        "unit": ""
    //    },
    //    "not_before": "2023-02-06T07:31:45Z",
    //    "not_after": "2024-02-06T07:31:45Z",
    //    "serial_number": 9852225575604409045021609199370,
    //    "is_trusted": true,
    //    "is_revoked": false,
    //    "key_usage": "Unknown",
    //    "parent_links": [
    //        "http://teszt.e-szigno.hu/TCA3.crt"
    //    ],
    //    "crl_link": "http://teszt.e-szigno.hu/TCA3.crl",
    //    "plugins": []
    // }   
}

```
