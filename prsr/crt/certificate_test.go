package crt

import (
	"testing"
)

const certString = `-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----
`

func TestLoadCertFromPath(t *testing.T) {
	cert, err := LoadCertFromPath("testdata/gts1c3.pem")
	if err != nil {
		t.Fatal(err)
	}
	if cert.GetSha256() != "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522" {
		t.Fatalf("Unexpected sha256: %s", cert.GetSha256())
	}
}

func TestLoadCertFromUri(t *testing.T) {
	cert, err := LoadCertFromUri("https://pki.goog/repo/certs/gts1c3.der")
	if err != nil {
		t.Fatal(err)
	}
	if cert.GetSha256() != "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522" {
		t.Fatalf("Unexpected sha256: %s", cert.GetSha256())
	}
}

func TestLoadCertFromString(t *testing.T) {
	cert, err := LoadCertFromString(certString)
	if err != nil {
		t.Fatal(err)
	}
	if cert.GetSha256() != "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522" {
		t.Fatalf("Unexpected sha256: %s", cert.GetSha256())
	}
}

func TestLoadCertFromUriWithInvalidUri(t *testing.T) {
	_, err := LoadCertFromUri("https://pki.goog/repo/certs/gts1c3.der/")
	if err == nil {
		t.Fatal("Expected error")
	}
}

func TestCertificate_GetIssuer(t *testing.T) {
	cert, err := LoadCertFromString(certString)
	if err != nil {
		t.Fatal(err)
	}
	issuer := cert.GetIssuer()
	if issuer.String() != "CN=GTS Root R1,O=Google Trust Services LLC,C=US" {
		t.Fatalf("Unexpected issuer: %s", cert.GetIssuer())
	}
	if issuer.Country[0] != "US" {
		t.Fatalf("Unexpected country: %s", issuer.Country)
	}
	if issuer.Organization[0] != "Google Trust Services LLC" {
		t.Fatalf("Unexpected organization: %s", issuer.Organization)
	}
	if issuer.CommonName != "GTS Root R1" {
		t.Fatalf("Unexpected common name: %s", issuer.CommonName)
	}
}
