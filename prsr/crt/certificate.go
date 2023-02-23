package crt

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

type Type int

const (
	Sha256 = iota
	Uri
	Path
)

type Id struct {
	Val    string
	IdType Type
}

type Certificate struct {
	X509Cert *x509.Certificate
	link     string // self link to crt (if any)
}

func NewCertificate(content []byte, uri string) (*Certificate, error) {
	x509Cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, err
	}
	return &Certificate{x509Cert, uri}, nil
}

func LoadCertFromPath(path string) (*Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return LoadCertFromString(string(content))
}

func LoadCertFromUri(uri string) (*Certificate, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return NewCertificate(content, uri)
}

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

func (c *Certificate) GetSha256() string {
	checksum := sha256.Sum256(c.X509Cert.Raw)
	return hex.EncodeToString(checksum[:])
}

func (c *Certificate) GetIssuer() pkix.Name {
	return c.X509Cert.Issuer
}

func (c *Certificate) GetSubject() pkix.Name {
	return c.X509Cert.Subject
}

func (c *Certificate) GetNotBefore() time.Time {
	return c.X509Cert.NotBefore
}

func (c *Certificate) GetNotAfter() time.Time {
	return c.X509Cert.NotAfter
}

func (c *Certificate) GetSerialNumber() *big.Int {
	return c.X509Cert.SerialNumber
}

func (c *Certificate) GetKeyUsage() []string {
	var keyUsage []string
	switch c.X509Cert.KeyUsage {
	case x509.KeyUsageDigitalSignature:
		keyUsage = append(keyUsage, "DigitalSignature")
	case x509.KeyUsageKeyEncipherment:
		keyUsage = append(keyUsage, "KeyEncipherment")
	case x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment:
		keyUsage = append(keyUsage, "DigitalSignature")
		keyUsage = append(keyUsage, "KeyEncipherment")
	case x509.KeyUsageContentCommitment:
		keyUsage = append(keyUsage, "ContentCommitment")
	case x509.KeyUsageDataEncipherment:
		keyUsage = append(keyUsage, "DataEncipherment")
	case x509.KeyUsageKeyAgreement:
		keyUsage = append(keyUsage, "KeyAgreement")
	case x509.KeyUsageCertSign:
		keyUsage = append(keyUsage, "CertSign")
	case x509.KeyUsageCRLSign:
		keyUsage = append(keyUsage, "CRLSign")
	case x509.KeyUsageEncipherOnly:
		keyUsage = append(keyUsage, "EncipherOnly")
	case x509.KeyUsageDecipherOnly:
		keyUsage = append(keyUsage, "DecipherOnly")
	}

	return keyUsage
}

func (c *Certificate) GetExtKeyUsage() []string {
	var extKeyUsage []string
	for _, usage := range c.X509Cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			extKeyUsage = append(extKeyUsage, "Any")
		case x509.ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsage = append(extKeyUsage, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			extKeyUsage = append(extKeyUsage, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			extKeyUsage = append(extKeyUsage, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			extKeyUsage = append(extKeyUsage, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			extKeyUsage = append(extKeyUsage, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUsage = append(extKeyUsage, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, "NetscapeServerGatedCrypto")
		}
	}
	return extKeyUsage
}

func (c *Certificate) GetParentLinks() []string {
	return c.X509Cert.IssuingCertificateURL
}

func (c *Certificate) GetCrlLink() string {
	// There is also an extension "Freshest CRL / Delta CRL Distribution Point".
	// I think that we should parse it here as well
	for _, url := range c.X509Cert.CRLDistributionPoints {
		return url
	}
	return ""
}

func (c *Certificate) GetDeltaCRLLink() string {
	for _, ext := range c.X509Cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 46}) {
			// Implementation is copied from the x509 package for the CRLDistributionPoints extension
			val := cryptobyte.String(ext.Value)
			if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
				return ""
			}
			var dpDER cryptobyte.String
			if !val.ReadASN1(&dpDER, cryptobyte_asn1.SEQUENCE) {
				return ""
			}
			var dpNameDER cryptobyte.String
			var dpNamePresent bool
			if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
				return ""
			}
			if !dpNamePresent {
				return ""
			}
			if !dpNameDER.ReadASN1(&dpNameDER, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
				return ""
			}
			if !dpNameDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
				return ""
			}
			var uri cryptobyte.String
			if !dpNameDER.ReadASN1(&uri, cryptobyte_asn1.Tag(6).ContextSpecific()) {
				return ""
			}
			return string(uri)
		}
	}
	return ""
}

func (c *Certificate) IsRoot() bool {
	for _, link := range c.GetParentLinks() {
		if link == c.link {
			return true
		}
	}
	return false
}
