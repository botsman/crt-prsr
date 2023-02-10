package crt

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
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
	x509Cert *x509.Certificate
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
	checksum := sha256.Sum256(c.x509Cert.Raw)
	return hex.EncodeToString(checksum[:])
}

func (c *Certificate) GetIssuer() pkix.Name {
	return c.x509Cert.Issuer
}

func (c *Certificate) GetSubject() pkix.Name {
	return c.x509Cert.Subject
}

func (c *Certificate) GetNotBefore() time.Time {
	return c.x509Cert.NotBefore
}

func (c *Certificate) GetNotAfter() time.Time {
	return c.x509Cert.NotAfter
}

func (c *Certificate) GetSerialNumber() *big.Int {
	return c.x509Cert.SerialNumber
}

func (c *Certificate) GetKeyUsage() string {
	switch c.x509Cert.KeyUsage {
	case x509.KeyUsageDigitalSignature:
		return "DigitalSignature"
	case x509.KeyUsageContentCommitment:
		return "ContentCommitment"
	case x509.KeyUsageKeyEncipherment:
		return "KeyEncipherment"
	case x509.KeyUsageDataEncipherment:
		return "DataEncipherment"
	case x509.KeyUsageKeyAgreement:
		return "KeyAgreement"
	case x509.KeyUsageCertSign:
		return "CertSign"
	case x509.KeyUsageCRLSign:
		return "CRLSign"
	case x509.KeyUsageEncipherOnly:
		return "EncipherOnly"
	case x509.KeyUsageDecipherOnly:
		return "DecipherOnly"
	default:
		return "Unknown"
	}
}

func (c *Certificate) GetExtensions() []string {
	var extensions []string
	for _, extension := range c.x509Cert.Extensions {
		//	Perhaps there is a better way to get the value of the extension
		extensions = append(extensions, extension.Id.String())
	}
	for _, extension := range c.x509Cert.ExtraExtensions {
		extensions = append(extensions, extension.Id.String())
	}
	for _, extension := range c.x509Cert.UnhandledCriticalExtensions {
		extensions = append(extensions, extension.String())
	}
	return extensions
}

func (c *Certificate) GetParentLinks() []string {
	return c.x509Cert.IssuingCertificateURL
}

func (c *Certificate) GetCrlLink() string {
	// There is also an extension "Freshest CRL / Delta CRL Distribution Point".
	// I think that we should parse it here as well
	for _, url := range c.x509Cert.CRLDistributionPoints {
		return url
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
