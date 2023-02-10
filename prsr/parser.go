package prsr

import (
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
	"math/big"
	"time"
)

type Plugin interface {
	Parse(c *crt.Certificate) PluginParseResult
}

type PluginParseResult interface{}

type Loader interface {
	Load(trustedCertificates []crt.Id) map[string]struct{}
}

type Parser struct {
	loader              Loader
	plugins             []Plugin
	trustedCertificates map[string]struct{}
}

func (p *Parser) IsTrusted(c *crt.Certificate) bool {
	/**
	Go through the certificate chain and check if any of the certificates
	are trusted. If so, return true. If not, return false.
	*/
	for {
		_, isTrusted := p.trustedCertificates[c.GetSha256()]
		if isTrusted {
			return true
		}
		if c.GetParentLinks() == nil {
			return false
		}
		if c.IsRoot() {
			return false
		}
		parent, err := ldr.LoadParentCertificate(c)
		if err != nil {
			return false
		}
		c = parent
	}

}

type CertificateDN struct {
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Locality           string `json:"locality"`
	Province           string `json:"province"`
	StreetAddress      string `json:"street_address"`
	PostalCode         string `json:"postal_code"`
	SerialNumber       string `json:"serial_number"`
	CommonName         string `json:"common_name"`
	Unit               string `json:"unit"`
}

type ParsedCertificate struct {
	Sha256       string              `json:"sha256"`
	Issuer       CertificateDN       `json:"issuer"`
	Subject      CertificateDN       `json:"subject"`
	NotBefore    time.Time           `json:"not_before"`
	NotAfter     time.Time           `json:"not_after"`
	SerialNumber *big.Int            `json:"serial_number"`
	IsTrusted    bool                `json:"is_trusted"`
	KeyUsage     string              `json:"key_usage"`
	ParentLinks  []string            `json:"parent_links"`
	CrlLink      string              `json:"crl_link"`
	Plugins      []PluginParseResult `json:"plugins"`
}

func NewParser(trustedCertificates []crt.Id) *Parser {
	loader := ldr.NewCertificateLoader()
	certsMap := loader.Load(trustedCertificates)
	return &Parser{
		loader:              loader,
		trustedCertificates: certsMap,
	}
}

func (p *Parser) Parse(crt *crt.Certificate) (ParsedCertificate, error) {
	issuer := CertificateDN{
		Country:      crt.GetIssuer().Country[0],
		Organization: crt.GetIssuer().Organization[0],
		Unit:         crt.GetIssuer().OrganizationalUnit[0],
	}
	_, isTrusted := p.trustedCertificates[crt.GetSha256()]
	plugins := make([]PluginParseResult, 0)
	for _, plugin := range p.plugins {
		plugins = append(plugins, plugin.Parse(crt))
	}
	res := ParsedCertificate{
		Sha256: crt.GetSha256(),
		Issuer: issuer,
		Subject: CertificateDN{
			Country:      crt.GetSubject().Country[0],
			Organization: crt.GetSubject().Organization[0],
			Unit:         crt.GetSubject().OrganizationalUnit[0],
		},
		NotBefore:    crt.GetNotBefore(),
		NotAfter:     crt.GetNotAfter(),
		SerialNumber: crt.GetSerialNumber(),
		IsTrusted:    isTrusted,
		KeyUsage:     crt.GetKeyUsage(),
		ParentLinks:  crt.GetParentLinks(),
		CrlLink:      crt.GetCrlLink(),
	}
	return res, nil
}

func (p *Parser) ToJson(cert *crt.Certificate) ([]byte, error) {
	parsed, err := p.Parse(cert)
	if err != nil {
		return nil, err
	}
	return json.Marshal(parsed)
}
