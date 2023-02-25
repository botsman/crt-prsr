package prsr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
	"math/big"
	"time"
)

type Plugin interface {
	Parse(c *crt.Certificate) PluginParseResult
}

type PluginParseResult interface {
	MarshalJSON() ([]byte, error)
}

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
	Go through the certificate chain until we find a trusted certificate or reach the root.
	*/
	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()
	parent := c
	var err error
	for {
		_, isTrusted := p.trustedCertificates[parent.GetSha256()]
		if isTrusted {
			roots.AddCert(parent.X509Cert)
			break
		}
		if parent.GetParentLinks() == nil {
			return false
		}
		if parent.IsRoot() {
			return false
		}
		parent, err = ldr.LoadParentCertificate(parent)
		if err != nil {
			return false
		}
		intermediates.AddCert(parent.X509Cert)
	}
	err = c.Verify(intermediates, roots, nil)
	return err == nil
}

type Organization struct {
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"street_address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	CommonName         string `json:"common_name,omitempty"`
	Unit               string `json:"unit,omitempty"`
}

type ParsedCertificate struct {
	Sha256       string              `json:"sha256"`
	Issuer       Organization        `json:"issuer"`
	Subject      Organization        `json:"subject"`
	NotBefore    time.Time           `json:"not_before"`
	NotAfter     time.Time           `json:"not_after"`
	SerialNumber *big.Int            `json:"serial_number"`
	IsTrusted    bool                `json:"is_trusted"`
	IsRevoked    bool                `json:"is_revoked"`
	KeyUsage     []string            `json:"key_usage"`
	ExtKeyUsage  []string            `json:"ext_key_usage"`
	ParentLinks  []string            `json:"parent_links"`
	CrlLink      string              `json:"crl_link"`
	Plugins      []PluginParseResult `json:"plugins"`
}

func NewParser(trustedCertificates []crt.Id, plugins []Plugin) *Parser {
	loader := ldr.NewCertificateLoader()
	certsMap := loader.Load(trustedCertificates)
	return &Parser{
		loader:              loader,
		trustedCertificates: certsMap,
		plugins:             plugins,
	}
}

func (p *Parser) ParseOrganization(org pkix.Name) Organization {
	var organization Organization
	if len(org.Country) != 0 {
		organization.Country = org.Country[0]
	}
	if len(org.Organization) != 0 {
		organization.Organization = org.Organization[0]
	}
	if len(org.OrganizationalUnit) != 0 {
		organization.OrganizationalUnit = org.OrganizationalUnit[0]
	}
	if len(org.Locality) != 0 {
		organization.Locality = org.Locality[0]
	}
	if len(org.Province) != 0 {
		organization.Province = org.Province[0]
	}
	if len(org.StreetAddress) != 0 {
		organization.StreetAddress = org.StreetAddress[0]
	}
	if len(org.PostalCode) != 0 {
		organization.PostalCode = org.PostalCode[0]
	}
	organization.SerialNumber = org.SerialNumber
	organization.CommonName = org.CommonName
	if len(org.OrganizationalUnit) != 0 {
		organization.Unit = org.OrganizationalUnit[0]
	}
	return organization
}

func (p *Parser) Parse(crt *crt.Certificate) (ParsedCertificate, error) {
	_, isTrusted := p.trustedCertificates[crt.GetSha256()]
	isRevoked, _ := ldr.IsRevoked(crt)
	plugins := make([]PluginParseResult, 0)
	pluginsResult := make(chan PluginParseResult)
	for _, plugin := range p.plugins {
		go func(out chan<- PluginParseResult, p Plugin) {
			out <- p.Parse(crt)
		}(pluginsResult, plugin)
	}
	for range p.plugins {
		plugins = append(plugins, <-pluginsResult)
	}
	res := ParsedCertificate{
		Sha256:       crt.GetSha256(),
		Issuer:       p.ParseOrganization(crt.GetIssuer()),
		Subject:      p.ParseOrganization(crt.GetSubject()),
		NotBefore:    crt.GetNotBefore(),
		NotAfter:     crt.GetNotAfter(),
		SerialNumber: crt.GetSerialNumber(),
		IsTrusted:    isTrusted,
		IsRevoked:    isRevoked,
		KeyUsage:     crt.GetKeyUsage(),
		ExtKeyUsage:  crt.GetExtKeyUsage(),
		ParentLinks:  crt.GetParentLinks(),
		CrlLink:      crt.GetCrlLink(),
		Plugins:      plugins,
	}
	return res, nil
}

func (p *Parser) Json(cert *crt.Certificate) ([]byte, error) {
	parsed, err := p.Parse(cert)
	if err != nil {
		return nil, err
	}
	return json.Marshal(parsed)
}
