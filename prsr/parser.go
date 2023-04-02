package prsr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/botsman/crt-prsr/prsr/crl"
	"github.com/botsman/crt-prsr/prsr/crt"
	"math/big"
	"time"
)

type Plugin interface {
	Parse(c *crt.Certificate) PluginParseResult
}

type PluginParseResult interface {
}

type Parser struct {
	Plugins             map[string]Plugin
	TrustedCertificates map[string]struct{}
}

func (p *Parser) AddTrustedCertificates(certificateHashes ...string) {
	for _, hash := range certificateHashes {
		p.TrustedCertificates[hash] = struct{}{}
	}
}

func (p *Parser) LoadCertFromBytes(content []byte, uri string) ([]*crt.Certificate, error) {
	return crt.LoadCertFromBytes(content, uri)
}

func (p *Parser) LoadChain(c *crt.Certificate) (*x509.CertPool, *x509.CertPool, error) {
	return x509.NewCertPool(), x509.NewCertPool(), nil
}

func (p *Parser) IsTrusted(c *crt.Certificate) (bool, error) {
	/**
	Go through the certificate chain until we find a trusted certificate or reach the root.
	*/
	if _, isTrusted := p.TrustedCertificates[c.GetSha256()]; isTrusted {
		return true, nil
	}
	roots, intermediates, err := p.LoadChain(c)
	if err != nil {
		return false, err
	}
	parent := c
	for {
		if parent.GetParentLinks() == nil {
			return false, nil
		}
		if parent.IsRoot() {
			return false, nil
		}
		parent, err = parent.LoadParentCertificate()
		if err != nil {
			return false, err
		}
		if _, isTrusted := p.TrustedCertificates[parent.GetSha256()]; isTrusted {
			roots.AddCert(parent.X509Cert)
			break
		}
		intermediates.AddCert(parent.X509Cert)
	}
	err = c.Verify(intermediates, roots, nil)
	return err == nil, err
}

func (p *Parser) IsRevoked(c *crt.Certificate) (bool, error) {
	list, err := crl.LoadCRL(c)
	if err != nil {
		return false, err
	}
	return list.IsRevoked(c.GetSerialNumber()), nil
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
	Sha256       string                       `json:"sha256"`
	Issuer       Organization                 `json:"issuer"`
	Subject      Organization                 `json:"subject"`
	NotBefore    time.Time                    `json:"not_before"`
	NotAfter     time.Time                    `json:"not_after"`
	SerialNumber *big.Int                     `json:"serial_number"`
	KeyUsage     []string                     `json:"key_usage"`
	ExtKeyUsage  []string                     `json:"ext_key_usage"`
	ParentLinks  []string                     `json:"parent_links"`
	CrlLink      string                       `json:"crl_link"`
	Plugins      map[string]PluginParseResult `json:"plugins"`
}

type ParsedAndValidatedCertificate struct {
	ParsedCertificate
	IsTrusted bool `json:"is_trusted"`
	IsRevoked bool `json:"is_revoked"`
	IsValid   bool `json:"is_valid"`
}

func NewParser(trustedCertificateHashes []string, plugins map[string]Plugin) *Parser {
	trustedCertificates := make(map[string]struct{}, 0)
	for _, hash := range trustedCertificateHashes {
		trustedCertificates[hash] = struct{}{}
	}
	return &Parser{
		TrustedCertificates: trustedCertificates,
		Plugins:             plugins,
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
	type PluginResultPair struct {
		Name  string
		Value PluginParseResult
	}
	plugins := make(map[string]PluginParseResult, 0)
	pluginsResult := make(chan PluginResultPair)
	for name, plugin := range p.Plugins {
		go func(out chan<- PluginResultPair, n string, p Plugin) {
			out <- PluginResultPair{Name: n, Value: p.Parse(crt)}
		}(pluginsResult, name, plugin)
	}
	for range p.Plugins {
		res := <-pluginsResult
		plugins[res.Name] = res.Value
	}
	res := ParsedCertificate{
		Sha256:       crt.GetSha256(),
		Issuer:       p.ParseOrganization(crt.GetIssuer()),
		Subject:      p.ParseOrganization(crt.GetSubject()),
		NotBefore:    crt.GetNotBefore(),
		NotAfter:     crt.GetNotAfter(),
		SerialNumber: crt.GetSerialNumber(),
		KeyUsage:     crt.GetKeyUsage(),
		ExtKeyUsage:  crt.GetExtKeyUsage(),
		ParentLinks:  crt.GetParentLinks(),
		CrlLink:      crt.GetCrlLink(),
		Plugins:      plugins,
	}
	return res, nil
}

func (p *Parser) ParseAndValidate(crt *crt.Certificate) (ParsedAndValidatedCertificate, error) {
	isTrusted, _ := p.IsTrusted(crt)
	isRevoked, _ := p.IsRevoked(crt)
	parseResult, err := p.Parse(crt)
	if err != nil {
		return ParsedAndValidatedCertificate{}, err
	}
	res := ParsedAndValidatedCertificate{
		ParsedCertificate: parseResult,
		IsTrusted:         isTrusted,
		IsRevoked:         isRevoked,
		IsValid:           isTrusted && !isRevoked,
	}
	return res, nil
}
