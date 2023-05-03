package prsr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/botsman/crt-prsr/prsr/crl"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
	"github.com/botsman/crt-prsr/prsr/svr"
	"github.com/botsman/crt-prsr/prsr/utils"
	"log"
	"math/big"
	"time"
)

type Plugin interface {
	Parse(c *crt.Certificate) PluginParseResult
}

type PluginParseResult interface {
}

type Parser struct {
	Plugins map[string]Plugin
	Loader  Loader
	Saver   Saver
}

func (p *Parser) LoadCertFromBytes(content []byte, uri string) ([]*crt.Certificate, error) {
	return crt.LoadCertFromBytes(content, uri)
}

func (p *Parser) LoadParentCertificates(c *crt.Certificate) ([]*crt.Certificate, error) {
	for _, url := range c.GetParentLinks() {
		certBytes, err := p.Loader.LoadCert(url, utils.Link)
		// Here we should probably try each Link until we find one that works
		// Perhaps do that concurrently
		if err != nil {
			log.Printf("Failed to load crt from uri %s: %s", url, err)
			continue
		}
		certs, err := crt.LoadCertFromBytes(certBytes, url)
		if err != nil {
			return nil, err
		}
		return certs, nil
	}
	return nil, nil
}

func (p *Parser) LoadRootChain(c *crt.Certificate) (*x509.CertPool, error) {
	chain := x509.NewCertPool()
	certs, err := p.Loader.LoadRootCerts()
	if err != nil {
		return chain, err
	}
	for _, certBytes := range certs {
		certs, err := crt.LoadCertFromBytes(certBytes, "")
		if err != nil {
			return chain, err
		}
		for _, cert := range certs {
			chain.AddCert(cert.X509Cert)
		}
	}
	return chain, nil
}

func (p *Parser) GetChain(certificates [][]byte) (*x509.CertPool, error) {
	chain := x509.NewCertPool()
	for _, certBytes := range certificates {
		certs, err := crt.LoadCertFromBytes(certBytes, "")
		if err != nil {
			return &x509.CertPool{}, err
		}
		for _, cert := range certs {
			chain.AddCert(cert.X509Cert)
		}
	}
	return chain, nil
}

func (p *Parser) IsTrusted(c *crt.Certificate) (bool, error) {
	/**
	Go through the certificate chain until we find a trusted certificate or reach the root.
	*/
	roots, err := p.LoadRootChain(c)
	intermediatesContent, cached, err := p.Loader.LoadIntermediateCerts(c)
	if err != nil {
		return false, err
	}
	intermediates := x509.NewCertPool()
	for _, certBytes := range intermediatesContent {
		certs, err := crt.LoadCertFromBytes(certBytes, "")
		if err != nil {
			return false, err
		}
		for _, cert := range certs {
			intermediates.AddCert(cert.X509Cert)
		}
	}
	err = c.Verify(intermediates, roots, nil)
	if !cached {

	}
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
	CrlLinks     []string                     `json:"crl_link"`
	Plugins      map[string]PluginParseResult `json:"plugins"`
}

type ParsedAndValidatedCertificate struct {
	ParsedCertificate
	IsTrusted bool `json:"is_trusted"`
	IsRevoked bool `json:"is_revoked"`
	IsValid   bool `json:"is_valid"`
}

// ChainLoadedError This error is thrown when the whole chain is loaded and we don't need to iterate through the links anymore
type ChainLoadedError struct {
	Err error
}

func (e *ChainLoadedError) Error() string {
	return "Whole chain is loaded"
}

type Loader interface {
	LoadCert(id string, idType utils.IdType) ([]byte, error)
	LoadIntermediateCerts(c *crt.Certificate) ([][]byte, bool, error)
	LoadRootCerts() ([][]byte, error)
}

type Saver interface {
	SaveIntermediateCerts(c *crt.Certificate, certs [][]byte) error
}

func NewParser(plugins map[string]Plugin, loader Loader, saver Saver) *Parser {
	if loader == nil {
		loader = ldr.Loader{}
	}
	if saver == nil {
		saver = svr.Saver{}
	}
	return &Parser{
		Plugins: plugins,
		Loader:  loader,
		Saver:   saver,
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
		CrlLinks:     crt.GetCrlLinks(),
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
