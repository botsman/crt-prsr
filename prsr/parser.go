package prsr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/botsman/crt-prsr/prsr/crl"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
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
	Plugins             map[string]Plugin
	TrustedCertificates map[string]struct{}
	Loader              Loader
}

func (p *Parser) AddTrustedCertificates(certificateHashes ...string) {
	for _, hash := range certificateHashes {
		p.TrustedCertificates[hash] = struct{}{}
	}
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
	trustedHashes := make([]string, 0)
	for hash := range p.TrustedCertificates {
		trustedHashes = append(trustedHashes, hash)
	}
	certs, err := p.Loader.LoadCerts(trustedHashes, utils.Sha256)
	if err != nil {
		return chain, err
	}
	for _, certBytes := range certs {
		certs, err := crt.LoadCertFromBytes(certBytes, "")
		if err != nil {
			return chain, err
		}
		for _, cert := range certs {
			if _, ok := p.TrustedCertificates[cert.GetSha256()]; ok {
				chain.AddCert(cert.X509Cert)
			}
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

func (p *Parser) LoadChains(c *crt.Certificate) (*x509.CertPool, *x509.CertPool, error) {
	roots, err := p.LoadRootChain(c)
	if err != nil {
		return nil, nil, err
	}
	intermediates := x509.NewCertPool()
	parent := c
	for {
		if parent.GetParentLinks() == nil {
			return intermediates, roots, nil
		}
		if parent.IsRoot() {
			return intermediates, roots, nil
		}
		parentsContent, err := p.Loader.LoadCert(parent.GetParentLinks()[0], utils.Link)
		var clr *ChainLoadedError
		var ok bool
		if err != nil {
			clr, ok = err.(*ChainLoadedError)
			if !ok {
				return intermediates, roots, nil
			}
		}
		parents, err := crt.LoadCertFromBytes(parentsContent, parent.GetParentLinks()[0])
		if err != nil {
			return intermediates, roots, nil
		}
		// If the error is a ChainLoadedError, it means that we already loaded the chain from the cache
		if clr != nil {
			log.Println("Loaded chain from cache")
			for _, cert := range parents {
				intermediates.AddCert(cert.X509Cert)
			}
			return intermediates, roots, nil
		}
		parent = parents[0]
		if _, isTrusted := p.TrustedCertificates[parent.GetSha256()]; isTrusted {
			// Trusted certificate should already be in the root chain
			roots.AddCert(parent.X509Cert)
			break
		}
		intermediates.AddCert(parent.X509Cert)
	}
	return intermediates, roots, nil
}

func (p *Parser) IsTrusted(c *crt.Certificate) (bool, error) {
	/**
	Go through the certificate chain until we find a trusted certificate or reach the root.
	*/
	if _, isTrusted := p.TrustedCertificates[c.GetSha256()]; isTrusted {
		return true, nil
	}
	roots, intermediates, err := p.LoadChains(c)
	if err != nil {
		return false, err
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
	LoadCerts(certs []string, idType utils.IdType) ([][]byte, error)
}

func NewParser(trustedCertificateHashes []string, plugins map[string]Plugin, loader Loader) *Parser {
	trustedCertificates := make(map[string]struct{}, 0)
	for _, hash := range trustedCertificateHashes {
		trustedCertificates[hash] = struct{}{}
	}
	if loader == nil {
		loader = ldr.Loader{}
	}
	return &Parser{
		TrustedCertificates: trustedCertificates,
		Plugins:             plugins,
		Loader:              loader,
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
