package prsr

import (
	"encoding/json"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
)

type Plugin interface {
}

type Parser struct {
	loader              *ldr.CertificateLoader // TODO: loader to interface
	plugins             []Plugin
	trustedCertificates map[string]struct{}
}

func NewParser(trustedCertificates []crt.Id) *Parser {
	loader := ldr.NewCertificateLoader()
	certsMap := loader.Load(trustedCertificates)
	return &Parser{
		loader:              loader,
		trustedCertificates: certsMap,
	}
}

func (p *Parser) Parse(crt *crt.Certificate) (map[string]string, error) {
	// TODO: parse plugins here as well
	return map[string]string{}, nil
}

func (p *Parser) ToJson(cert *crt.Certificate) ([]byte, error) {
	parsed, err := p.Parse(cert)
	if err != nil {
		return nil, err
	}
	return json.Marshal(parsed)
}
