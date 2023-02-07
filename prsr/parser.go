package prsr

import (
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/ldr"
)

type Parser struct {
	loader *ldr.CertificateLoader
}

func NewParser(loader *ldr.CertificateLoader) *Parser {
	return &Parser{
		loader: loader,
	}
}

func (p *Parser) Parse(content []byte) (*crt.Certificate, error) {
	cert, err := crt.NewCertificate(content)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
