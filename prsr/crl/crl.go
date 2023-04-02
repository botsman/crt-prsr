package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/botsman/crt-prsr/prsr/crt"
	"io"
	"math/big"
	"net/http"
	"os"
)

type CRL struct {
	certificateList *x509.RevocationList
}

func NewCRL(content []byte) (*CRL, error) {
	certList, err := x509.ParseRevocationList(content)
	if err != nil {
		return nil, err
	}
	return &CRL{certList}, nil
}

func (c *CRL) GetRevokedCertificates() []pkix.RevokedCertificate {
	return c.certificateList.RevokedCertificates
}

func (c *CRL) IsRevoked(serialNumber *big.Int) bool {
	for _, cert := range c.certificateList.RevokedCertificates {
		if cert.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}

func LoadCRLFromBytes(content []byte) (*CRL, error) {
	return NewCRL(content)
}

func LoadCRLFromPath(path string) (*CRL, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return LoadCRLFromBytes(content)
}

func LoadCRLFromUri(uri string) (*CRL, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return NewCRL(content)
}

func LoadCRL(c *crt.Certificate) (*CRL, error) {
	list, err := LoadCRLFromUri(c.GetCrlLinks()[0])
	if err != nil {
		return nil, err
	}
	return list, nil
}
