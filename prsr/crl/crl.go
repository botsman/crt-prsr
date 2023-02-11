package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
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

func (c *CRL) GetRevokedCertificates() []pkix.RevokedCertificate {
	return c.certificateList.RevokedCertificates
}

func (c *CRL) IsRevoked(serialNumber big.Int) bool {
	for _, crt := range c.certificateList.RevokedCertificates {
		if crt.SerialNumber.Cmp(&serialNumber) == 0 {
			return true
		}
	}
	return false
}
