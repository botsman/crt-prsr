package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
	for _, crt := range c.certificateList.RevokedCertificates {
		if crt.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}
