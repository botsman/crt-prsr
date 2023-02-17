package ldr

import (
	"github.com/botsman/crt-prsr/prsr/crl"
	"github.com/botsman/crt-prsr/prsr/crt"
	"log"
)

type CertificateLoader struct {
}

func NewCertificateLoader() *CertificateLoader {
	return &CertificateLoader{}
}

func (l *CertificateLoader) Load(trustedCertificates []crt.Id) map[string]struct{} {
	trustedHashes := make(map[string]struct{})
	hashesChan := make(chan string)
	for _, cId := range trustedCertificates {
		go func(cId crt.Id, out chan<- string) {
			if cId.IdType == crt.Sha256 {
				out <- cId.Val
				return
			}
			if cId.IdType == crt.Uri {
				cert, err := crt.LoadCertFromUri(cId.Val)
				if err != nil {
					log.Printf("Failed to load crt from uri %s: %s", cId.Val, err)
					return
				}
				out <- cert.GetSha256()
				return
			}
			if cId.IdType == crt.Path {
				cert, err := crt.LoadCertFromPath(cId.Val)
				if err != nil {
					log.Printf("Failed to load crt from path %s: %s", cId.Val, err)
					return
				}
				out <- cert.GetSha256()
				return
			}
		}(cId, hashesChan)
	}
	for range trustedCertificates {
		trustedHashes[<-hashesChan] = struct{}{}
	}
	return trustedHashes
}

func LoadParentCertificate(c *crt.Certificate) (*crt.Certificate, error) {
	for _, url := range c.GetParentLinks() {
		cert, err := crt.LoadCertFromUri(url)
		// Here we should probably try each link until we find one that works
		// Perhaps do that concurrently
		if err != nil {
			log.Printf("Failed to load crt from uri %s: %s", url, err)
			continue
		}
		return cert, nil
	}
	return nil, nil
}

func LoadRootCertificate(c *crt.Certificate) (*crt.Certificate, error) {
	previous := c
	var parent *crt.Certificate
	var err error
	for {
		parent, err = LoadParentCertificate(previous)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return previous, nil
		}
		if parent.IsRoot() {
			return parent, nil
		}
		previous = parent
	}
}

func LoadCRL(c *crt.Certificate) (*crl.CRL, error) {
	list, err := crl.LoadCRLFromUri(c.GetCrlLink())
	if err != nil {
		return nil, err
	}
	return list, nil
}

func IsRevoked(c *crt.Certificate) (bool, error) {
	list, err := LoadCRL(c)
	if err != nil {
		log.Printf("Failed to load CRL: %s", err)
		return false, err
	}
	return list.IsRevoked(c.GetSerialNumber()), nil
}
