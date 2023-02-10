package ldr

import (
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
	// TODO: load every crt in a goroutine
	for _, cId := range trustedCertificates {
		if cId.IdType == crt.Sha256 {
			trustedHashes[cId.Val] = struct{}{}
			continue
		}
		if cId.IdType == crt.Uri {
			cert, err := crt.LoadCertFromUri(cId.Val)
			if err != nil {
				log.Printf("Failed to load crt from uri %s: %s", cId.Val, err)
				continue
			}
			trustedHashes[cert.GetSha256()] = struct{}{}
			continue
		}
		if cId.IdType == crt.Path {
			cert, err := crt.LoadCertFromPath(cId.Val)
			if err != nil {
				log.Printf("Failed to load crt from path %s: %s", cId.Val, err)
				continue
			}
			trustedHashes[cert.GetSha256()] = struct{}{}
			continue
		}
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
