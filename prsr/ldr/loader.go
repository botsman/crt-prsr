package ldr

import (
	"github.com/botsman/crt-prsr/prsr/crt"
	"log"
)

type CertificateLoader struct {
	trustedCertificates []crt.Id
	loaded              bool
	trustedHashes       map[string]struct{}
}

func NewCertificateLoader(certs []crt.Id) *CertificateLoader {
	certLoader := &CertificateLoader{
		trustedCertificates: certs,
	}
	return certLoader
}

func (l *CertificateLoader) Load() {
	if l.loaded {
		return
	}
	// TODO: load every crt in a goroutine
	for _, cId := range l.trustedCertificates {
		if cId.IdType == crt.Sha256 {
			l.trustedHashes[cId.Val] = struct{}{}
			continue
		}
		if cId.IdType == crt.Uri {
			cert, err := crt.LoadCertFromUri(cId.Val)
			if err != nil {
				log.Printf("Failed to load crt from uri %s: %s", cId.Val, err)
				continue
			}
			l.trustedHashes[cert.GetSha256()] = struct{}{}
			continue
		}
		if cId.IdType == crt.Path {
			cert, err := crt.LoadCertFromPath(cId.Val)
			if err != nil {
				log.Printf("Failed to load crt from path %s: %s", cId.Val, err)
				continue
			}
			l.trustedHashes[cert.GetSha256()] = struct{}{}
			continue
		}
	}
	l.loaded = true
}

func (l *CertificateLoader) IsTrusted(cert crt.Certificate) bool {
	if !l.loaded {
		l.Load()
	}
	_, ok := l.trustedHashes[cert.GetSha256()]
	return ok
}

func loadParentCertificate(c *crt.Certificate) (*crt.Certificate, error) {
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

func loadRootCertificate(c *crt.Certificate) (*crt.Certificate, error) {
	if c.IsRoot() {
		return c, nil
	}
	for parent, err := loadParentCertificate(c); parent != nil; parent, err = loadParentCertificate(c) {
		if err != nil {
			return nil, err
		}
		if parent.IsRoot() {
			return parent, nil
		}
	}
	return nil, nil
}
