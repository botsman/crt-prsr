package ldr

import (
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/botsman/crt-prsr/prsr/crl"
	"github.com/botsman/crt-prsr/prsr/crt"
	"io"
	"log"
	"net/http"
	"os"
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
				cert, err := l.LoadCertFromUri(cId.Val)
				if err != nil {
					log.Printf("Failed to load crt from uri %s: %s", cId.Val, err)
					return
				}
				out <- cert.GetSha256()
				return
			}
			if cId.IdType == crt.Path {
				cert, err := l.LoadCertFromPath(cId.Val)
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

func (l *CertificateLoader) LoadParentCertificate(c *crt.Certificate) (*crt.Certificate, error) {
	for _, url := range c.GetParentLinks() {
		cert, err := l.LoadCertFromUri(url)
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

func (l *CertificateLoader) LoadRootCertificate(c *crt.Certificate) (*crt.Certificate, error) {
	previous := c
	var parent *crt.Certificate
	var err error
	for {
		parent, err = l.LoadParentCertificate(previous)
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

func (l *CertificateLoader) LoadCRLFromBytes(content []byte) (*crl.CRL, error) {
	return crl.NewCRL(content)
}

func (l *CertificateLoader) LoadCRLFromPath(path string) (*crl.CRL, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return l.LoadCRLFromBytes(content)
}

func (l *CertificateLoader) LoadCRLFromUri(uri string) (*crl.CRL, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return crl.NewCRL(content)
}

func (l *CertificateLoader) LoadCRL(c *crt.Certificate) (*crl.CRL, error) {
	list, err := l.LoadCRLFromUri(c.GetCrlLink())
	if err != nil {
		return nil, err
	}
	return list, nil
}

func (l *CertificateLoader) IsRevoked(c *crt.Certificate) (bool, error) {
	list, err := l.LoadCRL(c)
	if err != nil {
		log.Printf("Failed to load CRL: %s", err)
		return false, err
	}
	return list.IsRevoked(c.GetSerialNumber()), nil
}

func (l *CertificateLoader) LoadCertFromBytes(content []byte) (*crt.Certificate, error) {
	certDERBlock, _ := pem.Decode(content)
	if certDERBlock == nil {
		return nil, errors.New("invalid crt content")
	}
	if certDERBlock.Type != "CERTIFICATE" {
		return nil, errors.New(fmt.Sprintf("Only public certificates supported. Got: %s", certDERBlock.Type))
	}
	return crt.NewCertificate(certDERBlock.Bytes, "")
}

func (l *CertificateLoader) LoadCertFromPath(path string) (*crt.Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return l.LoadCertFromBytes(content)
}

func (l *CertificateLoader) LoadCertFromUri(uri string) (*crt.Certificate, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return crt.NewCertificate(content, uri)
}
