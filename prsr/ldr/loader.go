package ldr

import (
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/botsman/crt-prsr/prsr/crl"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/fullsailor/pkcs7"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type CertificateLoader struct {
}

func NewCertificateLoader() *CertificateLoader {
	return &CertificateLoader{}
}

func (l *CertificateLoader) Load(trustedCertificates []crt.Id) map[string]struct{} {
	trustedHashes := make(map[string]struct{})
	hashesChan := make(chan string)
	var wg sync.WaitGroup
	var innerWg sync.WaitGroup
	for _, cId := range trustedCertificates {
		wg.Add(1)
		go func(cId crt.Id, out chan<- string) {
			defer wg.Done()
			if cId.IdType == crt.Sha256 {
				innerWg.Add(1)
				out <- cId.Val
				return
			}
			if cId.IdType == crt.Uri {
				cert, err := l.LoadCertFromUri(cId.Val)
				if err != nil {
					log.Printf("Failed to load crt from uri %s: %s", cId.Val, err)
					return
				}
				for _, c := range cert {
					innerWg.Add(1)
					out <- c.GetSha256()
				}
				return
			}
			if cId.IdType == crt.Path {
				cert, err := l.LoadCertFromPath(cId.Val)
				if err != nil {
					log.Printf("Failed to load crt from path %s: %s", cId.Val, err)
					return
				}
				for _, c := range cert {
					innerWg.Add(1)
					out <- c.GetSha256()
				}
				return
			}
		}(cId, hashesChan)
	}
	finish := make(chan struct{})
	go func(in <-chan string, done <-chan struct{}) {
		for {
			select {
			case <-done:
				return
			case hash := <-in:
				innerWg.Done()
				trustedHashes[hash] = struct{}{}
			}
		}
	}(hashesChan, finish)
	wg.Wait()
	innerWg.Wait()
	finish <- struct{}{}
	return trustedHashes
}

func (l *CertificateLoader) LoadParentCertificate(c *crt.Certificate) (*crt.Certificate, error) {
	for _, url := range c.GetParentLinks() {
		certs, err := l.LoadCertFromUri(url)
		// Here we should probably try each link until we find one that works
		// Perhaps do that concurrently
		if err != nil {
			log.Printf("Failed to load crt from uri %s: %s", url, err)
			continue
		}
		// Assume that there is only one certificate in the response
		cert := certs[0]
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

func (l *CertificateLoader) LoadCertFromBytes(content []byte, uri string) ([]*crt.Certificate, error) {
	rest := content
	var certs []*crt.Certificate
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := crt.NewCertificate(block.Bytes, uri)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (l *CertificateLoader) LoadCertFromPKCS7(content []byte, uri string) ([]*crt.Certificate, error) {
	parsed, err := pkcs7.Parse(content)
	if err != nil {
		return nil, err
	}
	if len(parsed.Certificates) == 0 {
		return nil, errors.New("no certificates found")
	}
	certificates := make([]*crt.Certificate, len(parsed.Certificates))
	for i, cert := range parsed.Certificates {
		certificates[i], err = crt.NewCertificate(cert.Raw, uri)
		if err != nil {
			return nil, err
		}
	}
	return certificates, nil
}

func (l *CertificateLoader) LoadCertFromPath(path string) ([]*crt.Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return l.LoadCertFromBytes(content, "")
}

func (l *CertificateLoader) GetCertificateFormat(content []byte, filename string) crt.CertificateFormat {
	const pemPrefix = "-----BEGIN CERTIFICATE-----"
	if len(content) > len(pemPrefix) && string(content[:len(pemPrefix)]) == pemPrefix {
		return crt.PEM
	}
	if content[0] == 0x30 && content[1] == 0x82 {
		if strings.HasSuffix(filename, ".cer") || strings.HasSuffix(filename, ".der") || strings.HasSuffix(filename, ".crt") {
			return crt.DER
		}
		if strings.HasSuffix(filename, ".p7b") || strings.HasSuffix(filename, ".p7c") {
			return crt.PKCS7
		}
	}
	return crt.Unknown
}

func (l *CertificateLoader) LoadCertFromUri(uri string) ([]*crt.Certificate, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	switch l.GetCertificateFormat(content, uri) {
	case crt.PEM:
		return l.LoadCertFromBytes(content, uri)
	case crt.DER:
		cert, err := crt.NewCertificate(content, uri)
		if err != nil {
			return nil, err
		}
		return []*crt.Certificate{cert}, nil
	case crt.PKCS7:
		return l.LoadCertFromPKCS7(content, uri)
	default:
		return nil, errors.New(fmt.Sprintf("Unknown certificate format for %s", uri))
	}
}
