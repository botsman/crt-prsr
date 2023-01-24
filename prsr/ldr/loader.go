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
