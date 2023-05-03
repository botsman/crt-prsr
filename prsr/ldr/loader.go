package ldr

import (
	"encoding/pem"
	"github.com/botsman/crt-prsr/prsr/crt"
	"github.com/botsman/crt-prsr/prsr/utils"
)

type Loader struct {
}

func (l Loader) LoadCert(id string, idType utils.IdType) ([]byte, error) {
	return nil, nil
}

func (l Loader) LoadIntermediateCerts(c *crt.Certificate) ([][]byte, bool, error) {
	parent := c
	intermediates := make([][]byte, 0)
	for {
		if parent.GetParentLinks() == nil {
			break
		}
		if parent.IsRoot() {
			break
		}
		parentContent, err := utils.LoadUri(parent.GetParentLinks()[0])
		if err != nil {
			break
		}
		certs, err := crt.LoadCertFromBytes(parentContent, parent.GetParentLinks()[0])
		if err != nil {
			break
		}
		for _, cert := range certs {
			encodedCert := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.X509Cert.Raw,
			})
			intermediates = append(intermediates, encodedCert)
		}
		parent = certs[0]
	}
	return intermediates, false, nil
}

func (l Loader) LoadRootCerts() ([][]byte, error) {
	return make([][]byte, 0), nil
}
