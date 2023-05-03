package ldr

import (
	"github.com/botsman/crt-prsr/prsr/utils"
)

type Loader struct {
}

func (l Loader) LoadCert(uri string, idType utils.IdType) ([]byte, error) {
	return utils.LoadUri(uri)
}
func (l Loader) LoadCerts(certs []string, idType utils.IdType) ([][]byte, error) {
	return make([][]byte, 0), nil
}
