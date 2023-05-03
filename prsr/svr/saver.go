package svr

import "github.com/botsman/crt-prsr/prsr/crt"

type Saver struct {
}

func (s Saver) SaveIntermediateCerts(c *crt.Certificate, certs [][]byte) error {
	return nil
}
