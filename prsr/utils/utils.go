package utils

import (
	"io"
	"net/http"
)

type IdType int

const (
	Sha256 IdType = iota
	SerialNumber
	Link // Link to the certificate
)

func LoadUri(uri string) ([]byte, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(response.Body)
}
