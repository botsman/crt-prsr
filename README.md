# Certificate parser

Project is at the very beginning of development. It is not ready for use.

This parser is intended to be used for parsing certificates in both PEM and DER formats.   
Parser itself provides only basic functionality for parsing certificates.  
If you want to use it for some specific purpose, you need to implement your own plugin (see `/plugin`)

## Loader 
Existing Loader is implemented mostly for reference and testing purposes.
In real world you probably want to preserve loaded data (certificates, CRLs) in some database/cache.

## Usage

```go
package main

import (
	"fmt"
	"github.com/botsman/crt-prsr/prsr"
	"github.com/botsman/crt-prsr/prsr/crt"
)

func main() {
	// Initialize parser with a set of trusted certificates
	certs := []crt.Id{
		{
			Val:    "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
			IdType: crt.Sha256,
		},
		{
			Val:    "https://example.com/some/path/to/cert",
			IdType: crt.Uri,
		},
		{
			Val:    "some/path/to/cert",
			IdType: crt.Path,
		},
	}
	parser := prsr.NewParser(certs, nil)
	cert, err := crt.LoadCertFromPath("prsr/testdata/qwac.crt")
	if err != nil {
		panic(err)
	}
	result, err := parser.Json(cert)
	if err != nil {
		panic(err)
	}
    // Output:
    // {
    //    "sha256": "de8aa7c82edef27cb17b7a7b37a77b427f358100e0f5514429aa34162488d565",
    //    "issuer": {
    //        "country": "HU",
    //        "organization": "Microsec Ltd.",
    //        "organizational_unit": "",
    //        "locality": "",
    //        "province": "",
    //        "street_address": "",
    //        "postal_code": "",
    //        "serial_number": "",
    //        "common_name": "",
    //        "unit": "e-Szigno CA"
    //    },
    //    "subject": {
    //        "country": "FI",
    //        "organization": "Certificate Verifier",
    //        "organizational_unit": "",
    //        "locality": "",
    //        "province": "",
    //        "street_address": "",
    //        "postal_code": "",
    //        "serial_number": "",
    //        "common_name": "",
    //        "unit": ""
    //    },
    //    "not_before": "2023-02-06T07:31:45Z",
    //    "not_after": "2024-02-06T07:31:45Z",
    //    "serial_number": 9852225575604409045021609199370,
    //    "is_trusted": true,
    //    "is_revoked": false,
    //    "key_usage": "Unknown",
    //    "parent_links": [
    //        "http://teszt.e-szigno.hu/TCA3.crt"
    //    ],
    //    "crl_link": "http://teszt.e-szigno.hu/TCA3.crl",
    //    "plugins": []
    // }   
	fmt.Println(string(result))
}

```
