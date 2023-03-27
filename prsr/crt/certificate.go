package crt

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"time"
)

type Type int

type Certificate struct {
	X509Cert *x509.Certificate
	link     string // self link to crt (if any)
}

func NewCertificate(content []byte, uri string) (*Certificate, error) {
	x509Cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, err
	}
	return &Certificate{x509Cert, uri}, nil
}

func (c *Certificate) GetSha256() string {
	checksum := sha256.Sum256(c.X509Cert.Raw)
	return hex.EncodeToString(checksum[:])
}

func (c *Certificate) GetIssuer() pkix.Name {
	return c.X509Cert.Issuer
}

func (c *Certificate) GetSubject() pkix.Name {
	return c.X509Cert.Subject
}

func (c *Certificate) GetNotBefore() time.Time {
	return c.X509Cert.NotBefore
}

func (c *Certificate) GetNotAfter() time.Time {
	return c.X509Cert.NotAfter
}

func (c *Certificate) GetSerialNumber() *big.Int {
	return c.X509Cert.SerialNumber
}

func (c *Certificate) GetKeyUsage() []string {
	positiveBits := func(n int) []int {
		var result []int
		bit := 1
		for n != 0 {
			if n&bit != 0 {
				result = append(result, bit)
			}
			n &= ^bit
			bit <<= 1
		}
		return result
	}(int(c.X509Cert.KeyUsage))
	keyUsages := make([]string, len(positiveBits))
	for i, bit := range positiveBits {
		var keyUsage string
		switch x509.KeyUsage(bit) {
		case x509.KeyUsageDigitalSignature:
			keyUsage = "DigitalSignature"
		case x509.KeyUsageKeyEncipherment:
			keyUsage = "KeyEncipherment"
		case x509.KeyUsageContentCommitment:
			keyUsages = append(keyUsages, "ContentCommitment")
			keyUsage = "KeyEncipherment"
		case x509.KeyUsageDataEncipherment:
			keyUsage = "DataEncipherment"
		case x509.KeyUsageKeyAgreement:
			keyUsage = "KeyAgreement"
		case x509.KeyUsageCertSign:
			keyUsage = "CertSign"
		case x509.KeyUsageCRLSign:
			keyUsage = "CRLSign"
		case x509.KeyUsageEncipherOnly:
			keyUsage = "EncipherOnly"
		case x509.KeyUsageDecipherOnly:
			keyUsage = "DecipherOnly"
		}
		keyUsages[i] = keyUsage
	}

	return keyUsages
}

func (c *Certificate) GetExtKeyUsage() []string {
	var extKeyUsage []string
	for _, usage := range c.X509Cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			extKeyUsage = append(extKeyUsage, "Any")
		case x509.ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsage = append(extKeyUsage, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			extKeyUsage = append(extKeyUsage, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			extKeyUsage = append(extKeyUsage, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			extKeyUsage = append(extKeyUsage, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			extKeyUsage = append(extKeyUsage, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUsage = append(extKeyUsage, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, "NetscapeServerGatedCrypto")
		}
	}
	return extKeyUsage
}

func (c *Certificate) GetParentLinks() []string {
	return c.X509Cert.IssuingCertificateURL
}

func (c *Certificate) GetCrlLink() string {
	// There is also an extension "Freshest CRL / Delta CRL Distribution Point".
	// I think that we should parse it here as well
	for _, url := range c.X509Cert.CRLDistributionPoints {
		return url
	}
	return ""
}

func (c *Certificate) GetDeltaCRLLink() string {
	// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	//
	// DistributionPoint ::= SEQUENCE {
	//     distributionPoint       [0]     DistributionPointName OPTIONAL,
	//     reasons                 [1]     ReasonFlags OPTIONAL,
	//     cRLIssuer               [2]     GeneralNames OPTIONAL }
	//
	// DistributionPointName ::= CHOICE {
	//     fullName                [0]     GeneralNames,
	//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
	for _, ext := range c.X509Cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 46}) {
			// Perhaps there is a better way to parse this extension
			type DistributionPoint struct {
				Name asn1.RawValue `asn1:"tag:0,optional"`
			}
			var val []DistributionPoint
			if _, err := asn1.Unmarshal(ext.Value, &val); err != nil {
				return ""
			}
			for _, dp := range val {
				dpName := dp.Name
				var dpVal asn1.RawValue
				for dpName.IsCompound {
					if _, err := asn1.Unmarshal(dpName.Bytes, &dpVal); err != nil {
						break
					}
					dpName = dpVal
				}
				return string(dpVal.Bytes)
			}
		}
	}
	return ""
}

func (c *Certificate) IsRoot() bool {
	for _, link := range c.GetParentLinks() {
		if link == c.link {
			return true
		}
	}
	return false
}

func (c *Certificate) Verify(intermediates *x509.CertPool, roots *x509.CertPool, keyUsages []x509.ExtKeyUsage) error {
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     keyUsages,
	}
	if opts.KeyUsages == nil || len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	_, err := c.X509Cert.Verify(opts)
	return err
}
