package secsipid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"
)

func NewCerts(pubKey []byte) (Certs, *Error) {
	certs := Certs{}
	err := parseKeyIntoCerts(pubKey, &certs)
	if err != nil {
		return Certs{}, err
	}
	if certs.publicCert == nil {
		return Certs{}, &Error{
			Code: SJWTRetErrCertInvalidFormat,
			Msg:  "failed to parse certificate PEM",
		}
	}
	return certs, nil
}

func parseKeyIntoCerts(key []byte, certs *Certs) *Error {
	block, key := pem.Decode(key)
	if block == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &Error{Code: SJWTRetErrCertInvalidFormat, Msg: err.Error()}
	}
	certs.Add(cert)

	return parseKeyIntoCerts(key, certs) // Do it again for the next block
}

type Certs struct {
	publicCert        *x509.Certificate
	intermediateCerts []*x509.Certificate
}

// Adds an x509 Certificate to the list of certs.
// Assumes the first cert added is the public cert.
func (c *Certs) Add(cert *x509.Certificate) {
	if c.publicCert == nil {
		c.publicCert = cert
		return
	}
	c.intermediateCerts = append(c.intermediateCerts, cert)
}

func (c Certs) AddIntermediateCertsToPool(pool *x509.CertPool) {
	for _, cert := range c.intermediateCerts {
		pool.AddCert(cert)
	}
}

func (c Certs) VerifyWithTime() *Error {
	if !time.Now().Before(c.publicCert.NotAfter) {
		return &Error{Code: SJWTRetErrCertExpired, Msg: "certificate expired"}
	}
	if !time.Now().After(c.publicCert.NotBefore) {
		return &Error{Code: SJWTRetErrCertBeforeValidity, Msg: "certificate not valid yet"}
	}
	return nil
}

func (c Certs) VerifyWithCAs(rootCAs *x509.CertPool, interCAs *x509.CertPool) *Error {
	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: interCAs,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := c.publicCert.Verify(opts); err != nil {
		return &Error{Code: SJWTRetErrCertInvalid, Msg: err.Error()}
	}
	return nil
}

func (c Certs) ValidateWithCRL(rootCRL *pkix.CertificateList) *Error {
	for _, revoked := range rootCRL.TBSCertList.RevokedCertificates {
		if c.publicCert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return &Error{Code: SJWTRetErrCertRevoked, Msg: "serial number match - certificate is revoked"}
		}
	}
	return nil
}
