package secsipid

import (
	"crypto/x509"
	"io/ioutil"
)

func GetSystemCAs() (*x509.CertPool, *Error) {
	systemCAs, err := x509.SystemCertPool()
	if systemCAs == nil {
		return nil, &Error{Code: SJWTRetErrCertProcessing, Msg: err.Error()}
	}
	return systemCAs, nil
}

func AddCAToPool(fileName string, rootCAs *x509.CertPool) *Error {
	certsCA, err := ioutil.ReadFile(fileName)
	if err != nil {
		return &Error{Code: SJWTRetErrCertReadCAFile, Msg: "failed to read CA file"}
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certsCA); !ok {
		return &Error{Code: SJWTRetErrCertProcessing, Msg: "failed to append CA file"}
	}

	return nil
}
