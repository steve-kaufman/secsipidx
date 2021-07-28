package secsipid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
)

// SJWTPubKeyVerify -
func SJWTPubKeyVerify(pubKey []byte) (int, error) {
	if globalLibOptions.CertVerify == 0 {
		return SJWTRetOK, nil
	}

	certs, err := NewCerts(pubKey)
	if err != nil {
		return err.Code, err
	}

	if globalLibOptions.ShouldVerifyWithTime() {
		err := certs.VerifyWithTime()
		if err != nil {
			return err.Code, err
		}
	}

	rootCAs, err := getRootCAs()
	if err != nil {
		return err.Code, err
	}

	if globalLibOptions.ShouldVerifyWithCustomCA() {
		AddCustomCA(globalLibOptions.CertCAFile, rootCAs)
	}

	interCAs := x509.NewCertPool()
	if globalLibOptions.ShouldVerifyWithIntermediateCA() {
		AddCustomCA(globalLibOptions.CertCAInter, interCAs)
	}

	certs.AddIntermediateCertsToPool(interCAs)

	err = certs.VerifyWithCAs(rootCAs, interCAs)
	if err != nil {
		return err.Code, err
	}

	if globalLibOptions.ShouldVerifyWithCLRFile() {
		rootCRL, err := getRootCRL()
		if err != nil {
			return err.Code, err
		}
		err = certs.ValidateWithCRL(rootCRL)
		if err != nil {
			return err.Code, err
		}
	}

	return SJWTRetOK, nil
}

func getRootCAs() (*x509.CertPool, *Error) {
	if globalLibOptions.ShouldVerifyWithSystemCA() {
		return GetSystemCAs()
	}
	return x509.NewCertPool(), nil
}

func getRootCRL() (*pkix.CertificateList, *Error) {
	certsCRLData, err := ioutil.ReadFile(globalLibOptions.CertCRLFile)
	if err != nil {
		return nil, &Error{Code: SJWTRetErrCertReadCRLFile, Msg: "failed to read CRL file"}
	}
	rootCRL, err := x509.ParseCRL(certsCRLData)
	if err != nil {
		return nil, &Error{Code: SJWTRetErr, Msg: "failed to parse CRL file"}
	}
	return rootCRL, nil
}
