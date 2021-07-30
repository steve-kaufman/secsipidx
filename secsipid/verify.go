package secsipid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
)

// SJWTPubKeyVerify -
func SJWTPubKeyVerify(pubKey []byte) (int, error) {
	if globalLibOptions.ShouldNotVerify() {
		return SJWTRetOK, nil
	}

	return verifyKeyWithOptions(pubKey, globalLibOptions)
}

func verifyKeyWithOptions(pubKey []byte, options SJWTLibOptions) (int, error) {
	certs, err := NewCertsFromKey(pubKey)
	if err != nil {
		return err.Simplify()
	}

	return verifyCertsWithOptions(certs, options)
}

func verifyCertsWithOptions(certs Certs, options SJWTLibOptions) (int, error) {
	err := verifyPublicCertWithTime(options, certs)
	if err != nil {
		return err.Simplify()
	}

	rootCAs, err := buildRootCAs(options)
	if err != nil {
		return err.Simplify()
	}
	interCAs, err := buildInterCAs(options, certs)
	if err != nil {
		return err.Simplify()
	}

	err = certs.VerifyWithCAs(rootCAs, interCAs)
	if err != nil {
		return err.Simplify()
	}

	err = verifyWithCLRFile(options, certs)
	if err != nil {
		return err.Simplify()
	}

	return SJWTRetOK, nil
}

func verifyPublicCertWithTime(options SJWTLibOptions, certs Certs) *Error {
	if !options.ShouldVerifyWithTime() {
		return nil
	}
	err := certs.VerifyWithTime()
	if err != nil {
		return err
	}
	return nil
}

func buildRootCAs(options SJWTLibOptions) (*x509.CertPool, *Error) {
	rootCAs := x509.NewCertPool()
	if options.ShouldVerifyWithSystemCA() {
		systemCAs, err := x509.SystemCertPool()
		if err != nil {
			return nil, &Error{Code: SJWTRetErrCertProcessing, Msg: err.Error()}
		}
		rootCAs = systemCAs
	}
	if options.ShouldVerifyWithCustomCA() {
		err := AddCAToPool(options.CertCAFile, rootCAs)
		if err != nil {
			return nil, err
		}
	}
	return rootCAs, nil
}

func buildInterCAs(options SJWTLibOptions, certs Certs) (*x509.CertPool, *Error) {
	interCAs := x509.NewCertPool()
	if options.ShouldVerifyWithIntermediateCA() {
		err := AddCAToPool(globalLibOptions.CertCAInter, interCAs)
		if err != nil {
			return nil, err
		}
		certs.AddIntermediateCertsToPool(interCAs)
	}
	return interCAs, nil
}

func verifyWithCLRFile(options SJWTLibOptions, certs Certs) *Error {
	if !options.ShouldVerifyWithCLRFile() {
		return nil
	}

	rootCRL, err := getRootCRL()
	if err != nil {
		return err
	}
	err = certs.ValidateWithCRL(rootCRL)
	if err != nil {
		return err
	}

	return nil
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
