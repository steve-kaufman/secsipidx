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

	err = verifyCertsWithCAs(options, certs)
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

func verifyCertsWithCAs(options SJWTLibOptions, certs Certs) *Error {
	rootCAs, interCAs, err := buildCAsWithOptions(options, certs)
	if err != nil {
		return err
	}

	err = certs.VerifyWithCAs(rootCAs, interCAs)
	if err != nil {
		return err
	}
	return nil
}

func buildCAsWithOptions(options SJWTLibOptions, certs Certs) (*x509.CertPool, *x509.CertPool, *Error) {
	rootCAs, err := buildRootCAsWithOptions(options)
	if err != nil {
		return nil, nil, err
	}
	interCAs, err := buildInterCAsWithOptions(options, certs)
	if err != nil {
		return nil, nil, err
	}
	return rootCAs, interCAs, nil
}

func buildRootCAsWithOptions(options SJWTLibOptions) (*x509.CertPool, *Error) {
	rootCAs, err := getBaseRootCAs(options)
	if err != nil {
		return nil, err
	}

	err = addCustomCAsIfNeeded(options, rootCAs)
	if err != nil {
		return nil, err
	}

	return rootCAs, nil
}

func getBaseRootCAs(options SJWTLibOptions) (*x509.CertPool, *Error) {
	if !options.ShouldVerifyWithSystemCA() {
		return x509.NewCertPool(), nil
	}
	systemCAs, err := SystemCertPool()
	if err != nil {
		return nil, &Error{Code: SJWTRetErrCertProcessing, Msg: err.Error()}
	}
	return systemCAs, nil
}

func addCustomCAsIfNeeded(options SJWTLibOptions, rootCAs *x509.CertPool) *Error {
	if !options.ShouldVerifyWithCustomCA() {
		return nil
	}
	if options.CertCAFile == "" {
		return &Error{Code: SJWTRetErrCertNoCAFile, Msg: "no CA file"}
	}
	err := addCAFileToPool(options.CertCAFile, rootCAs)
	if err != nil {
		return err
	}
	return nil
}

func buildInterCAsWithOptions(options SJWTLibOptions, certs Certs) (*x509.CertPool, *Error) {
	interCAs := x509.NewCertPool()
	if !options.ShouldVerifyWithIntermediateCA() {
		return interCAs, nil
	}
	if options.CertCAInter == "" {
		return nil, &Error{Code: SJWTRetErrCertNoCAInter, Msg: "no intermediate CA file"}
	}
	err := addInterCAFileToPool(globalLibOptions.CertCAInter, interCAs)
	if err != nil {
		return nil, err
	}
	certs.AddIntermediateCertsToPool(interCAs)

	return interCAs, nil
}

func addCAFileToPool(fileName string, rootCAs *x509.CertPool) *Error {
	certsCA, err := ioutil.ReadFile(fileName)
	if err != nil {
		return &Error{Code: SJWTRetErrCertReadCAFile, Msg: "failed to read CA file"}
	}

	if ok := rootCAs.AppendCertsFromPEM(certsCA); !ok {
		return &Error{Code: SJWTRetErrCertProcessing, Msg: "failed to append CA file"}
	}

	return nil
}

func addInterCAFileToPool(fileName string, interCAs *x509.CertPool) *Error {
	certsCA, err := ioutil.ReadFile(fileName)
	if err != nil {
		return &Error{Code: SJWTRetErrCertReadCAInter, Msg: "failed to read intermediate CA file"}
	}

	if ok := interCAs.AppendCertsFromPEM(certsCA); !ok {
		return &Error{Code: SJWTRetErrCertProcessing, Msg: "failed to append intermediate CA file"}
	}

	return nil
}

func verifyWithCLRFile(options SJWTLibOptions, certs Certs) *Error {
	if !options.ShouldVerifyWithCLRFile() {
		return nil
	}
	if options.CertCRLFile == "" {
		return &Error{Code: SJWTRetErrCertNoCRLFile, Msg: "no CRL file"}
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
