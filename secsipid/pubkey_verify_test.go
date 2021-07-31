package secsipid_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/asipto/secsipidx/secsipid"
	"github.com/gomagedon/expectate"
)

type PubKeyVerifyTest struct {
	certVerify int
	inputKey   []byte

	expectedErrCode int
	expectedErrMsg  string
}

func TestPubKeyVerify(t *testing.T) {
	runTest := func(t *testing.T, testCase PubKeyVerifyTest) {
		expect := expectate.Expect(t) // testing utility

		secsipid.SJWTLibOptSetN("CertVerify", testCase.certVerify)

		errCode, err := secsipid.SJWTPubKeyVerify(testCase.inputKey)
		errMsg := getMsgFromErr(err)

		expect(errCode).ToBe(testCase.expectedErrCode)
		expect(errMsg).ToBe(testCase.expectedErrMsg)
	}

	// Test
	t.Run("OK when certVerify is 0", func(t *testing.T) {
		runTest(t, PubKeyVerifyTest{
			certVerify: 0,
			inputKey:   []byte("foo"),

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})
	})

	// Test (for every non-zero value of certVerify)
	for certVerify := 1; certVerify <= 32; certVerify += 1 {
		t.Run("ErrCertInvalidFormat when key is invalid format", func(t *testing.T) {
			runTest(t, PubKeyVerifyTest{
				certVerify: certVerify,
				inputKey:   []byte("this is an invalid cert"),

				expectedErrCode: secsipid.SJWTRetErrCertInvalidFormat,
				expectedErrMsg:  "failed to parse certificate PEM",
			})
		})
	}

	certGenerator := NewDummyCA()

	t.Run("ErrCertExpired", func(t *testing.T) {
		cert := certGenerator.generateExpiredCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b0001,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertExpired,
			expectedErrMsg:  "certificate expired",
		})
	})

	t.Run("ErrCertBeforeValidity", func(t *testing.T) {
		cert := certGenerator.generateCertBeforeValidity()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b0001,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertBeforeValidity,
			expectedErrMsg:  "certificate not valid yet",
		})
	})

	t.Run("ErrCertInvalid with no root CAs", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b0001, // haven't enabled system CA or custom CA
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertInvalid,
			expectedErrMsg:  "x509: certificate signed by unknown authority",
		})
	})

	t.Run("ErrCertInvalid with default system CAs", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b0010,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertInvalid,
			expectedErrMsg:  "x509: certificate signed by unknown authority",
		})
	})

	t.Run("Cert is valid with dummy system CAs", func(t *testing.T) {
		workDir, _ := os.Getwd()
		os.Setenv("SSL_CERT_DIR", workDir)
		os.Setenv("SSL_CERT_FILE", path.Join(workDir, "dummyCA.pem"))

		println(os.Getenv("SSL_CERT_DIR"))

		cert := certGenerator.generateValidCert()
		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)

		secsipid.ResetSystemCertPool()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b0010,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("dummyCA.pem")
	})
}

func getMsgFromErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type DummyCertGenerator struct {
	ca         *x509.Certificate
	caPEMBytes []byte
	caPrivKey  *rsa.PrivateKey
}

func NewDummyCA() DummyCertGenerator {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Foo, Inc."},
			Country:       []string{"Fantasyland"},
			Province:      []string{""},
			Locality:      []string{"Metropolis"},
			StreetAddress: []string{"111 Main St."},
			PostalCode:    []string{"11111"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)

	caBytes, _ := x509.CreateCertificate(
		rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return DummyCertGenerator{
		ca:         ca,
		caPrivKey:  caPrivKey,
		caPEMBytes: caPEM.Bytes(),
	}
}

func (gen DummyCertGenerator) generateExpiredCert() []byte {
	return gen.generateCertWithTimes(
		time.Now().AddDate(-1, 0, 0), // 1 year ago
		time.Now().AddDate(0, 0, -1), // 1 day ago
	)
}

func (gen DummyCertGenerator) generateCertBeforeValidity() []byte {
	return gen.generateCertWithTimes(
		time.Now().AddDate(1, 0, 0), // 1 year from now
		time.Now().AddDate(2, 0, 0), // 2 years from now
	)
}

func (gen DummyCertGenerator) generateValidCert() []byte {
	return gen.generateCertWithTimes(
		time.Now(),
		time.Now().AddDate(1, 0, 0), // 1 year from now
	)
}

func (gen DummyCertGenerator) generateCertWithTimes(notBefore time.Time, notAfter time.Time) []byte {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Bar, Inc."},
			Country:       []string{"Fantasyland"},
			Province:      []string{""},
			Locality:      []string{"Metropolis"},
			StreetAddress: []string{"222 Main St."},
			PostalCode:    []string{"11111"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)
	certBytes, _ := x509.CreateCertificate(
		rand.Reader, cert, gen.ca, &certPrivKey.PublicKey, gen.caPrivKey)

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM.Bytes()
}
