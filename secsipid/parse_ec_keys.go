package secsipid

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// SJWTParseECPrivateKeyFromPEM Parse PEM encoded Elliptic Curve Private Key Structure
func SJWTParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, int, error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, SJWTRetErrPrvKeyInvalidFormat, errors.New("key must be PEM encoded")
	}

	return parsePrivateKeyFromPEMBlock(block)
}

func parsePrivateKeyFromPEMBlock(block *pem.Block) (*ecdsa.PrivateKey, int, error) {
	parsedKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return parsedKey, SJWTRetOK, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, SJWTRetErrPrvKeyInvalid, err
	}
	return asECDSA(pkcs8Key)
}

func asECDSA(parsedKey interface{}) (*ecdsa.PrivateKey, int, error) {
	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, SJWTRetErrPrvKeyInvalidEC, errors.New("not EC private key")
	}

	return pkey, SJWTRetOK, nil
}
