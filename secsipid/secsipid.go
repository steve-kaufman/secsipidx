package secsipid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// SJWTHeader - header for JWT
type SJWTHeader struct {
	Alg string `json:"alg"`
	Ppt string `json:"ppt"`
	Typ string `json:"typ"`
	X5u string `json:"x5u"`
}

// SJWTDest --
type SJWTDest struct {
	TN []string `json:"tn"`
}

// SJWTOrig --
type SJWTOrig struct {
	TN string `json:"tn"`
}

// SJWTPayload - JWT payload
type SJWTPayload struct {
	ATTest string   `json:"attest"`
	Dest   SJWTDest `json:"dest"`
	IAT    int64    `json:"iat"`
	Orig   SJWTOrig `json:"orig"`
	OrigID string   `json:"origid"`
}

var (
	sES256KeyBits = 256
	sES256KeySize = 32
)

// SetFileCacheOptions --
func SetURLFileCacheOptions(path string, expire int) {
	globalLibOptions.CacheDirPath = path
	globalLibOptions.CacheExpire = expire
}

// SJWTLibOptSetS --
func SJWTLibOptSetS(optname string, optval string) int {
	switch optname {
	case "CacheDirPath":
		globalLibOptions.CacheDirPath = optval
		return SJWTRetOK
	case "CertCAFile":
		globalLibOptions.CertCAFile = optval
		return SJWTRetOK
	case "CertCRLFile":
		globalLibOptions.CertCRLFile = optval
		return SJWTRetOK
	case "CertCAInter":
		globalLibOptions.CertCAInter = optval
		return SJWTRetOK
	case "x5u":
		globalLibOptions.X5u = optval
		return SJWTRetOK
	}
	return SJWTRetErr
}

// SJWTLibOptSetN --
func SJWTLibOptSetN(optname string, optval int) int {
	switch optname {
	case "CacheExpires":
		globalLibOptions.CacheExpire = optval
		return SJWTRetOK
	case "CertVerify":
		globalLibOptions.CertVerify = optval
		return SJWTRetOK
	}
	return SJWTRetErr
}

// SJWTLibOptSetV --
func SJWTLibOptSetV(optnameval string) int {
	optArray := strings.SplitN(optnameval, "=", 2)
	optName := optArray[0]
	optVal := optArray[1]
	switch optName {
	case "CacheExpires", "CertVerify":
		intVal, _ := strconv.Atoi(optVal)
		return SJWTLibOptSetN(optName, intVal)
	case "CacheDirPath", "CertCAFile", "CertCAInter", "CertCRLFile":
		return SJWTLibOptSetS(optName, optVal)
	}
	return SJWTRetErr
}

// SJWTRemoveWhiteSpaces --
func SJWTRemoveWhiteSpaces(s string) string {
	rout := make([]rune, 0, len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			rout = append(rout, r)
		}
	}
	return string(rout)
}

// SJWTRemoveWhiteSpaces --
func SJWTGetURLCacheFilePath(urlVal string) string {
	filePath := strings.Replace(urlVal, "://", "_", -1)
	filePath = strings.Replace(filePath, "/", "_", -1)
	if len(globalLibOptions.CacheDirPath) > 0 {
		filePath = globalLibOptions.CacheDirPath + "/" + filePath
	}
	return filePath
}

// SJWTParseECPrivateKeyFromPEM Parse PEM encoded Elliptic Curve Private Key Structure
func SJWTParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, int, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, SJWTRetErrPrvKeyInvalidFormat, errors.New("key must be PEM encoded")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, SJWTRetErrPrvKeyInvalid, err
		}
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, SJWTRetErrPrvKeyInvalidEC, errors.New("not EC private key")
	}

	return pkey, SJWTRetOK, nil
}

// SJWTParseECPublicKeyFromPEM Parse PEM encoded PKCS1 or PKCS8 public key
func SJWTParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, int, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, SJWTRetErrCertInvalidFormat, errors.New("key must be PEM encoded")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, SJWTRetErrCertInvalid, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, SJWTRetErrCertInvalidEC, errors.New("not EC public key")
	}

	return pkey, SJWTRetOK, nil
}

// SJWTBase64EncodeString encode string to base64 with padding stripped
func SJWTBase64EncodeString(src string) string {
	return strings.
		TrimRight(base64.URLEncoding.
			EncodeToString([]byte(src)), "=")
}

// SJWTBase64DecodeString takes in a base 64 encoded string and returns the
// actual string or an error of it fails to decode the string
func SJWTBase64DecodeString(src string) (string, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		return "", fmt.Errorf("decoding error %s", err)
	}
	return string(decoded), nil
}

// SJWTBase64EncodeBytes encode bytes array to base64 with padding stripped
func SJWTBase64EncodeBytes(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// SJWTBase64DecodeBytes takes in a base 64 encoded string and returns the
// actual bytes array or an error of it fails to decode the string
func SJWTBase64DecodeBytes(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

// SJWTGetURLCachedContent --
func SJWTGetURLCachedContent(urlVal string) ([]byte, error) {
	filePath := SJWTGetURLCacheFilePath(urlVal)

	fileStat, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	tnow := time.Now()
	if int(tnow.Sub(fileStat.ModTime()).Seconds()) > globalLibOptions.CacheExpire {
		os.Remove(filePath)
		return nil, nil
	}
	return ioutil.ReadFile(filePath)
}

// SJWTSetURLCachedContent --
func SJWTSetURLCachedContent(urlVal string, data []byte) error {
	filePath := SJWTGetURLCacheFilePath(urlVal)

	return ioutil.WriteFile(filePath, data, 0640)
}

// SJWTGetURLContent --
func SJWTGetURLContent(urlVal string, timeoutVal int) ([]byte, int, error) {
	if len(urlVal) == 0 {
		return nil, SJWTRetErrHTTPInvalidURL, errors.New("no URL value")
	}

	if !(strings.HasPrefix(urlVal, "http://") || strings.HasPrefix(urlVal, "https://")) {
		return nil, SJWTRetErrHTTPInvalidURL, errors.New("invalid URL value")
	}

	if len(globalLibOptions.CacheDirPath) > 0 {
		cdata, cerr := SJWTGetURLCachedContent(urlVal)
		if cdata != nil {
			return cdata, SJWTRetOK, cerr
		}
	}
	httpClient := http.Client{
		Timeout: time.Duration(timeoutVal) * time.Second,
	}
	resp, err := httpClient.Get(urlVal)
	if err != nil {
		return nil, SJWTRetErrHTTPGet, fmt.Errorf("http get failure: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, SJWTRetErrHTTPStatusCode, fmt.Errorf("http status error: %v", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, SJWTRetErrHTTPReadBody, fmt.Errorf("read http body failure: %v", err)
	}

	if len(globalLibOptions.CacheDirPath) > 0 {
		SJWTSetURLCachedContent(urlVal, data)
	}

	return data, SJWTRetOK, nil
}

// SJWTGetValidPayload --
func SJWTGetValidPayload(base64Payload string, expireVal int) (*SJWTPayload, int, error) {
	if len(base64Payload) == 0 {
		return nil, SJWTRetErrJSONPayloadParse, errors.New("empty payload")
	}
	decodedPayload, payloadErr := SJWTBase64DecodeString(base64Payload)
	if payloadErr != nil {
		return nil, SJWTRetErrJSONPayloadParse, fmt.Errorf("invalid payload: %s", payloadErr.Error())
	}
	payload := SJWTPayload{}

	err := json.Unmarshal([]byte(decodedPayload), &payload)
	if err != nil {
		return nil, SJWTRetErrJSONPayloadParse, fmt.Errorf("invalid payload: %s", err.Error())
	}

	if payload.IAT == 0 || time.Now().Unix() > payload.IAT+int64(expireVal) {
		return nil, SJWTRetErrJSONPayloadIATExpired, errors.New("expired token")
	}

	return &payload, SJWTRetOK, nil
}

// SJWTVerifyWithPubKey - implements the verify
// For this verify method, key must be an ecdsa.PublicKey struct
func SJWTVerifyWithPubKey(signingString string, signature string, key interface{}) (int, error) {
	var err error

	var sig []byte
	if sig, err = SJWTBase64DecodeBytes(signature); err != nil {
		return -1, err
	}

	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return SJWTRetErrCertInvalidFormat, errors.New("invalid key type")
	}

	if len(sig) != 2*sES256KeySize {
		return SJWTRetErrJSONSignatureSize, errors.New("ECDSA signature size verification failed")
	}

	r := big.NewInt(0).SetBytes(sig[:sES256KeySize])
	s := big.NewInt(0).SetBytes(sig[sES256KeySize:])

	if !crypto.SHA256.Available() {
		return SJWTRetErrJSONSignatureHashing, errors.New("hashing function unavailable")
	}
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	if ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s) {
		return SJWTRetOK, nil
	}
	return SJWTRetErrJSONSignatureInvalid, errors.New("ECDSA verification failed")
}

// SJWTSignWithPrvKey - implements the signing
// For this signing method, key must be an ecdsa.PrivateKey struct
func SJWTSignWithPrvKey(signingString string, key interface{}) (string, int, error) {
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", SJWTRetErrPrvKeyInvalidEC, errors.New("invalid key type")
	}

	if !crypto.SHA256.Available() {
		return "", SJWTRetErrJSONSignatureHashing, errors.New("hashing function not available")
	}

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil))
	if err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if sES256KeyBits != curveBits {
			return "", SJWTRetErrJSONSignatureSize, errors.New("invalid key size")
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)

		return SJWTBase64EncodeBytes(out), SJWTRetOK, nil
	}
	return "", SJWTRetErrJSONSignatureFailure, err
}

// SJWTEncode - encode payload to JWT
func SJWTEncode(header SJWTHeader, payload SJWTPayload, prvkey interface{}) string {
	str, _ := json.Marshal(header)
	jwthdr := SJWTBase64EncodeString(string(str))
	encodedPayload, _ := json.Marshal(payload)
	signingValue := jwthdr + "." +
		SJWTBase64EncodeString(string(encodedPayload))
	signatureValue, _, _ := SJWTSignWithPrvKey(signingValue, prvkey)
	return signingValue + "." + signatureValue
}

// SJWTDecodeWithPubKey - decode JWT string
func SJWTDecodeWithPubKey(jwt string, expireVal int, pubkey interface{}) (*SJWTPayload, error) {
	var ret int
	var err error
	var payload *SJWTPayload

	token := strings.Split(strings.TrimSpace(jwt), ".")

	if len(token) != 3 {
		splitErr := errors.New("invalid token - must contain header, payload and signature")
		return nil, splitErr
	}

	payload, ret, err = SJWTGetValidPayload(token[1], expireVal)
	if err != nil {
		return nil, fmt.Errorf("getting payload failed: (%d) %v", ret, err)
	}

	signatureValue := token[0] + "." + token[1]

	ret, err = SJWTVerifyWithPubKey(signatureValue, token[2], pubkey)
	if err != nil {
		return nil, fmt.Errorf("verify failed: (%d) %v", ret, err)
	}
	return payload, nil
}

// SJWTEncodeText - encode header and payload to JWT
func SJWTEncodeText(headerJSON string, payloadJSON string, prvkeyPath string) (string, int, error) {
	var ret int
	var err error
	var signatureValue string
	var ecdsaPrvKey *ecdsa.PrivateKey

	prvkey, _ := ioutil.ReadFile(prvkeyPath)

	if ecdsaPrvKey, ret, err = SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
		return "", ret, err
	}

	signingValue := SJWTBase64EncodeString(strings.TrimSpace(headerJSON)) +
		"." + SJWTBase64EncodeString(strings.TrimSpace(payloadJSON))
	signatureValue, ret, err = SJWTSignWithPrvKey(signingValue, ecdsaPrvKey)
	if err != nil {
		return "", ret, fmt.Errorf("failed to build signature: %v", err)
	}
	return signingValue + "." + signatureValue, SJWTRetOK, nil
}

// SJWTCheckAttributes - implements the verify of attributes
func SJWTCheckAttributes(bToken string, paramInfo string) (int, error) {
	vHeader, err := SJWTBase64DecodeString(bToken)
	if err != nil {
		return SJWTRetErr, err
	}

	header := SJWTHeader{}
	err = json.Unmarshal([]byte(vHeader), &header)
	if err != nil {
		return SJWTRetErrJSONHdrParse, err
	}
	if len(header.Alg) > 0 && header.Alg != "ES256" {
		return SJWTRetErrJSONHdrAlg, fmt.Errorf("invalid value for alg in json header")
	}
	if len(header.Ppt) > 0 && header.Ppt != "shaken" {
		return SJWTRetErrJSONHdrPpt, fmt.Errorf("invalid value for ppt in json header")
	}
	if len(header.Typ) > 0 && header.Typ != "passport" {
		return SJWTRetErrJSONHdrTyp, fmt.Errorf("invalid value for typ in json header")
	}
	if len(header.X5u) > 0 && header.X5u != paramInfo {
		return SJWTRetErrJSONHdrX5u, fmt.Errorf("mismatching value for x5u and info attributes")
	}
	return SJWTRetOK, nil
}

// SJWTCheckIdentityPKMode - implements the verify of identity
func SJWTCheckIdentityPKMode(identityVal string, expireVal int, pubkeyVal string, pubkeyMode int, timeoutVal int) (int, error) {
	var err error
	var ret int
	var ecdsaPubKey *ecdsa.PublicKey
	var pubkey []byte
	var payload *SJWTPayload

	token := strings.Split(strings.TrimSpace(identityVal), ".")

	if len(token) != 3 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("invalid token - must contain header, payload and signature")
	}

	payload, ret, err = SJWTGetValidPayload(token[1], expireVal)
	if err != nil {
		return ret, err
	}

	if pubkeyMode == 1 {
		pubkey = []byte(pubkeyVal)
	} else {
		if strings.HasPrefix(pubkeyVal, "http://") || strings.HasPrefix(pubkeyVal, "https://") {
			pubkey, ret, err = SJWTGetURLContent(pubkeyVal, timeoutVal)
		} else if strings.HasPrefix(pubkeyVal, "file://") {
			fileUrl, _ := url.Parse(pubkeyVal)
			pubkey, err = ioutil.ReadFile(fileUrl.Path)
			ret = SJWTRetErrFileRead
		} else {
			pubkey, err = ioutil.ReadFile(pubkeyVal)
			ret = SJWTRetErrFileRead
		}
		if err != nil {
			return ret, err
		}
	}

	ret, err = SJWTPubKeyVerify(pubkey)
	if ret != SJWTRetOK {
		return ret, err
	}

	if ecdsaPubKey, ret, err = SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		return ret, err
	}
	ret, err = SJWTVerifyWithPubKey(token[0]+"."+token[1], token[2], ecdsaPubKey)
	if err == nil {
		return SJWTRetOK, nil
	}

	return ret, fmt.Errorf("failed to verify - origid (%s) (%d) %v", payload.OrigID, ret, err)
}

// SJWTCheckIdentity - implements the verify of identity
func SJWTCheckIdentity(identityVal string, expireVal int, pubkeyPath string, timeoutVal int) (int, error) {
	return SJWTCheckIdentityPKMode(identityVal, expireVal, pubkeyPath, 0, timeoutVal)
}

// SJWTGetValidInfoAttr - return info param value of alg and ppt are valid
func SJWTGetValidInfoAttr(hdrtoken []string) (string, int, error) {
	paramInfo := ""
	for i := 1; i < len(hdrtoken); i++ {
		ptoken := strings.Split(hdrtoken[i], "=")
		if len(ptoken) == 2 {
			if ptoken[0] == "alg" {
				if ptoken[1] != "ES256" {
					return "", SJWTRetErrSIPHdrAlg, fmt.Errorf("invalid value for alg header parameter")
				}
			} else if ptoken[0] == "ppt" {
				if ptoken[1] != "shaken" && ptoken[1] != `"shaken"` {
					return "", SJWTRetErrSIPHdrPpt, fmt.Errorf("invalid value for ppt header parameter")
				}
			} else if ptoken[0] == "info" {
				paramInfo = ptoken[1]
			}
		}
	}
	if len(paramInfo) <= 2 {
		return "", SJWTRetErrSIPHdrInfo, fmt.Errorf("invalid value info header parameter")
	}
	if paramInfo[0] == '<' && paramInfo[len(paramInfo)-1] == '>' {
		paramInfo = paramInfo[1 : len(paramInfo)-1]
	}

	return paramInfo, SJWTRetOK, nil
}

// SJWTCheckFullIdentity - implements the verify of identity
func SJWTCheckFullIdentity(identityVal string, expireVal int, pubkeyPath string, timeoutVal int) (int, error) {
	if len(pubkeyPath) == 0 {
		return SJWTCheckFullIdentityURL(identityVal, expireVal, timeoutVal)
	}

	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	ret, err := SJWTCheckIdentity(hdrtoken[0], expireVal, pubkeyPath, timeoutVal)
	if ret != 0 {
		return ret, err
	}

	if len(hdrtoken) == 1 {
		return SJWTRetErrSIPHdrParse, nil
	}

	paramInfo := ""
	paramInfo, ret, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return ret, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken[0]) == 0 {
		return SJWTRetErrJSONHdrParse, nil
	}
	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTCheckFullIdentityURL - implements the verify of identity using URL
func SJWTCheckFullIdentityURL(identityVal string, expireVal int, timeoutVal int) (int, error) {
	var ecdsaPubKey *ecdsa.PublicKey
	var ret int
	var err error
	var pubkey []byte

	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	if len(hdrtoken) <= 1 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("missing parts of the message header")
	}

	paramInfo := ""
	paramInfo, ret, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return ret, err
	}

	pubkey, ret, err = SJWTGetURLContent(paramInfo, timeoutVal)

	if pubkey == nil {
		return ret, err
	}

	ret, err = SJWTPubKeyVerify(pubkey)
	if ret != SJWTRetOK {
		return ret, err
	}

	if ecdsaPubKey, ret, err = SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		return ret, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken) != 3 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("invalid token - must contain header, payload and signature")
	}

	if len(btoken[0]) == 0 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("no json header part")
	}

	var payload *SJWTPayload
	payload, ret, err = SJWTGetValidPayload(btoken[1], expireVal)
	if payload == nil || err != nil {
		return ret, err
	}

	ret, err = SJWTVerifyWithPubKey(btoken[0]+"."+btoken[1], btoken[2], ecdsaPubKey)
	if err != nil {
		return ret, err
	}

	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTCheckFullIdentityPubKey - implements the verify of identity using public key
func SJWTCheckFullIdentityPubKey(identityVal string, expireVal int, pubkeyVal string) (int, error) {
	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	ret, err := SJWTCheckIdentityPKMode(hdrtoken[0], expireVal, pubkeyVal, 1, 5)
	if ret != 0 {
		return ret, err
	}

	if len(hdrtoken) == 1 {
		return SJWTRetOK, nil
	}

	paramInfo := ""
	paramInfo, ret, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return ret, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken[0]) == 0 {
		return SJWTRetOK, nil
	}
	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTGetIdentityPrvKey --
func SJWTGetIdentityPrvKey(origTN string, destTN string, attestVal string, origID string, x5uVal string, prvkeyData []byte) (string, int, error) {
	var ret int
	var err error
	var vOrigID string

	header := SJWTHeader{
		Alg: "ES256",
		Ppt: "shaken",
		Typ: "passport",
		X5u: globalLibOptions.X5u,
	}
	if len(x5uVal) > 0 {
		header.X5u = x5uVal
	}
	if len(origID) > 0 {
		vOrigID = origID
	} else {
		vuuid := uuid.New()
		vOrigID = vuuid.String()
	}

	payload := SJWTPayload{
		ATTest: attestVal,
		Dest: SJWTDest{
			TN: []string{destTN},
		},
		IAT: time.Now().Unix(),
		Orig: SJWTOrig{
			TN: origTN,
		},
		OrigID: vOrigID,
	}

	var ecdsaPrvKey *ecdsa.PrivateKey
	if ecdsaPrvKey, ret, err = SJWTParseECPrivateKeyFromPEM(prvkeyData); err != nil {
		return "", ret, fmt.Errorf("unable to parse ECDSA private key: %v", err)
	}
	token := SJWTEncode(header, payload, ecdsaPrvKey)

	if len(token) > 0 {
		return token + ";info=<" + header.X5u + ">;alg=ES256;ppt=shaken", SJWTRetOK, nil
	}
	return "", SJWTRetErrSIPHdrEmpty, errors.New("empty result")
}

// SJWTGetIdentity --
func SJWTGetIdentity(origTN string, destTN string, attestVal string, origID string, x5uVal string, prvkeyPath string) (string, int, error) {
	var prvkey []byte
	var err error

	prvkey, err = ioutil.ReadFile(prvkeyPath)
	if err != nil {
		return "", SJWTRetErrFileRead, fmt.Errorf("unable to read private key file: %v", err)
	}
	return SJWTGetIdentityPrvKey(origTN, destTN, attestVal, origID, x5uVal, prvkey)
}
