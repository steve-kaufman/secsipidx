package secsipid

import "fmt"

type Error struct {
	Code int
	Msg  string
}

func (e Error) Error() string {
	return e.Msg
}

func (e Error) Simplify() (int, error) {
	return e.Code, fmt.Errorf(e.Msg)
}

// return and error code values
const (
	SJWTRetOK = 0
	// generic errors
	SJWTRetErr = -1
	// public certificate and private key errors: -100..-199
	SJWTRetErrCertInvalid         = -101
	SJWTRetErrCertInvalidFormat   = -102
	SJWTRetErrCertExpired         = -103
	SJWTRetErrCertBeforeValidity  = -104
	SJWTRetErrCertProcessing      = -105
	SJWTRetErrCertNoCAFile        = -106
	SJWTRetErrCertReadCAFile      = -107
	SJWTRetErrCertNoCAInter       = -108
	SJWTRetErrCertReadCAInter     = -109
	SJWTRetErrCertNoCRLFile       = -110
	SJWTRetErrCertReadCRLFile     = -111
	SJWTRetErrCertRevoked         = -112
	SJWTRetErrCertInvalidEC       = -114
	SJWTRetErrPrvKeyInvalid       = -151
	SJWTRetErrPrvKeyInvalidFormat = -152
	SJWTRetErrPrvKeyInvalidEC     = -152
	// identity JSON header, payload and signature errors: -200..-299
	SJWTRetErrJSONHdrParse          = -201
	SJWTRetErrJSONHdrAlg            = -202
	SJWTRetErrJSONHdrPpt            = -203
	SJWTRetErrJSONHdrTyp            = -204
	SJWTRetErrJSONHdrX5u            = -205
	SJWTRetErrJSONPayloadParse      = -231
	SJWTRetErrJSONPayloadIATExpired = -232
	SJWTRetErrJSONSignatureInvalid  = -251
	SJWTRetErrJSONSignatureHashing  = -252
	SJWTRetErrJSONSignatureSize     = -253
	SJWTRetErrJSONSignatureFailure  = -254
	// identity SIP header errors: -300..-399
	SJWTRetErrSIPHdrParse = -301
	SJWTRetErrSIPHdrAlg   = -302
	SJWTRetErrSIPHdrPpt   = -303
	SJWTRetErrSIPHdrInfo  = -303
	SJWTRetErrSIPHdrEmpty = -304
	// http and file operations errors: -400..-499
	SJWTRetErrHTTPInvalidURL = -401
	SJWTRetErrHTTPGet        = -402
	SJWTRetErrHTTPStatusCode = -403
	SJWTRetErrHTTPReadBody   = -404
	SJWTRetErrFileRead       = -451
)
