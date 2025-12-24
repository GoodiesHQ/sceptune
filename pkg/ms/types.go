package ms

const (
	// Generic failure
	HResultFail = 0x80004005
	// Invalid argument
	HResultInvalidArg = 0x80070057
	// Certificate request denied
	HResultCertDenied = 0x80094004
	// CA not available
	HResultCAUnavailable = 0x800706BA
	// Unexpected error
	HResultUnexpected = 0x8000FFFF
)

type NotifySuccess struct {
	CertificateRequest           string `json:"certificateRequest"`
	TransactionID                string `json:"transactionId"`
	CertificateThumbprint        string `json:"certificateThumbprint"`
	CertificateSerialNumber      string `json:"certificateSerialNumber"`
	CertificateExpirationDateUTC string `json:"certificateExpirationDateUtc"`
	IssuingCertificateAuthority  string `json:"issuingCertificateAuthority"`
	CAConfiguration              string `json:"caConfiguration"`
	CertificateAuthority         string `json:"certificateAuthority"`
	CallerInfo                   string `json:"callerInfo"`
}

type NotifySuccessRequest struct {
	Notification NotifySuccess `json:"notification"`
}

type NotifyFailure struct {
	CertificateRequest string `json:"certificateRequest"`
	TransactionID      string `json:"transactionId"`
	HResult            int64  `json:"hResult"`
	ErrorDescription   string `json:"errorDescription"`
	CallerInfo         string `json:"callerInfo"`
}

type NotifyFailureRequest struct {
	Notification NotifyFailure `json:"notification"`
}

type ValidateCSRRequestInner struct {
	CertificateRequest string `json:"certificateRequest"`
	TransactionID      string `json:"transactionId"`
	CallerInfo         string `json:"callerInfo"`
}

type ValidateCSRRequest struct {
	Request ValidateCSRRequestInner `json:"request"`
}

type IntuneResponse struct {
	// ODataContext     string `json:"@odata.context,omitempty"`
	Code             string `json:"code"`
	ErrorDescription string `json:"errorDescription,omitempty"`
}
