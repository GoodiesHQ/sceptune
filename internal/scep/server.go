package scep

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	"github.com/goodieshq/sceptune/internal/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/smallstep/scep"
)

type SCEPServerWindows struct {
	raCrt                *x509.Certificate
	raKey                crypto.PrivateKey
	caChain              []*x509.Certificate
	log                  zerolog.Logger
	signer               utils.Signer
	verifier             utils.Verifier
	store                utils.Store
	muPurge              sync.Mutex
	complianceRequired   bool
	complianceAllowGrace bool
	intuneCnType         utils.IntuneCnType
	isPurging            bool
}

// NewSCEPServerWindows creates a new SCEP server instance
func NewSCEPServerWindows(
	raCert *x509.Certificate, raKey crypto.PrivateKey, caChain []*x509.Certificate,
	verifier utils.Verifier, signer utils.Signer, store utils.Store,
	complianceRequired, complianceAllowGrace bool, intuneCnType utils.IntuneCnType) *SCEPServerWindows {
	return &SCEPServerWindows{
		raCrt:    raCert,
		raKey:    raKey,
		caChain:  caChain,
		verifier: verifier,
		signer:   signer,
		store:    store,
		log:      log.Logger.With().Str("component", "scep_windows").Logger(),
		intuneCnType: 	   intuneCnType,
		complianceRequired:   complianceRequired,
		complianceAllowGrace: complianceAllowGrace,
	}
}

func (s *SCEPServerWindows) StartPurging(ctx context.Context) {
	s.muPurge.Lock()
	if s.isPurging {
		s.muPurge.Unlock()
		return
	}
	s.isPurging = true
	s.muPurge.Unlock()

	go func() {
		// Purge expired certificates every hour
		timer := time.NewTicker(time.Hour)
		defer func() {
			timer.Stop()
			s.muPurge.Lock()
			s.isPurging = false
			s.muPurge.Unlock()
		}()

		// Initial purge immediately
		_, err := s.store.PurgeExpired()
		if err != nil {
			s.log.Error().Err(err).Msg("Error purging expired certificates")
		}

		for {
			select {
			case <-timer.C:
				_, err := s.store.PurgeExpired()
				if err != nil {
					s.log.Error().Err(err).Msg("Error purging expired certificates")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ServeHTTP implements the http.Handler interface
func (s *SCEPServerWindows) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse operation from query parameters
	operation := r.URL.Query().Get("operation")
	s.log.Debug().Str("operation", operation).Str("remote_addr", r.RemoteAddr).Msgf("Received %s request", r.Method)

	switch operation {
	case "GetCACaps":
		s.handleGetCACaps(w, r)
	case "GetCACert":
		s.handleGetCACert(w, r)
	case "PKIOperation":
		s.handlePKIOperation(w, r)
	default:
		s.log.Warn().Str("operation", operation).Msg("Unknown operation")
		http.Error(w, "Unknown operation", http.StatusBadRequest)
	}
}

// logCSRDetails logs detailed information about the CSR
func (s *SCEPServerWindows) logCSRDetails(csr *x509.CertificateRequest) {
	s.log.Trace().
		Str("subject_common_name", csr.Subject.CommonName).
		Strs("subject_organization", csr.Subject.Organization).
		Strs("subject_organizational_unit", csr.Subject.OrganizationalUnit).
		Strs("subject_country", csr.Subject.Country).
		Strs("subject_locality", csr.Subject.Locality).
		Strs("subject_province", csr.Subject.Province).
		Str("public_key_algorithm", csr.PublicKeyAlgorithm.String()).
		Str("signature_algorithm", csr.SignatureAlgorithm.String()).
		Strs("dns_names", csr.DNSNames).
		Strs("email_addresses", csr.EmailAddresses).
		Msg("Logging CSR details")

	/*
		// Log the CSR in PEM format for easy copying
		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr.Raw,
		})
		s.log.Printf("\nCSR (PEM format):\n%s\n", string(csrPEM))

		// Log base64 encoded CSR for Intune API
		csrBase64 := base64.StdEncoding.EncodeToString(csr.Raw)
		s.log.Printf("CSR (Base64 - for Intune API):\n%s\n", csrBase64)
	*/
}

// sendFailureResponse sends a SCEP failure response
func (s *SCEPServerWindows) sendFailureResponse(w http.ResponseWriter, msg *scep.PKIMessage, failInfo scep.FailInfo) {
	s.log.Warn().Str("fail_info", failInfo.String()).Msg("Sending failure response")

	// Create failure response
	certRep, err := msg.Fail(s.raCrt, s.raKey, failInfo)
	if err != nil {
		s.log.Error().Err(err).Msg("Error creating failure response")
		http.Error(w, "Failed to create response", http.StatusInternalServerError)
		return
	}

	// Send the response
	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(certRep.Raw)
	s.log.Debug().Msg("Sent failure response")
}
