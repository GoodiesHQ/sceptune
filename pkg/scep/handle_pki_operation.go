package scep

import (
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"

	"github.com/goodieshq/sceptune/pkg/ms"
	"github.com/goodieshq/sceptune/pkg/utils"
	"github.com/smallstep/scep"
)

// handlePKIOperation processes SCEP PKI operations (CSR enrollment, etc.)
func (s *SCEPServerWindows) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	s.log.Debug().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Str("user_agent", r.UserAgent()).
		Msg("Handling PKIOperation Request")

	// Read the request body
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20) // 5 MB limit
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.log.Error().Err(err).Msg("Error reading request body")
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse the SCEP PKI message
	msg, err := scep.ParsePKIMessage(body)
	if err != nil {
		s.log.Error().Err(err).Msg("Error parsing PKI message")
		http.Error(w, "Failed to parse SCEP message", http.StatusBadRequest)
		return
	}

	s.log.Info().
		Str("message_type", msg.MessageType.String()).
		Str("transaction_id", string(msg.TransactionID)).
		Msg("Parsed PKI message successfully")

	// Handle different message types
	switch msg.MessageType {
	case scep.PKCSReq, scep.RenewalReq, scep.UpdateReq:
		s.handleCSRRequest(w, r, msg)
	case scep.GetCRL:
		s.log.Error().Msg("GetCRL not implemented")
		http.Error(w, "GetCRL not implemented", http.StatusNotImplemented)
	case scep.GetCert:
		s.log.Error().Msg("GetCert not implemented")
		http.Error(w, "GetCert not implemented", http.StatusNotImplemented)
	case scep.CertPoll:
		s.log.Error().Msg("CertPoll not implemented")
		http.Error(w, "CertPoll not implemented", http.StatusNotImplemented)
	default:
		s.log.Error().Msgf("Unknown message type: %s", msg.MessageType)
		http.Error(w, "Unknown message type", http.StatusBadRequest)
	}
}

// handleCSRRequest processes a certificate signing request
func (s *SCEPServerWindows) handleCSRRequest(w http.ResponseWriter, r *http.Request, msg *scep.PKIMessage) {
	s.log.Info().Msg("Handling CSR Request")
	if msg == nil {
		s.log.Error().Msg("Received nil PKI message")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Use the RA cert/key to decrypt the PKI envelope to extract the CSR
	if err := msg.DecryptPKIEnvelope(s.raCrt, s.raKey); err != nil {
		s.log.Error().Err(err).Msg("Error decrypting PKI envelope")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Extract CSR and challenge password
	if msg.CSRReqMessage == nil {
		s.log.Error().Msg("No CSR request message found")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Verify the CSR with Intune
	csr := msg.CSRReqMessage.CSR
	challenge := msg.CSRReqMessage.ChallengePassword
	s.logCSRDetails(csr) // Log CSR details for debugging, TODO: disable in production
	csrBase64 := base64.StdEncoding.EncodeToString(csr.Raw)
	dbid := utils.CreateDBID(csrBase64, challenge)

	crt, notified, err := s.store.GetCert(csrBase64, challenge)
	if err != nil {
		s.log.Error().Err(err).Msg("Error checking existing certificate in store")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	if crt != nil {
		// Certificate already exists, notify Intune
		s.log.Info().Msg("Certificate already exists in store, notifying Intune.")
		msgCrt, err := msg.Success(s.raCrt, s.raKey, crt)
		if err != nil {
			s.log.Error().Err(err).Msg("Error creating success response from existing cert")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}

		if !notified {
			if err := s.verifier.NotifySuccess(r.Context(), csrBase64, challenge, crt, s.caChain[0]); err == nil {
				_, err := s.store.MarkIntuneNotified(csrBase64, challenge)
				if err != nil {
					s.log.Warn().Err(err).Msg("Error marking certificate as notified in store")
				}
				w.Header().Set("Content-Type", "application/x-pki-message")
				w.WriteHeader(http.StatusOK)
				w.Write(msgCrt.Raw)
				s.log.Info().Msgf("Returned existing certificate for DBID %s", dbid)
				return
			}
			s.log.Error().Err(err).Msg("Error notifying Intune of existing certificate")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}

		// Already notified, just return the certificate
		w.Header().Set("Content-Type", "application/x-pki-message")
		w.WriteHeader(http.StatusOK)
		w.Write(msgCrt.Raw)
		s.log.Info().Msgf("Returned existing certificate for DBID %s", dbid)
		return
	}

	// Verify CSR (with Intune API)
	valid, err := s.verifier.VerifyCSR(r.Context(), csrBase64, challenge)
	if err != nil {
		s.log.Error().Err(err).Msg("Error verifying CSR with Intune")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Invalid CSR/Challenge combination
	if !valid {
		s.log.Warn().Msg("CSR verification failed for Transaction ID.")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// From this point on, all failues must be reported back to Intune

	s.log.Info().Msg("CSR/Challenge verified successfully.")

	// Sign the CSR
	signedCrt, err := s.signer.SignCSR(r.Context(), csr)
	if err != nil {
		s.log.Error().Err(err).Msg("Error signing CSR")
		s.verifier.NotifyFailure(r.Context(), csrBase64, challenge, ms.HResultCAUnavailable, "Certificate Authority Unavailable")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Notify Intune of success
	err = s.verifier.NotifySuccess(r.Context(), csrBase64, challenge, signedCrt, s.caChain[0])
	if err != nil {
		s.log.Error().Err(err).Msg("Error notifying Intune of successful CSR signing, not sending response to client")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Store the signed certificate
	if err := s.store.StoreCert(csrBase64, challenge, signedCrt); err != nil {
		s.log.Warn().Err(err).Msg("Error storing signed certificate")
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedCrt.Raw,
	})
	s.log.Info().Str("pem", string(pem)).Msg("CSR signed successfully.")

	// Create success response
	certRep, err := msg.Success(s.raCrt, s.raKey, signedCrt)
	if err != nil {
		s.log.Error().Err(err).Msg("Error creating a success response from new cert")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(certRep.Raw)
	s.log.Info().Msgf("Returned signed certificate for DBID %s", dbid)
}
