package scep

import (
	"fmt"
	"net/http"
	"strings"
)

// handleGetCACaps returns the CA capabilities
func (s *SCEPServerWindows) handleGetCACaps(w http.ResponseWriter, r *http.Request) {
	s.log.Debug().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Str("user_agent", r.UserAgent()).
		Msg("Handling GetCACaps Request")

	caps := []string{
		"POSTPKIOperation", // Support POST for PKIOperation
		"SHA-256",          // Support SHA-256 hashing
		"SHA-512",          // Support SHA-512 hashing
		"AES",              // Support AES encryption
		"DES3",             // Support 3DES encryption (sometimes required)
		"SCEPStandard",     // RFC 8894 compliant
	}

	capsText := strings.Join(caps, "\n")

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(capsText)))
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, capsText)
}
