package crt

import (
	"crypto/x509"
	"net/http"
)

// CrlServer is an HTTP server that serves the Certificate Revocation List (CRL).
type CrtServer struct {
	crt *x509.Certificate
}

func NewCrtServer(crt *x509.Certificate) *CrtServer {
	return &CrtServer{
		crt: crt,
	}
}

// Implement http.Handler
func (s *CrtServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(s.crt.Raw)
}
