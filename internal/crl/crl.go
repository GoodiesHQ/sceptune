package crl

import (
	"fmt"
	"net/http"

	"github.com/goodieshq/sceptune/internal/utils"
)

type CrlServer struct {
	signer utils.Signer
}

func NewCrlServer(signer utils.Signer) *CrlServer {
	return &CrlServer{
		signer: signer,
	}
}

func (s *CrlServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	crl, err := s.signer.GetCRL(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get CRL: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(crl.Raw)
}
