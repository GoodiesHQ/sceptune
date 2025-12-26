package utils

import (
	"context"
	"crypto/x509"
)

type Signer interface {
	SignCSR(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
	GetCRL(ctx context.Context) (*x509.RevocationList, error)
}

type Verifier interface {
	VerifyCSR(ctx context.Context, csr string, txid string) (bool, error)
	NotifyFailure(ctx context.Context, csr, txid string, hResult int64, errorDescription string) error
	NotifySuccess(ctx context.Context, csr, txid string, crt, root *x509.Certificate) error
}

type Store interface {
	StoreCert(csr, txid string, cert *x509.Certificate) error
	GetCert(csr, txid string) (*x509.Certificate, bool, error)
	MarkIntuneNotified(csr, txid string) (bool, error)
	PurgeExpired() (int64, error)
	Close() error
}
