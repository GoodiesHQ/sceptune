package utils

import (
	"context"
	"crypto"
	"crypto/x509"
)

type IntuneCnType string

const (
	IntuneCnTypeAADDeviceID IntuneCnType = "AAD_Device_ID"
	IntuneCnTypeDeviceID    IntuneCnType = "DeviceId"
)

type Certs interface {
	GetCrt() *x509.Certificate
	GetKey() crypto.PrivateKey
	GetChain() []*x509.Certificate
}

type Signer interface {
	SignCSR(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
	GetCRL(ctx context.Context) (*x509.RevocationList, error)
}

type Verifier interface {
	VerifyCSR(ctx context.Context, csr string, challenge string) (bool, error)
	NotifyFailure(ctx context.Context, csr, challenge string, hResult int64, errorDescription string) error
	NotifySuccess(ctx context.Context, csr, challenge string, crt, root *x509.Certificate) error
}

type Store interface {
	StoreCert(ctx context.Context, csr, txid string, cert *x509.Certificate) error
	GetCert(ctx context.Context, csr, txid string) (*x509.Certificate, bool, error)
	MarkIntuneNotified(ctx context.Context, csr, txid string) (bool, error)
	PurgeExpired(ctx context.Context) (int64, error)
	Close() error
}
