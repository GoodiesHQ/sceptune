package step

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/goodieshq/sceptune/pkg/utils"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
)

type StepClient struct {
	apiUrl          string
	provisionerName string
	caFingerprint   string
	jwk             jose.SigningKey
	client          *ca.Client
	kid             string
}

func NewStepClient(apiUrl, provisionerName, caFingerprint string, jwk *jose.JSONWebKey) (*StepClient, error) {
	url, err := url.Parse(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid Step CA API URL: %w", err)
	}

	if url.Scheme != "http" && url.Scheme != "https" {
		return nil, fmt.Errorf("invalid Step CA API URL: unsupported scheme %q", url.Scheme)
	}
	if url.Host == "" {
		return nil, fmt.Errorf("invalid Step CA API URL: missing host")
	}
	apiUrl = strings.TrimRight(apiUrl, "/")
	client, err := ca.NewClient(
		apiUrl,
		// ca.WithRootSHA256(caFingerprint),
		ca.WithInsecure(),
		ca.WithTimeout(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Step CA client: %w", err)
	}

	return &StepClient{
		apiUrl:          apiUrl,
		provisionerName: provisionerName,
		caFingerprint:   caFingerprint,
		client:          client,
		kid:             jwk.KeyID,
		jwk:             jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
	}, nil
}

func (c *StepClient) CreateToken(subject string, sans []string) (string, error) {
	now := time.Now()
	nowMinus30 := now.Add(-30 * time.Second) // allow for clock skew
	nowPlus300 := now.Add(5 * time.Minute)   // token valid for 5 minutes

	claims := jwt.Claims{
		Issuer:    c.provisionerName,
		Subject:   subject,
		Audience:  jwt.Audience{c.apiUrl + "/sign"},
		IssuedAt:  jwt.NewNumericDate(nowMinus30),
		NotBefore: jwt.NewNumericDate(nowMinus30),
		Expiry:    jwt.NewNumericDate(nowPlus300),
		ID:        utils.GenerateActivityID(),
	}

	type stepClaims struct {
		jwt.Claims
		SHA  string   `json:"sha"`
		SANs []string `json:"sans,omitempty"`
	}

	fullClaims := stepClaims{
		Claims: claims,
		SHA:    c.caFingerprint,
		SANs:   sans,
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts.WithHeader("kid", c.kid)

	signer, err := jose.NewSigner(c.jwk, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %w", err)
	}

	token, err := jwt.Signed(signer).Claims(fullClaims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return token, nil
}

func (c *StepClient) SignCSR(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	subject := csr.Subject.CommonName
	sans := utils.ExtractSANsFromCSR(csr)

	token, err := c.CreateToken(subject, sans)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	signRequest := &api.SignRequest{
		CsrPEM: api.NewCertificateRequest(csr),
		OTT:    token,
	}

	signResponse, err := c.client.SignWithContext(ctx, signRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR with Step CA: %w", err)
	}

	if signResponse.ServerPEM.Certificate == nil {
		return nil, fmt.Errorf("no certificate returned from Step CA")
	}

	return signResponse.ServerPEM.Certificate, nil
}
