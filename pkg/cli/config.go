package cli

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/goodieshq/sceptune/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

type Params struct {
	TenantID        string
	ClientID        string
	ClientSecret    string
	Port            uint16
	ScepPath        string
	CaCrt           *x509.Certificate
	RaCrt           *x509.Certificate
	RaKey           crypto.PrivateKey
	CaChain         []*x509.Certificate
	JWK             *jose.JSONWebKey
	APIURL          string
	ProvisionerName string
	DBPath          string
}

func loadParams(c *cli.Command) (*Params, error) {
	port := c.Uint16("port")
	scepPath := c.String("scep-path")
	tenantID := c.String("tenant-id")
	clientID := c.String("client-id")
	clientSecret := c.String("client-secret")
	clientSecretFile := c.String("client-secret-file")
	caCrtFile := c.String("ca-crt")
	raCrtFile := c.String("ra-crt")
	raKeyFile := c.String("ra-key")
	caChainFile := c.String("ca-chain")
	jwkFile := c.String("json-web-key-file")
	jwkPassword := c.String("json-web-key-password")
	jwkPasswordFile := c.String("json-web-key-password-file")
	apiUrl := c.String("step-api-url")
	provisionerName := c.String("step-provisioner-name")
	dbPath := c.String("database-path")

	// verify required parameters
	if tenantID == "" || clientID == "" || (clientSecret == "" && clientSecretFile == "") {
		return nil, fmt.Errorf("Tenant ID, Client ID, and Client Secret are required")
	}

	if apiUrl == "" {
		return nil, fmt.Errorf("Step API URL is required")
	}

	if provisionerName == "" {
		return nil, fmt.Errorf("Step provisioner name is required")
	}

	if dbPath == "" {
		return nil, fmt.Errorf("A valid database path is required")
	}

	if clientSecret == "" {
		secretBytes, err := os.ReadFile(clientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client secret file: %w", err)
		}
		clientSecret = string(secretBytes)
	}
	log.Info().Msg("[+] Loaded Azure Application details")

	if caCrtFile == "" || !utils.IsFile(caCrtFile) {
		return nil, fmt.Errorf("Signer CA certificate file is required")
	}

	if raCrtFile == "" || !utils.IsFile(raCrtFile) {
		return nil, fmt.Errorf("RA certificate file is required")
	}

	if raKeyFile == "" || !utils.IsFile(raKeyFile) {
		return nil, fmt.Errorf("RA key file is required")
	}

	if caChainFile == "" || !utils.IsFile(caChainFile) {
		return nil, fmt.Errorf("CA chain file is required")
	}

	if jwkFile == "" || !utils.IsFile(jwkFile) {
		return nil, fmt.Errorf("JSON Web Key file is required")
	}

	if jwkPassword == "" {
		if jwkPasswordFile != "" {
			if !utils.IsFile(jwkPasswordFile) {
				return nil, fmt.Errorf("JWK password file does not exist")
			}
			passwordBytes, err := os.ReadFile(jwkPasswordFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read JWK password file: %w", err)
			}
			jwkPassword = string(passwordBytes)
		}
	}

	jwkBytes, err := os.ReadFile(jwkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWK file: %w", err)
	}

	jwk, err := utils.ParseJWK(jwkBytes, jwkPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK file: %w", err)
	}

	if jwk.IsPublic() {
		return nil, fmt.Errorf("JWK must contain a private key for signing, but only a public key was found")
	}
	log.Info().Msg("[+] Loaded JSON Web Key for interacting with the Step API")

	// read the certificate and key files

	caCrtBytes, err := os.ReadFile(caCrtFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
	}

	raCrtBytes, err := os.ReadFile(raCrtFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RA certificate file: %w", err)
	}

	raKeyBytes, err := os.ReadFile(raKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RA key file: %w", err)
	}

	chainBytes, err := os.ReadFile(caChainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA chain file: %w", err)
	}

	chain, err := utils.TryParseChain(chainBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA chain: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("CA chain file contains no certificates")
	}

	log.Info().Msg("[+] Loaded CA chain certificates:")
	for i, cert := range chain {
		log.Info().Msgf("    [+] CA Chain Cert %d: Subject=%s", i+1, cert.Subject.String())
	}

	// parse the certificate and key as optional PEM

	caCrt, err := utils.TryParseCertificate(caCrtBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	log.Info().Str("fingerprint", utils.FingerprintSha256(caCrt)).Msgf("[+] Loaded Signer CA certificate")

	raCrt, err := utils.TryParseCertificate(raCrtBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RA certificate: %w", err)
	}

	raKey, err := utils.TryParseKey(raKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RA private key: %w", err)
	}

	switch keyType := raKey.(type) {
	case *rsa.PrivateKey:
	default:
		return nil, fmt.Errorf("only RSA keys are supported for this SCEP server, got %T", keyType)
	}

	// check if crt and key match each other
	match, err := utils.CheckCrtKeyMatch(raCrt, raKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify matching CA certificate and key: %w", err)
	}
	if !match {
		return nil, fmt.Errorf("CA certificate and key do not match")
	}

	log.Info().Msgf("[+] Loaded RA certificate and key: Subject=%s", raCrt.Subject.String())

	return &Params{
		TenantID:        tenantID,
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		Port:            port,
		ScepPath:        "/" + strings.TrimLeft(scepPath, "/"),
		CaCrt:           caCrt,
		RaCrt:           raCrt,
		RaKey:           raKey,
		CaChain:         chain,
		JWK:             jwk,
		APIURL:          apiUrl,
		ProvisionerName: provisionerName,
		DBPath:          dbPath,
	}, nil
}
