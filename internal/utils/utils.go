package utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/smallstep/pkcs7"
	"github.com/youmark/pkcs8"
)

// Ptr converts a value to a pointer.
func Ptr[T any](v T) *T {
	return &v
}

// Deref dereferences a pointer.O
func Deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// IsFile checks if the given path is a file.
func IsFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// TryParsePEM attempts to parse a non-encrypted PEM-encoded block from the given data.
func TryParsePEM(data []byte) []byte {
	block, rest := pem.Decode(data)
	if block != nil {
		return block.Bytes
	}
	return rest
}

// TryParseCertificate attempts to parse a PEM/DER certificate from the given data.
func TryParseCertificate(data []byte) (*x509.Certificate, error) {
	data = TryParsePEM(data)
	return x509.ParseCertificate(data)
}

// TryParseChain attempts to parse a PEM-encoded certificate chain from the given data.
func TryParseChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			data = rest
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in chain: %w", err)
		}
		certs = append(certs, cert)
		data = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in data")
	}
	return certs, nil
}

func getPrivateKeyBlock(data []byte) *pem.Block {
	block, _ := pem.Decode(data)
	if block != nil && strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return block
	}
	return nil
}

func tryParseKeyDER(der []byte, password []byte) (crypto.PrivateKey, error) {
	if len(password) > 0 {
		if k, err := pkcs8.ParsePKCS8PrivateKey(der, password); err == nil {
			return k.(crypto.PrivateKey), nil
		}
	}

	if k, err := pkcs8.ParsePKCS8PrivateKey(der); err == nil {
		return k.(crypto.PrivateKey), nil
	}

	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}

	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}

	return nil, fmt.Errorf("failed to parse private key in DER format")
}

func tryParseKeyPEM(block *pem.Block, password []byte) (crypto.PrivateKey, error) {
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if len(password) == 0 {
			return nil, fmt.Errorf("private key is encrypted but no password was provided")
		}

		var err error
		der, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key PEM block (%s): %w", block.Type, err)
		}
	}

	switch block.Type {
	case "ENCRYPTED PRIVATE KEY": // pkcs8
		if len(password) == 0 {
			return nil, fmt.Errorf("private key is encrypted but no password was provided")
		}
		k, err := pkcs8.ParsePKCS8PrivateKey(der, password)
		if err != nil {
			return nil, fmt.Errorf("failed to parse encrypted PKCS8 private key: %w", err)
		}
		return k.(crypto.PrivateKey), nil
	case "PRIVATE KEY":
		k, err := pkcs8.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		return k.(crypto.PrivateKey), nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return k, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return k, nil
	default:
		return tryParseKeyDER(der, password)
	}
}

// TryParseKey attempts to parse a private key from the given data.
func TryParseKey(data []byte, password *string) (crypto.PrivateKey, error) {
	pw := []byte(nil)
	if password != nil {
		pw = []byte(*password)
	}

	block := getPrivateKeyBlock(data)
	if block != nil {
		return tryParseKeyPEM(block, pw)
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// CheckCrtKeyMatch checks if the given key is valid for the given certificate
func CheckCrtKeyMatch(crt *x509.Certificate, key crypto.PrivateKey) (bool, error) {
	var pubKeyFromCrt crypto.PublicKey = crt.PublicKey

	switch pk := key.(type) {
	case *rsa.PrivateKey:
		pubKeyFromKey := &pk.PublicKey
		pubKeyFromCrt, ok := pubKeyFromCrt.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("mismatched key types")
		}
		return pubKeyFromKey.Equal(pubKeyFromCrt), nil
	case *ecdsa.PrivateKey:
		pubKeyFromKey := &pk.PublicKey
		pubKeyFromCrt, ok := pubKeyFromCrt.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("mismatched key types")
		}
		return pubKeyFromKey.Equal(pubKeyFromCrt), nil
	default:
		return false, fmt.Errorf("unsupported private key type")
	}
}

// pseudoRandomDataSimple generates a small amount of pseudo-random data without errors
func pseudoRandomDataSimple() []byte {
	var buf bytes.Buffer

	// use current time as additional entropy
	now := time.Now().UnixNano()
	binary.Write(&buf, binary.LittleEndian, now)

	// use the process ID as additional entropy
	pid := os.Getpid()
	binary.Write(&buf, binary.LittleEndian, pid)

	// use a pointer address as additional entropy
	x := new(int)
	buf.WriteString(fmt.Sprintf("%p", x))

	return buf.Bytes()
}

// GenerateActivityID generates a new UUID. Prefers random UUID, falls back to simpler pseudorandom data.
func GenerateActivityID() string {
	// prefer new random
	uid, err := uuid.NewRandom()
	if err != nil {
		// fallback to a pseudo-random UUID
		uid = uuid.NewSHA1(uuid.Nil, pseudoRandomDataSimple())
	}
	return uid.String()
}

// BuildBundle creates a PKCS7 bundle from the RA certificate and CA chain.
func BuildBundle(raCrt *x509.Certificate, caChain []*x509.Certificate) ([]byte, error) {
	if raCrt == nil {
		return nil, fmt.Errorf("RA certificate is nil")
	}

	sd, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS7 signed data: %w", err)
	}

	sd.AddCertificate(raCrt)
	for _, cert := range caChain {
		if cert == nil {
			continue
		}
		sd.AddCertificate(cert)
	}

	sd.Detach()

	der, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finish PKCS7 signed data: %w", err)
	}

	return der, nil
}

// All supported key algorithms for JWK parsing
var allKeyAlgorithms = []jose.KeyAlgorithm{
	jose.ED25519, jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT,
	jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
	jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
}

// All supported content encryption algorithms for JWK parsing
var allEncryptionAlgorithms = []jose.ContentEncryption{
	jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512,
	jose.A128GCM, jose.A192GCM, jose.A256GCM,
}

// ParseJWK attempts to parse a JSON Web Key (JWK) from the given data.
func ParseJWK(data []byte, password string) (*jose.JSONWebKey, error) {
	// Attempt to parse the JWK plaintext first
	var jwe *jose.JSONWebEncryption
	var jwk jose.JSONWebKey
	var err error

	err = json.Unmarshal(data, &jwk)
	if err == nil {
		return &jwk, nil
	}

	// Failed to unmarshal, attempt to parse as encrypted JWK
	jwe, err = jose.ParseEncryptedJSON(string(data), allKeyAlgorithms, allEncryptionAlgorithms)
	if err == nil {
		decrypted, err := jwe.Decrypt(password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt JWK: %w", err)
		}
		err = json.Unmarshal(decrypted, &jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal decrypted JWK: %w", err)
		}
		return &jwk, nil
	}

	return nil, err
}

// Check if a JWT token contains a specific role by name, does not validate the token in any way, just decodes the claims and checks for the role.
func TokenHasRole(token string, roleName string) bool {
	type rolesClaim struct {
		Roles []string `json:"roles"`
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	bufSize := base64.RawURLEncoding.DecodedLen(len(parts[1]))
	bufClaims := make([]byte, bufSize)

	_, err := base64.RawURLEncoding.Decode(bufClaims, []byte(parts[1]))
	if err != nil {
		return false
	}

	var claims rolesClaim
	if err := json.Unmarshal(bufClaims, &claims); err != nil {
		return false
	}

	for _, role := range claims.Roles {
		if strings.EqualFold(role, roleName) {
			return true
		}
	}
	return false
}

// DedupStrings removes duplicate strings from a slice.
func DedupStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, str := range input {
		if str == "" {
			continue
		}
		if _, ok := seen[str]; !ok {
			seen[str] = struct{}{}
			result = append(result, str)
		}
	}

	return result
}

// Get all SANs from a CSR
func ExtractSANsFromCSR(csr *x509.CertificateRequest) []string {
	var sans []string

	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

	return DedupStrings(sans)
}

// NormalizeHex will remove common symbols from a hex string (e.g. thumbprints/fingerprints/serial numbers)
func NormalizeHex(fingerprint string) string {
	fingerprint = strings.ToLower(fingerprint)
	fingerprint = strings.ReplaceAll(fingerprint, ":", "")
	fingerprint = strings.ReplaceAll(fingerprint, "-", "")
	fingerprint = strings.ReplaceAll(fingerprint, " ", "")
	return fingerprint
}

// FingerprintSha256 returns the SHA-256 fingerprint of a certificate as a normalized hex string.
func FingerprintSha256(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return NormalizeHex(hex.EncodeToString(hash[:]))
}

// FingerprintSha1 returns the SHA-1 fingerprint of a certificate as a normalized hex string.
func FingerprintSha1(cert *x509.Certificate) string {
	hash := sha1.Sum(cert.Raw)
	return NormalizeHex(hex.EncodeToString(hash[:]))
}

// Create a Database Identifier from a CSR and Transaction ID/Challenge
func CreateDBID(csr, txid string) string {
	hash := sha256.New()
	hash.Write([]byte(csr))
	hash.Write([]byte{0x00})
	hash.Write([]byte(txid))

	return hex.EncodeToString(hash.Sum(nil))
}

func EscapeODataString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func ReadTextFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Trim whitespace from the beginning and end of the file contents
	return strings.TrimSpace(string(data)), nil
}
