package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RSA key size in bits
const rsaKeySize = 2048

// NewSigningKey creates a new signing key for the given algorithm
func NewSigningKey(alg string, curve string) (jwk.Key, error) {
	// Generate a random key ID (base64url, no padding)
	keyID, err := genKid()
	if err != nil {
		return nil, err
	}

	rawKey, algorithm, err := genKey(alg, curve)
	if err != nil {
		return nil, err
	}

	// Create JWK from the raw key
	signingKey, err := jwk.Import(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to import signing key: %w", err)
	}

	// Set key ID
	err = signingKey.Set(jwk.KeyIDKey, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	err = signingKey.Set(jwk.AlgorithmKey, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	return signingKey, nil
}

func genKid() (string, error) {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func genKey(alg string, curve string) (rawKey any, algorithm jwa.SignatureAlgorithm, err error) {
	switch alg {
	case "RS256":
		algorithm = jwa.RS256()
		rsaKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			return nil, algorithm, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		return rsaKey, algorithm, nil

	case "ES256":
		algorithm = jwa.ES256()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, algorithm, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		return ecKey, algorithm, nil

	case "ES384":
		algorithm = jwa.ES384()
		ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, algorithm, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		return ecKey, algorithm, nil

	case "ES512":
		algorithm = jwa.ES512()
		ecKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, algorithm, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		return ecKey, algorithm, nil

	case "EdDSA":
		algorithm = jwa.EdDSA()
		// Currently only Ed25519 is supported
		if curve != "" && curve != "Ed25519" {
			return nil, algorithm, fmt.Errorf("unsupported EdDSA curve: %s (only ed25519 is supported)", curve)
		}
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, algorithm, fmt.Errorf("failed to generate EdDSA key: %w", err)
		}
		return edKey, algorithm, nil

	default:
		return nil, algorithm, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}
