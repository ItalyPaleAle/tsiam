package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/italypaleale/go-kit/utils"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
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
	signingKey, err := jwk.Import[jwk.Key](rawKey)
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

	// Set key usage
	err = signingKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	return signingKey, nil
}

// ValidateSigningKey checks that key is a valid private signing key for a supported algorithm
func ValidateSigningKey(key jwk.Key) error {
	keyAlgorithm, ok := key.Algorithm()
	if !ok {
		return errors.New("signing key does not contain an algorithm")
	}

	alg, ok := keyAlgorithm.(jwa.SignatureAlgorithm)
	if !ok {
		return errors.New("signing key algorithm is not a signature algorithm")
	}

	kty, crv, ok := keyTypeForAlgorithm(alg.String())
	if !ok {
		return fmt.Errorf("signing key algorithm '%s' is not supported: supported algorithms: RS256, ES256, ES384, ES512, EdDSA", alg.String())
	}

	if key.KeyType().String() != kty {
		return fmt.Errorf("signing key has type '%s', which can't be used with algorithm '%s'", key.KeyType().String(), alg.String())
	}
	if crv != "" && keyCurve(key) != crv {
		return fmt.Errorf("signing key has curve '%s', which can't be used with algorithm '%s'", keyCurve(key), alg.String())
	}

	asymmetricKey, ok := key.(jwk.AsymmetricKey)
	if !ok {
		return errors.New("signing key must be asymmetric")
	} else if !asymmetricKey.IsPrivate() {
		return errors.New("signing key must be private")
	}

	kid, _ := key.KeyID()
	if kid == "" {
		return errors.New("signing key does not contain a key ID ('kid')")
	}
	if !utils.IsPrintableASCII(kid) {
		return errors.New("signing key ID ('kid') must contain only printable ASCII characters")
	}

	use, ok := key.KeyUsage()
	if ok && use != string(jwk.ForSignature) {
		return fmt.Errorf("signing key has usage ('use') '%s', but it must be 'sig'", use)
	}

	return nil
}

// KeyAlgorithm returns the key's algorithm name, or an empty string if unset
func KeyAlgorithm(key jwk.Key) string {
	alg, ok := key.Algorithm()
	if !ok {
		return ""
	}
	return alg.String()
}

// Returns the expected key type and curve for a signing algorithm
func keyTypeForAlgorithm(alg string) (kty string, crv string, ok bool) {
	switch alg {
	case "RS256":
		return jwa.RSA().String(), "", true
	case "ES256":
		return jwa.EC().String(), jwa.P256().String(), true
	case "ES384":
		return jwa.EC().String(), jwa.P384().String(), true
	case "ES512":
		return jwa.EC().String(), jwa.P521().String(), true
	case "EdDSA":
		return jwa.OKP().String(), jwa.Ed25519().String(), true
	default:
		return "", "", false
	}
}

// Returns the curve of an EC or OKP key, or an empty string for other key types
func keyCurve(key jwk.Key) string {
	curveKey, ok := key.(interface {
		Crv() (jwa.EllipticCurveAlgorithm, bool)
	})
	if !ok {
		return ""
	}

	crv, ok := curveKey.Crv()
	if !ok {
		return ""
	}

	return crv.String()
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
