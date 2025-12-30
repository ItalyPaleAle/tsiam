package jwks

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// GetPublicJWKSAsJSON creates a JWKS with the public part of the key, and returns it encoded as JSON
func GetPublicJWKSAsJSON(key jwk.Key) ([]byte, error) {
	set := jwk.NewSet()

	// Ensure the key is a public key
	publicKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	err = set.AddKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to add key to JWKS set: %w", err)
	}

	enc, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("failed to encode JWKS to JSON: %w", err)
	}

	return enc, nil
}
