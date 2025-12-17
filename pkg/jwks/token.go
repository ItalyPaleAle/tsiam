package jwks

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/italypaleale/tsiam/pkg/types"
)

type TokenRequest struct {
	Issuer   string
	Audience string
	Lifetime time.Duration
	Key      jwk.Key
	Subject  types.TailscaleWhoIs
}

// NewToken creates a new signed JWT
func NewToken(opts TokenRequest) (string, error) {
	alg, ok := opts.Key.Algorithm()
	if !ok {
		return "", errors.New("signing key does not contain an algorithm")
	}

	// Create JWT token
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(opts.Issuer).
		Subject(opts.Subject.NodeID).
		Audience([]string{opts.Audience}).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(opts.Lifetime)).
		Claim("tailscale", opts.Subject).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build token: %w", err)
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(alg, opts.Key))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}
