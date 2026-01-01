package jwks

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
)

type TokenRequest struct {
	Issuer   string
	Audience string
	Lifetime time.Duration
	Subject  tsnetserver.TailscaleWhoIs
}

type TokenResponse struct {
	Token     string
	JTI       string
	ExpiresIn int64
	ExpiresOn int64
	NotBefore int64
}

// NewToken creates a new signed JWT
func NewToken(key jwk.Key, opts TokenRequest) (TokenResponse, error) {
	alg, ok := key.Algorithm()
	if !ok {
		return TokenResponse{}, errors.New("signing key does not contain an algorithm")
	}

	// Generate jti (JWT ID) using 24 cryptographically random bytes
	jtiBytes := make([]byte, 24)
	_, err := rand.Read(jtiBytes)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to generate jti: %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)

	// Create JWT token
	now := time.Now()
	exp := now.Add(opts.Lifetime)
	b := jwt.NewBuilder().
		JwtID(jti).
		Subject(opts.Subject.Name).
		IssuedAt(now).
		NotBefore(now).
		Expiration(exp).
		Claim(buildinfo.AppNamespace, opts.Subject)
	if opts.Issuer != "" {
		b = b.Issuer(opts.Issuer)
	}
	if opts.Audience != "" {
		b = b.Audience([]string{opts.Audience})
	}

	token, err := b.Build()
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to build token: %w", err)
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(alg, key))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return TokenResponse{
		Token:     string(signed),
		JTI:       jti,
		ExpiresIn: int64(opts.Lifetime.Seconds()),
		ExpiresOn: exp.Unix(),
		NotBefore: now.Unix(),
	}, nil
}
