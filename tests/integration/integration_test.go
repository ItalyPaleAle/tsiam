//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const requestTimeout = 15 * time.Second

var (
	tsiamURL     string
	testAudience string
	httpClient   *http.Client
)

func TestMain(m *testing.M) {
	tsiamURL = os.Getenv("TSIAM_URL")
	if tsiamURL == "" {
		panic("TSIAM_URL environment variable is required")
	}

	testAudience = os.Getenv("TEST_AUDIENCE")
	if testAudience == "" {
		testAudience = "https://test.example.com"
	}

	// Create HTTP client that trusts Tailscale certificates
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	os.Exit(m.Run())
}

// tokenResponse represents the response from POST /token
//
//nolint:tagliatelle
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
	ExpiresOn   string `json:"expires_on"`
	NotBefore   string `json:"not_before"`
}

// apiError represents an error response from the API
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func TestTokenEndpoint(t *testing.T) {
	t.Run("successful token request", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token?audience="+testAudience, nil)
		require.NoError(t, err)
		req.Header.Set("X-Tsiam", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode, "Expected 200 OK")

		var tokenResp tokenResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		// Verify response structure
		assert.NotEmpty(t, tokenResp.AccessToken, "access_token should not be empty")
		assert.Equal(t, "Bearer", tokenResp.TokenType, "token_type should be Bearer")
		assert.NotEmpty(t, tokenResp.ExpiresIn, "expires_in should not be empty")
		assert.NotEmpty(t, tokenResp.ExpiresOn, "expires_on should not be empty")
		assert.NotEmpty(t, tokenResp.NotBefore, "not_before should not be empty")

		// Parse and validate JWT claims
		parsedToken, err := jwt.Parse([]byte(tokenResp.AccessToken), jwt.WithVerify(false))
		require.NoError(t, err)

		// Verify standard claims
		sub, ok := parsedToken.Subject()
		require.True(t, ok, "sub claim should be present")
		assert.NotEmpty(t, sub, "sub claim should not be empty")

		audiences, ok := parsedToken.Audience()
		require.True(t, ok, "aud claim should be present")
		require.Len(t, audiences, 1)
		assert.Equal(t, testAudience, audiences[0], "aud claim should match requested audience")

		jti, ok := parsedToken.JwtID()
		require.True(t, ok, "jti claim should be present")
		assert.NotEmpty(t, jti, "jti claim should not be empty")

		exp, ok := parsedToken.Expiration()
		require.True(t, ok, "exp claim should be present")
		assert.True(t, exp.After(time.Now()), "exp should be in the future")

		iat, ok := parsedToken.IssuedAt()
		require.True(t, ok, "iat claim should be present")
		assert.True(t, iat.Before(time.Now().Add(time.Minute)), "iat should be recent")

		nbf, ok := parsedToken.NotBefore()
		require.True(t, ok, "nbf claim should be present")
		assert.True(t, nbf.Before(time.Now().Add(time.Minute)), "nbf should be recent")

		// Verify custom tsiam claim
		var tsiamClaim map[string]any
		err = parsedToken.Get("italypaleale.me/tsiam", &tsiamClaim)
		require.NoError(t, err, "italypaleale.me/tsiam claim should be present")

		assert.NotEmpty(t, tsiamClaim["nodeId"], "nodeId should be present in tsiam claim")
		assert.NotEmpty(t, tsiamClaim["name"], "name should be present in tsiam claim")
		assert.NotEmpty(t, tsiamClaim["hostname"], "hostname should be present in tsiam claim")
	})

	t.Run("resource parameter works as alias for audience", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token?resource="+testAudience, nil)
		require.NoError(t, err)
		req.Header.Set("X-Tsiam", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode, "Expected 200 OK with resource parameter")
	})
}

func TestTokenSignatureVerification(t *testing.T) {
	// First fetch the JWKS
	ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
	defer cancel()
	jwksReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tsiamURL+"/.well-known/jwks.json", nil)
	require.NoError(t, err)

	jwksResp, err := httpClient.Do(jwksReq)
	require.NoError(t, err)
	defer func() { _ = jwksResp.Body.Close() }()

	require.Equal(t, http.StatusOK, jwksResp.StatusCode)

	jwksBody, err := io.ReadAll(jwksResp.Body)
	require.NoError(t, err)

	keySet, err := jwk.Parse(jwksBody)
	require.NoError(t, err)
	require.Positive(t, keySet.Len(), "JWKS should contain at least one key")

	// Now request a token
	ctx, cancel = context.WithTimeout(t.Context(), requestTimeout)
	defer cancel()
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token?audience="+testAudience, nil)
	require.NoError(t, err)
	tokenReq.Header.Set("X-Tsiam", "1")

	tokenResp, err := httpClient.Do(tokenReq)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenData tokenResponse
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	require.NoError(t, err)

	// Verify the token signature using the JWKS
	parsedToken, err := jwt.Parse([]byte(tokenData.AccessToken), jwt.WithKeySet(keySet))
	require.NoError(t, err, "Token signature should be valid against JWKS")
	assert.NotNil(t, parsedToken)

	// Verify the subject matches the Tailscale node
	sub, ok := parsedToken.Subject()
	require.True(t, ok)
	assert.NotEmpty(t, sub)
}

func TestOIDCEndpoints(t *testing.T) {
	t.Run("healthz endpoint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tsiamURL+"/healthz", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode, "healthz should return 204 No Content")
	})

	t.Run("JWKS endpoint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tsiamURL+"/.well-known/jwks.json", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Verify it's valid JWKS
		keySet, err := jwk.Parse(body)
		require.NoError(t, err)
		assert.Positive(t, keySet.Len(), "JWKS should contain at least one key")
	})

	t.Run("OpenID Configuration endpoint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tsiamURL+"/.well-known/openid-configuration", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

		//nolint:tagliatelle
		var oidcConfig struct {
			Issuer        string `json:"issuer"`
			TokenEndpoint string `json:"token_endpoint"`
			JWKSURI       string `json:"jwks_uri"`
		}
		err = json.NewDecoder(resp.Body).Decode(&oidcConfig)
		require.NoError(t, err)

		assert.NotEmpty(t, oidcConfig.Issuer, "issuer should not be empty")
		assert.NotEmpty(t, oidcConfig.TokenEndpoint, "token_endpoint should not be empty")
		assert.NotEmpty(t, oidcConfig.JWKSURI, "jwks_uri should not be empty")
		assert.Contains(t, oidcConfig.TokenEndpoint, "/token")
		assert.Contains(t, oidcConfig.JWKSURI, "/.well-known/jwks.json")
	})
}

func TestTokenEndpointErrors(t *testing.T) {
	t.Run("missing X-Tsiam header returns 403", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token?audience="+testAudience, nil)
		require.NoError(t, err)
		// Intentionally not setting X-Tsiam header

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		var errResp apiError
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "no_browser", errResp.Error)
	})

	t.Run("missing audience returns 400", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token", nil)
		require.NoError(t, err)
		req.Header.Set("X-Tsiam", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp apiError
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "missing_audience", errResp.Error)
	})

	t.Run("disallowed audience returns 403", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token?audience=https://not-allowed.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("X-Tsiam", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		var errResp apiError
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "audience_not_allowed", errResp.Error)
	})

	t.Run("conflicting resource and audience returns 400", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsiamURL+"/token?resource=https://one.example.com&audience=https://two.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("X-Tsiam", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp apiError
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "audience_conflict", errResp.Error)
	})
}
