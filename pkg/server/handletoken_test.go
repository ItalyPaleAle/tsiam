package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/tsnet"
)

const (
	testHostname   = "tsiam.test-tailnet.ts.net"
	testAudience   = "https://api.example.com"
	testWhoisName  = "alice.test-tailnet.ts.net"
	testWhoisNode  = "nABCDEF123"
	testWhoisLogin = "alice@example.com"
)

// Builds a Server wired with the given whoIs stub, a fresh ES256 signing key, and no appMetrics
// `cfg` is applied to the global config via SetTestConfig; the caller is expected to defer the returned restore func
func newTestServer(t *testing.T, cfg func(*config.Config), whoIs func(*http.Request) (tsnetserver.TailscaleWhoIs, error)) (*Server, func()) {
	t.Helper()

	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)

	publicJwks, err := jwks.GetPublicJWKSAsJSON(signingKey)
	require.NoError(t, err)

	s := &Server{
		whoIs:      whoIs,
		hostname:   func() string { return testHostname },
		signingKey: signingKey,
		publicJwks: publicJwks,
	}

	restore := config.SetTestConfig(func(c *config.Config) {
		c.Tokens.AllowedAudiences = []string{testAudience}
		c.Tokens.Lifetime = 5 * time.Minute
		c.Tokens.SubjectClaim = config.SubjectClaimNodeID
		c.Tokens.AllowEmptyNodeCapability = true
		if cfg != nil {
			cfg(c)
		}
	})

	return s, restore
}

// Builds an authorized whois for a personal (untagged) node with the test audience in its capability
func defaultWhois() tsnetserver.TailscaleWhoIs {
	return tsnetserver.TailscaleWhoIs{
		NodeID:        testWhoisNode,
		Name:          testWhoisName,
		Hostname:      "alice",
		IP4:           "100.64.0.1",
		IP6:           "fd7a:115c:a1e0::1",
		UserLoginName: testWhoisLogin,
		CapMap: tailcfg.PeerCapMap{
			tsnet.AudienceCapability: []tailcfg.RawMessage{
				tailcfg.RawMessage(`{"allowedAudiences":["` + testAudience + `"]}`),
			},
		},
	}
}

// Fires a request through handlePostToken; query is appended verbatim, including the leading `?` if present
func postToken(t *testing.T, s *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token"+query, nil)
	rr := httptest.NewRecorder()
	s.handlePostToken(rr, req)
	return rr
}

func TestHandlePostToken_WhoIsFailure(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		return tsnetserver.TailscaleWhoIs{}, errors.New("whois failed")
	})
	defer restore()

	rr := postToken(t, s, "?resource="+testAudience)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "node_identity")
}

func TestHandlePostToken_MissingAudience(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		return defaultWhois(), nil
	})
	defer restore()

	rr := postToken(t, s, "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing_audience")
}

func TestHandlePostToken_ConflictingAudienceParams(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		return defaultWhois(), nil
	})
	defer restore()

	rr := postToken(t, s, "?resource=https://a.example.com&audience=https://b.example.com")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "audience_conflict")
}

func TestHandlePostToken_AudienceNotInGlobalAllowlist(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		// Caller has a capability for a different audience, but it's not in the global allowlist either way
		whois := defaultWhois()
		whois.CapMap[tsnet.AudienceCapability] = []tailcfg.RawMessage{
			tailcfg.RawMessage(`{"allowedAudiences":["https://other.example.com"]}`),
		}
		return whois, nil
	})
	defer restore()

	rr := postToken(t, s, "?resource=https://other.example.com")

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "audience_not_allowed")
}

func TestHandlePostToken_AudienceNotPermittedByCaller(t *testing.T) {
	// Caller has no capability and the operator did not opt in to allowing capability-less callers
	s, restore := newTestServer(t, func(c *config.Config) {
		c.Tokens.AllowEmptyNodeCapability = false
	}, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		whois := defaultWhois()
		whois.CapMap = nil
		return whois, nil
	})
	defer restore()

	rr := postToken(t, s, "?resource="+testAudience)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "audience_not_permitted")
}

func TestHandlePostToken_Success(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		return defaultWhois(), nil
	})
	defer restore()

	rr := postToken(t, s, "?resource="+testAudience)

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	//nolint:tagliatelle
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   string `json:"expires_in"`
		ExpiresOn   string `json:"expires_on"`
		NotBefore   string `json:"not_before"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "300", resp.ExpiresIn)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.ExpiresOn)
	assert.NotEmpty(t, resp.NotBefore)

	// Decode the token and verify the claims wired through correctly
	parsed, err := jwt.Parse([]byte(resp.AccessToken),
		jwt.WithKey(mustAlg(t, s), s.signingKey),
	)
	require.NoError(t, err)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	assert.Equal(t, testWhoisNode, sub, "sub should default to NodeID")

	iss, ok := parsed.Issuer()
	require.True(t, ok)
	assert.Equal(t, "https://"+testHostname, iss)

	auds, ok := parsed.Audience()
	require.True(t, ok)
	assert.Equal(t, []string{testAudience}, auds)
}

func TestHandlePostToken_SubjectClaimSources(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*config.Config)
		expectSub   string
		capOverride []tailcfg.RawMessage
	}{
		{
			name:      "nodeId default",
			expectSub: testWhoisNode,
		},
		{
			name:      "name",
			configure: func(c *config.Config) { c.Tokens.SubjectClaim = config.SubjectClaimName },
			expectSub: testWhoisName,
		},
		{
			name:      "capability falls back to nodeId when grant has no subject",
			configure: func(c *config.Config) { c.Tokens.SubjectClaim = config.SubjectClaimCapability },
			expectSub: testWhoisNode,
		},
		{
			name:      "capability uses grant subject when set",
			configure: func(c *config.Config) { c.Tokens.SubjectClaim = config.SubjectClaimCapability },
			capOverride: []tailcfg.RawMessage{
				tailcfg.RawMessage(`{"allowedAudiences":["` + testAudience + `"],"subject":"workload-group-a"}`),
			},
			expectSub: "workload-group-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, restore := newTestServer(t, tt.configure, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
				whois := defaultWhois()
				if tt.capOverride != nil {
					whois.CapMap[tsnet.AudienceCapability] = tt.capOverride
				}
				return whois, nil
			})
			defer restore()

			rr := postToken(t, s, "?resource="+testAudience)
			require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

			//nolint:tagliatelle
			var resp struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

			parsed, err := jwt.Parse([]byte(resp.AccessToken),
				jwt.WithKey(mustAlg(t, s), s.signingKey),
			)
			require.NoError(t, err)

			sub, ok := parsed.Subject()
			require.True(t, ok)
			assert.Equal(t, tt.expectSub, sub)
		})
	}
}

func TestHandlePostToken_TaggedNodeBlanksUserLoginInClaim(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		whois := defaultWhois()
		// Tag actor's email; with the sanitizeWhois fix this should be blanked in the issued token
		whois.Tags = []string{"tag:db-backup"}
		whois.UserLoginName = "admin@example.com"
		return whois, nil
	})
	defer restore()

	rr := postToken(t, s, "?resource="+testAudience)
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	//nolint:tagliatelle
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	parsed, err := jwt.Parse([]byte(resp.AccessToken),
		jwt.WithKey(mustAlg(t, s), s.signingKey),
	)
	require.NoError(t, err)

	claim, err := jwt.Get[map[string]any](parsed, "italypaleale.me/tsiam")
	require.NoError(t, err)
	// The TailscaleWhoIs JSON tags use omitempty, so an empty UserLoginName is dropped from the encoded claim rather than emitted as ""
	// Either form (missing key, or empty-string value) is acceptable evidence of the sanitization fix
	v, present := claim["userLoginName"]
	if present {
		assert.Empty(t, v, "tagged-node UserLoginName must be blanked in the tsiam claim")
	}
}

func TestHandlePostToken_ResourceAndAudienceAliases(t *testing.T) {
	// Both query parameter names should be accepted; resource wins when both are set to the same value
	cases := []string{
		"?resource=" + testAudience,
		"?audience=" + testAudience,
		"?resource=" + testAudience + "&audience=" + testAudience,
	}
	for _, q := range cases {
		t.Run(strings.TrimPrefix(q, "?"), func(t *testing.T) {
			s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
				return defaultWhois(), nil
			})
			defer restore()

			rr := postToken(t, s, q)
			assert.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		})
	}
}

// Returns the signing algorithm registered on the test signing key
func mustAlg(t *testing.T, s *Server) jwa.KeyAlgorithm {
	t.Helper()
	alg, ok := s.signingKey.Algorithm()
	require.True(t, ok, "test signing key must have an algorithm set")
	return alg
}
