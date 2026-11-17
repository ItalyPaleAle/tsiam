package tsnet

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestIsAudiencePermittedForCaller(t *testing.T) {
	// Helper to create RawMessage from capability object
	makeCapabilityMsg := func(audiences ...string) tailcfg.RawMessage {
		if len(audiences) == 0 {
			return tailcfg.RawMessage(`{"allowedAudiences":[]}`)
		}
		// Build JSON array of audiences
		var audiencesJSON strings.Builder
		audiencesJSON.WriteString(`[`)
		for i, aud := range audiences {
			if i > 0 {
				audiencesJSON.WriteRune(',')
			}
			audiencesJSON.WriteString(`"` + aud + `"`)
		}
		audiencesJSON.WriteString(`]`)
		return tailcfg.RawMessage(`{"allowedAudiences":` + audiencesJSON.String() + `}`)
	}

	tests := []struct {
		name                   string
		audience               string
		capMap                 tailcfg.PeerCapMap
		allowWithoutCapability bool
		expected               bool
	}{
		{
			name:     "Caller has capability with matching audience",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					makeCapabilityMsg("https://api.example.com", "https://other.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               true,
		},
		{
			name:     "Caller has capability but audience not in list",
			audience: "https://notallowed.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					makeCapabilityMsg("https://api.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:                   "Caller has no capability and allowWithoutCapability is true",
			audience:               "https://api.example.com",
			capMap:                 tailcfg.PeerCapMap{},
			allowWithoutCapability: true,
			expected:               true,
		},
		{
			name:                   "Caller has no capability and allowWithoutCapability is false",
			audience:               "https://api.example.com",
			capMap:                 tailcfg.PeerCapMap{},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:     "Caller has different capability",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				"other/capability": []tailcfg.RawMessage{
					makeCapabilityMsg("https://api.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:     "Capability has malformed JSON (should be ignored)",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					"not valid json",
					makeCapabilityMsg("https://api.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               true,
		},
		{
			name:     "Capability has only malformed values",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					"123",
					"true",
					`{"wrongField": ["https://api.example.com"]}`,
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			// Typo in field name should be rejected by DisallowUnknownFields rather than silently producing an empty allowedAudiences list
			name:     "Capability with typo in field name is rejected, not silently empty",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					`{"allowedAudience":["https://api.example.com"]}`,
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:     "Multiple audiences in capability",
			audience: "https://service2.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					makeCapabilityMsg("https://service1.example.com", "https://service2.example.com", "https://service3.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               true,
		},
		{
			name:     "Case sensitive capability check",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					makeCapabilityMsg("https://API.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:     "Empty allowedAudiences array",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					makeCapabilityMsg(),
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:     "Multiple capability values with audience in second one",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					makeCapabilityMsg("https://other.example.com"),
					makeCapabilityMsg("https://api.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whois := tsnetserver.TailscaleWhoIs{
				NodeID: "test-node",
				CapMap: tt.capMap,
			}

			result := IsAudiencePermittedForCaller(t.Context(), &whois, tt.audience, tt.allowWithoutCapability)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchAudienceCapability(t *testing.T) {
	const audience = "https://api.example.com"

	grants := func(values ...string) tailcfg.PeerCapMap {
		msgs := make([]tailcfg.RawMessage, len(values))
		for i, v := range values {
			msgs[i] = tailcfg.RawMessage(v)
		}
		return tailcfg.PeerCapMap{AudienceCapability: msgs}
	}

	tests := []struct {
		name                   string
		capMap                 tailcfg.PeerCapMap
		allowWithoutCapability bool
		expectMatched          bool
		expectSubjects         []string
	}{
		{
			name:           "Matching grant with subject populates subject",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"workload-group-a"}`),
			expectMatched:  true,
			expectSubjects: []string{"workload-group-a"},
		},
		{
			name:           "Matching grant without subject returns no subjects",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"]}`),
			expectMatched:  true,
			expectSubjects: nil,
		},
		{
			name: "Only matching grants add their subject, not earlier non-matching grants",
			capMap: grants(
				`{"allowedAudiences":["https://other.example.com"],"subject":"other-group"}`,
				`{"allowedAudiences":["https://api.example.com"],"subject":"target-group"}`,
			),
			expectMatched:  true,
			expectSubjects: []string{"target-group"},
		},
		{
			name: "Grant with subject wins over grant without, in either order",
			capMap: grants(
				`{"allowedAudiences":["https://api.example.com"]}`,
				`{"allowedAudiences":["https://api.example.com"],"subject":"worker-fleet"}`,
				`{"allowedAudiences":["https://api.example.com"]}`,
			),
			expectMatched:  true,
			expectSubjects: []string{"worker-fleet"},
		},
		{
			name: "Grants with the same subject return it once",
			capMap: grants(
				`{"allowedAudiences":["https://api.example.com"],"subject":"worker-fleet"}`,
				`{"allowedAudiences":["https://api.example.com","https://other.example.com"],"subject":" worker-fleet "}`,
			),
			expectMatched:  true,
			expectSubjects: []string{"worker-fleet"},
		},
		{
			name: "Grants with different subjects return all of them, sorted",
			capMap: grants(
				`{"allowedAudiences":["https://api.example.com"],"subject":"group-b"}`,
				`{"allowedAudiences":["https://api.example.com"],"subject":"group-a"}`,
			),
			expectMatched:  true,
			expectSubjects: []string{"group-a", "group-b"},
		},
		{
			name:           "Whitespace-only subject counts as no subject",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"   "}`),
			expectMatched:  true,
			expectSubjects: nil,
		},
		{
			name:           "Subject is trimmed",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"  group-a\t"}`),
			expectMatched:  true,
			expectSubjects: []string{"group-a"},
		},
		{
			name:           "Grant with control characters in the subject is skipped",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"group-a\nfake log line"}`),
			expectMatched:  false,
			expectSubjects: nil,
		},
		{
			name:           "Grant with a BiDi override in the subject is skipped",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"group-\u202ea"}`),
			expectMatched:  false,
			expectSubjects: nil,
		},
		{
			name:           "Grant with a subject longer than 512 characters is skipped",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"` + strings.Repeat("a", 513) + `"}`),
			expectMatched:  false,
			expectSubjects: nil,
		},
		{
			name:           "Grant with a subject of 512 characters is accepted",
			capMap:         grants(`{"allowedAudiences":["https://api.example.com"],"subject":"` + strings.Repeat("a", 512) + `"}`),
			expectMatched:  true,
			expectSubjects: []string{strings.Repeat("a", 512)},
		},
		{
			name: "Malformed grant is skipped and the next grant still matches",
			capMap: grants(
				`{"allowedAudiences":["https://api.example.com"],"subject":"group-a"} {"subject":"group-b"}`,
				`{"allowedAudiences":["https://api.example.com"],"subject":"group-c"}`,
			),
			expectMatched:  true,
			expectSubjects: []string{"group-c"},
		},
		{
			name:           "Non-matching grants return no subjects",
			capMap:         grants(`{"allowedAudiences":["https://other.example.com"],"subject":"other-group"}`),
			expectMatched:  false,
			expectSubjects: nil,
		},
		{
			name:                   "No capability with allowWithoutCapability returns no subjects but matched",
			capMap:                 tailcfg.PeerCapMap{},
			allowWithoutCapability: true,
			expectMatched:          true,
			expectSubjects:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whois := tsnetserver.TailscaleWhoIs{
				NodeID: "test-node",
				CapMap: tt.capMap,
			}

			subjects, ok := MatchAudienceCapability(t.Context(), &whois, audience, tt.allowWithoutCapability)
			assert.Equal(t, tt.expectMatched, ok)
			assert.Equal(t, tt.expectSubjects, subjects)
		})
	}
}

func TestParseCapability(t *testing.T) {
	t.Run("valid grant", func(t *testing.T) {
		tsiamCap, err := parseCapability(tailcfg.RawMessage(` {"allowedAudiences":["https://api.example.com"],"subject":"group-a"} `))
		require.NoError(t, err)
		assert.Equal(t, []string{"https://api.example.com"}, tsiamCap.AllowedAudiences)
		assert.Equal(t, "group-a", tsiamCap.Subject)
	})

	for name, raw := range map[string]string{
		"null":            `null`,
		"empty":           ``,
		"whitespace":      `  `,
		"number":          `123`,
		"string":          `"https://api.example.com"`,
		"array":           `[{"allowedAudiences":["https://api.example.com"]}]`,
		"invalid JSON":    `not valid json`,
		"unknown field":   `{"allowedAudience":["https://api.example.com"]}`,
		"trailing object": `{"allowedAudiences":["https://api.example.com"]}{}`,
		"trailing value":  `{"allowedAudiences":["https://api.example.com"]} 1`,
		"trailing brace":  `{"allowedAudiences":["https://api.example.com"]}}`,
		"truncated":       `{"allowedAudiences":["https://api.example.com"]`,
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := parseCapability(tailcfg.RawMessage(raw))
			require.Error(t, err)
		})
	}
}

// MatchAudienceCapability consumes attacker-influenced JSON straight out of Tailscale ACL grants
// The fuzzer verifies that no malformed input can panic the parser or trick it into approving an audience it shouldn't
func FuzzMatchAudienceCapability(f *testing.F) {
	// Seed with known-good and known-malformed shapes
	f.Add([]byte(`{"allowedAudiences":["https://api.example.com"]}`))
	f.Add([]byte(`{"allowedAudiences":["https://api.example.com"],"subject":"group-a"}`))
	f.Add([]byte(`{"allowedAudiences":["https://api.example.com"],"subject":"  "}`))
	f.Add([]byte(`{"allowedAudiences":["https://api.example.com"]} {"subject":"group-a"}`))
	f.Add([]byte(`{"allowedAudiences":[]}`))
	f.Add([]byte(`{"allowedAudience":["https://api.example.com"]}`)) // typo - unknown field
	f.Add([]byte(`not valid json`))
	f.Add([]byte(`null`))
	f.Add([]byte(`123`))
	f.Add([]byte(``))

	const targetAudience = "https://api.example.com"

	f.Fuzz(func(t *testing.T, raw []byte) {
		whois := &tsnetserver.TailscaleWhoIs{
			NodeID: "fuzz-node",
			CapMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{tailcfg.RawMessage(raw)},
			},
		}

		// Must never panic, regardless of input
		subjects, ok := MatchAudienceCapability(t.Context(), whois, targetAudience, false)

		// If we matched, the input MUST decode to a TsiamCapability containing the target audience
		// This catches a regression where DisallowUnknownFields is removed and a typo'd field silently passes, or where trailing data after the object is ignored
		if ok {
			var decoded TsiamCapability
			err := json.Unmarshal(raw, &decoded)
			if err != nil {
				t.Fatalf("matched %q but unmarshal failed: %v", raw, err)
			}
			if !slices.Contains(decoded.AllowedAudiences, targetAudience) {
				t.Fatalf("matched %q but allowedAudiences %v does not contain %q", raw, decoded.AllowedAudiences, targetAudience)
			}

			// And the returned subject must be the one in the grant, trimmed
			var expectSubjects []string
			subject := strings.TrimSpace(decoded.Subject)
			if subject != "" {
				expectSubjects = []string{subject}
			}
			if !slices.Equal(subjects, expectSubjects) {
				t.Fatalf("subjects=%q but decoded.Subject=%q for input %q", subjects, decoded.Subject, raw)
			}
		}
	})
}
