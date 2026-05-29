package tsnet

import (
	"strings"
	"testing"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/stretchr/testify/assert"
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

			result := IsAudiencePermittedForCaller(&whois, tt.audience, tt.allowWithoutCapability)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchAudienceCapability(t *testing.T) {
	const audience = "https://api.example.com"

	tests := []struct {
		name                   string
		capMap                 tailcfg.PeerCapMap
		allowWithoutCapability bool
		expectMatched          bool
		expectSubject          string
	}{
		{
			name: "Matching grant with subject populates subject",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allowedAudiences":["https://api.example.com"],"subject":"workload-group-a"}`),
				},
			},
			expectMatched: true,
			expectSubject: "workload-group-a",
		},
		{
			name: "Matching grant without subject returns empty subject",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allowedAudiences":["https://api.example.com"]}`),
				},
			},
			expectMatched: true,
			expectSubject: "",
		},
		{
			name: "Only the matching grant's subject is returned, not earlier non-matching grants",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allowedAudiences":["https://other.example.com"],"subject":"other-group"}`),
					tailcfg.RawMessage(`{"allowedAudiences":["https://api.example.com"],"subject":"target-group"}`),
				},
			},
			expectMatched: true,
			expectSubject: "target-group",
		},
		{
			name: "Non-matching grants return zero capability",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					tailcfg.RawMessage(`{"allowedAudiences":["https://other.example.com"],"subject":"other-group"}`),
				},
			},
			expectMatched: false,
			expectSubject: "",
		},
		{
			name:                   "No capability with allowWithoutCapability returns zero capability but matched",
			capMap:                 tailcfg.PeerCapMap{},
			allowWithoutCapability: true,
			expectMatched:          true,
			expectSubject:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whois := tsnetserver.TailscaleWhoIs{
				NodeID: "test-node",
				CapMap: tt.capMap,
			}

			matched, ok := MatchAudienceCapability(&whois, audience, tt.allowWithoutCapability)
			assert.Equal(t, tt.expectMatched, ok)
			assert.Equal(t, tt.expectSubject, matched.Subject)
		})
	}
}
