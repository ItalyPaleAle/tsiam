package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

func TestWhois_IsAudiencePermittedForCaller(t *testing.T) {
	// Helper to create RawMessage from string
	makeRawMsg := func(s string) tailcfg.RawMessage {
		return tailcfg.RawMessage(`"` + s + `"`)
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
					makeRawMsg("https://api.example.com"),
					makeRawMsg("https://other.example.com"),
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
					makeRawMsg("https://api.example.com"),
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
					makeRawMsg("https://api.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
		{
			name:     "Capability has non-string JSON values (should be ignored)",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					"123",
					"true",
					makeRawMsg("https://api.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               true,
		},
		{
			name:     "Capability has only non-string values",
			audience: "https://api.example.com",
			capMap: tailcfg.PeerCapMap{
				AudienceCapability: []tailcfg.RawMessage{
					"123",
					"true",
					`{"key": "value"}`,
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
					makeRawMsg("https://service1.example.com"),
					makeRawMsg("https://service2.example.com"),
					makeRawMsg("https://service3.example.com"),
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
					makeRawMsg("https://API.example.com"),
				},
			},
			allowWithoutCapability: false,
			expected:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whois := TailscaleWhoIs{
				NodeID: "test-node",
				CapMap: tt.capMap,
			}

			result := whois.IsAudiencePermittedForCaller(tt.audience, tt.allowWithoutCapability)
			assert.Equal(t, tt.expected, result)
		})
	}
}
