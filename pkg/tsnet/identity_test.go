package tsnet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSameTailnet(t *testing.T) {
	const self = "tsiam.example-tailnet.ts.net"

	tests := []struct {
		name     string
		nodeName string
		selfName string
		expected bool
	}{
		{name: "same tailnet", nodeName: "alice.example-tailnet.ts.net", selfName: self, expected: true},
		{name: "trailing dots", nodeName: "alice.example-tailnet.ts.net.", selfName: self + ".", expected: true},
		{name: "case insensitive", nodeName: "alice.Example-Tailnet.ts.net", selfName: self, expected: true},
		{name: "other tailnet", nodeName: "alice.other-tailnet.ts.net", selfName: self, expected: false},
		{name: "other tailnet ending with this tailnet's domain", nodeName: "alice.evil.example-tailnet.ts.net", selfName: self, expected: false},
		{name: "bare hostname", nodeName: "alice", selfName: self, expected: false},
		{name: "empty host label", nodeName: ".example-tailnet.ts.net", selfName: self, expected: false},
		{name: "empty node name", nodeName: "", selfName: self, expected: false},
		{name: "empty self name", nodeName: "alice.example-tailnet.ts.net", selfName: "", expected: false},
		{name: "self name without domain", nodeName: "alice.example-tailnet.ts.net", selfName: "tsiam", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsSameTailnet(tt.nodeName, tt.selfName))
		})
	}
}
