package tsnet

import (
	"strings"
)

// IsSameTailnet returns true if nodeName is the MagicDNS name of a node in the same tailnet as selfName
// MagicDNS names have the form "<host>.<tailnet domain>", and nodes from other tailnets keep the domain of their own tailnet
// Returns false if either name is malformed, so callers fail closed
func IsSameTailnet(nodeName string, selfName string) bool {
	_, selfDomain, ok := strings.Cut(strings.TrimSuffix(selfName, "."), ".")
	if !ok || selfDomain == "" {
		return false
	}

	host, nodeDomain, ok := strings.Cut(strings.TrimSuffix(nodeName, "."), ".")
	return ok && host != "" && strings.EqualFold(nodeDomain, selfDomain)
}
