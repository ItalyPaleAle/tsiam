package tsnet

import (
	"strings"
)

// IsSameTailnet returns true if nodeName is in the same tailnet domain as selfName
func IsSameTailnet(nodeName string, selfName string) bool {
	_, selfDomain, ok := strings.Cut(strings.TrimSuffix(selfName, "."), ".")
	if !ok || selfDomain == "" {
		return false
	}

	host, nodeDomain, ok := strings.Cut(strings.TrimSuffix(nodeName, "."), ".")
	return ok && host != "" && strings.EqualFold(nodeDomain, selfDomain)
}
