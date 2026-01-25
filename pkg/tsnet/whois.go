package tsnet

import (
	"encoding/json"
	"slices"

	"github.com/italypaleale/go-kit/tsnetserver"
	"tailscale.com/tailcfg"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
)

const (
	// AudienceCapability is the Tailscale ACL capability name used for per-caller audience authorization
	// Callers must have this capability with their allowed audiences in Tailscale ACL grants
	AudienceCapability = tailcfg.PeerCapability(buildinfo.AppNamespace)
)

// TsiamCapability represents the structure of the tsiam capability value
type TsiamCapability struct {
	AllowedAudiences []string `json:"allowedAudiences"`
}

// IsAudiencePermittedForCaller checks if the caller has permission to request this audience
func IsAudiencePermittedForCaller(whois *tsnetserver.TailscaleWhoIs, audience string, allowWithoutCapability bool) bool {
	// Check if the caller has the capability
	capValues, ok := whois.CapMap[AudienceCapability]
	if !ok {
		// If allowWithoutCapability is true, allow access to any globally-allowed audience
		return allowWithoutCapability
	}

	// Caller has the capability, check if the audience is in their allowed list
	var err error
	for _, capValue := range capValues {
		// capValue is a RawMessage (JSON-encoded object)
		// Try to unmarshal it as a TsiamCapability object
		var tsiamCap TsiamCapability
		err = json.Unmarshal([]byte(capValue), &tsiamCap)
		if err == nil {
			// Check if the audience is in the allowedAudiences list
			if slices.Contains(tsiamCap.AllowedAudiences, audience) {
				return true
			}
		}
	}

	return false
}
