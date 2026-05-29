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
	// Audiences this grant authorizes the caller to request
	AllowedAudiences []string `json:"allowedAudiences"`
	// Optional value placed in the JWT `sub` claim when the operator enables `tokens.subjectClaim: "capability"`
	// Lets multiple nodes share a single workload identity by setting the same `subject` in their grant
	Subject string `json:"subject,omitempty"`
}

// MatchAudienceCapability finds the capability grant that authorizes the requested audience for this caller
// Returns the matched grant (zero value when none) and whether the caller is authorized to request the audience
// When allowWithoutCapability is true and the caller has no tsiam capability at all, returns (zero, true)
func MatchAudienceCapability(whois *tsnetserver.TailscaleWhoIs, audience string, allowWithoutCapability bool) (TsiamCapability, bool) {
	// Check if the caller has the capability
	capValues, ok := whois.CapMap[AudienceCapability]
	if !ok {
		// If allowWithoutCapability is true, allow access to any globally-allowed audience
		return TsiamCapability{}, allowWithoutCapability
	}

	// Caller has the capability, look for one that lists the requested audience
	var err error
	for _, capValue := range capValues {
		// capValue is a RawMessage (JSON-encoded object)
		// Try to unmarshal it as a TsiamCapability object
		var tsiamCap TsiamCapability
		err = json.Unmarshal([]byte(capValue), &tsiamCap)
		if err != nil {
			continue
		}
		// Check if the audience is in the allowedAudiences list
		if slices.Contains(tsiamCap.AllowedAudiences, audience) {
			return tsiamCap, true
		}
	}

	return TsiamCapability{}, false
}

// IsAudiencePermittedForCaller checks if the caller has permission to request this audience
func IsAudiencePermittedForCaller(whois *tsnetserver.TailscaleWhoIs, audience string, allowWithoutCapability bool) bool {
	_, ok := MatchAudienceCapability(whois, audience, allowWithoutCapability)
	return ok
}
