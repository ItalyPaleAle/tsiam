package types

import (
	"encoding/json"

	"tailscale.com/tailcfg"
)

const (
	// AudienceCapability is the Tailscale ACL capability name used for per-caller audience authorization
	// Callers must have this capability with their allowed audiences in Tailscale ACL grants
	AudienceCapability = tailcfg.PeerCapability("https://italypaleale.me/tsiam")
)

type TailscaleWhoIs struct {
	NodeID        string             `json:"nodeId"`
	Name          string             `json:"name"`
	IP4           string             `json:"ip4"`
	IP6           string             `json:"ip6"`
	UserLoginName string             `json:"userLoginName"`
	Tags          []string           `json:"tags,omitempty"`
	CapMap        tailcfg.PeerCapMap `json:"capMap,omitempty"`
}

// IsAudiencePermittedForCaller checks if the caller has permission to request this audience
func (w *TailscaleWhoIs) IsAudiencePermittedForCaller(audience string, allowWithoutCapability bool) bool {
	// Check if the caller has the capability
	capValues, ok := w.CapMap[AudienceCapability]
	if !ok {
		// If allowWithoutCapability is true, allow access to any globally-allowed audience
		return allowWithoutCapability
	}

	// Caller has the capability, check if the audience is in their allowed list
	for _, capValue := range capValues {
		// capValue is a RawMessage (JSON-encoded string)
		// Try to unmarshal it as a string
		var audStr string
		err := json.Unmarshal([]byte(capValue), &audStr)
		if err == nil && audStr == audience {
			return true
		}
	}

	return false
}
