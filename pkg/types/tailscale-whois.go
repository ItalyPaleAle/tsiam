package types

import (
	"tailscale.com/tailcfg"
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
