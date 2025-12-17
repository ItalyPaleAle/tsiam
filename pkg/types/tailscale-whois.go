package types

type TailscaleWhoIs struct {
	NodeID        string   `json:"nodeId"`
	Name          string   `json:"name"`
	IP4           string   `json:"ip4"`
	IP6           string   `json:"ip6"`
	Tags          []string `json:"tags,omitempty"`
	UserLoginName string   `json:"userLoginName"`
}
