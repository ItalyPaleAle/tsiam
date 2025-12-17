package tsnetserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/italypaleale/tsiam/pkg/types"
)

// WhoIs performs a "whois" request with the LocalClient and returns information about the node
func (t *TSNetServer) WhoIs(r *http.Request) (res types.TailscaleWhoIs, err error) {
	// Get the remote address from the request
	remoteAddr := r.RemoteAddr
	if remoteAddr == "" {
		return res, errors.New("no remote address HTTP in request")
	}

	// Get the LocalClient to query the WhoIs API
	lc, err := t.server.LocalClient()
	if err != nil {
		return res, fmt.Errorf("failed to get Tailscale local client: %w", err)
	}

	// Query the WhoIs API to get secure node identity
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	whois, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return res, fmt.Errorf("failed to query Tailscale whois: %w", err)
	}

	res = types.TailscaleWhoIs{
		// Node ID: use the "stable" ID, which is a string
		NodeID: string(whois.Node.StableID),

		// For the host name, we use ComputedNameWithHost
		// This is usually the Magic DNS name
		Name: whois.Node.ComputedNameWithHost,

		Tags:          whois.Node.Tags,
		UserLoginName: whois.UserProfile.LoginName,
	}

	// Addresses
	for _, a := range whois.Node.Addresses {
		if !a.IsValid() {
			continue
		}

		addr := a.Addr()
		if addr.Is6() {
			res.IP6 = a.String()
		} else if addr.Is4() {
			res.IP4 = a.String()
		}
	}
	return res, nil
}
