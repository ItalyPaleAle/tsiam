package main

import (
	// Enables tsnet workload identity federation (TS_CLIENT_ID + TS_AUDIENCE auth).
	// As of tailscale v1.98, this is gated behind an opt-in import
	_ "tailscale.com/feature/identityfederation"
)
