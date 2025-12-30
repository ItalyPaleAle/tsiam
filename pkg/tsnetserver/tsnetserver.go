package tsnetserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/italypaleale/tsiam/pkg/config"
)

// TSNetServer wraps a tsnet.Server for use in the application
type TSNetServer struct {
	server   *tsnet.Server
	hostname string
	ip4      string
	ip6      string
}

// NewTSNetServer creates a new TSNetServer instance
func NewTSNetServer(ctx context.Context) (*TSNetServer, error) {
	cfg := config.Get()

	stateDir := cfg.TSNet.StateDir
	if stateDir == "" {
		loaded := cfg.GetLoadedConfigPath()
		if loaded != "" {
			stateDir = filepath.Join(filepath.Dir(loaded), "tsnet")
		}
	}

	tsLogger := slog.With("scope", "tsnet")
	tsrv := &tsnet.Server{
		Hostname:  cfg.TSNet.Hostname,
		AuthKey:   cfg.TSNet.AuthKey,
		Dir:       stateDir,
		Ephemeral: cfg.TSNet.Ephemeral,
		Logf: func(format string, args ...any) {
			tsLogger.Debug(fmt.Sprintf(format, args...))
		},
	}

	// Bring up the Tailscale node, this will also give us the IP
	state, err := tsrv.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to bring up Tailscale node: %w", err)
	}

	t := &TSNetServer{
		hostname: strings.TrimSuffix(state.Self.DNSName, "."),
		server:   tsrv,
	}

	for _, addr := range state.TailscaleIPs {
		if !addr.IsValid() {
			continue
		}
		if addr.Is6() {
			t.ip6 = addr.String()
		} else if addr.Is4() {
			t.ip4 = addr.String()
		}
	}

	return t, nil
}

func (t *TSNetServer) Hostname() string {
	return t.hostname
}

func (t *TSNetServer) TailscaleIPs() (ip4 string, ip6 string) {
	return t.ip4, t.ip6
}

func (t *TSNetServer) LocalClient() (*local.Client, error) {
	lc, err := t.server.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tailscale local client: %w", err)
	}

	return lc, nil
}

func (t *TSNetServer) Listen(port int) (net.Listener, error) {
	ln, err := t.server.ListenTLS("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		_ = t.server.Close()
		return nil, fmt.Errorf("failed to create tsnet listener: %w", err)
	}

	return ln, nil
}

func (t *TSNetServer) ListenFunnel(port int) (net.Listener, error) {
	ln, err := t.server.ListenFunnel("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("failed to create tsnet funnel listener: %w", err)
	}

	return ln, nil
}

// Close closes the tsnet server
func (t *TSNetServer) Close(_ context.Context) error {
	err := t.server.Close()
	if err != nil {
		return fmt.Errorf("failed to close tsnet server: %w", err)
	}
	return nil
}
