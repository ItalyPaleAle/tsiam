package tsnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/italypaleale/go-kit/utils"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
)

const (
	// AudienceCapability is the Tailscale ACL capability key for tsiam
	AudienceCapability = peercap.Cap(buildinfo.AppNamespace)
)

// TsiamCapability represents a tsiam capability grant in Tailscale ACLs
type TsiamCapability struct {
	AllowedAudiences []string `json:"allowedAudiences"`
	Subject          string   `json:"subject,omitempty"`
}

const maxSubjectLength = 512

// MatchAudienceCapability checks if the caller's capability grants allow the requested audience
// It returns the distinct subjects from matching grants and whether the audience is permitted
func MatchAudienceCapability(ctx context.Context, whois *tsnetserver.TailscaleWhoIs, audience string, allowWithoutCapability bool) (subjects []string, ok bool) {
	// Check if the caller has the capability
	capValues, ok := whois.CapMap[AudienceCapability]
	if !ok {
		// If allowWithoutCapability is true, allow access to any globally-allowed audience
		return nil, allowWithoutCapability
	}

	// Check all grants that allow the requested audience
	var permitted bool
	for i, capValue := range capValues {
		tsiamCap, err := parseCapability(capValue)
		if err != nil {
			slog.WarnContext(ctx, "Skipping malformed tsiam capability grant",
				slog.String("nodeId", whois.NodeID),
				slog.Int("capIndex", i),
				slog.Any("error", err),
			)
			continue
		}

		// Check if the audience is in the allowedAudiences list
		if !slices.Contains(tsiamCap.AllowedAudiences, audience) {
			continue
		}

		permitted = true
		if tsiamCap.Subject != "" && !slices.Contains(subjects, tsiamCap.Subject) {
			subjects = append(subjects, tsiamCap.Subject)
		}
	}

	slices.Sort(subjects)
	return subjects, permitted
}

// Parses and validates a single tsiam capability grant
func parseCapability(capValue tailcfg.RawMessage) (TsiamCapability, error) {
	var tsiamCap TsiamCapability

	data := bytes.TrimSpace([]byte(capValue))
	if len(data) == 0 || data[0] != '{' {
		return tsiamCap, errors.New("grant is not a JSON object")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err := dec.Decode(&tsiamCap)
	if err != nil {
		return tsiamCap, fmt.Errorf("grant is not valid: %w", err)
	}

	// Ensure there is no trailing data after the JSON object
	_, err = dec.Token()
	if !errors.Is(err, io.EOF) {
		return tsiamCap, errors.New("grant contains data after the JSON object")
	}

	tsiamCap.Subject = strings.TrimSpace(tsiamCap.Subject)
	if len(tsiamCap.Subject) > maxSubjectLength {
		return tsiamCap, fmt.Errorf("grant's subject is longer than %d characters", maxSubjectLength)
	}
	if utils.HasControlChars(tsiamCap.Subject) {
		return tsiamCap, errors.New("grant's subject contains control characters")
	}

	return tsiamCap, nil
}

// IsAudiencePermittedForCaller checks if the caller has permission to request this audience
func IsAudiencePermittedForCaller(ctx context.Context, whois *tsnetserver.TailscaleWhoIs, audience string, allowWithoutCapability bool) bool {
	_, ok := MatchAudienceCapability(ctx, whois, audience, allowWithoutCapability)
	return ok
}
