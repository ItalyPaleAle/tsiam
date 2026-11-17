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
	// AudienceCapability is the Tailscale ACL capability name used for per-caller audience authorization
	// Callers must have this capability with their allowed audiences in Tailscale ACL grants
	AudienceCapability = peercap.Cap(buildinfo.AppNamespace)
)

// TsiamCapability represents the structure of the tsiam capability value
type TsiamCapability struct {
	// Audiences this grant authorizes the caller to request
	AllowedAudiences []string `json:"allowedAudiences"`
	// Optional value placed in the JWT `sub` claim when the operator enables `tokens.subjectClaim: "capability"`
	// Lets multiple nodes share a single workload identity by setting the same `subject` in their grant
	// Leading and trailing whitespace is removed; the value can be up to 512 characters long, and it can't contain control characters
	Subject string `json:"subject,omitempty"`
}

// Maximum length of the subject in a capability grant
const maxSubjectLength = 512

// MatchAudienceCapability finds the capability grants that authorize the requested audience for this caller
// Returns the distinct subjects set by those grants, sorted, and whether the caller is authorized to request the audience
// Grants without a subject don't add to the list, so a caller that matches a grant with a subject and one without gets the subject
// More than one subject means the grants disagree, and it's up to the caller to decide whether that matters
// When allowWithoutCapability is true and the caller has no tsiam capability at all, returns (nil, true)
// Malformed grants (anything other than a single JSON object, unknown fields, or an invalid subject) are logged at WARN level keyed by NodeID and skipped, so operator typos surface in the logs instead of silently denying access
func MatchAudienceCapability(ctx context.Context, whois *tsnetserver.TailscaleWhoIs, audience string, allowWithoutCapability bool) (subjects []string, ok bool) {
	// Check if the caller has the capability
	capValues, ok := whois.CapMap[AudienceCapability]
	if !ok {
		// If allowWithoutCapability is true, allow access to any globally-allowed audience
		return nil, allowWithoutCapability
	}

	// Caller has the capability, look at every grant that lists the requested audience
	// The order of the grants isn't meaningful, so all of them are checked instead of stopping at the first match
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

// Parses the value of a tsiam capability grant
// The value must be a single JSON object, and unknown fields are rejected, so typos don't silently produce an empty allowedAudiences list
// The subject is trimmed, so a subject with only whitespace counts as no subject
func parseCapability(capValue tailcfg.RawMessage) (TsiamCapability, error) {
	var tsiamCap TsiamCapability

	// Other JSON values would decode without errors, and "null" would produce an empty grant
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

	// Decode stops after the first JSON value, so make sure that nothing follows it
	_, err = dec.Token()
	if !errors.Is(err, io.EOF) {
		return tsiamCap, errors.New("grant contains data after the JSON object")
	}

	// The subject ends up in the token's `sub` claim and in logs
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
