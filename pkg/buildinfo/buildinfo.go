package buildinfo

import (
	"fmt"
	"runtime/debug"

	"github.com/italypaleale/tsiam/pkg/utils"
)

// These variables will be set at build time
var (
	AppName    string = "tsiam"
	AppVersion string = "canary"
	BuildId    string
	CommitHash string
	BuildDate  string
	Production string
)

// Set during initialization
var (
	BuildDescription string = "tsiam"
	Package          string
)

func init() {
	buildinfo, ok := debug.ReadBuildInfo()
	if ok {
		BuildDescription = buildinfo.Main.Path
	}

	if BuildId != "" && BuildDate != "" && CommitHash != "" {
		BuildDescription = fmt.Sprintf("%s, %s (%s)", BuildId, BuildDate, CommitHash)
	} else {
		BuildDescription = "null"
	}

	if !utils.IsTruthy(Production) {
		BuildDescription += " (non-production)"
	}
}
