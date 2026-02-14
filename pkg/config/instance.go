package config

import (
	"time"

	configkit "github.com/italypaleale/go-kit/config"
)

var (
	config *Config

	defaultDevConfig ConfigDev
)

func init() {
	// Set the default config at startup
	config = GetDefaultConfig()

	// Set the instance ID
	// This may panic if there's not enough entropy in the system
	var err error
	config.internal.instanceID, err = configkit.GetInstanceID()
	if err != nil {
		panic("failed to set instance ID: " + err.Error())
	}
}

// Get returns the singleton instance
func Get() *Config {
	return config
}

// GetDefaultConfig returns the default configuration.
func GetDefaultConfig() *Config {
	return &Config{
		Logs: ConfigLogs{
			Level:            "info",
			OmitHealthChecks: true,
		},
		Tokens: ConfigTokens{
			Lifetime: 5 * time.Minute,
		},
		TSNet: ConfigTSNet{
			Hostname:  "tsiam",
			Ephemeral: false,
		},
		SigningKey: ConfigSigningKey{
			Storage:   "file",
			Algorithm: "ES256",
		},
		Dev: defaultDevConfig,
	}
}
