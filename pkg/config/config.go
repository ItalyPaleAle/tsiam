package config

import (
	"encoding/json"
	"errors"
	"log/slog"
)

// Config represents the application configuration
type Config struct {
	// TSNet configuration
	TSNet ConfigTSNet `yaml:"tsnet"`

	// Logs contains configuration for logging
	Logs ConfigLogs `yaml:"logs"`

	// SigningKey contains configuration for JWT signing keys
	SigningKey ConfigSigningKey `yaml:"signingKey"`

	// Dev is meant for development only; it's undocumented
	Dev ConfigDev `yaml:"-"`

	// Internal keys
	internal internal `yaml:"-"`
}

// ConfigLogs represents logging configuration
type ConfigLogs struct {
	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default "info"
	Level string `yaml:"level"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default true
	OmitHealthChecks bool `yaml:"omitHealthChecks"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// Defaults to false if a TTY is attached (e.g. when running the binary directly in the terminal or in development); true otherwise.
	JSON bool `yaml:"json"`
}

// ConfigTSNet holds tsnet configuration
type ConfigTSNet struct {
	// Hostname to use for the tsnet node.
	// +default "tsiam"
	Hostname string `yaml:"hostname"`

	// AuthKey can be used to authenticate the tsnet node automatically.
	// If empty, tsnet will rely on existing state in the database.
	AuthKey string `yaml:"authKey"`

	// Directory where tsnet stores its state.
	// If empty, defaults to a folder next to the loaded config file.
	StateDir string `yaml:"stateDir"`

	// If true, the tsnet node is ephemeral (not persisted in the tailnet).
	// +default false
	Ephemeral bool `yaml:"ephemeral"`
}

// ConfigSigningKey holds JWT signing key configuration
type ConfigSigningKey struct {
	// Signing algorithm to use. Supported values: RS256, ES256, ES384, ES512, EdDSA.
	// +default "ES256"
	Algorithm string `yaml:"algorithm"`

	// Curve for EdDSA algorithm.
	// Currently only Ed25519 is supported.
	Curve string `yaml:"curve"`

	// Path to store signing key. If empty, key will be ephemeral (not persisted).
	StoragePath string `yaml:"storagePath"`
}

// ConfigDev includes options using during development only
type ConfigDev struct {
}

// Internal properties
type internal struct {
	instanceID       string
	configFileLoaded string // Path to the config file that was loaded
}

// String implements fmt.Stringer and prints out the config for debugging
func (c *Config) String() string {
	//nolint:errchkjson,musttag
	enc, _ := json.Marshal(c)
	return string(enc)
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c *Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// GetInstanceID returns the instance ID.
func (c *Config) GetInstanceID() string {
	return c.internal.instanceID
}

// Validates the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Signing key algorithm
	switch c.SigningKey.Algorithm {
	case "RS256", "ES256", "ES384", "ES512":
		if c.SigningKey.Curve != "" {
			return errors.New("configuration option 'signingKey.curve' is only supported when 'signingKey.algorithm' is 'EdDSA'")
		}
	case "EdDSA":
		switch c.SigningKey.Curve {
		case "Ed25519":
			// All good
		case "":
			// Set Ed25519 as default
			c.SigningKey.Curve = "Ed25519"
		default:
			return errors.New("configuration option 'signingKey.curve' is not valid; only allowed value is 'Ed25519'")
		}
	default:
		return errors.New("configuration option 'signingKey.algorithm' is not valid; allowed values: 'RS256', 'ES256', 'ES384', 'ES512', 'EdDSA'")
	}
	return nil
}
