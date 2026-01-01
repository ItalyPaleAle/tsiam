package config

import (
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"time"
)

// Config represents the application configuration
type Config struct {
	// TSNet configuration
	TSNet ConfigTSNet `yaml:"tsnet"`

	// Logs contains configuration for logging
	Logs ConfigLogs `yaml:"logs"`

	// Tokens contains configuration for tokens
	Tokens ConfigTokens `yaml:"tokens"`

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

// ConfigTokens holds tokens configuration
type ConfigTokens struct {
	// Token life time, as a Go duration
	// Must be between 1 and 60 minutes
	// +default "5m"
	Lifetime time.Duration `yaml:"lifetime"`

	// Allowed audiences (aud claim values) for JWT tokens
	// Only audiences listed here can be requested by clients
	//
	// Examples:
	// - AWS: `sts.amazonaws.com` (for OIDC federation with AWS IAM)
	// - Microsoft Entra ID (Azure AD): `api://AzureADTokenExchange` (for Workload Identity Federation)
	// - Google Cloud: Your workload identity pool audience (e.g., `//iam.googleapis.com/projects/PROJECT_ID/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID`)
	// - Custom APIs: Use your API's identifier (e.g., `https://api.example.com`)
	// +required
	AllowedAudiences []string `yaml:"allowedAudiences"`

	// If true, allows nodes without the audience capability to request any globally-allowed audience
	// If false (default), all nodes must have the capability explicitly granted
	// +default false
	AllowEmptyNodeCapability bool `yaml:"allowEmptyNodeCapability"`
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

	// If true, enables Tailscale Funnel to expose the .well-known endpoints publicly.
	// This allows external OIDC clients to discover the JWKS without being on the tailnet.
	// Note: see requirements for enabling Tailscale Funnel: https://tailscale.com/kb/1223/funnel
	// +default false
	Funnel bool `yaml:"funnel"`
}

// ConfigSigningKey holds JWT signing key configuration
type ConfigSigningKey struct {
	// Key storage provider
	// Allowed values: "file" (default), "memory", "AzureKeyVaultKeys", "AzureKeyVaultSecrets"
	// +default "file"
	Storage string `yaml:"storage"`

	// Signing algorithm to use. Supported values: RS256, ES256, ES384, ES512, EdDSA.
	// +default "ES256"
	Algorithm string `yaml:"algorithm"`

	// Curve for EdDSA algorithm.
	// Currently only Ed25519 is supported.
	Curve string `yaml:"curve"`

	// Options for the "file" key storage
	File *ConfigStorageFile `yaml:"file,omitempty"`

	// Options for the "AzureKeyVaultKeys" key storage
	AzureKeyVaultKeys *ConfigStorageAzureKeyVaultKeys `yaml:"azureKeyVaultKeys,omitempty"`

	// Options for the "AzureKeyVaultSecrets" key storage
	AzureKeyVaultSecrets *ConfigStorageAzureKeyVaultSecrets `yaml:"azureKeyVaultSecrets,omitempty"`
}

// ConfigStorageFile holds configuration for the Azure Key Vault Keys ("AzureKeyVaultKeys") storage
type ConfigStorageFile struct {
	// StoragePath is the path to store signing key on disk.
	// The key is not encrypted on disk.
	// +required
	StoragePath string `yaml:"storagePath,omitempty"`
}

// ConfigStorageAzureKeyVaultKeys holds configuration for the Azure Key Vault Keys ("AzureKeyVaultKeys") storage
type ConfigStorageAzureKeyVaultKeys struct {
	// VaultURL is the URL of the Azure Key Vault (e.g., https://myvault.vault.azure.net/).
	// +required
	VaultURL string `yaml:"vaultUrl"`

	// KeyName is the name of the key in Azure Key Vault used for wrapping/unwrapping.
	// The key is unwrapped using Azure Key Vault on app startup.
	// +required
	KeyName string `yaml:"keyName,omitempty"`

	// StoragePath is the path to store the wrapped signing key on disk.
	// +required
	StoragePath string `yaml:"storagePath,omitempty"`

	// TenantID is the Azure AD tenant ID for authentication.
	// If empty, DefaultAzureCredential will be used (which can leverage authentication methods including: environmental variables, managed identity, workload identity).
	TenantID string `yaml:"tenantId,omitempty"`

	// ClientID is the Azure AD application (client) ID for authentication.
	// If empty, DefaultAzureCredential will be used (which can leverage authentication methods including: environmental variables, managed identity, workload identity).
	ClientID string `yaml:"clientId,omitempty"`

	// ClientSecret is the Azure AD application client secret for authentication.
	// If empty, DefaultAzureCredential will be used (which can leverage authentication methods including: environmental variables, managed identity, workload identity).
	ClientSecret string `yaml:"clientSecret,omitempty"`
}

// ConfigAzureKeyVault holds configuration for the Azure Key Vault Secrets ("AzureKeyVaultSecrets") storage
type ConfigStorageAzureKeyVaultSecrets struct {
	// VaultURL is the URL of the Azure Key Vault (e.g., https://myvault.vault.azure.net/).
	// +required
	VaultURL string `yaml:"vaultUrl"`

	// SecretName is the name of the secret in Azure Key Vault that stores the signing key.
	// The entire key is stored in Azure Key Vault.
	// +required
	SecretName string `yaml:"secretName,omitempty"`

	// TenantID is the Azure AD tenant ID for authentication.
	// If empty, DefaultAzureCredential will be used (which can leverage authentication methods including: environmental variables, managed identity, workload identity).
	TenantID string `yaml:"tenantId,omitempty"`

	// ClientID is the Azure AD application (client) ID for authentication.
	// If empty, DefaultAzureCredential will be used (which can leverage authentication methods including: environmental variables, managed identity, workload identity).
	ClientID string `yaml:"clientId,omitempty"`

	// ClientSecret is the Azure AD application client secret for authentication.
	// If empty, DefaultAzureCredential will be used (which can leverage authentication methods including: environmental variables, managed identity, workload identity).
	ClientSecret string `yaml:"clientSecret,omitempty"`
}

// ConfigDev includes options using during development only
type ConfigDev struct{}

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
	// Token configuration
	c.Tokens.Lifetime = c.Tokens.Lifetime.Truncate(time.Second)
	if c.Tokens.Lifetime < time.Minute {
		return errors.New("configuration open 'tokens.lifetime' must be at least 1 minute")
	}
	if c.Tokens.Lifetime > 60*time.Minute {
		return errors.New("configuration open 'tokens.lifetime' must not be more than 60 minutes")
	}

	// Audience configuration
	if len(c.Tokens.AllowedAudiences) == 0 {
		return errors.New("configuration option 'tokens.allowedAudiences' must contain at least one audience")
	}
	// Normalize and validate each audience
	for i, aud := range c.Tokens.AllowedAudiences {
		trimmed := strings.TrimSpace(aud)
		if trimmed == "" {
			return errors.New("configuration option 'tokens.allowedAudiences' contains an empty audience")
		}
		if len(trimmed) > 512 {
			return errors.New("configuration option 'tokens.allowedAudiences' contains an audience exceeding 512 characters")
		}
		c.Tokens.AllowedAudiences[i] = trimmed
	}

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

	// Keys storage
	c.SigningKey.Storage = strings.ToLower(c.SigningKey.Storage)
	switch c.SigningKey.Storage {
	// File storage (default when value is empty)
	case "file", "":
		c.SigningKey.Storage = "file"
		if c.SigningKey.File == nil {
			return errors.New("configuration option 'signingKey.file' must be set when 'signingKey.storage' is 'file'")
		}
		if c.SigningKey.File.StoragePath == "" {
			return errors.New("configuration option 'signingKey.file.storagePath' must be set when 'signingKey.storage' is 'file'")
		}

	// Memory storage is primarily meant for testing, show a warning
	case "memory":
		slog.Warn("Using ephemeral signing key (will not persist across restarts)")

	// Azure Key Vault Keys
	case "azurekeyvaultkeys":
		if c.SigningKey.AzureKeyVaultKeys == nil {
			return errors.New("configuration option 'signingKey.azureKeyVaultKeys' must be set when 'signingKey.storage' is 'AzureKeyVaultKeys'")
		}
		if c.SigningKey.AzureKeyVaultKeys.VaultURL == "" {
			return errors.New("configuration option 'signingKey.azureKeyVaultKeys.vaultURL' must be set when 'signingKey.storage' is 'AzureKeyVaultKeys'")
		}
		if c.SigningKey.AzureKeyVaultKeys.KeyName == "" {
			return errors.New("configuration option 'signingKey.azureKeyVaultKeys.keyName' must be set when 'signingKey.storage' is 'AzureKeyVaultKeys'")
		}
		if c.SigningKey.AzureKeyVaultKeys.StoragePath == "" {
			return errors.New("configuration option 'signingKey.azureKeyVaultKeys.storagePath' must be set when 'signingKey.storage' is 'AzureKeyVaultKeys'")
		}

	// Azure Key Vault Secrets
	case "azurekeyvaultsecrets":
		if c.SigningKey.AzureKeyVaultSecrets == nil {
			return errors.New("configuration option 'signingKey.azureKeyVaultSecrets' must be set when 'signingKey.storage' is 'AzureKeyVaultSecrets'")
		}
		if c.SigningKey.AzureKeyVaultSecrets.VaultURL == "" {
			return errors.New("configuration option 'signingKey.azureKeyVaultSecrets.vaultURL' must be set when 'signingKey.storage' is 'AzureKeyVaultSecrets'")
		}
		if c.SigningKey.AzureKeyVaultSecrets.SecretName == "" {
			return errors.New("configuration option 'signingKey.azureKeyVaultSecrets.secretName' must be set when 'signingKey.storage' is 'AzureKeyVaultSecrets'")
		}

	default:
		return errors.New("invalid value for 'signingKey.storage'")
	}

	return nil
}

func (c *Config) GetTSNetStateDir() string {
	stateDir := c.TSNet.StateDir
	if stateDir == "" {
		loaded := c.GetLoadedConfigPath()
		if loaded != "" {
			stateDir = filepath.Join(filepath.Dir(loaded), "tsnet")
		}
	}

	return stateDir
}
