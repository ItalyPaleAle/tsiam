package config

import (
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Returns a minimal valid Config for tests
func newValidConfig() *Config {
	c := GetDefaultConfig()
	c.Tokens.AllowedAudiences = []string{"https://api.example.com"}
	c.Tokens.Lifetime = 5 * time.Minute
	c.SigningKey.Storage = "memory"
	return c
}

func TestValidateClaimName(t *testing.T) {
	t.Run("defaults to the app namespace", func(t *testing.T) {
		c := newValidConfig()
		err := c.Validate(slog.Default())
		require.NoError(t, err)
		assert.Equal(t, "italypaleale.me/tsiam", c.Tokens.ClaimName)
	})

	t.Run("empty value falls back to the default", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.ClaimName = "  "
		err := c.Validate(slog.Default())
		require.NoError(t, err)
		assert.Equal(t, "italypaleale.me/tsiam", c.Tokens.ClaimName)
	})

	t.Run("custom value is trimmed and kept", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.ClaimName = " tsiam "
		err := c.Validate(slog.Default())
		require.NoError(t, err)
		assert.Equal(t, "tsiam", c.Tokens.ClaimName)
	})

	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		t.Run("rejects registered claim "+name, func(t *testing.T) {
			c := newValidConfig()
			c.Tokens.ClaimName = name
			err := c.Validate(slog.Default())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "tokens.claimName")
		})
	}

	for _, name := range []string{"azp", "nonce", "auth_time", "acr", "amr", "cnf", "act", "may_act", "scope", "client_id"} {
		t.Run("rejects claim interpreted by relying parties "+name, func(t *testing.T) {
			c := newValidConfig()
			c.Tokens.ClaimName = name
			err := c.Validate(slog.Default())
			require.ErrorContains(t, err, "must not be a claim that relying parties interpret")
		})
	}

	t.Run("rejects a value longer than 256 characters", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.ClaimName = strings.Repeat("a", 257)
		err := c.Validate(slog.Default())
		require.ErrorContains(t, err, "must not be longer than 256 characters")
	})

	t.Run("rejects a value with control characters", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.ClaimName = "example.com/\nidentity"
		err := c.Validate(slog.Default())
		require.ErrorContains(t, err, "must not contain control characters")
	})
}

func TestValidateLogs(t *testing.T) {
	for _, level := range []string{"", "debug", "info", "warn", "error", "ERROR"} {
		t.Run("accepts level "+level, func(t *testing.T) {
			c := newValidConfig()
			c.Logs.Level = level
			err := c.Validate(slog.Default())
			require.NoError(t, err)
		})
	}

	t.Run("rejects an invalid level", func(t *testing.T) {
		c := newValidConfig()
		c.Logs.Level = "verbose"
		err := c.Validate(slog.Default())
		require.ErrorContains(t, err, "configuration option 'logs.level' is not valid")
	})
}

func TestValidateTSNet(t *testing.T) {
	t.Run("accepts valid values", func(t *testing.T) {
		c := newValidConfig()
		c.TSNet.Hostname = "tsiam-prod-1"
		c.TSNet.AdvertiseTags = []string{"tag:tsiam", "tag:prod-1"}
		err := c.Validate(slog.Default())
		require.NoError(t, err)
	})

	for _, hostname := range []string{"", "-tsiam", "tsiam.example", "ts iam", strings.Repeat("a", 64)} {
		t.Run("rejects hostname "+hostname, func(t *testing.T) {
			c := newValidConfig()
			c.TSNet.Hostname = hostname
			err := c.Validate(slog.Default())
			require.ErrorContains(t, err, "configuration option 'tsnet.hostname' is not valid")
		})
	}

	for _, tag := range []string{"tsiam", "tag:", "tag:1tsiam", "tag:ts_iam"} {
		t.Run("rejects tag "+tag, func(t *testing.T) {
			c := newValidConfig()
			c.TSNet.AdvertiseTags = []string{"tag:ok", tag}
			err := c.Validate(slog.Default())
			require.ErrorContains(t, err, "configuration option 'tsnet.advertiseTags' contains an invalid tag")
		})
	}
}

func TestValidateAllowedAudiences(t *testing.T) {
	t.Run("entries are trimmed", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.AllowedAudiences = []string{" https://api.example.com ", "sts.amazonaws.com"}
		err := c.Validate(slog.Default())
		require.NoError(t, err)
		assert.Equal(t, []string{"https://api.example.com", "sts.amazonaws.com"}, c.Tokens.AllowedAudiences)
	})

	t.Run("rejects an empty list", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.AllowedAudiences = nil
		err := c.Validate(slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tokens.allowedAudiences")
	})

	t.Run("rejects an empty entry", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.AllowedAudiences = []string{"https://api.example.com", "  "}
		err := c.Validate(slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty audience")
	})

	t.Run("rejects an entry longer than 512 characters", func(t *testing.T) {
		c := newValidConfig()
		c.Tokens.AllowedAudiences = []string{"https://" + strings.Repeat("a", 512)}
		err := c.Validate(slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeding 512 characters")
	})

	for name, aud := range map[string]string{
		"NUL":     "https://api.example.com/\x00",
		"newline": "https://api.example.com/\nfoo",
		"tab":     "https://api\t.example.com",
		"ESC":     "https://api.example.com/\x1b[31m",
		"DEL":     "https://api.example.com/\x7f",
	} {
		t.Run("rejects an entry with "+name, func(t *testing.T) {
			c := newValidConfig()
			c.Tokens.AllowedAudiences = []string{aud}
			err := c.Validate(slog.Default())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "control or non-printable characters")
		})
	}
}

func TestValidateAzureKeyVaultKeysKeyVersion(t *testing.T) {
	newConfig := func(keyVersion string) *Config {
		c := newValidConfig()
		c.SigningKey.Storage = "AzureKeyVaultKeys"
		c.SigningKey.AzureKeyVaultKeys = &ConfigStorageAzureKeyVaultKeys{
			VaultURL:    "https://myvault.vault.azure.net/",
			KeyName:     "tsiam",
			KeyVersion:  keyVersion,
			StoragePath: "/data/signing-key.json",
		}
		return c
	}

	for _, keyVersion := range []string{"", "latest", "Latest"} {
		t.Run("warns when not pinned: '"+keyVersion+"'", func(t *testing.T) {
			var buf strings.Builder
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			c := newConfig(keyVersion)
			err := c.Validate(logger)
			require.NoError(t, err)
			assert.Contains(t, buf.String(), "signingKey.azureKeyVaultKeys.keyVersion")
		})
	}

	t.Run("no warning when pinned", func(t *testing.T) {
		var buf strings.Builder
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		c := newConfig("0123456789abcdef0123456789abcdef")
		err := c.Validate(logger)
		require.NoError(t, err)
		assert.NotContains(t, buf.String(), "keyVersion")
	})
}

func TestValidateAzureKeyVault(t *testing.T) {
	newKeysConfig := func(vaultURL string) *Config {
		c := newValidConfig()
		c.SigningKey.Storage = "AzureKeyVaultKeys"
		c.SigningKey.AzureKeyVaultKeys = &ConfigStorageAzureKeyVaultKeys{
			VaultURL:    vaultURL,
			KeyName:     "tsiam",
			KeyVersion:  "0123456789abcdef0123456789abcdef",
			StoragePath: "/data/signing-key.json",
		}
		return c
	}
	newSecretsConfig := func(vaultURL string) *Config {
		c := newValidConfig()
		c.SigningKey.Storage = "AzureKeyVaultSecrets"
		c.SigningKey.AzureKeyVaultSecrets = &ConfigStorageAzureKeyVaultSecrets{
			VaultURL:   vaultURL,
			SecretName: "tsiam",
		}
		return c
	}

	validURLs := []string{
		"https://myvault.vault.azure.net/",
		"https://myvault.vault.azure.net",
		"https://myvault.vault.azure.net:443/",
		"HTTPS://myvault.vault.azure.net/",
	}
	for _, vaultURL := range validURLs {
		t.Run("accepts vault URL "+vaultURL, func(t *testing.T) {
			err := newKeysConfig(vaultURL).Validate(slog.Default())
			require.NoError(t, err)

			err = newSecretsConfig(vaultURL).Validate(slog.Default())
			require.NoError(t, err)
		})
	}

	invalidURLs := []string{
		"http://myvault.vault.azure.net/",
		"myvault.vault.azure.net",
		"https://",
		"https:myvault.vault.azure.net",
		"https://user:pass@myvault.vault.azure.net/",
		"https://myvault.vault.azure.net/keys/tsiam",
		"https://myvault.vault.azure.net/?api-version=7.4",
		"https://myvault.vault.azure.net/?",
		"https://myvault.vault.azure.net/#frag",
		"https://myvault.vault.azure.net:abc/",
	}
	for _, vaultURL := range invalidURLs {
		t.Run("rejects vault URL "+vaultURL, func(t *testing.T) {
			err := newKeysConfig(vaultURL).Validate(slog.Default())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "signingKey.azureKeyVaultKeys.vaultUrl")

			err = newSecretsConfig(vaultURL).Validate(slog.Default())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "signingKey.azureKeyVaultSecrets.vaultUrl")
		})
	}

	credentials := []struct {
		name         string
		tenantID     string
		clientID     string
		clientSecret string
		valid        bool
	}{
		{name: "no credentials", valid: true},
		{name: "client secret with tenant and client IDs", tenantID: "tenant", clientID: "client", clientSecret: "secret", valid: true},
		{name: "client ID only", clientID: "client", valid: true},
		{name: "tenant ID only", tenantID: "tenant", valid: true},
		{name: "tenant and client IDs", tenantID: "tenant", clientID: "client", valid: true},
		{name: "client secret only", clientSecret: "secret"},
		{name: "client secret without tenant ID", clientID: "client", clientSecret: "secret"},
		{name: "client secret without client ID", tenantID: "tenant", clientSecret: "secret"},
	}
	for _, tt := range credentials {
		t.Run(tt.name, func(t *testing.T) {
			keys := newKeysConfig("https://myvault.vault.azure.net/")
			keys.SigningKey.AzureKeyVaultKeys.TenantID = tt.tenantID
			keys.SigningKey.AzureKeyVaultKeys.ClientID = tt.clientID
			keys.SigningKey.AzureKeyVaultKeys.ClientSecret = tt.clientSecret

			secrets := newSecretsConfig("https://myvault.vault.azure.net/")
			secrets.SigningKey.AzureKeyVaultSecrets.TenantID = tt.tenantID
			secrets.SigningKey.AzureKeyVaultSecrets.ClientID = tt.clientID
			secrets.SigningKey.AzureKeyVaultSecrets.ClientSecret = tt.clientSecret

			keysErr := keys.Validate(slog.Default())
			secretsErr := secrets.Validate(slog.Default())
			if tt.valid {
				require.NoError(t, keysErr)
				require.NoError(t, secretsErr)
				return
			}

			require.Error(t, keysErr)
			assert.Contains(t, keysErr.Error(), "signingKey.azureKeyVaultKeys.clientSecret")
			require.Error(t, secretsErr)
			assert.Contains(t, secretsErr.Error(), "signingKey.azureKeyVaultSecrets.clientSecret")
		})
	}
}

func TestLogsJSONDefault(t *testing.T) {
	t.Run("a pipe is not a terminal", func(t *testing.T) {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		defer func() { _ = r.Close() }()
		defer func() { _ = w.Close() }()

		assert.False(t, isTerminal(w))
	})

	t.Run("logs are JSON when stdout isn't a terminal", func(t *testing.T) {
		assert.Equal(t, !isTerminal(os.Stdout), GetDefaultConfig().Logs.JSON)
	})
}
