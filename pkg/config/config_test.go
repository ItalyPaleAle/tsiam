package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Returns a config that passes validation, so each test only changes the option it is checking
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

	// Leading and trailing whitespace control characters (e.g. a trailing newline) are trimmed, so only embedded ones reach the check
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
