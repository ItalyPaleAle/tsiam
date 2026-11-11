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

func TestHasControlChars(t *testing.T) {
	assert.False(t, HasControlChars(""))
	assert.False(t, HasControlChars("https://api.example.com"))
	assert.False(t, HasControlChars("api://AzureADTokenExchange"))
	assert.False(t, HasControlChars("https://café.example.com/ñ"))
	assert.True(t, HasControlChars("a\x00b"))
	assert.True(t, HasControlChars("a\rb"))
	assert.True(t, HasControlChars("a\nb"))
	assert.True(t, HasControlChars("\x1f"))
	assert.True(t, HasControlChars("\x7f"))
}
