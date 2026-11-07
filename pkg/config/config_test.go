package config

import (
	"log/slog"
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
