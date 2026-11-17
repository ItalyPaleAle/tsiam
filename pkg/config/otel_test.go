package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestGetOtelResource(t *testing.T) {
	// Returns the value of an attribute of the resource, or an empty string if it's not set
	getAttr := func(t *testing.T, c *Config, key attribute.Key) string {
		t.Helper()
		res, err := c.GetOtelResource("tsiam")
		require.NoError(t, err)
		value, _ := res.Set().Value(key)
		return value.AsString()
	}

	t.Run("uses tsiam's attributes by default", func(t *testing.T) {
		t.Setenv("OTEL_SERVICE_NAME", "")
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")

		c := newValidConfig()
		c.internal.instanceID = "test-instance"
		assert.Equal(t, "tsiam", getAttr(t, c, "service.name"))
		assert.NotEmpty(t, getAttr(t, c, "service.version"))
		assert.Equal(t, "test-instance", getAttr(t, c, "service.instance.id"))
		assert.Equal(t, "opentelemetry", getAttr(t, c, "telemetry.sdk.name"))
	})

	t.Run("OTEL_SERVICE_NAME overrides the service name", func(t *testing.T) {
		t.Setenv("OTEL_SERVICE_NAME", "tsiam-prod")
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")

		assert.Equal(t, "tsiam-prod", getAttr(t, newValidConfig(), "service.name"))
	})

	t.Run("OTEL_RESOURCE_ATTRIBUTES overrides tsiam's attributes and adds others", func(t *testing.T) {
		t.Setenv("OTEL_SERVICE_NAME", "")
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=from-attributes,service.version=1.2.3,deployment.environment.name=production")

		c := newValidConfig()
		assert.Equal(t, "from-attributes", getAttr(t, c, "service.name"))
		assert.Equal(t, "1.2.3", getAttr(t, c, "service.version"))
		assert.Equal(t, "production", getAttr(t, c, "deployment.environment.name"))
	})
}
