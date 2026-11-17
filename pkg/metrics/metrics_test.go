package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestRecordAuth(t *testing.T) {
	// Records one authentication, and returns the attributes of the data point
	record := func(t *testing.T, includeNodeName bool) attribute.Set {
		t.Helper()

		reader := sdkmetric.NewManualReader()
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		counter, err := provider.Meter("test").Int64Counter(prefix + "_auths")
		require.NoError(t, err)

		m := &AppMetrics{auths: counter, includeNodeName: includeNodeName}
		m.RecordAuth(t.Context(), "node1.tailnet.ts.net", "https://api.example.com")

		var rm metricdata.ResourceMetrics
		err = reader.Collect(t.Context(), &rm)
		require.NoError(t, err)
		require.Len(t, rm.ScopeMetrics, 1)
		require.Len(t, rm.ScopeMetrics[0].Metrics, 1)
		sum, ok := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Sum[int64])
		require.True(t, ok)
		require.Len(t, sum.DataPoints, 1)
		assert.Equal(t, int64(1), sum.DataPoints[0].Value)
		return sum.DataPoints[0].Attributes
	}

	t.Run("the node name is left out by default", func(t *testing.T) {
		attrs := record(t, false)

		endpoint, _ := attrs.Value("endpoint")
		assert.Equal(t, "https://api.example.com", endpoint.AsString())
		_, ok := attrs.Value("node")
		assert.False(t, ok)
	})

	t.Run("the node name is included when enabled", func(t *testing.T) {
		attrs := record(t, true)

		node, _ := attrs.Value("node")
		assert.Equal(t, "node1.tailnet.ts.net", node.AsString())
	})

	t.Run("nil metrics are ignored", func(t *testing.T) {
		var m *AppMetrics
		m.RecordAuth(t.Context(), "node", "audience")
	})
}
