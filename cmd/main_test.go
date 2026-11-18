package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShutdownManager(t *testing.T) {
	t.Run("runs the functions one at a time, in reverse order", func(t *testing.T) {
		var (
			order   []string
			running bool
		)
		record := func(name string) func(ctx context.Context) error {
			return func(ctx context.Context) error {
				assert.False(t, running, "%s started while another function was running", name)
				running = true
				time.Sleep(10 * time.Millisecond)
				order = append(order, name)
				running = false
				return nil
			}
		}

		s := &shutdownManager{timeout: time.Second}
		s.Add(record("logger"))
		s.Add(record("metrics"))
		s.Add(record("traces"))
		s.Add(record("tsnet"))
		s.Run(slog.Default())

		assert.Equal(t, []string{"tsnet", "traces", "metrics", "logger"}, order)
	})

	t.Run("a function that hangs doesn't use up the next one's time", func(t *testing.T) {
		var loggerCtxErr error
		s := &shutdownManager{timeout: 50 * time.Millisecond}
		s.Add(func(ctx context.Context) error {
			loggerCtxErr = ctx.Err()
			return nil
		})
		s.Add(func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		})
		s.Run(slog.Default())

		require.NoError(t, loggerCtxErr)
	})

	t.Run("errors and panics are logged and the other functions still run", func(t *testing.T) {
		var buf strings.Builder
		log := slog.New(slog.NewTextHandler(&buf, nil))

		var loggerRan bool
		s := &shutdownManager{timeout: time.Second}
		s.Add(func(ctx context.Context) error {
			loggerRan = true
			return nil
		})
		s.Add(func(ctx context.Context) error {
			panic("simulated panic")
		})
		s.Add(func(ctx context.Context) error {
			return errors.New("simulated error")
		})
		s.Run(log)

		assert.True(t, loggerRan)
		assert.Contains(t, buf.String(), "simulated error")
		assert.Contains(t, buf.String(), "simulated panic")
	})

	t.Run("runs each function only once", func(t *testing.T) {
		var calls int
		s := &shutdownManager{timeout: time.Second}
		s.Add(func(ctx context.Context) error {
			calls++
			return nil
		})
		s.Run(slog.Default())
		s.Run(slog.Default())

		assert.Equal(t, 1, calls)
	})
}
