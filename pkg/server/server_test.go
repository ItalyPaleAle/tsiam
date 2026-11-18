package server

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunShutdown(t *testing.T) {
	startServer := func(t *testing.T, shutdownTimeout time.Duration, handler http.HandlerFunc) (addr string, stop func() error) {
		t.Helper()

		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)

		s := &Server{
			handler:         handler,
			tsListener:      ln,
			shutdownTimeout: shutdownTimeout,
		}

		ctx, cancel := context.WithCancel(t.Context())
		runErr := make(chan error, 1)
		go func() {
			runErr <- s.Run(ctx)
		}()

		stop = func() error {
			cancel()
			select {
			case err := <-runErr:
				return err
			case <-time.After(5 * time.Second):
				t.Fatal("Run didn't return")
				return nil
			}
		}
		return ln.Addr().String(), stop
	}

	t.Run("requests still running after the timeout are canceled", func(t *testing.T) {
		started := make(chan struct{})
		canceled := make(chan struct{})
		addr, stop := startServer(t, 100*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
			close(canceled)
		})

		clientErr := make(chan error, 1)
		go func() {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/", nil)
			if err != nil {
				clientErr <- err
				return
			}
			res, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = res.Body.Close()
			}
			clientErr <- err
		}()
		<-started

		err := stop()
		require.NoError(t, err)

		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("handler's context wasn't canceled after Run returned")
		}

		select {
		case err = <-clientErr:
			require.Error(t, err)
		case <-time.After(time.Second):
			t.Fatal("client request didn't fail")
		}
	})

	t.Run("requests that complete within the timeout get their response", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		addr, stop := startServer(t, 5*time.Second, func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-release
			w.WriteHeader(http.StatusNoContent)
		})

		clientRes := make(chan int, 1)
		go func() {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/", nil)
			if err != nil {
				clientRes <- 0
				return
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				clientRes <- 0
				return
			}
			_ = res.Body.Close()
			clientRes <- res.StatusCode
		}()
		<-started

		go func() {
			time.Sleep(100 * time.Millisecond)
			close(release)
		}()

		err := stop()
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, <-clientRes)
	})
}
