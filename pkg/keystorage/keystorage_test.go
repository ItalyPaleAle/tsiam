package keystorage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureKeyDir(t *testing.T) {
	t.Run("Creates a missing directory with mode 0700", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "a", "b")

		err := ensureKeyDir(filepath.Join(dir, "key.json"))
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		// Permission bits are not meaningful on Windows
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
		}
	})

	t.Run("Leaves an existing directory unchanged", func(t *testing.T) {
		// Permission bits are not meaningful on Windows
		if runtime.GOOS == "windows" {
			t.Skip("skipping permission check on Windows")
		}

		dir := filepath.Join(t.TempDir(), "shared")
		err := os.Mkdir(dir, 0700)
		require.NoError(t, err)
		err = os.Chmod(dir, 0755) //nolint:gosec
		require.NoError(t, err)

		err = ensureKeyDir(filepath.Join(dir, "key.json"))
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
	})

	t.Run("Fails when the parent is a file", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "file")
		err := os.WriteFile(parent, []byte("x"), 0600)
		require.NoError(t, err)

		err = ensureKeyDir(filepath.Join(parent, "key.json"))
		require.ErrorContains(t, err, "is not a directory")
	})
}
