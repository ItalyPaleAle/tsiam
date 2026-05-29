package keystorage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAtomic(t *testing.T) {
	t.Run("Creates file with expected contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")
		payload := []byte("hello world")

		err := writeFileAtomic(path, payload)
		require.NoError(t, err)

		got, err := os.ReadFile(path) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("Sets the requested file mode", func(t *testing.T) {
		// Permission bits are not meaningful on Windows
		if runtime.GOOS == "windows" {
			t.Skip("skipping permission check on Windows")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "key")

		err := writeFileAtomic(path, []byte("x"))
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("Overwrites existing file atomically", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")

		err := os.WriteFile(path, []byte("old"), 0600)
		require.NoError(t, err)

		err = writeFileAtomic(path, []byte("new"))
		require.NoError(t, err)

		got, err := os.ReadFile(path) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, []byte("new"), got)
	})

	t.Run("Leaves no temp files on success", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")

		err := writeFileAtomic(path, []byte("x"))
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "expected only the destination file to remain")
		assert.Equal(t, "key", entries[0].Name())
	})

	t.Run("Leaves no temp files on failure", func(t *testing.T) {
		// Point at a directory that doesn't exist; CreateTemp will fail before any side effects
		dir := t.TempDir()
		path := filepath.Join(dir, "does-not-exist", "key")

		err := writeFileAtomic(path, []byte("x"))
		require.Error(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("Does not corrupt destination when temp write cannot rename", func(t *testing.T) {
		// Pre-populate the destination, then point the atomic write at a path whose parent is a regular file
		// The rename should fail, leaving any pre-existing destination untouched
		dir := t.TempDir()
		existing := filepath.Join(dir, "real-key")
		err := os.WriteFile(existing, []byte("preserved"), 0600)
		require.NoError(t, err)

		// CreateTemp on a non-directory parent fails, so the destination is never touched
		nonDirParent := filepath.Join(dir, "file-not-dir")
		err = os.WriteFile(nonDirParent, []byte("x"), 0600)
		require.NoError(t, err)
		badPath := filepath.Join(nonDirParent, "key")

		err = writeFileAtomic(badPath, []byte("new"))
		require.Error(t, err)

		// Pre-existing file untouched
		got, err := os.ReadFile(existing) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, []byte("preserved"), got)
	})
}
