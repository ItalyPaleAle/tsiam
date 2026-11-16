package keystorage

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
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

func TestWriteFileExclusive(t *testing.T) {
	// Returns the names of the files in dir
	listDir := func(t *testing.T, dir string) []string {
		t.Helper()
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		return names
	}

	t.Run("Creates file with expected contents and mode", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")

		err := writeFileExclusive(path, []byte("hello world"))
		require.NoError(t, err)

		got, err := os.ReadFile(path) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, []byte("hello world"), got)
		assert.Equal(t, []string{"key"}, listDir(t, dir), "temp file should be removed")

		// Permission bits are not meaningful on Windows
		if runtime.GOOS != "windows" {
			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		}
	})

	t.Run("Does not overwrite an existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")
		err := os.WriteFile(path, []byte("old"), 0600)
		require.NoError(t, err)

		err = writeFileExclusive(path, []byte("new"))
		require.ErrorIs(t, err, fs.ErrExist)

		got, err := os.ReadFile(path) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, []byte("old"), got)
		assert.Equal(t, []string{"key"}, listDir(t, dir), "temp file should be removed")
	})

	t.Run("Replaces an existing empty file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")
		err := os.WriteFile(path, nil, 0600)
		require.NoError(t, err)

		err = writeFileExclusive(path, []byte("new"))
		require.NoError(t, err)

		got, err := os.ReadFile(path) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, []byte("new"), got)
		assert.Equal(t, []string{"key"}, listDir(t, dir), "temp file should be removed")
	})

	t.Run("Only one of many concurrent writers succeeds", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")

		const writers = 20
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for i := range writers {
			wg.Go(func() {
				errs[i] = writeFileExclusive(path, []byte(strconv.Itoa(i)))
			})
		}
		wg.Wait()

		winner := -1
		for i, err := range errs {
			if err == nil {
				require.Equal(t, -1, winner, "only one writer should succeed")
				winner = i
				continue
			}
			require.ErrorIs(t, err, fs.ErrExist)
		}
		require.NotEqual(t, -1, winner, "one writer should succeed")

		got, err := os.ReadFile(path) //nolint:gosec
		require.NoError(t, err)
		assert.Equal(t, strconv.Itoa(winner), string(got))
		assert.Equal(t, []string{"key"}, listDir(t, dir), "temp files should be removed")
	})

	t.Run("Leaves no temp files on failure", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "does-not-exist", "key")

		err := writeFileExclusive(path, []byte("x"))
		require.Error(t, err)
		assert.Empty(t, listDir(t, dir))
	})
}
