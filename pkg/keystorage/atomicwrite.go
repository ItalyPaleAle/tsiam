package keystorage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// File mode used by keystorage backends when persisting (wrapped or unwrapped) signing-key material
const keyFileMode os.FileMode = 0600

// Writes data to path atomically (by creating a temp file in the same directory, fsyncing it, renaming it over the destination, then fsyncing the directory)
// On failure mid-write the temp file is removed and the destination is left untouched, so a torn write cannot leave an unparseable key file on disk
// The final file mode is keyFileMode (0600)
func writeFileAtomic(path string, data []byte) error {
	tmpPath, err := writeTempFile(path, data)
	if err != nil {
		return err
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file into place: %w", err)
	}

	syncDir(filepath.Dir(path))

	return nil
}

// Writes data to path atomically like writeFileAtomic, but only if path doesn't exist yet
// If path exists, it returns an error that wraps fs.ErrExist and leaves the file untouched
// Hard-linking the temp file to the destination fails when the destination exists, so concurrent writers can't overwrite each other
// An existing empty file is replaced, since keystorage backends treat it as missing
// On filesystems that don't support hard links, it falls back to a rename, which doesn't protect against concurrent writers
func writeFileExclusive(path string, data []byte) error {
	tmpPath, err := writeTempFile(path, data)
	if err != nil {
		return err
	}

	// After a successful link, the destination is another name for the temp file, so the temp file is always removed
	defer os.Remove(tmpPath) //nolint:errcheck

	linkErr := os.Link(tmpPath, path)
	if linkErr == nil {
		syncDir(filepath.Dir(path))
		return nil
	}

	// Find out whether the link failed because the destination exists, or because the filesystem doesn't support hard links
	info, err := os.Stat(path)
	switch {
	case err == nil && info.Size() > 0:
		return fmt.Errorf("file '%s' already exists: %w", path, fs.ErrExist)
	case err == nil:
		// Empty file, which is replaced
	case errors.Is(err, fs.ErrNotExist) && !errors.Is(linkErr, fs.ErrExist):
		// Hard links are not supported
	default:
		return fmt.Errorf("failed to link temp file into place: %w", linkErr)
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		return fmt.Errorf("failed to rename temp file into place: %w", err)
	}

	syncDir(filepath.Dir(path))

	return nil
}

// Writes data to a new temp file in the same directory as path, and returns the path of the temp file
// The temp file has mode keyFileMode (0600), and its contents are synced to disk
// On failure, the temp file is removed
func writeTempFile(path string, data []byte) (tmpPath string, err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath = f.Name()

	// A double-close of an already-closed *os.File just returns an error which we ignore
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// Change the mode through the open file, and not its path, which another user with write access to the directory could replace with a symlink
	// CreateTemp already uses 0600, but the umask could have removed some bits
	err = f.Chmod(keyFileMode)
	if err != nil {
		return "", fmt.Errorf("failed to chmod temp file: %w", err)
	}

	_, err = f.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}

	err = f.Sync()
	if err != nil {
		return "", fmt.Errorf("failed to sync temp file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	return tmpPath, nil
}

// Syncs the directory, so the entry for a file that was just renamed or linked into it survives a crash or power loss
// This is best-effort: the file is already in place, and some filesystems don't support syncing directories
func syncDir(dir string) {
	// Windows can't open directories as files
	if runtime.GOOS == "windows" {
		return
	}

	d, err := os.Open(dir) // #nosec G304 -- The directory of the key file, which is set in the configuration
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
