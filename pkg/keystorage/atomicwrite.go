package keystorage

import (
	"fmt"
	"os"
	"path/filepath"
)

// File mode used by keystorage backends when persisting (wrapped or unwrapped) signing-key material
const keyFileMode os.FileMode = 0600

// Writes data to path atomically (by creating a temp file in the same directory, fsyncing it, then renaming over the destination)
// On failure mid-write the temp file is removed and the destination is left untouched, so a torn write cannot leave an unparseable key file on disk
// The final file mode is keyFileMode (0600)
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	f, err := os.CreateTemp(dir, ".tmp-"+base+"-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := f.Name()

	// Clean up on any failure before the rename succeeds
	// A double-close of an already-closed *os.File just returns an error which we ignore
	renamed := false
	defer func() {
		if !renamed {
			_ = f.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	err = os.Chmod(tmpPath, keyFileMode)
	if err != nil {
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	err = f.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		return fmt.Errorf("failed to rename temp file into place: %w", err)
	}
	renamed = true

	return nil
}
