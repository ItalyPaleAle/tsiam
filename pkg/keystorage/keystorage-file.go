package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// FileKeyStorage implements KeyStorage using local filesystem
type FileKeyStorage struct {
	path string
}

// NewFileKeyStorage creates a new file-based key storage
func NewFileKeyStorage(path string) (*FileKeyStorage, error) {
	// Ensure directory exists with restrictive permissions
	// MkdirAll only honors the mode on creation, so an existing dir with looser bits would silently remain world-readable, the explicit Chmod enforces 0700 on every run
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage directory: %w", err)
	}
	err = os.Chmod(dir, 0700) //nolint:gosec // directory needs the execute bit, gosec only knows about files
	if err != nil {
		return nil, fmt.Errorf("failed to chmod key storage directory: %w", err)
	}

	return &FileKeyStorage{
		path: path,
	}, nil
}

// Load loads the signing key from a file
func (f *FileKeyStorage) Load(ctx context.Context) (jwk.Key, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		// Key doesn't exist yet
		slog.DebugContext(ctx, "No signing key found in file storage", slog.String("path", f.path))
		return nil, errKeyNoExist
	} else if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// A zero-byte file is treated as missing rather than a parse error
	if len(data) == 0 {
		slog.DebugContext(ctx, "Ignoring empty signing key file in file storage", slog.String("path", f.path))
		return nil, errKeyNoExist
	}

	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	slog.InfoContext(ctx, "Loaded signing key from file storage",
		slog.String("path", f.path),
		slog.String("keyId", keyID(key)),
	)

	return key, nil
}

// Store saves the signing key to a file
func (f *FileKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// Atomic write so a torn write cannot leave an unparseable key file on disk
	err = writeFileAtomic(f.path, data)
	if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	slog.InfoContext(ctx, "Stored signing key to file storage",
		slog.String("path", f.path),
		slog.String("keyId", keyID(key)),
	)

	return nil
}
