package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"runtime"

	"github.com/italypaleale/go-kit/fsutil"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// FileKeyStorage implements KeyStorage using local filesystem
type FileKeyStorage struct {
	path string
}

// NewFileKeyStorage creates a new file-based key storage
func NewFileKeyStorage(path string) (*FileKeyStorage, error) {
	err := ensureKeyDir(path)
	if err != nil {
		return nil, err
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

	// Treat an empty file as missing
	if len(data) == 0 {
		slog.WarnContext(ctx, "Signing key file is empty, so a new signing key is generated and replaces it", slog.String("path", f.path))
		return nil, errKeyNoExist
	}

	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	warnIfKeyFileAccessible(ctx, f.path)

	slog.InfoContext(ctx, "Loaded signing key from file storage",
		slog.String("path", f.path),
		slog.String("keyId", keyID(key)),
	)

	return key, nil
}

// Store saves the signing key to a file if it does not already exist
func (f *FileKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	err = fsutil.CreateFile(f.path, data, keyFileMode, fsutil.WithReplaceEmpty())
	if errors.Is(err, fs.ErrExist) {
		return errKeyExists
	} else if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	slog.InfoContext(ctx, "Stored signing key to file storage",
		slog.String("path", f.path),
		slog.String("keyId", keyID(key)),
	)

	return nil
}

// Logs a warning if the key file is accessible by users other than its owner
func warnIfKeyFileAccessible(ctx context.Context, path string) {
	if runtime.GOOS == "windows" {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		slog.WarnContext(ctx, "Signing key file can be accessed by users other than its owner, so they may be able to read or replace the signing key - change its mode to 0600",
			slog.String("path", path),
			slog.String("mode", fmt.Sprintf("%#o", perm)),
		)
	}
}
