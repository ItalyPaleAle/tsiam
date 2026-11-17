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

	// A zero-byte file is treated as missing rather than a parse error
	// tsiam never writes an empty file, so this is logged as a warning: the new key has a different ID, and tokens signed with the old key stop working
	if len(data) == 0 {
		slog.WarnContext(ctx, "Signing key file is empty, so a new signing key is generated and replaces it", slog.String("path", f.path))
		return nil, errKeyNoExist
	}

	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// The file contains the private key unencrypted
	warnIfKeyFileAccessible(ctx, f.path)

	slog.InfoContext(ctx, "Loaded signing key from file storage",
		slog.String("path", f.path),
		slog.String("keyId", keyID(key)),
	)

	return key, nil
}

// Store saves the signing key to a file, if the file doesn't exist yet
func (f *FileKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// Atomic write so a torn write cannot leave an unparseable key file on disk
	err = writeFileExclusive(f.path, data)
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

// Logs a warning if users other than the owner can access the key file
// Following symlinks is intentional, since Kubernetes mounts Secrets as symlinks, so this checks the file they point to
func warnIfKeyFileAccessible(ctx context.Context, path string) {
	// Permission bits don't apply on Windows, where access is controlled by the ACLs that the file inherits from its directory
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
