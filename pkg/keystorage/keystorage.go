package keystorage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

var (
	errKeyNoExist = errors.New("key not found")
	errKeyExists  = errors.New("key already exists")
)

// keyID returns the key's `kid` for use in log fields, or an empty string if unset
func keyID(key jwk.Key) string {
	kid, _ := key.KeyID()
	return kid
}

// KeyStorage is an interface for persisting signing keys
type KeyStorage interface {
	// Load loads the signing key from storage
	// If the key doesn't exist, returns an error for which IsKeyNotExistError returns true
	Load(ctx context.Context) (jwk.Key, error)
	// Store saves a new signing key to storage, if the storage doesn't contain a key yet
	// If it does, returns an error for which IsKeyExistError returns true, so instances that start at the same time end up using the same key
	// Storage backends that can't check this atomically overwrite the existing key instead
	Store(ctx context.Context, key jwk.Key) error
}

// IsKeyNotExistError returns true if the error indicates that the storage doesn't contain a key
func IsKeyNotExistError(err error) bool {
	return errors.Is(err, errKeyNoExist)
}

// IsKeyExistError returns true if the error indicates that the storage already contains a key
func IsKeyExistError(err error) bool {
	return errors.Is(err, errKeyExists)
}

// Creates the directory that contains the key file at path, if it doesn't exist
// New directories get mode 0700, but existing ones are left as they are: they can be shared, or owned by another user (like a volume's mount point), and key files have mode 0600 anyway
func ensureKeyDir(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return fmt.Errorf("failed to create key storage directory: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("failed to check key storage directory: %w", err)
	case !info.IsDir():
		return fmt.Errorf("key storage path '%s' is not a directory", dir)
	}

	// Permission bits don't apply on Windows
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o002 != 0 {
		slog.Warn("Key storage directory is writable by every user, so other users may be able to replace the signing key", slog.String("path", dir))
	}

	return nil
}
