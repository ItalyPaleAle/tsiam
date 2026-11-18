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

const keyFileMode os.FileMode = 0600

func keyID(key jwk.Key) string {
	kid, _ := key.KeyID()
	return kid
}

// KeyStorage is an interface for persisting signing keys
type KeyStorage interface {
	// Load loads the signing key from storage
	Load(ctx context.Context) (jwk.Key, error)
	// Store saves a new signing key to storage
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

// Creates the parent directory for path with mode 0700 if it does not exist
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

	if runtime.GOOS != "windows" && info.Mode().Perm()&0o002 != 0 {
		slog.Warn("Key storage directory is writable by every user, so other users may be able to replace the signing key", slog.String("path", dir))
	}

	return nil
}
