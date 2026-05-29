package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// FileKeyStorage implements KeyStorage using local filesystem
type FileKeyStorage struct {
	path string
}

// NewFileKeyStorage creates a new file-based key storage
func NewFileKeyStorage(path string) (*FileKeyStorage, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage directory: %w", err)
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
		return nil, errKeyNoExist
	} else if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// A zero-byte file is treated as missing rather than a parse error
	if len(data) == 0 {
		return nil, errKeyNoExist
	}

	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

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

	return nil
}
