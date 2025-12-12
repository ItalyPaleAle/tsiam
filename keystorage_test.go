package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

func TestFileKeyStorage(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	// Create storage
	storage, err := NewFileKeyStorage(keyPath)
	if err != nil {
		t.Fatalf("Failed to create file storage: %v", err)
	}

	ctx := context.Background()

	// Test loading non-existent key
	key, err := storage.Load(ctx)
	if err != nil {
		t.Fatalf("Failed to load non-existent key: %v", err)
	}
	if key != nil {
		t.Error("Expected nil key for non-existent file")
	}

	// Generate a test key
	if err := generateSigningKey("RS256", ""); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	originalKeyID := keyID

	// Store the key
	if err := storage.Store(ctx, signingKey); err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Load the key back
	loadedKey, err := storage.Load(ctx)
	if err != nil {
		t.Fatalf("Failed to load stored key: %v", err)
	}
	if loadedKey == nil {
		t.Fatal("Loaded key is nil")
	}

	// Verify key properties
	if kid, ok := loadedKey.KeyID(); ok {
		if kid != originalKeyID {
			t.Errorf("Key ID mismatch: expected %s, got %s", originalKeyID, kid)
		}
	} else {
		t.Error("Loaded key has no key ID")
	}

	if alg, ok := loadedKey.Algorithm(); ok {
		if alg != jwa.RS256() {
			t.Errorf("Algorithm mismatch: expected RS256, got %s", alg)
		}
	} else {
		t.Error("Loaded key has no algorithm")
	}
}

func TestFileKeyStorage_InvalidPath(t *testing.T) {
	// Try to create storage with invalid path
	_, err := NewFileKeyStorage("/invalid/nonexistent/path/key.pem")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}
