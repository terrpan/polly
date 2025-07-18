package storage

import (
	"testing"

	"github.com/terrpan/polly/internal/config"
)

// TestValkeyStore_InterfaceCompliance tests that ValkeyStore implements the Store interface
// This is a compile-time check that doesn't require a running Valkey server
func TestValkeyStore_InterfaceCompliance(t *testing.T) {
	// This will fail to compile if ValkeyStore doesn't implement Store interface
	var _ Store = (*ValkeyStore)(nil)
}

func TestValkeyStore_Constructor(t *testing.T) {
	t.Run("constructor with valid config tries to connect", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Address:  "localhost:6379",
			Username: "",
			Password: "",
			DB:       0,
		}

		// This should try to connect and fail (since no server is running)
		// but the error should be a connection error, not a configuration error
		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no Valkey server running
			t.Logf("Expected connection error: %v", err)
		}
		if store != nil {
			// If somehow we got a connection, clean it up
			_ = store.Close()
		}
	})

	t.Run("constructor with empty address", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Address: "", // Empty address should cause an error
		}

		store, err := NewValkeyStore(cfg)
		// Should get an error due to invalid address
		if err == nil {
			t.Error("Expected error with empty address")
			if store != nil {
				_ = store.Close()
			}
		} else {
			t.Logf("Got expected error with empty address: %v", err)
		}
	})
}

// TestValkeyStore_ErrorConstants tests that we properly handle Valkey-specific errors
func TestValkeyStore_ErrorMapping(t *testing.T) {
	// Test that our error constants are properly defined
	if ErrKeyNotFound == nil {
		t.Error("ErrKeyNotFound should be defined")
	}

	if ErrInvalidType == nil {
		t.Error("ErrInvalidType should be defined")
	}

	// Verify error messages are descriptive
	if ErrKeyNotFound.Error() != "key not found" {
		t.Errorf("ErrKeyNotFound has unexpected message: %s", ErrKeyNotFound.Error())
	}

	if ErrInvalidType.Error() != "invalid storage type" {
		t.Errorf("ErrInvalidType has unexpected message: %s", ErrInvalidType.Error())
	}
}
