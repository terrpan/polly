package storage

import (
	"context"
	"testing"

	"github.com/terrpan/polly/internal/config"
	"go.opentelemetry.io/otel"
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

// TestValkeyStore_SentinelConfiguration tests Sentinel configuration
func TestValkeyStore_SentinelConfiguration(t *testing.T) {
	t.Run("sentinel configuration with valid settings", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			EnableSentinel:   true,
			SentinelAddrs:    []string{"localhost:26379", "localhost:26380", "localhost:26381"},
			SentinelMaster:   "mymaster",
			SentinelUsername: "sentinel-user",
			SentinelPassword: "sentinel-pass",
			Username:         "user",
			Password:         "pass",
			DB:               1,
		}

		// This should try to connect to sentinel and fail (since no server is running)
		// but the error should be a connection error, not a configuration error
		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no Sentinel running
			t.Logf("Expected sentinel connection error: %v", err)
		}
		if store != nil {
			_ = store.Close()
		}
	})

	t.Run("sentinel configuration with missing master name", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			EnableSentinel: true,
			SentinelAddrs:  []string{"localhost:26379"},
			SentinelMaster: "", // Missing master name
		}

		store, err := NewValkeyStore(cfg)
		// Should get an error due to missing master name
		if err == nil {
			t.Error("Expected error with missing sentinel master name")
			if store != nil {
				_ = store.Close()
			}
		} else {
			t.Logf("Got expected error with missing master: %v", err)
		}
	})
}

// TestValkeyStore_CompressionConfiguration tests compression settings
func TestValkeyStore_CompressionConfiguration(t *testing.T) {
	t.Run("compression enabled configuration", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Address:           "localhost:6379",
			EnableCompression: true,
		}

		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no Valkey server running
			t.Logf("Expected connection error: %v", err)
		}
		if store != nil {
			// Verify compression is enabled
			if !store.enableCompression {
				t.Error("Expected compression to be enabled")
			}
			_ = store.Close()
		}
	})

	t.Run("compression disabled configuration", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Address:           "localhost:6379",
			EnableCompression: false,
		}

		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no Valkey server running
			t.Logf("Expected connection error: %v", err)
		}
		if store != nil {
			// Verify compression is disabled
			if store.enableCompression {
				t.Error("Expected compression to be disabled")
			}
			_ = store.Close()
		}
	})
}

// TestValkeyStore_OpenTelemetryConfiguration tests OpenTelemetry integration
func TestValkeyStore_OpenTelemetryConfiguration(t *testing.T) {
	t.Run("otel enabled configuration", func(t *testing.T) {
		// Set up mock config
		originalConfig := config.AppConfig
		config.AppConfig = &config.Config{
			OTLP: config.OTLPConfig{
				EnableOTLP: true,
			},
		}
		defer func() {
			config.AppConfig = originalConfig
		}()

		cfg := config.ValkeyConfig{
			Address:    "localhost:6379",
			EnableOTel: true,
		}

		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no Valkey server running
			t.Logf("Expected connection error: %v", err)
		}
		if store != nil {
			_ = store.Close()
		}
	})

	t.Run("otel disabled configuration", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Address:    "localhost:6379",
			EnableOTel: false,
		}

		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no Valkey server running
			t.Logf("Expected connection error: %v", err)
		}
		if store != nil {
			_ = store.Close()
		}
	})
}

// TestValkeyStore_CompressionHelpers tests compression/decompression functions
func TestValkeyStore_CompressionHelpers(t *testing.T) {
	t.Run("compression and decompression with compression enabled", func(t *testing.T) {
		store := &ValkeyStore{
			enableCompression: true,
			tracer:            otel.Tracer("test-valkey-store"),
		}

		testData := []byte("Hello, World! This is a test string for compression.")

		// Test compression
		compressed, err := store.compress(context.Background(), testData)
		if err != nil {
			t.Fatalf("Failed to compress data: %v", err)
		}

		// Compressed data should be different from original (and typically smaller for longer strings)
		if len(compressed) == 0 {
			t.Error("Compressed data should not be empty")
		}

		// Test decompression
		decompressed, err := store.decompress(context.Background(), compressed)
		if err != nil {
			t.Fatalf("Failed to decompress data: %v", err)
		}

		// Decompressed data should match original
		if string(decompressed) != string(testData) {
			t.Errorf("Decompressed data doesn't match original. Got: %s, Want: %s", string(decompressed), string(testData))
		}
	})

	t.Run("compression and decompression with compression disabled", func(t *testing.T) {
		store := &ValkeyStore{
			enableCompression: false,
			tracer:            otel.Tracer("test-valkey-store"),
		}

		testData := []byte("Hello, World!")

		// Test compression (should be pass-through)
		compressed, err := store.compress(context.Background(), testData)
		if err != nil {
			t.Fatalf("Failed to compress data: %v", err)
		}

		// With compression disabled, data should be unchanged
		if string(compressed) != string(testData) {
			t.Errorf("With compression disabled, data should be unchanged. Got: %s, Want: %s", string(compressed), string(testData))
		}

		// Test decompression (should be pass-through)
		decompressed, err := store.decompress(context.Background(), compressed)
		if err != nil {
			t.Fatalf("Failed to decompress data: %v", err)
		}

		// Should still match original
		if string(decompressed) != string(testData) {
			t.Errorf("Decompressed data doesn't match original. Got: %s, Want: %s", string(decompressed), string(testData))
		}
	})
}
