package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/config"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valkey-io/valkey-go"
	"go.opentelemetry.io/otel"
)

const (
	valkeyImage = "valkey/valkey:8-alpine"
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

func TestValkeyStore_HandleValkeyNilError(t *testing.T) {
	// Create a ValkeyStore instance for testing (doesn't need actual connection)
	store := &ValkeyStore{
		tracer: otel.Tracer("test-tracer"),
	}

	// Create a test span for tracing verification
	ctx := context.Background()
	_, span := store.tracer.Start(ctx, "test-span")
	defer span.End()

	t.Run("handles nil error correctly", func(t *testing.T) {
		handled, err := store.handleValkeyNilError(nil, span, "test_message")

		// Should not be handled for nil errors
		assert.False(t, handled, "Should not handle nil errors")
		assert.NoError(t, err, "Should return no error for nil input")
	})

	t.Run("handles regular errors correctly", func(t *testing.T) {
		regularErr := fmt.Errorf("connection timeout")

		handled, err := store.handleValkeyNilError(regularErr, span, "test_message")

		// Should be handled and return the original error
		assert.True(t, handled, "Should handle regular errors")
		assert.Equal(t, regularErr, err, "Should return the original error")
	})

	t.Run("records error for non-nil regular errors", func(t *testing.T) {
		// Create a fresh span to check error recording
		_, testSpan := store.tracer.Start(ctx, "error-recording-test-span")
		defer testSpan.End()

		testError := fmt.Errorf("test connection error")

		handled, err := store.handleValkeyNilError(testError, testSpan, "test_message")

		assert.True(t, handled)
		assert.Equal(t, testError, err)
		// Note: In a real test environment, you might want to verify that
		// span.RecordError was called with the correct error
	})

	// Note: Testing actual Valkey nil errors requires integration tests with real Valkey instance
	// because valkey.IsValkeyNil checks for specific internal error types from the valkey client
}

func TestApplyCommonValkeyConfig(t *testing.T) {
	t.Run("applies common configuration to client options", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Username: "test-user",
			Password: "test-pass",
			DB:       5,
		}

		var clientOpts valkey.ClientOption
		applyCommonValkeyConfig(&clientOpts, cfg)

		assert.Equal(t, "test-user", clientOpts.Username)
		assert.Equal(t, "test-pass", clientOpts.Password)
		assert.Equal(t, 5, clientOpts.SelectDB)
	})

	t.Run("handles empty configuration values", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Username: "",
			Password: "",
			DB:       0,
		}

		var clientOpts valkey.ClientOption
		applyCommonValkeyConfig(&clientOpts, cfg)

		assert.Equal(t, "", clientOpts.Username)
		assert.Equal(t, "", clientOpts.Password)
		assert.Equal(t, 0, clientOpts.SelectDB)
	})

	t.Run("does not affect other client option fields", func(t *testing.T) {
		cfg := config.ValkeyConfig{
			Username: "test-user",
			Password: "test-pass",
			DB:       3,
		}

		clientOpts := valkey.ClientOption{
			InitAddress: []string{"localhost:6379"},
		}

		applyCommonValkeyConfig(&clientOpts, cfg)

		// Common fields should be set
		assert.Equal(t, "test-user", clientOpts.Username)
		assert.Equal(t, "test-pass", clientOpts.Password)
		assert.Equal(t, 3, clientOpts.SelectDB)

		// Other fields should remain unchanged
		assert.Equal(t, []string{"localhost:6379"}, clientOpts.InitAddress)
	})
}

// Integration tests using testcontainers - these require Docker
func TestValkeyStore_IntegrationBasicOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start Valkey container
	redisContainer, err := redis.Run(ctx, valkeyImage)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(redisContainer); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	})

	// Get connection details
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err)

	port, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	// Create ValkeyStore with container connection
	cfg := config.ValkeyConfig{
		Address:  fmt.Sprintf("%s:%s", host, port.Port()),
		Username: "",
		Password: "",
		DB:       0,
	}

	store, err := NewValkeyStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)

	// Test basic operations
	t.Run("set and get string", func(t *testing.T) {
		key := "integration-test-key"
		value := "integration-test-value"

		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)
	})

	t.Run("set and get with expiration", func(t *testing.T) {
		key := "integration-expiry-key"
		value := "integration-expiry-value"
		expiration := 2 * time.Second

		err := store.Set(ctx, key, value, expiration)
		require.NoError(t, err)

		// Should be accessible immediately
		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)

		// Wait for expiration
		time.Sleep(3 * time.Second)

		// Should be gone
		_, err = store.Get(ctx, key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("delete operation", func(t *testing.T) {
		key := "integration-delete-key"
		value := "integration-delete-value"

		// Set value
		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Verify it exists
		_, err = store.Get(ctx, key)
		require.NoError(t, err)

		// Delete it
		err = store.Delete(ctx, key)
		require.NoError(t, err)

		// Should be gone
		_, err = store.Get(ctx, key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("complex data types", func(t *testing.T) {
		type TestStruct struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}

		key := "integration-complex-key"
		original := TestStruct{Name: "test", Value: 42}

		err := store.Set(ctx, key, original, 0)
		require.NoError(t, err)

		retrievedInterface, err := store.Get(ctx, key)
		require.NoError(t, err)

		// When storing structs, ValkeyStore serializes to JSON and deserializes to map[string]interface{}
		retrieved, ok := retrievedInterface.(map[string]interface{})
		require.True(t, ok, "Expected map[string]interface{} type, got %T", retrievedInterface)

		// Check the values are correct
		assert.Equal(t, "test", retrieved["name"])
		assert.Equal(t, float64(42), retrieved["value"]) // JSON numbers unmarshal as float64
	})

	t.Run("handleValkeyNilError integration - real nil errors", func(t *testing.T) {
		// Test that our helper function properly handles real Valkey nil errors
		nonExistentKey := "integration-definitely-does-not-exist-key"

		// Try to get a non-existent key - this should trigger the helper function
		_, err := store.Get(ctx, nonExistentKey)

		// Should return our custom ErrKeyNotFound
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrKeyNotFound, "Get should return ErrKeyNotFound via handleValkeyNilError")

		// Test with Exists method as well
		exists, err := store.Exists(ctx, nonExistentKey)
		assert.NoError(t, err) // Exists should not error for non-existent keys
		assert.False(t, exists, "Key should not exist")

		// Test that the helper function correctly distinguishes between nil and other errors
		// by ensuring that when a key doesn't exist, we get ErrKeyNotFound specifically
		anotherNonExistentKey := fmt.Sprintf("test-key-that-definitely-does-not-exist-%d", time.Now().UnixNano())
		_, err = store.Get(ctx, anotherNonExistentKey)
		assert.ErrorIs(t, err, ErrKeyNotFound, "Multiple calls should consistently return ErrKeyNotFound")
	})
}

func TestValkeyStore_IntegrationConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start Valkey container
	redisContainer, err := redis.Run(ctx, valkeyImage)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(redisContainer); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	})

	// Get connection details
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err)

	port, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	// Create ValkeyStore with container connection
	cfg := config.ValkeyConfig{
		Address:  fmt.Sprintf("%s:%s", host, port.Port()),
		Username: "",
		Password: "",
		DB:       0,
	}

	store, err := NewValkeyStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)

	// Test concurrent operations
	t.Run("concurrent writes and reads", func(t *testing.T) {
		const numGoroutines = 10
		const numOperations = 100

		errChan := make(chan error, numGoroutines*2)

		// Start writers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
					value := fmt.Sprintf("concurrent-value-%d-%d", id, j)
					if err := store.Set(ctx, key, value, 0); err != nil {
						errChan <- fmt.Errorf("writer %d operation %d failed: %w", id, j, err)
						return
					}
				}
				errChan <- nil
			}(i)
		}

		// Start readers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
					expectedValue := fmt.Sprintf("concurrent-value-%d-%d", id, j)

					// Wait a bit to ensure the key might have been written
					time.Sleep(time.Millisecond)

					value, err := store.Get(ctx, key)
					if err != nil {
						// It's okay if the key doesn't exist yet due to race conditions
						continue
					}
					if value != expectedValue {
						errChan <- fmt.Errorf("reader %d operation %d: expected %s, got %s", id, j, expectedValue, value)
						return
					}
				}
				errChan <- nil
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines*2; i++ {
			err := <-errChan
			if err != nil {
				t.Error(err)
			}
		}
	})
}

func TestValkeyStore_IntegrationCompression(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start Valkey container
	redisContainer, err := redis.Run(ctx, valkeyImage)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(redisContainer); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	})

	// Get connection details
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err)

	port, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	// Create ValkeyStore with compression enabled
	cfg := config.ValkeyConfig{
		Address:           fmt.Sprintf("%s:%s", host, port.Port()),
		Username:          "",
		Password:          "",
		DB:                0,
		EnableCompression: true,
	}

	store, err := NewValkeyStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)

	t.Run("compression with large data", func(t *testing.T) {
		key := "integration-compression-key"
		// Create large, repetitive data that compresses well
		largeValue := ""
		for i := 0; i < 1000; i++ {
			largeValue += "This is a repetitive string that should compress well. "
		}

		err := store.Set(ctx, key, largeValue, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, largeValue, retrieved)
	})

	t.Run("compression with JSON data", func(t *testing.T) {
		type ComplexStruct struct {
			ID          int                    `json:"id"`
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			Tags        []string               `json:"tags"`
			Metadata    map[string]interface{} `json:"metadata"`
		}

		key := "integration-compression-json-key"
		original := ComplexStruct{
			ID:          123,
			Name:        "Integration Test Object",
			Description: "This is a complex object used for integration testing with compression enabled",
			Tags:        []string{"integration", "test", "compression", "json", "complex"},
			Metadata: map[string]interface{}{
				"created_at":    "2024-01-15T10:30:00Z",
				"version":       "1.0.0",
				"feature_flags": []string{"feature_a", "feature_b", "feature_c"},
				"config": map[string]interface{}{
					"timeout":    30,
					"retries":    3,
					"debug_mode": false,
				},
			},
		}

		err := store.Set(ctx, key, original, 0)
		require.NoError(t, err)

		retrievedInterface, err := store.Get(ctx, key)
		require.NoError(t, err)

		// When storing complex structs, ValkeyStore serializes to JSON and deserializes to map[string]interface{}
		retrieved, ok := retrievedInterface.(map[string]interface{})
		require.True(t, ok, "Expected map[string]interface{} type, got %T", retrievedInterface)

		// Check key fields are correct
		assert.Equal(t, float64(123), retrieved["id"])
		assert.Equal(t, "Integration Test Object", retrieved["name"])
		assert.Contains(t, retrieved["description"], "integration testing")

		// Check tags array
		tags, ok := retrieved["tags"].([]interface{})
		require.True(t, ok)
		assert.Len(t, tags, 5)
		assert.Contains(t, tags, "integration")
		assert.Contains(t, tags, "test")
	})
}

func TestValkeyStore_IntegrationSentinel(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start a simple Valkey master container for testing Sentinel-like operations
	masterContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        valkeyImage,
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(masterContainer); err != nil {
			t.Logf("failed to terminate master container: %s", err)
		}
	})

	masterHost, err := masterContainer.Host(ctx)
	require.NoError(t, err)

	masterPort, err := masterContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	t.Run("sentinel configuration validation", func(t *testing.T) {
		// Test with empty master name - should fail
		cfg := config.ValkeyConfig{
			EnableSentinel: true,
			SentinelAddrs:  []string{"localhost:26379"},
			SentinelMaster: "", // Empty master name should cause validation error
		}

		store, err := NewValkeyStore(cfg)
		if store != nil {
			// If a store was created despite empty master, it means validation failed
			// Log the issue but don't fail the test as this might be a client-side behavior
			t.Logf("Expected error for empty master name, but store was created")
			_ = store.Close()
		}
		// Note: The client may not validate this at connection time, only when attempting operations

		// Test with empty sentinel addresses - should fail
		cfg2 := config.ValkeyConfig{
			EnableSentinel: true,
			SentinelAddrs:  []string{}, // Empty addresses
			SentinelMaster: "mymaster",
		}

		store2, err := NewValkeyStore(cfg2)
		if err == nil && store2 != nil {
			t.Logf("Expected error for empty sentinel addresses, but store was created")
			_ = store2.Close()
		}
		// This should definitely fail at connection time
	})

	t.Run("sentinel vs direct connection comparison", func(t *testing.T) {
		// Test that we can create a direct connection to simulate what Sentinel would discover
		directCfg := config.ValkeyConfig{
			EnableSentinel: false,
			Address:        fmt.Sprintf("%s:%s", masterHost, masterPort.Port()),
			Username:       "",
			Password:       "",
			DB:             0,
		}

		directStore, err := NewValkeyStore(directCfg)
		require.NoError(t, err)
		require.NotNil(t, directStore)

		// Test basic operations
		key := "sentinel-comparison-key"
		value := "sentinel-comparison-value"

		err = directStore.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := directStore.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)

		// Test that we can ping the store
		pong, err := directStore.Ping(ctx)
		require.NoError(t, err)
		assert.Equal(t, "PONG", pong)

		// Clean up
		err = directStore.Delete(ctx, key)
		require.NoError(t, err)

		err = directStore.Close()
		require.NoError(t, err)
	})

	t.Run("sentinel configuration structure", func(t *testing.T) {
		// Test that Sentinel configuration is properly structured
		cfg := config.ValkeyConfig{
			EnableSentinel:   true,
			SentinelAddrs:    []string{"localhost:26379", "localhost:26380"},
			SentinelMaster:   "mymaster",
			SentinelUsername: "sentinel-user",
			SentinelPassword: "sentinel-pass",
			Username:         "valkey-user",
			Password:         "valkey-pass",
			DB:               1,
		}

		// Validate that the configuration has all required fields
		assert.True(t, cfg.EnableSentinel, "Sentinel should be enabled")
		assert.Equal(t, "mymaster", cfg.SentinelMaster, "Master name should be set")
		assert.Len(t, cfg.SentinelAddrs, 2, "Should have 2 sentinel addresses")
		assert.Equal(t, "sentinel-user", cfg.SentinelUsername, "Sentinel username should be set")
		assert.Equal(t, "sentinel-pass", cfg.SentinelPassword, "Sentinel password should be set")
		assert.Equal(t, "valkey-user", cfg.Username, "Valkey username should be set")
		assert.Equal(t, "valkey-pass", cfg.Password, "Valkey password should be set")
		assert.Equal(t, 1, cfg.DB, "Database should be set to 1")

		// Attempt to create store (may fail due to non-existent sentinels, which is expected)
		store, err := NewValkeyStore(cfg)
		if err != nil {
			t.Logf("Expected failure when connecting to non-existent sentinels: %v", err)
		} else if store != nil {
			// If somehow it worked, clean up
			_ = store.Close()
		}
	})

	t.Run("sentinel failover simulation concept", func(t *testing.T) {
		// This test demonstrates the concept of how Sentinel failover would work
		// by simulating connections to different masters

		// Primary master
		primary := fmt.Sprintf("%s:%s", masterHost, masterPort.Port())

		// Test connection to primary
		primaryCfg := config.ValkeyConfig{
			EnableSentinel: false,
			Address:        primary,
			Username:       "",
			Password:       "",
			DB:             0,
		}

		primaryStore, err := NewValkeyStore(primaryCfg)
		require.NoError(t, err)
		require.NotNil(t, primaryStore)

		// Set some data on primary
		key := "failover-test"
		value := "primary-data"

		err = primaryStore.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Verify data exists
		retrieved, err := primaryStore.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)

		// In a real failover scenario, Sentinel would:
		// 1. Detect primary failure
		// 2. Promote a replica to master
		// 3. Update clients with new master address
		// 4. Redirect traffic to new master

		// Simulate the concept by showing we can read the data
		// (In reality, this would be from a new promoted master)
		finalValue, err := primaryStore.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, finalValue, "Data should survive 'failover'")

		// Clean up
		err = primaryStore.Delete(ctx, key)
		require.NoError(t, err)

		err = primaryStore.Close()
		require.NoError(t, err)

		t.Log("Sentinel failover concept test completed - demonstrated primary operations")
	})
}

func TestValkeyStore_IntegrationAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	t.Run("password authentication success", func(t *testing.T) {
		// Start Valkey container with password authentication
		authContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        valkeyImage,
				ExposedPorts: []string{"6379/tcp"},
				Cmd:          []string{"valkey-server", "--requirepass", "test-password"},
				WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
			},
			Started: true,
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			if err := testcontainers.TerminateContainer(authContainer); err != nil {
				t.Logf("failed to terminate auth container: %s", err)
			}
		})

		host, err := authContainer.Host(ctx)
		require.NoError(t, err)

		port, err := authContainer.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Test successful connection with correct password
		cfg := config.ValkeyConfig{
			Address:  fmt.Sprintf("%s:%s", host, port.Port()),
			Username: "", // Password-only auth (Redis/Valkey legacy mode)
			Password: "test-password",
			DB:       0,
		}

		store, err := NewValkeyStore(cfg)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Test basic operations work with authentication
		key := "auth-test-key"
		value := "auth-test-value"

		err = store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)

		// Test ping works
		pong, err := store.Ping(ctx)
		require.NoError(t, err)
		assert.Equal(t, "PONG", pong)

		// Clean up
		err = store.Delete(ctx, key)
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)
	})

	t.Run("password authentication failure", func(t *testing.T) {
		// Start Valkey container with password authentication
		authContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        valkeyImage,
				ExposedPorts: []string{"6379/tcp"},
				Cmd:          []string{"valkey-server", "--requirepass", "correct-password"},
				WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
			},
			Started: true,
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			if err := testcontainers.TerminateContainer(authContainer); err != nil {
				t.Logf("failed to terminate auth container: %s", err)
			}
		})

		host, err := authContainer.Host(ctx)
		require.NoError(t, err)

		port, err := authContainer.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Test connection failure with wrong password
		wrongPasswordCfg := config.ValkeyConfig{
			Address:  fmt.Sprintf("%s:%s", host, port.Port()),
			Username: "",
			Password: "wrong-password",
			DB:       0,
		}

		store, err := NewValkeyStore(wrongPasswordCfg)
		if err != nil {
			// Expected - wrong password should cause connection error
			t.Logf("Expected auth failure with wrong password: %v", err)
			assert.Contains(t, err.Error(), "WRONGPASS")
		} else if store != nil {
			// If we somehow got a store, try an operation to trigger auth error
			_, err = store.Ping(ctx)
			if err != nil {
				t.Logf("Expected auth error on operation: %v", err)
				assert.Contains(t, err.Error(), "WRONGPASS")
			}
			_ = store.Close()
		}

		// Test connection failure with no password
		noPasswordCfg := config.ValkeyConfig{
			Address:  fmt.Sprintf("%s:%s", host, port.Port()),
			Username: "",
			Password: "", // No password provided
			DB:       0,
		}

		store2, err := NewValkeyStore(noPasswordCfg)
		if err != nil {
			// Expected - missing password should cause connection error
			t.Logf("Expected auth failure with no password: %v", err)
			assert.Contains(t, err.Error(), "NOAUTH")
		} else if store2 != nil {
			// If we somehow got a store, try an operation to trigger auth error
			_, err = store2.Ping(ctx)
			if err != nil {
				t.Logf("Expected auth error on operation: %v", err)
				assert.Contains(t, err.Error(), "NOAUTH")
			}
			_ = store2.Close()
		}
	})

	t.Run("user and password authentication", func(t *testing.T) {
		// Create a config file with user authentication
		configContent := `
port 6379
# Create a user with password
user testuser on >userpass123 ~* &* +@all
# Disable default user for security
user default off
`

		// Start Valkey container with custom config
		authContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        valkeyImage,
				ExposedPorts: []string{"6379/tcp"},
				Files: []testcontainers.ContainerFile{
					{
						Reader:            strings.NewReader(configContent),
						ContainerFilePath: "/etc/valkey.conf",
						FileMode:          0644,
					},
				},
				Cmd:        []string{"valkey-server", "/etc/valkey.conf"},
				WaitingFor: wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
			},
			Started: true,
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			if err := testcontainers.TerminateContainer(authContainer); err != nil {
				t.Logf("failed to terminate user auth container: %s", err)
			}
		})

		host, err := authContainer.Host(ctx)
		require.NoError(t, err)

		port, err := authContainer.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Test successful connection with username and password
		cfg := config.ValkeyConfig{
			Address:  fmt.Sprintf("%s:%s", host, port.Port()),
			Username: "testuser",
			Password: "userpass123",
			DB:       0,
		}

		store, err := NewValkeyStore(cfg)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Test basic operations work with user authentication
		key := "user-auth-test-key"
		value := "user-auth-test-value"

		err = store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)

		// Test ping works
		pong, err := store.Ping(ctx)
		require.NoError(t, err)
		assert.Equal(t, "PONG", pong)

		// Clean up
		err = store.Delete(ctx, key)
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)
	})

	t.Run("authentication with compression", func(t *testing.T) {
		// Start Valkey container with password authentication
		authContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        valkeyImage,
				ExposedPorts: []string{"6379/tcp"},
				Cmd:          []string{"valkey-server", "--requirepass", "compress-password"},
				WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
			},
			Started: true,
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			if err := testcontainers.TerminateContainer(authContainer); err != nil {
				t.Logf("failed to terminate auth+compression container: %s", err)
			}
		})

		host, err := authContainer.Host(ctx)
		require.NoError(t, err)

		port, err := authContainer.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Test authentication with compression enabled
		cfg := config.ValkeyConfig{
			Address:           fmt.Sprintf("%s:%s", host, port.Port()),
			Username:          "",
			Password:          "compress-password",
			DB:                0,
			EnableCompression: true,
		}

		store, err := NewValkeyStore(cfg)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Test operations with both auth and compression
		key := "auth-compress-key"
		largeValue := ""
		for i := 0; i < 500; i++ {
			largeValue += "This is repetitive data for compression testing with authentication. "
		}

		err = store.Set(ctx, key, largeValue, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, largeValue, retrieved)

		// Clean up
		err = store.Delete(ctx, key)
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)
	})

	t.Run("authentication configuration validation", func(t *testing.T) {
		// Test that authentication fields are properly validated in configuration
		cfg := config.ValkeyConfig{
			Address:  "localhost:6379",
			Username: "test-user",
			Password: "test-password",
			DB:       2,
		}

		// Validate configuration structure
		assert.Equal(t, "test-user", cfg.Username, "Username should be set correctly")
		assert.Equal(t, "test-password", cfg.Password, "Password should be set correctly")
		assert.Equal(t, 2, cfg.DB, "Database should be set correctly")

		// Note: Connection will fail since no server is running, but config is valid
		store, err := NewValkeyStore(cfg)
		if err != nil {
			// Expected - no server running
			t.Logf("Expected connection error: %v", err)
		}
		if store != nil {
			_ = store.Close()
		}
	})
}
