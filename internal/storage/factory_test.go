package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/terrpan/polly/internal/config"
)

func TestNewStore_Memory(t *testing.T) {
	cfg := config.StorageConfig{
		Type: "memory",
	}

	store, err := NewStore(cfg)
	require.NoError(t, err)
	assert.NotNil(t, store)

	// Verify it's a memory store
	_, ok := store.(*MemoryStore)
	assert.True(t, ok, "Expected MemoryStore type")

	// Test basic functionality
	ctx := context.Background()
	err = store.Set(ctx, "test-key", "test-value", 0)
	assert.NoError(t, err)

	value, err := store.Get(ctx, "test-key")
	assert.NoError(t, err)
	assert.Equal(t, "test-value", value)

	err = store.Close()
	assert.NoError(t, err)
}

func TestNewStore_Valkey(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		cfg := config.StorageConfig{
			Type: "valkey",
			Valkey: config.ValkeyConfig{
				Address:  "localhost:16379", // Use a port that's definitely not running
				Username: "",
				Password: "",
				DB:       0,
			},
		}

		store, err := NewStore(cfg)
		// We expect this to fail since no Valkey server is running on port 16379
		// but the error should be a connection error, not a configuration error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create Valkey store")
		assert.Nil(t, store)
	})

	t.Run("invalid configuration gets caught", func(t *testing.T) {
		// Test that the factory properly attempts to create Valkey store
		// even if it will fail due to connection issues
		cfg := config.StorageConfig{
			Type: "valkey",
			Valkey: config.ValkeyConfig{
				Address: "", // Invalid address
			},
		}

		store, err := NewStore(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create Valkey store")
		assert.Nil(t, store)
	})
}

func TestNewStore_InvalidType(t *testing.T) {
	cfg := config.StorageConfig{
		Type: "invalid-type",
	}

	store, err := NewStore(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidType))
	assert.Contains(t, err.Error(), "unsupported storage type invalid-type")
	assert.Nil(t, store)
}

func TestNewStore_EmptyType(t *testing.T) {
	cfg := config.StorageConfig{
		Type: "",
	}

	store, err := NewStore(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidType))
	assert.Contains(t, err.Error(), "unsupported storage type")
	assert.Nil(t, store)
}

func TestStoreType_Constants(t *testing.T) {
	// Test that the constants are correctly defined
	assert.Equal(t, StoreType("memory"), StoreTypeMemory)
	assert.Equal(t, StoreType("valkey"), StoreTypeValkey)

	// Test string conversion
	assert.Equal(t, "memory", string(StoreTypeMemory))
	assert.Equal(t, "valkey", string(StoreTypeValkey))
}

func TestNewStore_TypeStringMatching(t *testing.T) {
	t.Run("string matches constant", func(t *testing.T) {
		cfg := config.StorageConfig{
			Type: string(StoreTypeMemory),
		}

		store, err := NewStore(cfg)
		require.NoError(t, err)
		assert.NotNil(t, store)

		_, ok := store.(*MemoryStore)
		assert.True(t, ok)

		err = store.Close()
		assert.NoError(t, err)
	})

	t.Run("case sensitivity", func(t *testing.T) {
		cfg := config.StorageConfig{
			Type: "MEMORY", // Different case
		}

		store, err := NewStore(cfg)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidType))
		assert.Nil(t, store)
	})
}

// Integration tests for the factory with real Valkey instance
func TestNewStore_IntegrationValkey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start Valkey container
	redisContainer, err := redis.Run(ctx, "valkey/valkey:8-alpine")
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

	t.Run("create valkey store with container", func(t *testing.T) {
		cfg := config.StorageConfig{
			Type: "valkey",
			Valkey: config.ValkeyConfig{
				Address:  fmt.Sprintf("%s:%s", host, port.Port()),
				Username: "",
				Password: "",
				DB:       0,
			},
		}

		store, err := NewStore(cfg)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Verify it's a valkey store
		_, ok := store.(*ValkeyStore)
		assert.True(t, ok, "Expected ValkeyStore type")

		// Test basic functionality with real connection
		err = store.Set(ctx, "integration-factory-test-key", "integration-factory-test-value", 0)
		require.NoError(t, err)

		value, err := store.Get(ctx, "integration-factory-test-key")
		require.NoError(t, err)
		assert.Equal(t, "integration-factory-test-value", value)

		// Test ping
		pong, err := store.Ping(ctx)
		require.NoError(t, err)
		assert.Equal(t, "PONG", pong)
	})

	t.Run("create valkey store with compression", func(t *testing.T) {
		cfg := config.StorageConfig{
			Type: "valkey",
			Valkey: config.ValkeyConfig{
				Address:           fmt.Sprintf("%s:%s", host, port.Port()),
				Username:          "",
				Password:          "",
				DB:                0,
				EnableCompression: true,
			},
		}

		store, err := NewStore(cfg)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Test with large data that benefits from compression
		largeValue := ""
		for i := 0; i < 100; i++ {
			largeValue += "This is a test string that should compress well when repeated. "
		}

		err = store.Set(ctx, "integration-compression-key", largeValue, 10*time.Second)
		require.NoError(t, err)

		value, err := store.Get(ctx, "integration-compression-key")
		require.NoError(t, err)
		assert.Equal(t, largeValue, value)
	})
}

func TestNewStore_IntegrationFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("valkey store with invalid connection", func(t *testing.T) {
		cfg := config.StorageConfig{
			Type: "valkey",
			Valkey: config.ValkeyConfig{
				Address:  "localhost:99999", // Invalid port
				Username: "",
				Password: "",
				DB:       0,
			},
		}

		_, err := NewStore(cfg)
		// The store creation should fail with invalid port error
		assert.Error(t, err, "Expected error for invalid port")
		assert.Contains(t, err.Error(), "invalid port")
	})
}
