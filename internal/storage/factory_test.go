package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
