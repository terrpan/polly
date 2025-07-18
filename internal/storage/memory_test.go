package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_BasicOperations(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	t.Run("set and get string", func(t *testing.T) {
		key := "test-key"
		value := "test-value"

		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)
	})

	t.Run("set and get int64", func(t *testing.T) {
		key := "test-int-key"
		value := int64(42)

		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)
	})

	t.Run("set and get complex object", func(t *testing.T) {
		key := "test-object-key"
		value := map[string]interface{}{
			"name": "test",
			"id":   123,
			"tags": []string{"a", "b", "c"},
		}

		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)
	})

	t.Run("get non-existent key", func(t *testing.T) {
		_, err := store.Get(ctx, "non-existent-key")
		assert.Equal(t, ErrKeyNotFound, err)
	})
}

func TestMemoryStore_Exists(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	t.Run("key exists", func(t *testing.T) {
		key := "existing-key"
		value := "test-value"

		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		exists, err := store.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("key does not exist", func(t *testing.T) {
		exists, err := store.Exists(ctx, "non-existent-key")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	t.Run("delete existing key", func(t *testing.T) {
		key := "delete-me"
		value := "test-value"

		// Set the key
		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Verify it exists
		exists, err := store.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		// Delete it
		err = store.Delete(ctx, key)
		require.NoError(t, err)

		// Verify it's gone
		exists, err = store.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)

		// Verify Get returns error
		_, err = store.Get(ctx, key)
		assert.Equal(t, ErrKeyNotFound, err)
	})

	t.Run("delete non-existent key", func(t *testing.T) {
		// Should not error
		err := store.Delete(ctx, "non-existent-key")
		assert.NoError(t, err)
	})
}

func TestMemoryStore_Expiration(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	t.Run("key expires after duration", func(t *testing.T) {
		key := "expiring-key"
		value := "test-value"
		expiration := 100 * time.Millisecond

		// Set with expiration
		err := store.Set(ctx, key, value, expiration)
		require.NoError(t, err)

		// Key should exist initially
		exists, err := store.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		// Get should work initially
		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Key should be expired
		exists, err = store.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)

		// Get should return error
		_, err = store.Get(ctx, key)
		assert.Equal(t, ErrKeyNotFound, err)
	})

	t.Run("key without expiration does not expire", func(t *testing.T) {
		key := "no-expiry-key"
		value := "test-value"

		// Set without expiration (0 duration)
		err := store.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Wait a bit
		time.Sleep(50 * time.Millisecond)

		// Key should still exist
		exists, err := store.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrieved)
	})

	t.Run("overwrite key removes old expiration", func(t *testing.T) {
		key := "overwrite-key"
		value1 := "test-value-1"
		value2 := "test-value-2"

		// Set with short expiration
		err := store.Set(ctx, key, value1, 50*time.Millisecond)
		require.NoError(t, err)

		// Immediately overwrite with no expiration
		err = store.Set(ctx, key, value2, 0)
		require.NoError(t, err)

		// Wait past original expiration
		time.Sleep(100 * time.Millisecond)

		// Key should still exist with new value
		retrieved, err := store.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value2, retrieved)
	})
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	t.Run("concurrent reads and writes", func(t *testing.T) {
		const numGoroutines = 10
		const numOperations = 100

		// Channel to collect errors
		errChan := make(chan error, numGoroutines*numOperations)
		done := make(chan bool, numGoroutines*2)

		// Start multiple writers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					value := fmt.Sprintf("value-%d-%d", id, j)
					if err := store.Set(ctx, key, value, 0); err != nil {
						errChan <- err
					}
				}
			}(i)
		}

		// Start multiple readers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					// Try to read - might not exist yet, that's OK
					_, err := store.Get(ctx, key)
					if err != nil && err != ErrKeyNotFound {
						errChan <- err
					}
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines*2; i++ {
			<-done
		}

		// Check for errors
		close(errChan)
		for err := range errChan {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	})
}

func TestMemoryStore_Close(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Add some data
	err := store.Set(ctx, "test-key", "test-value", 0)
	require.NoError(t, err)

	// Verify data exists
	exists, err := store.Exists(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, exists)

	// Close the store
	err = store.Close()
	require.NoError(t, err)

	// After close, data should be cleared
	exists, err = store.Exists(ctx, "test-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMemoryStore_Overwrite(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	key := "overwrite-key"
	value1 := "original-value"
	value2 := int64(42)

	// Set initial value
	err := store.Set(ctx, key, value1, 0)
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value1, retrieved)

	// Overwrite with different type
	err = store.Set(ctx, key, value2, 0)
	require.NoError(t, err)

	retrieved, err = store.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value2, retrieved)
}
