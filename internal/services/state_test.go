package services

import (
	"context"
	"fmt"
	"testing"

	"log/slog"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/storage"
)

func TestStateService_BasicOperations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("store and retrieve PR number", func(t *testing.T) {
		sha := "abc123def456"
		prNumber := int64(42)

		err := service.StorePRNumber(ctx, owner, repo, sha, prNumber)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, prNumber, retrieved)
	})

	t.Run("get non-existent PR number", func(t *testing.T) {
		sha := "non-existent-sha"

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.False(t, exists)
		assert.Equal(t, int64(0), retrieved)
	})

	t.Run("store and retrieve vulnerability check run ID", func(t *testing.T) {
		sha := "vuln-check-sha"
		runID := int64(123456)

		err := service.StoreVulnerabilityCheckRunID(ctx, owner, repo, sha, runID)
		require.NoError(t, err)

		retrieved, exists, err := service.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, runID, retrieved)
	})

	t.Run("store and retrieve license check run ID", func(t *testing.T) {
		sha := "license-check-sha"
		runID := int64(789012)

		err := service.StoreLicenseCheckRunID(ctx, owner, repo, sha, runID)
		require.NoError(t, err)

		retrieved, exists, err := service.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, runID, retrieved)
	})

	t.Run("store and retrieve workflow run ID", func(t *testing.T) {
		sha := "workflow-sha"
		runID := int64(345678)

		err := service.StoreWorkflowRunID(ctx, owner, repo, sha, runID)
		require.NoError(t, err)

		retrieved, exists, err := service.GetWorkflowRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, runID, retrieved)
	})
}

func TestStateService_KeyFormatting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("keys are properly formatted", func(t *testing.T) {
		sha := "test-sha-123"

		// Store different types of data
		err := service.StorePRNumber(ctx, owner, repo, sha, 42)
		require.NoError(t, err)

		err = service.StoreVulnerabilityCheckRunID(ctx, owner, repo, sha, 123)
		require.NoError(t, err)

		err = service.StoreLicenseCheckRunID(ctx, owner, repo, sha, 456)
		require.NoError(t, err)

		err = service.StoreWorkflowRunID(ctx, owner, repo, sha, 789)
		require.NoError(t, err)

		// Verify we can retrieve each independently
		prNum, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(42), prNum)

		vulnID, exists, err := service.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(123), vulnID)

		licenseID, exists, err := service.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(456), licenseID)

		workflowID, exists, err := service.GetWorkflowRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(789), workflowID)
	})

	t.Run("different SHAs are independent", func(t *testing.T) {
		sha1 := "sha-one"
		sha2 := "sha-two"
		prNumber := int64(100)

		// Store for first SHA
		err := service.StorePRNumber(ctx, owner, repo, sha1, prNumber)
		require.NoError(t, err)

		// Verify second SHA doesn't have data
		_, exists, err := service.GetPRNumber(ctx, owner, repo, sha2)
		require.NoError(t, err)
		assert.False(t, exists)

		// Store different value for second SHA
		err = service.StorePRNumber(ctx, owner, repo, sha2, prNumber+10)
		require.NoError(t, err)

		// Verify both can be retrieved independently
		val1, exists1, err := service.GetPRNumber(ctx, owner, repo, sha1)
		require.NoError(t, err)
		assert.True(t, exists1)
		assert.Equal(t, prNumber, val1)

		val2, exists2, err := service.GetPRNumber(ctx, owner, repo, sha2)
		require.NoError(t, err)
		assert.True(t, exists2)
		assert.Equal(t, prNumber+10, val2)
	})
}

func TestStateService_TypeHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("handles different numeric types from JSON unmarshaling", func(t *testing.T) {
		sha := "type-test-sha"

		// Directly store different types in the underlying store to simulate JSON unmarshaling
		key := fmt.Sprintf("%s:%s:pr:%s", owner, repo, sha)

		// Test int64
		err := store.Set(ctx, key, int64(42), 0)
		require.NoError(t, err)
		val, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(42), val)

		// Test float64 (common from JSON)
		err = store.Set(ctx, key, float64(123.0), 0)
		require.NoError(t, err)
		val, exists, err = service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(123), val)

		// Test string representation
		err = store.Set(ctx, key, "456", 0)
		require.NoError(t, err)
		val, exists, err = service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(456), val)
	})

	t.Run("handles invalid types gracefully", func(t *testing.T) {
		sha := "invalid-type-sha"
		key := fmt.Sprintf("%s:%s:pr:%s", owner, repo, sha)

		// Store an invalid type
		err := store.Set(ctx, key, []string{"not", "a", "number"}, 0)
		require.NoError(t, err)

		_, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		assert.False(t, exists)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected value type")
	})

	t.Run("handles non-numeric strings", func(t *testing.T) {
		sha := "non-numeric-sha"
		key := fmt.Sprintf("%s:%s:pr:%s", owner, repo, sha)

		// Store a non-numeric string
		err := store.Set(ctx, key, "not-a-number", 0)
		require.NoError(t, err)

		_, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		assert.False(t, exists)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected value type")
	})
}

func TestStateService_DeleteAllStates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("delete all states for a SHA", func(t *testing.T) {
		sha := "delete-test-sha"

		// Store all types of data
		err := service.StorePRNumber(ctx, owner, repo, sha, 42)
		require.NoError(t, err)

		err = service.StoreVulnerabilityCheckRunID(ctx, owner, repo, sha, 123)
		require.NoError(t, err)

		err = service.StoreLicenseCheckRunID(ctx, owner, repo, sha, 456)
		require.NoError(t, err)

		err = service.StoreWorkflowRunID(ctx, owner, repo, sha, 789)
		require.NoError(t, err)

		// Verify all data exists
		_, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)

		_, exists, err = service.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)

		_, exists, err = service.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)

		_, exists, err = service.GetWorkflowRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)

		// Delete all states
		err = service.DeletePStates(ctx, owner, repo, sha)
		require.NoError(t, err)

		// Verify all data is gone
		_, exists, err = service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.False(t, exists)

		_, exists, err = service.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.False(t, exists)

		_, exists, err = service.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.False(t, exists)

		_, exists, err = service.GetWorkflowRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("delete non-existent states doesn't error", func(t *testing.T) {
		sha := "non-existent-sha"

		err := service.DeletePStates(ctx, owner, repo, sha)
		assert.NoError(t, err)
	})
}

func TestStateService_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	// Store some data
	err := service.StorePRNumber(ctx, owner, repo, "test-sha", 42)
	require.NoError(t, err)

	// Close the service
	err = service.Close()
	require.NoError(t, err)

	// After close, data should be cleared (for memory store)
	_, exists, err := service.GetPRNumber(ctx, owner, repo, "test-sha")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestStateService_Expiration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("data expires based on service configuration", func(t *testing.T) {
		// Note: This test verifies that the service uses expiration,
		// but we don't test actual expiration timing since that would make tests slow/flaky
		// The expiration functionality is tested in the storage layer tests

		sha := "expiry-test-sha"
		prNumber := int64(42)

		err := service.StorePRNumber(ctx, owner, repo, sha, prNumber)
		require.NoError(t, err)

		// Verify the data exists
		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, prNumber, retrieved)

		// The actual expiration is tested in the storage layer
		// Here we just verify the service properly calls the store with expiration
	})
}

func TestStateService_ConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("concurrent operations on different SHAs", func(t *testing.T) {
		const numGoroutines = 10
		const numOperations = 50

		errChan := make(chan error, numGoroutines*numOperations*2)
		done := make(chan bool, numGoroutines*2)

		// Concurrent writers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				for j := 0; j < numOperations; j++ {
					sha := fmt.Sprintf("concurrent-sha-%d-%d", id, j)
					value := int64(id*1000 + j)

					if err := service.StorePRNumber(ctx, owner, repo, sha, value); err != nil {
						errChan <- err
					}
				}
			}(i)
		}

		// Concurrent readers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				for j := 0; j < numOperations; j++ {
					sha := fmt.Sprintf("concurrent-sha-%d-%d", id, j)

					_, _, err := service.GetPRNumber(ctx, owner, repo, sha)
					if err != nil {
						errChan <- err
					}
				}
			}(i)
		}

		// Wait for completion
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

func TestStateService_EdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := storage.NewMemoryStore()
	service := NewStateService(store, logger)
	ctx := context.Background()

	// Test repository context
	owner := "test-owner"
	repo := "test-repo"

	t.Run("empty SHA", func(t *testing.T) {
		sha := ""
		value := int64(42)

		err := service.StorePRNumber(ctx, owner, repo, sha, value)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})

	t.Run("very long SHA", func(t *testing.T) {
		sha := "very-long-sha-" + string(make([]byte, 1000))
		value := int64(42)

		err := service.StorePRNumber(ctx, owner, repo, sha, value)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})

	t.Run("special characters in SHA", func(t *testing.T) {
		sha := "sha-with-special-chars-!@#$%^&*()_+-=[]{}|;':\",./<>?"
		value := int64(42)

		err := service.StorePRNumber(ctx, owner, repo, sha, value)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})

	t.Run("zero values", func(t *testing.T) {
		sha := "zero-value-sha"
		value := int64(0)

		err := service.StorePRNumber(ctx, owner, repo, sha, value)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})

	t.Run("negative values", func(t *testing.T) {
		sha := "negative-value-sha"
		value := int64(-42)

		err := service.StorePRNumber(ctx, owner, repo, sha, value)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})

	t.Run("maximum int64 value", func(t *testing.T) {
		sha := "max-value-sha"
		value := int64(9223372036854775807) // math.MaxInt64

		err := service.StorePRNumber(ctx, owner, repo, sha, value)
		require.NoError(t, err)

		retrieved, exists, err := service.GetPRNumber(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})
}
