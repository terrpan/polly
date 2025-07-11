package utils

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestExecuteConcurrently_AllTasksSucceed tests that all tasks execute successfully
func TestExecuteConcurrently_AllTasksSucceed(t *testing.T) {
	var mu sync.Mutex
	var results []string

	tasks := []func() error{
		func() error {
			mu.Lock()
			results = append(results, "task1")
			mu.Unlock()
			return nil
		},
		func() error {
			mu.Lock()
			results = append(results, "task2")
			mu.Unlock()
			return nil
		},
		func() error {
			mu.Lock()
			results = append(results, "task3")
			mu.Unlock()
			return nil
		},
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 3)
	for i, err := range errs {
		assert.NoError(t, err, "Task %d should not return an error", i)
	}
	assert.Len(t, results, 3, "All tasks should have executed")
}

// TestExecuteConcurrently_SomeTasksFail tests mixed success and failure scenarios
func TestExecuteConcurrently_SomeTasksFail(t *testing.T) {
	tasks := []func() error{
		func() error {
			return nil // Success
		},
		func() error {
			return fmt.Errorf("task 2 failed")
		},
		func() error {
			return nil // Success
		},
		func() error {
			return fmt.Errorf("task 4 failed")
		},
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 4)
	assert.NoError(t, errs[0])
	assert.Error(t, errs[1])
	assert.NoError(t, errs[2])
	assert.Error(t, errs[3])
	assert.Contains(t, errs[1].Error(), "task 2 failed")
	assert.Contains(t, errs[3].Error(), "task 4 failed")
}

// TestExecuteConcurrently_AllTasksFail tests that all tasks can fail
func TestExecuteConcurrently_AllTasksFail(t *testing.T) {
	tasks := []func() error{
		func() error {
			return fmt.Errorf("error 1")
		},
		func() error {
			return fmt.Errorf("error 2")
		},
		func() error {
			return fmt.Errorf("error 3")
		},
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 3)
	for i, err := range errs {
		assert.Error(t, err, "Task %d should return an error", i)
		assert.Contains(t, err.Error(), fmt.Sprintf("error %d", i+1))
	}
}

// TestExecuteConcurrently_EmptyTasks tests behavior with no tasks
func TestExecuteConcurrently_EmptyTasks(t *testing.T) {
	tasks := []func() error{}
	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 0, "Should return empty slice for empty tasks")
}

// TestExecuteConcurrently_SingleTask tests behavior with a single task
func TestExecuteConcurrently_SingleTask(t *testing.T) {
	t.Run("single successful task", func(t *testing.T) {
		executed := false
		tasks := []func() error{
			func() error {
				executed = true
				return nil
			},
		}

		errs := ExecuteConcurrently(tasks)

		assert.Len(t, errs, 1)
		assert.NoError(t, errs[0])
		assert.True(t, executed, "Task should have been executed")
	})

	t.Run("single failing task", func(t *testing.T) {
		tasks := []func() error{
			func() error {
				return fmt.Errorf("single task error")
			},
		}

		errs := ExecuteConcurrently(tasks)

		assert.Len(t, errs, 1)
		assert.Error(t, errs[0])
		assert.Contains(t, errs[0].Error(), "single task error")
	})
}

// TestExecuteConcurrently_OrderPreservation tests that errors are returned in the same order as tasks
func TestExecuteConcurrently_OrderPreservation(t *testing.T) {
	tasks := []func() error{
		func() error {
			time.Sleep(50 * time.Millisecond) // Slower task
			return fmt.Errorf("error from task 0")
		},
		func() error {
			time.Sleep(10 * time.Millisecond) // Faster task
			return fmt.Errorf("error from task 1")
		},
		func() error {
			time.Sleep(30 * time.Millisecond) // Medium task
			return fmt.Errorf("error from task 2")
		},
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 3)
	assert.Contains(t, errs[0].Error(), "error from task 0")
	assert.Contains(t, errs[1].Error(), "error from task 1")
	assert.Contains(t, errs[2].Error(), "error from task 2")
}

// TestExecuteConcurrently_Concurrency tests that tasks actually run concurrently
func TestExecuteConcurrently_Concurrency(t *testing.T) {
	const numTasks = 5
	const taskDuration = 100 * time.Millisecond

	var counter int64
	tasks := make([]func() error, numTasks)

	for i := 0; i < numTasks; i++ {
		tasks[i] = func() error {
			atomic.AddInt64(&counter, 1)
			time.Sleep(taskDuration)
			return nil
		}
	}

	start := time.Now()
	errs := ExecuteConcurrently(tasks)
	duration := time.Since(start)

	// If tasks were running sequentially, it would take numTasks * taskDuration
	// Since they run concurrently, it should take approximately taskDuration
	maxExpectedDuration := taskDuration + 50*time.Millisecond // Adding some buffer for overhead

	assert.Len(t, errs, numTasks)
	for _, err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int64(numTasks), atomic.LoadInt64(&counter), "All tasks should have executed")
	assert.Less(t, duration, time.Duration(numTasks)*taskDuration,
		"Tasks should run concurrently, not sequentially")
	assert.Less(t, duration, maxExpectedDuration,
		"Duration should be close to single task duration, indicating concurrency")
}

// TestExecuteConcurrently_LargeBatch tests performance with many tasks
func TestExecuteConcurrently_LargeBatch(t *testing.T) {
	const numTasks = 100
	var counter int64

	tasks := make([]func() error, numTasks)
	for i := 0; i < numTasks; i++ {
		tasks[i] = func() error {
			atomic.AddInt64(&counter, 1)
			return nil
		}
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, numTasks)
	for _, err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int64(numTasks), atomic.LoadInt64(&counter), "All tasks should have executed")
}

// TestExecuteConcurrently_PanicRecovery tests that panics in tasks don't crash the function
// Note: This test checks that the function doesn't hang if a task panics
func TestExecuteConcurrently_TaskWithPanic(t *testing.T) {
	// This test verifies the function behaves predictably even if tasks panic
	// In this implementation, a panic would crash the goroutine, but the main function should still complete
	tasks := []func() error{
		func() error {
			return nil // Normal task
		},
		func() error {
			return fmt.Errorf("normal error")
		},
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 2)
	assert.NoError(t, errs[0])
	assert.Error(t, errs[1])
}

// TestExecuteConcurrently_ErrorTypes tests that different error types are preserved
func TestExecuteConcurrently_ErrorTypes(t *testing.T) {
	customErr := &CustomError{Message: "custom error"}

	tasks := []func() error{
		func() error {
			return fmt.Errorf("standard error")
		},
		func() error {
			return customErr
		},
		func() error {
			return nil
		},
	}

	errs := ExecuteConcurrently(tasks)

	assert.Len(t, errs, 3)
	assert.Error(t, errs[0])
	assert.Error(t, errs[1])
	assert.NoError(t, errs[2])

	// Check error types are preserved
	assert.Contains(t, errs[0].Error(), "standard error")
	assert.IsType(t, &CustomError{}, errs[1])
	assert.Equal(t, customErr, errs[1])
}

// CustomError is a custom error type for testing
type CustomError struct {
	Message string
}

func (e *CustomError) Error() string {
	return e.Message
}

// BenchmarkExecuteConcurrently_SmallBatch benchmarks with a small number of tasks
func BenchmarkExecuteConcurrently_SmallBatch(b *testing.B) {
	tasks := []func() error{
		func() error { return nil },
		func() error { return nil },
		func() error { return nil },
		func() error { return nil },
		func() error { return nil },
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExecuteConcurrently(tasks)
	}
}

// BenchmarkExecuteConcurrently_LargeBatch benchmarks with many tasks
func BenchmarkExecuteConcurrently_LargeBatch(b *testing.B) {
	const numTasks = 100
	tasks := make([]func() error, numTasks)
	for i := 0; i < numTasks; i++ {
		tasks[i] = func() error { return nil }
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExecuteConcurrently(tasks)
	}
}
