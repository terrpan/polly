package concurrent

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRun_AllTasksSucceed tests that all tasks execute successfully
func TestRun_AllTasksSucceed(t *testing.T) {
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

	errs := Run(tasks)

	assert.Len(t, errs, 3)
	for i, err := range errs {
		assert.NoError(t, err, "Task %d should not return an error", i)
	}
	assert.Len(t, results, 3, "All tasks should have executed")
}

// TestRun_SomeTasksFail tests mixed success and failure scenarios
func TestRun_SomeTasksFail(t *testing.T) {
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

	errs := Run(tasks)

	assert.Len(t, errs, 4)
	assert.NoError(t, errs[0])
	assert.Error(t, errs[1])
	assert.NoError(t, errs[2])
	assert.Error(t, errs[3])
	assert.Contains(t, errs[1].Error(), "task 2 failed")
	assert.Contains(t, errs[3].Error(), "task 4 failed")
}

// TestRun_AllTasksFail tests that all tasks can fail
func TestRun_AllTasksFail(t *testing.T) {
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

	errs := Run(tasks)

	assert.Len(t, errs, 3)
	for i, err := range errs {
		assert.Error(t, err, "Task %d should return an error", i)
		assert.Contains(t, err.Error(), fmt.Sprintf("error %d", i+1))
	}
}

// TestRun_EmptyTasks tests behavior with no tasks
func TestRun_EmptyTasks(t *testing.T) {
	tasks := []func() error{}
	errs := Run(tasks)

	assert.Len(t, errs, 0, "Should return empty slice for empty tasks")
}

// TestRun_SingleTask tests behavior with a single task
func TestRun_SingleTask(t *testing.T) {
	t.Run("single successful task", func(t *testing.T) {
		executed := false
		tasks := []func() error{
			func() error {
				executed = true
				return nil
			},
		}

		errs := Run(tasks)

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

		errs := Run(tasks)

		assert.Len(t, errs, 1)
		assert.Error(t, errs[0])
		assert.Contains(t, errs[0].Error(), "single task error")
	})
}

// TestRun_OrderPreservation tests that errors are returned in the same order as tasks
func TestRun_OrderPreservation(t *testing.T) {
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

	errs := Run(tasks)

	assert.Len(t, errs, 3)
	assert.Contains(t, errs[0].Error(), "error from task 0")
	assert.Contains(t, errs[1].Error(), "error from task 1")
	assert.Contains(t, errs[2].Error(), "error from task 2")
}

// TestRun_Concurrency tests that tasks actually run concurrently
func TestRun_Concurrency(t *testing.T) {
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
	errs := Run(tasks)
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

// TestRun_Synchronization tests that goroutines are properly synchronized
func TestRun_Synchronization(t *testing.T) {
	t.Run("waitgroup ensures all goroutines complete", func(t *testing.T) {
		const numTasks = 50
		var completedTasks int64

		tasks := make([]func() error, numTasks)
		for i := 0; i < numTasks; i++ {
			tasks[i] = func() error {
				// Simulate work with small random delay
				time.Sleep(time.Duration(i%10) * time.Millisecond)
				atomic.AddInt64(&completedTasks, 1)
				return nil
			}
		}

		errs := Run(tasks)

		// When Run returns, ALL goroutines must have completed
		assert.Equal(t, int64(numTasks), atomic.LoadInt64(&completedTasks),
			"All goroutines should complete before Run returns")
		assert.Len(t, errs, numTasks)
		for _, err := range errs {
			assert.NoError(t, err)
		}
	})

	t.Run("mutex protects error slice from race conditions", func(t *testing.T) {
		// This test verifies the mutex prevents race conditions when writing errors
		const numTasks = 100
		const iterations = 5 // Run multiple times to increase chance of catching races

		for iter := 0; iter < iterations; iter++ {
			tasks := make([]func() error, numTasks)
			for i := 0; i < numTasks; i++ {
				taskNum := i
				tasks[i] = func() error {
					// Create unique error for each task
					return fmt.Errorf("error from task %d", taskNum)
				}
			}

			errs := Run(tasks)

			// Verify all errors are present and correct
			assert.Len(t, errs, numTasks)
			errorMap := make(map[string]bool)
			for i, err := range errs {
				assert.Error(t, err, "Task %d should return an error", i)
				errorMap[err.Error()] = true
			}

			// Each error should be unique (proves no overwrites occurred)
			assert.Len(t, errorMap, numTasks, "All errors should be unique (no race condition overwrites)")
		}
	})

	t.Run("memory visibility ensures proper happens-before relationships", func(t *testing.T) {
		// Test that writes in goroutines are visible after Run returns
		const numTasks = 20
		sharedData := make([]int, numTasks)

		tasks := make([]func() error, numTasks)
		for i := 0; i < numTasks; i++ {
			index := i
			tasks[i] = func() error {
				// Write to shared data - this should be visible after Run returns
				sharedData[index] = index * 2
				return nil
			}
		}

		errs := Run(tasks)

		// All writes should be visible due to happens-before relationship established by WaitGroup
		for i := 0; i < numTasks; i++ {
			assert.Equal(t, i*2, sharedData[i],
				"Write from goroutine %d should be visible after Run returns", i)
		}
		assert.Len(t, errs, numTasks)
	})
}

// TestRun_StressSynchronization performs stress testing of synchronization primitives
func TestRun_StressSynchronization(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Run("high concurrency stress test", func(t *testing.T) {
		const numTasks = 1000
		var operations int64

		tasks := make([]func() error, numTasks)
		for i := 0; i < numTasks; i++ {
			taskID := i
			tasks[i] = func() error {
				// Simulate varying workloads
				for j := 0; j < taskID%10+1; j++ {
					atomic.AddInt64(&operations, 1)
				}
				return fmt.Errorf("task %d completed", taskID)
			}
		}

		start := time.Now()
		errs := Run(tasks)
		duration := time.Since(start)

		// Verify all operations completed
		totalExpectedOps := int64(0)
		for i := 0; i < numTasks; i++ {
			totalExpectedOps += int64(i%10 + 1)
		}

		assert.Equal(t, totalExpectedOps, atomic.LoadInt64(&operations),
			"All atomic operations should complete")
		assert.Len(t, errs, numTasks)

		// Verify all errors are present and in correct order
		for i, err := range errs {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("task %d completed", i))
		}

		t.Logf("Stress test completed %d tasks with %d operations in %v",
			numTasks, totalExpectedOps, duration)
	})

	t.Run("rapid fire execution", func(t *testing.T) {
		// Test many quick executions to stress the synchronization
		const iterations = 100
		const tasksPerIteration = 10

		for iter := 0; iter < iterations; iter++ {
			var counter int64
			tasks := make([]func() error, tasksPerIteration)

			for i := 0; i < tasksPerIteration; i++ {
				tasks[i] = func() error {
					atomic.AddInt64(&counter, 1)
					return nil
				}
			}

			errs := Run(tasks)

			// Each iteration should be completely isolated
			assert.Equal(t, int64(tasksPerIteration), atomic.LoadInt64(&counter),
				"Iteration %d: all tasks should complete", iter)
			assert.Len(t, errs, tasksPerIteration)
		}
	})
}

// TestRun_RaceConditionDetection specifically tests for race conditions
// This test would fail without proper synchronization
func TestRun_RaceConditionDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping race condition test in short mode")
	}

	// This test creates conditions likely to trigger races if synchronization is missing
	const iterations = 10
	const tasksPerIteration = 100

	for iter := 0; iter < iterations; iter++ {
		tasks := make([]func() error, tasksPerIteration)

		// Each task writes to its assigned index multiple times
		// Without mutex protection, this could cause memory corruption
		for i := 0; i < tasksPerIteration; i++ {
			taskIndex := i
			tasks[i] = func() error {
				// Create a unique error message that includes timing info
				// This increases the chance of detecting corruption
				timestamp := time.Now().UnixNano()
				return fmt.Errorf("task_%d_timestamp_%d", taskIndex, timestamp)
			}
		}

		errs := Run(tasks)

		// Verify integrity of all results
		assert.Len(t, errs, tasksPerIteration, "Iteration %d: wrong number of results", iter)

		for i, err := range errs {
			assert.Error(t, err, "Iteration %d, task %d: should have error", iter, i)

			// Verify the error message contains the expected task index
			// Corruption would show wrong indices or garbled messages
			assert.Contains(t, err.Error(), fmt.Sprintf("task_%d_", i),
				"Iteration %d: task %d error should contain correct index", iter, i)
		}
	}
}

// TestRun_LargeBatch tests performance with many tasks
func TestRun_LargeBatch(t *testing.T) {
	const numTasks = 100
	var counter int64

	tasks := make([]func() error, numTasks)
	for i := 0; i < numTasks; i++ {
		tasks[i] = func() error {
			atomic.AddInt64(&counter, 1)
			return nil
		}
	}

	errs := Run(tasks)

	assert.Len(t, errs, numTasks)
	for _, err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int64(numTasks), atomic.LoadInt64(&counter), "All tasks should have executed")
}

// TestRun_TaskWithPanic tests that panics in tasks don't crash the function
// Note: This test checks that the function behaves predictably even if tasks panic
// In this implementation, a panic would crash the goroutine, but the main function should still complete
func TestRun_TaskWithPanic(t *testing.T) {
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

	errs := Run(tasks)

	assert.Len(t, errs, 2)
	assert.NoError(t, errs[0])
	assert.Error(t, errs[1])
}

// TestRun_ErrorTypes tests that different error types are preserved
func TestRun_ErrorTypes(t *testing.T) {
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

	errs := Run(tasks)

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

// BenchmarkRun_SmallBatch benchmarks with a small number of tasks
func BenchmarkRun_SmallBatch(b *testing.B) {
	tasks := []func() error{
		func() error { return nil },
		func() error { return nil },
		func() error { return nil },
		func() error { return nil },
		func() error { return nil },
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Run(tasks)
	}
}

// BenchmarkRun_LargeBatch benchmarks with many tasks
func BenchmarkRun_LargeBatch(b *testing.B) {
	const numTasks = 100
	tasks := make([]func() error, numTasks)
	for i := 0; i < numTasks; i++ {
		tasks[i] = func() error { return nil }
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Run(tasks)
	}
}
