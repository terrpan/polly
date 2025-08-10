// Package concurrent provides utilities for running tasks concurrently.
package concurrent

import "sync"

// Run executes a slice of tasks in parallel and returns their errors.
// The returned slice has the same length as the input tasks, with each
// error at the same index as its corresponding task.
func Run(tasks []func() error) []error {
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

	errs := make([]error, len(tasks))
	wg.Add(len(tasks))

	for i, task := range tasks {
		go func(i int, task func() error) {
			defer wg.Done()

			err := task()

			mu.Lock()

			errs[i] = err

			mu.Unlock()
		}(i, task)
	}

	wg.Wait()

	return errs
}
