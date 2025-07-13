package utils

import "sync"

// ExecuteConcurrently runs a slice of tasks in parallel and returns their errors.
func ExecuteConcurrently(tasks []func() error) []error {
	var wg sync.WaitGroup
	errs := make([]error, len(tasks))
	wg.Add(len(tasks))
	for i, task := range tasks {
		go func(i int, task func() error) {
			defer wg.Done()
			errs[i] = task()
		}(i, task)
	}
	wg.Wait()
	return errs
}
