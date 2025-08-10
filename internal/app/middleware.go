// Package app provides the application and dependency injection container.
// This file contains HTTP middleware for the application.
package app

import "net/http"

// jsonContentType is a constant for the Content-Type header value used in the middleware
const jsonContent = "application/json"

// jsonContentMiddleware is a middleware that sets the Content-Type header to application/json
func jsonContentTypeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", jsonContent)
		next.ServeHTTP(w, r)
	}
}
