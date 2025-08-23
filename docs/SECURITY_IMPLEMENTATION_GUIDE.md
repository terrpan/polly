# Security and Credential Handling Implementation Guide

This guide provides step-by-step instructions for implementing the security improvements defined in [ADR-011](ADR-011-security-credential-handling-improvements.md).

## Prerequisites

- Go 1.21+
- Existing Polly development environment
- Understanding of the current service architecture

## Phase 1: Configuration Sanitization (Foundation)

### Step 1.1: Add UUID Dependency

```bash
go get github.com/google/uuid@latest
go mod tidy
```

### Step 1.2: Create Secure Configuration Types

Create `internal/config/secure_types.go`:

```go
package config

import (
	"encoding/json"
)

// SecureString represents a sensitive string value that redacts itself in logs and JSON
type SecureString struct {
	value string
}

// NewSecureString creates a new SecureString with the given value
func NewSecureString(value string) SecureString {
	return SecureString{value: value}
}

// String implements the Stringer interface, returning [REDACTED] for non-empty values
func (s SecureString) String() string {
	if s.value == "" {
		return ""
	}
	return "[REDACTED]"
}

// Value returns the actual string value (use with caution)
func (s SecureString) Value() string {
	return s.value
}

// IsEmpty returns true if the secure string has no value
func (s SecureString) IsEmpty() bool {
	return s.value == ""
}

// MarshalJSON implements json.Marshaler to redact values in JSON output
func (s SecureString) MarshalJSON() ([]byte, error) {
	if s.value == "" {
		return json.Marshal("")
	}
	return json.Marshal("[REDACTED]")
}

// UnmarshalJSON implements json.Unmarshaler for proper deserialization
func (s *SecureString) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	s.value = value
	return nil
}
```

### Step 1.3: Create Configuration Sanitizer

Create `internal/config/sanitizer.go`:

```go
package config

import (
	"errors"
	"reflect"
	"regexp"
)

// SanitizeConfigForLogging returns a map representation of the config with sensitive fields redacted
func SanitizeConfigForLogging(cfg *Config) map[string]interface{} {
	result := make(map[string]interface{})
<<<<<<< Updated upstream
	
	v := reflect.ValueOf(cfg).Elem()
	t := reflect.TypeOf(cfg).Elem()
	
=======

	v := reflect.ValueOf(cfg).Elem()
	t := reflect.TypeOf(cfg).Elem()

>>>>>>> Stashed changes
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		fieldName := fieldType.Name
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		if field.CanInterface() {
			result[fieldName] = sanitizeValue(field.Interface())
		}
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	return result
}

// sanitizeValue recursively sanitizes configuration values
func sanitizeValue(value interface{}) interface{} {
	v := reflect.ValueOf(value)
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	switch v.Kind() {
	case reflect.Struct:
		result := make(map[string]interface{})
		t := reflect.TypeOf(value)
<<<<<<< Updated upstream
		
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := t.Field(i)
			
=======

		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := t.Field(i)

>>>>>>> Stashed changes
			if field.CanInterface() {
				fieldName := fieldType.Name
				result[fieldName] = sanitizeValue(field.Interface())
			}
		}
		return result
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
	case reflect.String:
		str := v.String()
		if isSensitiveField(str) {
			return "[REDACTED]"
		}
		return str
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
	default:
		return value
	}
}

// isSensitiveField checks if a string value looks like sensitive data
func isSensitiveField(value string) bool {
	if value == "" {
		return false
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// Patterns that indicate sensitive data
	sensitivePatterns := []string{
		`(?i).*password.*`,
		`(?i).*secret.*`,
		`(?i).*key.*`,
		`(?i).*token.*`,
		`-----BEGIN.*PRIVATE KEY-----`,
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	for _, pattern := range sensitivePatterns {
		if matched, _ := regexp.MatchString(pattern, value); matched {
			return true
		}
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	return false
}

// SanitizeError sanitizes error messages to remove sensitive information
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
<<<<<<< Updated upstream
	
	message := err.Error()
	message = sanitizeString(message)
	
=======

	message := err.Error()
	message = sanitizeString(message)

>>>>>>> Stashed changes
	return errors.New(message)
}

// sanitizeString removes sensitive patterns from strings
func sanitizeString(s string) string {
	patterns := []struct {
		pattern     string
		replacement string
	}{
		{`password=\S+`, `password=[REDACTED]`},
		{`token=\S+`, `token=[REDACTED]`},
		{`key=\S+`, `key=[REDACTED]`},
		{`secret=\S+`, `secret=[REDACTED]`},
		{`-----BEGIN[^-]*PRIVATE KEY-----[^-]*-----END[^-]*PRIVATE KEY-----`, `[REDACTED_PRIVATE_KEY]`},
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		s = re.ReplaceAllString(s, p.replacement)
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	return s
}
```

### Step 1.4: Update Configuration Structs

Update `internal/config/config.go` to use `SecureString` for sensitive fields and add request ID configuration:

```go
// GitHubAppConfig represents the configuration for a GitHub App
type GitHubAppConfig struct {
	AppID          int64        `mapstructure:"app_id"`
	InstallationID int64        `mapstructure:"installation_id"`
	PrivateKeyPath string       `mapstructure:"private_key_path"`
	PrivateKey     SecureString `mapstructure:"private_key"` // Changed to SecureString
	BaseURL        string       `mapstructure:"base_url"`
	UploadURL      string       `mapstructure:"upload_url"`
}

// ValkeyConfig represents the configuration for Valkey
type ValkeyConfig struct {
	Address           string       `mapstructure:"address"`
	Username          string       `mapstructure:"username"`
	Password          SecureString `mapstructure:"password"` // Changed to SecureString
	DB                int          `mapstructure:"db"`
	EnableSentinel    bool         `mapstructure:"enable_sentinel"`
	SentinelAddrs     []string     `mapstructure:"sentinel_addrs"`
	SentinelMaster    string       `mapstructure:"sentinel_master"`
	SentinelUsername  string       `mapstructure:"sentinel_username"`
	SentinelPassword  SecureString `mapstructure:"sentinel_password"` // Changed to SecureString
	EnableCompression bool         `mapstructure:"enable_compression"`
	EnableOTel        bool         `mapstructure:"enable_otel"`
}

// LoggerConfig represents the configuration for the logger
type LoggerConfig struct {
	Level         string `mapstructure:"level"`
	JSONOutput    bool   `mapstructure:"json_output"`
	AddSource     bool   `mapstructure:"add_source"`
	EnableRequestID bool `mapstructure:"enable_request_id"` // New: Enable request ID correlation
}

// Config represents the application configuration
type Config struct {
	Port        int               `mapstructure:"port"`
	GitHubToken SecureString      `mapstructure:"github_token"` // Changed to SecureString
	Logger      LoggerConfig      `mapstructure:"logger"`
	GitHubApp   GitHubAppConfig   `mapstructure:"github_app"`
	Opa         OpaConfig         `mapstructure:"opa"`
	OTLP        OTLPConfig        `mapstructure:"otlp"`
	Storage     StorageConfig     `mapstructure:"storage"`
}
```

Also update the default configuration to enable request ID by default:

```go
// Update the defaultConfig variable
var defaultConfig = Config{
	Port:        8080,
	GitHubToken: NewSecureString(""),
	Logger: LoggerConfig{
		Level:           "debug",
		JSONOutput:      true,
		AddSource:       false,
		EnableRequestID: true, // Enable by default for better observability
	},
	// ... rest of config
}
```

### Step 1.5: Update Configuration Loading

Update the `LoadGitHubAppConfig` function in `internal/config/config.go`:

```go
func LoadGitHubAppConfig() (*clients.GitHubAppConfig, error) {
	appConfig := AppConfig.GitHubApp

	// Validate required fields
	if appConfig.AppID == 0 {
		return nil, fmt.Errorf("GITHUB_APP_ID is required")
	}

	if appConfig.InstallationID == 0 {
		return nil, fmt.Errorf("GITHUB_INSTALLATION_ID is required")
	}

	// Handle GitHub Enterprise URLs
	if appConfig.BaseURL != "" && appConfig.BaseURL != "https://api.github.com" {
		if _, err := url.Parse(appConfig.BaseURL); err != nil {
			return nil, fmt.Errorf("invalid GITHUB_BASE_URL: %w", err)
		}
	}

	if appConfig.UploadURL != "" && appConfig.UploadURL != "https://uploads.github.com" {
		if _, err := url.Parse(appConfig.UploadURL); err != nil {
			return nil, fmt.Errorf("invalid GITHUB_UPLOAD_URL: %w", err)
		}
	}

	var (
		privateKey []byte
		err        error
	)

	// Try to load private key from direct content first
	switch {
	case !appConfig.PrivateKey.IsEmpty():
		privateKey = []byte(appConfig.PrivateKey.Value()) // Use Value() method
	case appConfig.PrivateKeyPath != "":
		// Load from file path
		privateKey, err = os.ReadFile(appConfig.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
	default:
		return nil, fmt.Errorf("either GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH is required")
	}

	return &clients.GitHubAppConfig{
		AppID:          appConfig.AppID,
		InstallationID: appConfig.InstallationID,
		PrivateKey:     privateKey,
		BaseURL:        appConfig.BaseURL,
		UploadURL:      appConfig.UploadURL,
	}, nil
}
```

## Phase 2: Request ID Middleware (Correlation)

### Request ID Configuration

The request ID feature is now configurable via the `POLLY_LOGGER_ENABLE_REQUEST_ID` environment variable:

```bash
# Enable request ID correlation (default: true)
POLLY_LOGGER_ENABLE_REQUEST_ID=true

<<<<<<< Updated upstream
# Disable request ID correlation  
=======
# Disable request ID correlation
>>>>>>> Stashed changes
POLLY_LOGGER_ENABLE_REQUEST_ID=false
```

**Benefits of making it configurable:**
- **Performance**: Teams can disable if request correlation isn't needed
- **Privacy**: Some environments may prefer not to track request IDs
- **Flexibility**: Gradual rollout or A/B testing of the feature
- **Debugging**: Can be temporarily disabled if issues arise

### Step 2.1: Create Request ID Middleware

Create `internal/app/request_id.go`:

```go
package app

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

const requestIDKey = "request_id"

// RequestIDMiddleware adds request ID correlation to all HTTP requests
func RequestIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		// 1. Check for existing request ID from load balancer/proxy
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = r.Header.Get("X-Trace-Id")
		}
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		// 2. Generate UUID if no external ID (independent of tracing)
		if requestID == "" {
			requestID = uuid.New().String()
		}
<<<<<<< Updated upstream
		
		// 3. Store in context for use throughout the request
		ctx = context.WithValue(ctx, requestIDKey, requestID)
		
		// 4. Return in response header for debugging
		w.Header().Set("X-Request-Id", requestID)
		
=======

		// 3. Store in context for use throughout the request
		ctx = context.WithValue(ctx, requestIDKey, requestID)

		// 4. Return in response header for debugging
		w.Header().Set("X-Request-Id", requestID)

>>>>>>> Stashed changes
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID := ctx.Value(requestIDKey); requestID != nil {
		return requestID.(string)
	}
	return ""
}
```

### Step 2.2: Update Route Registration

Update `internal/app/routes.go` to conditionally apply request ID middleware:

```go
package app

import (
	"net/http"
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	"github.com/terrpan/polly/internal/config"
)

// RegisterRoutes sets up all HTTP routes with conditional middleware
func RegisterRoutes(container *Container) *http.ServeMux {
	mux := http.NewServeMux()

	// Create base handlers
	webhookHandler := jsonContentTypeMiddleware(container.WebhookRouter.ServeHTTP)
	healthHandler := jsonContentTypeMiddleware(container.HealthHandler.ServeHTTP)

	// Conditionally apply request ID middleware based on configuration
	if config.AppConfig.Logger.EnableRequestID {
		webhookHandler = RequestIDMiddleware(webhookHandler)
		healthHandler = RequestIDMiddleware(healthHandler)
	}

	mux.HandleFunc("POST /webhook", webhookHandler)
	mux.HandleFunc("GET /health", healthHandler)

	return mux
}
```

### Step 2.3: Enhanced Logger with Request ID

Update `internal/config/logger.go`:

```go
package config

import (
	"context"
	"log/slog"
	"os"
)

// NewLogger creates a new slog.Logger based on the application configuration.
func NewLogger() *slog.Logger {
	level := parseLogLevel(AppConfig.Logger.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: AppConfig.Logger.AddSource,
	}

	var handler slog.Handler
	if AppConfig.Logger.JSONOutput {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// NewLoggerWithRequestID creates a logger with request ID correlation
func NewLoggerWithRequestID(ctx context.Context) *slog.Logger {
	logger := NewLogger()
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// Only add request ID if the feature is enabled and ID is available
	if config.AppConfig.Logger.EnableRequestID {
		if requestID := ctx.Value("request_id"); requestID != nil {
			logger = logger.With("request_id", requestID)
		}
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	return logger
}

// parseLogLevel parses the log level from a string and returns the corresponding slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
```

### Step 2.4: Enhanced Telemetry Helper

Update `internal/telemetry/helper.go` to add request ID correlation:

```go
// Add this method to the Helper struct
func (t *Helper) StartSpanWithRequestID(
	ctx context.Context,
	name string,
) (context.Context, oteltrace.Span) {
	// Start span (works even if tracing disabled - returns NoOp span)
	ctx, span := t.tracer.Start(ctx, name)
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// Add request ID to span attributes if feature is enabled and ID is available
	if config.AppConfig.Logger.EnableRequestID {
		if requestID := ctx.Value("request_id"); requestID != nil {
			span.SetAttributes(attribute.String("request.id", requestID.(string)))
		}
	}
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	return ctx, span
}
```

## Phase 3: Audit and Fix Credential Exposure

### Step 3.1: Fix GitHub Client Logging

Update `internal/clients/github.go` to remove direct logging:

```go
// Remove or replace the problematic fmt.Printf at line 55
// Before:
// fmt.Printf("failed to configure GitHub Enterprise URLs: %v\n", err)

// After: Return error to caller for proper handling
client, err = client.WithEnterpriseURLs(baseURL, upURL)
if err != nil {
	// Return error to caller instead of logging here
	return nil, fmt.Errorf("failed to configure GitHub Enterprise URLs: %w", err)
}
```

### Step 3.2: Update Service Layer Patterns

Update all services to use request-aware logging. Example pattern:

```go
// In any service method
func (s *SomeService) someMethod(ctx context.Context, ...) error {
	logger := config.NewLoggerWithRequestID(ctx)
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	result, err := s.client.SomeOperation(...)
	if err != nil {
		// Sanitize before logging
		sanitizedErr := config.SanitizeError(err)
<<<<<<< Updated upstream
		logger.ErrorContext(ctx, "Operation failed", 
			"operation", "some_operation",
			"error", sanitizedErr)
		
		return fmt.Errorf("operation failed: %w", sanitizedErr)
	}
	
	logger.InfoContext(ctx, "Operation completed successfully",
		"operation", "some_operation")
	
=======
		logger.ErrorContext(ctx, "Operation failed",
			"operation", "some_operation",
			"error", sanitizedErr)

		return fmt.Errorf("operation failed: %w", sanitizedErr)
	}

	logger.InfoContext(ctx, "Operation completed successfully",
		"operation", "some_operation")

>>>>>>> Stashed changes
	return nil
}
```

### Step 3.3: Update Handler Patterns

Update handlers to use request-aware logging. Example for `internal/handlers/webhook_router.go`:

```go
func (r *WebhookRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Use enhanced telemetry helper
	ctx, span := r.telemetry.StartSpanWithRequestID(req.Context(), "webhook.handle")
	defer span.End()
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// Log with request ID correlation
	logger := config.NewLoggerWithRequestID(ctx)
	logger.InfoContext(ctx, "Webhook received",
		"method", req.Method,
		"path", req.URL.Path,
	)
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// ... rest of handler logic
}
```

## Phase 4: Security Testing Framework

### Step 4.1: Configuration Security Tests

Create `internal/config/security_test.go`:

```go
package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureString_String(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "empty string",
			value:    "",
			expected: "",
		},
		{
			name:     "non-empty string",
			value:    "secret-password",
			expected: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSecureString(tt.value)
			assert.Equal(t, tt.expected, s.String())
		})
	}
}

func TestSecureString_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "empty string",
			value:    "",
			expected: `""`,
		},
		{
			name:     "non-empty string",
			value:    "secret-password",
			expected: `"[REDACTED]"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSecureString(tt.value)
			result, err := json.Marshal(s)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestSanitizeConfigForLogging(t *testing.T) {
	config := &Config{
		Port:        8080,
		GitHubToken: NewSecureString("ghp_secret_token"),
		GitHubApp: GitHubAppConfig{
			AppID:      12345,
			PrivateKey: NewSecureString("-----BEGIN RSA PRIVATE KEY-----"),
		},
		Storage: StorageConfig{
			Valkey: ValkeyConfig{
				Address:  "localhost:6379",
				Password: NewSecureString("secret-password"),
			},
		},
	}

	sanitized := SanitizeConfigForLogging(config)
<<<<<<< Updated upstream
	
	// Convert to JSON to check serialization
	jsonData, err := json.Marshal(sanitized)
	require.NoError(t, err)
	
	jsonStr := string(jsonData)
	
=======

	// Convert to JSON to check serialization
	jsonData, err := json.Marshal(sanitized)
	require.NoError(t, err)

	jsonStr := string(jsonData)

>>>>>>> Stashed changes
	// Verify no credentials appear in the sanitized output
	assert.NotContains(t, jsonStr, "ghp_secret_token")
	assert.NotContains(t, jsonStr, "-----BEGIN RSA PRIVATE KEY-----")
	assert.NotContains(t, jsonStr, "secret-password")
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// Verify redaction markers are present
	assert.Contains(t, jsonStr, "[REDACTED]")
}

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "error with password",
			input:    "connection failed: password=secret123 invalid",
			expected: "connection failed: password=[REDACTED] invalid",
		},
		{
			name:     "error with token",
			input:    "auth failed: token=ghp_abc123 expired",
			expected: "auth failed: token=[REDACTED] expired",
		},
		{
			name:     "error with private key",
			input:    "key parsing failed: -----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----",
			expected: "key parsing failed: [REDACTED_PRIVATE_KEY]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.input)
			sanitized := SanitizeError(err)
			assert.Equal(t, tt.expected, sanitized.Error())
		})
	}
}

func TestNoCredentialLeaksInConfigOutput(t *testing.T) {
	// Test that config doesn't leak credentials in various output scenarios
	config := &Config{
		GitHubToken: NewSecureString("ghp_secret_token"),
		GitHubApp: GitHubAppConfig{
			PrivateKey: NewSecureString("-----BEGIN RSA PRIVATE KEY-----"),
		},
		Storage: StorageConfig{
			Valkey: ValkeyConfig{
				Password: NewSecureString("secret-password"),
			},
		},
	}

	// Test String() representation
	configStr := fmt.Sprintf("%+v", config)
	assert.NotContains(t, configStr, "ghp_secret_token")
	assert.NotContains(t, configStr, "-----BEGIN RSA PRIVATE KEY-----")
	assert.NotContains(t, configStr, "secret-password")

	// Test JSON marshaling
	jsonData, err := json.Marshal(config)
	require.NoError(t, err)
	jsonStr := string(jsonData)
	assert.NotContains(t, jsonStr, "ghp_secret_token")
	assert.NotContains(t, jsonStr, "-----BEGIN RSA PRIVATE KEY-----")
	assert.NotContains(t, jsonStr, "secret-password")
}
```

### Step 4.2: Request ID Middleware Tests

Create `internal/app/request_id_test.go`:

```go
package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestIDMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		requestHeaders map[string]string
		expectNewID   bool
	}{
		{
			name: "uses existing X-Request-Id",
			requestHeaders: map[string]string{
				"X-Request-Id": "external-request-123",
			},
			expectNewID: false,
		},
		{
			name: "uses existing X-Trace-Id",
			requestHeaders: map[string]string{
				"X-Trace-Id": "external-trace-456",
			},
			expectNewID: false,
		},
		{
			name:          "generates new ID when none provided",
			requestHeaders: map[string]string{},
			expectNewID:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequestID string
			var capturedContext context.Context

			handler := RequestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
				capturedContext = r.Context()
				capturedRequestID = GetRequestID(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			// Check response header
			responseRequestID := recorder.Header().Get("X-Request-Id")
			assert.NotEmpty(t, responseRequestID)
			assert.Equal(t, capturedRequestID, responseRequestID)

			// Check context value
			assert.NotEmpty(t, capturedRequestID)
			assert.Equal(t, capturedRequestID, GetRequestID(capturedContext))

			if !tt.expectNewID {
				// Should use the provided ID
				for _, headerValue := range tt.requestHeaders {
					if capturedRequestID == headerValue {
						return // Found the expected ID
					}
				}
				t.Errorf("Expected to use provided request ID, but got: %s", capturedRequestID)
			} else {
				// Should generate new UUID (36 characters with dashes)
				assert.Len(t, capturedRequestID, 36)
				assert.Contains(t, capturedRequestID, "-")
			}
		})
	}
}

func TestRequestIDConfiguration(t *testing.T) {
	t.Run("request ID in logs when enabled", func(t *testing.T) {
		// Set up config with request ID enabled
		originalConfig := config.AppConfig
		defer func() { config.AppConfig = originalConfig }()
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		config.AppConfig = &config.Config{
			Logger: config.LoggerConfig{
				EnableRequestID: true,
			},
		}

		ctx := context.WithValue(context.Background(), "request_id", "test-id-123")
		logger := config.NewLoggerWithRequestID(ctx)
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		// Verify logger includes request ID
		// Note: This would require capturing log output to fully test
		assert.NotNil(t, logger)
	})

	t.Run("no request ID in logs when disabled", func(t *testing.T) {
		// Set up config with request ID disabled
		originalConfig := config.AppConfig
		defer func() { config.AppConfig = originalConfig }()
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		config.AppConfig = &config.Config{
			Logger: config.LoggerConfig{
				EnableRequestID: false,
			},
		}

		ctx := context.WithValue(context.Background(), "request_id", "test-id-123")
		logger := config.NewLoggerWithRequestID(ctx)
<<<<<<< Updated upstream
		
=======

>>>>>>> Stashed changes
		// Verify logger doesn't include request ID
		// Note: This would require capturing log output to fully test
		assert.NotNil(t, logger)
	})
}

func TestGetRequestID(t *testing.T) {
	t.Run("returns empty string when no request ID in context", func(t *testing.T) {
		ctx := context.Background()
		requestID := GetRequestID(ctx)
		assert.Empty(t, requestID)
	})

	t.Run("returns request ID when present in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "request_id", "test-id-123")
		requestID := GetRequestID(ctx)
		assert.Equal(t, "test-id-123", requestID)
	})
}
```

### Step 4.3: Integration Security Tests

Create `internal/app/security_integration_test.go`:

```go
package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndToEndNoCredentialExposure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a test container with mocked dependencies
	container := &Container{
		// Initialize with test configuration that includes credentials
	}

	// Set up routes with middleware
	mux := RegisterRoutes(container)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test webhook endpoint
	webhookPayload := map[string]interface{}{
		"action": "opened",
		"pull_request": map[string]interface{}{
			"id": 123,
			"head": map[string]interface{}{
				"sha": "abc123",
			},
		},
		"repository": map[string]interface{}{
			"owner": map[string]interface{}{
				"login": "testowner",
			},
			"name": "testrepo",
		},
	}

	payloadJSON, err := json.Marshal(webhookPayload)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", server.URL+"/webhook", bytes.NewBuffer(payloadJSON))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")

	// Capture response
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify request ID is present in response
	requestID := resp.Header.Get("X-Request-Id")
	assert.NotEmpty(t, requestID)
	assert.Len(t, requestID, 36) // UUID format

	// Additional security checks could include:
	// - Monitoring log output for credentials
	// - Checking error responses for sensitive data
	// - Verifying trace data doesn't contain credentials
}

func TestConfigurationSanitizationInProduction(t *testing.T) {
	// Test that configuration logging doesn't expose credentials
	// This would typically involve capturing log output and scanning for patterns
<<<<<<< Updated upstream
	
=======

>>>>>>> Stashed changes
	// Example: Set up logger capture and verify no credentials appear
	// in startup logs or error scenarios
}
```

## Verification Steps

### After Phase 1 (Configuration Sanitization)
1. Run tests: `go test ./internal/config/...`
2. Verify config fields use `SecureString`
3. Test JSON marshaling doesn't expose credentials
4. Verify `String()` methods redact sensitive data

### After Phase 2 (Request ID Middleware)
1. Run tests: `go test ./internal/app/...`
2. Test with request ID enabled:
   ```bash
   POLLY_LOGGER_ENABLE_REQUEST_ID=true go run cmd/server/main.go
   ```
   - Verify `X-Request-Id` headers in responses
   - Check logs contain `request_id` field
3. Test with request ID disabled:
   ```bash
   POLLY_LOGGER_ENABLE_REQUEST_ID=false go run cmd/server/main.go
   ```
   - Verify no `X-Request-Id` headers in responses
   - Check logs don't contain `request_id` field
4. Verify request IDs work with and without tracing enabled

### After Phase 3 (Credential Exposure Fixes)
1. Search codebase for `fmt.Printf` and similar patterns
2. Verify error messages are sanitized
3. Test service layer logging patterns
4. Run full integration tests

### After Phase 4 (Security Testing)
1. Run all security tests: `go test -tags=security ./...`
2. Run integration tests: `go test ./...`
3. Verify no credential patterns in log output
4. Test error scenarios for credential leaks

## Rollback Strategy

If issues are encountered:

1. **Phase 1**: Revert `SecureString` changes by changing fields back to `string` type
2. **Phase 2**: Remove middleware from route registration
3. **Phase 3**: Restore original client logging if needed
4. **Phase 4**: Tests can be disabled without affecting functionality

Each phase is designed to be independently deployable and reversible.

## Production Deployment

1. Deploy with feature flag to enable/disable new security features
2. Monitor logs for any issues with request ID correlation
3. Verify credential redaction is working in production logs
4. Gradually enable security features across all environments

This implementation guide provides a safe, step-by-step approach to implementing comprehensive security improvements while maintaining system reliability and backward compatibility.
