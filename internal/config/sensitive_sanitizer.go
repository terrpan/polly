// Package config provides configuration settings for the application
// this file contains types and functions for handling sensitive data in the logger and storage
package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
)

// Sensitive data patterns for detection and sanitization
const (
	// Pattern for password-like fields (case insensitive)
	PatternPassword = `(?i).*password.*`

	// Pattern for secret-like fields (case insensitive)
	PatternSecret = `(?i).*secret.*`

	// Pattern for key-like fields (case insensitive)
	PatternKey = `(?i).*key.*`

	// Pattern for token-like fields (case insensitive)
	PatternToken = `(?i).*token.*`

	// Pattern for PEM private keys
	PatternPrivateKey = `-----BEGIN.*PRIVATE KEY-----`
)

// Error sanitization patterns for removing sensitive data from error messages
const (
	// Pattern for password parameters in URLs or error messages
	PatternPasswordParam = `password=\S+`

	// Pattern for token parameters in URLs or error messages
	PatternTokenParam = `token=\S+`

	// Pattern for key parameters in URLs or error messages
	PatternKeyParam = `key=\S+`

	// Pattern for secret parameters in URLs or error messages
	PatternSecretParam = `secret=\S+`

	// Pattern for complete PEM private keys in error messages
	PatternPEMPrivateKey = `-----BEGIN[^-]*PRIVATE KEY-----[^-]*-----END[^-]*PRIVATE KEY-----`
)

// Replacement values for sanitized data
const (
	RedactedValue      = "[REDACTED]"
	RedactedPassword   = "password=[REDACTED]"
	RedactedToken      = "token=[REDACTED]"
	RedactedKey        = "key=[REDACTED]"
	RedactedSecret     = "secret=[REDACTED]"
	RedactedPrivateKey = "[REDACTED_PRIVATE_KEY]"
)

// SanitizeConfigForLogging returns a map representation of the config with sensitive fields redacted
func SanitizeConfigForLogging(cfg *Config) map[string]interface{} {
	result := make(map[string]interface{})

	v := reflect.ValueOf(cfg).Elem()
	t := reflect.TypeOf(cfg).Elem()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		fieldName := fieldType.Name
		if field.CanInterface() {
			result[fieldName] = sanitizeValue(field.Interface())
		}
	}

	return result
}

// sanitizeValue recursively sanitizes configuration values
func sanitizeValue(value interface{}) interface{} {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Struct:
		result := make(map[string]interface{})
		t := reflect.TypeOf(value)

		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := t.Field(i)

			if field.CanInterface() {
				fieldName := fieldType.Name
				result[fieldName] = sanitizeValue(field.Interface())
			}
		}

		return result
	case reflect.String:
		str := v.String()
		if isSensitiveField(str) {
			return "[REDACTED]"
		}

		return str
	default:
		return value
	}
}

// isSensitiveField checks if a string value looks like sensitive data
func isSensitiveField(value string) bool {
	if value == "" {
		return false
	}

	// Patterns that indicate sensitive data
	sensitivePatterns := []string{
		PatternPassword,
		PatternSecret,
		PatternKey,
		PatternToken,
		PatternPrivateKey,
	}

	for _, pattern := range sensitivePatterns {
		if matched, err := regexp.MatchString(pattern, value); matched {
			return true
		} else if err != nil {
			fmt.Printf("Error matching regex pattern %s: %v", pattern, err)
			continue
		}
	}

	return false
}

// SanitizeError sanitizes error messages to remove sensitive information
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}

	message := err.Error()
	message = sanitizeString(message)

	return errors.New(message)
}

// sanitizeString removes sensitive patterns from strings
func sanitizeString(s string) string {
	// Define patterns and their replacements using constants
	patterns := []struct {
		pattern     string
		replacement string
	}{
		{PatternPasswordParam, RedactedPassword},
		{PatternTokenParam, RedactedToken},
		{PatternKeyParam, RedactedKey},
		{PatternSecretParam, RedactedSecret},
		{PatternPEMPrivateKey, RedactedPrivateKey},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		s = re.ReplaceAllString(s, p.replacement)
	}

	return s
}
