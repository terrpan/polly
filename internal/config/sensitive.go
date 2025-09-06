// Package config provides configuration settings for the application
// this file contains types and functions for handling sensitive data in the logger and storage
package config

import "encoding/json"

// SecureString represents a string that contains sensitive information and needs to be redacted in logs and error messages
type SecureString struct {
	value string
}

// NewSecureString creates a new SecureString with the given value
func NewSecureString(value string) SecureString {
	return SecureString{value: value}
}

// String returns the Stringer interface, always returning [REDACTED] to prevent sensitive data leakage
func (s SecureString) String() string {
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

// MarshalJSON implements json.Marshaler to always redact values in JSON output
func (s SecureString) MarshalJSON() ([]byte, error) {
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
