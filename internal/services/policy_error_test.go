package services

import (
	"fmt"
	"net"
	"testing"
)

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "connection refused",
			err:      fmt.Errorf("dial tcp [::1]:8181: connect: connection refused"),
			expected: true,
		},
		{
			name:     "connection timeout",
			err:      fmt.Errorf("dial tcp 127.0.0.1:8181: connect: connection timeout"),
			expected: true,
		},
		{
			name:     "no such host",
			err:      fmt.Errorf("dial tcp: lookup test-opa: no such host"),
			expected: true,
		},
		{
			name:     "network unreachable",
			err:      fmt.Errorf("network is unreachable"),
			expected: true,
		},
		{
			name:     "timeout error",
			err:      fmt.Errorf("timeout occurred"),
			expected: true,
		},
		{
			name:     "non-network error",
			err:      fmt.Errorf("some other error"),
			expected: false,
		},
		{
			name:     "policy evaluation error",
			err:      fmt.Errorf("policy evaluation failed"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNetworkError(tt.err)
			if result != tt.expected {
				t.Errorf("isNetworkError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestNetworkErrorInterface(t *testing.T) {
	// Test with actual net.Error
	var netErr net.Error = &net.DNSError{
		Err:         "no such host",
		Name:        "test-opa",
		Server:      "8.8.8.8",
		IsTimeout:   false,
		IsTemporary: true,
	}

	if !isNetworkError(netErr) {
		t.Error("Expected net.Error to be detected as network error")
	}
}
