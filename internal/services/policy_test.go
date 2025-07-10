package services

import (
	"context"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/terrpan/polly/internal/clients"
)

func TestNewPolicyService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	policyService := NewPolicyService(opaClient, logger)

	assert.NotNil(t, policyService)
	assert.Equal(t, opaClient, policyService.opaClient)
	assert.Equal(t, logger, policyService.logger)
}

func TestPolicyService_HelloInput_Structure(t *testing.T) {
	input := HelloInput{
		Message: "test message",
	}

	assert.Equal(t, "test message", input.Message)
}

func TestPolicyService_VulnerabilityPolicyResult_Structure(t *testing.T) {
	result := VulnerabilityPolicyResult{
		Compliant:            true,
		TotalVulnerabilities: 5,
		NonCompliantCount:    2,
		NonCompliantVulnerabilities: []VulnerabilityPolicyVuln{
			{
				ID:       "CVE-2021-1234",
				Package:  "test-package",
				Version:  "1.0.0",
				Severity: "HIGH",
				Score:    7.5,
			},
		},
	}

	assert.True(t, result.Compliant)
	assert.Equal(t, 5, result.TotalVulnerabilities)
	assert.Equal(t, 2, result.NonCompliantCount)
	assert.Len(t, result.NonCompliantVulnerabilities, 1)
	assert.Equal(t, "CVE-2021-1234", result.NonCompliantVulnerabilities[0].ID)
}

// TestPolicyService_EvaluatePolicy_ErrorHandling tests error scenarios in policy evaluation
func TestPolicyService_EvaluatePolicy_ErrorHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	service := NewPolicyService(opaClient, logger)

	ctx := context.Background()

	// Test hello policy with invalid context
	ctx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	input := HelloInput{Message: "hello"}
	passed, err := service.CheckHelloPolicy(ctx, input)
	assert.Error(t, err)
	assert.False(t, passed)
}

// TestPolicyService_CheckVulnerabilityPolicy_EdgeCases tests edge cases for vulnerability policy
func TestPolicyService_CheckVulnerabilityPolicy_EdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	service := NewPolicyService(opaClient, logger)

	ctx := context.Background()

	tests := []struct {
		name    string
		payload *VulnerabilityPayload
		wantErr bool
	}{
		{
			name: "empty payload",
			payload: &VulnerabilityPayload{
				Summary: VulnerabilitySummary{},
			},
			wantErr: true, // Will fail due to no OPA connection
		},
		{
			name: "payload with vulnerabilities",
			payload: &VulnerabilityPayload{
				Summary: VulnerabilitySummary{
					Critical: 1,
					High:     2,
					Medium:   3,
					Low:      4,
				},
				Vulnerabilities: []Vulnerability{
					{
						ID:       "CVE-2024-1234",
						Package:  Package{Name: "test-package", Version: "1.0.0"},
						Severity: "CRITICAL",
					},
				},
			},
			wantErr: true, // Will fail due to no OPA connection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.CheckVulnerabilityPolicy(ctx, tt.payload)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestPolicyService_ContextTimeout tests context timeout handling
func TestPolicyService_ContextTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	service := NewPolicyService(opaClient, logger)

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give the timeout a chance to expire
	time.Sleep(10 * time.Millisecond)

	input := HelloInput{Message: "hello"}
	passed, err := service.CheckHelloPolicy(ctx, input)
	assert.Error(t, err)
	assert.False(t, passed)
	assert.Contains(t, err.Error(), "context")
}
