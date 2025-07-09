package services

import (
"testing"
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
Compliant:               true,
TotalVulnerabilities:    5,
NonCompliantCount:       2,
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
