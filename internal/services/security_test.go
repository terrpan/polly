package services

import (
"context"
"testing"
"log/slog"
"os"

"github.com/stretchr/testify/assert"
"github.com/terrpan/polly/internal/clients"
)

func TestNewSecurityService(t *testing.T) {
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
githubClient := clients.NewGitHubClient(context.Background())

service := NewSecurityService(githubClient, logger)

assert.NotNil(t, service)
assert.Equal(t, githubClient, service.githubClient)
assert.Equal(t, logger, service.logger)
}

func TestSecurityService_VulnerabilityPayload_Structure(t *testing.T) {
payload := VulnerabilityPayload{
Type: "vulnerability_json",
Metadata: PayloadMetadata{
ToolName:   "trivy",
ScanTarget: "package.json",
},
Vulnerabilities: []Vulnerability{
{
ID:       "CVE-2021-1234",
Severity: "HIGH",
Package: Package{
Name:    "test-package",
Version: "1.0.0",
},
},
},
Summary: VulnerabilitySummary{
TotalVulnerabilities: 1,
High:                 1,
},
}

assert.Equal(t, "vulnerability_json", payload.Type)
assert.Equal(t, "trivy", payload.Metadata.ToolName)
assert.Len(t, payload.Vulnerabilities, 1)
assert.Equal(t, "CVE-2021-1234", payload.Vulnerabilities[0].ID)
assert.Equal(t, 1, payload.Summary.TotalVulnerabilities)
}
