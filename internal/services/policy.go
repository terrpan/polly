package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/terrpan/polly/internal/clients"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	helloPolicyPath         = "/v1/data/playground/hello"
	licensePolicyPath       = "/v1/data/playground/license"
	vulnerabilityPolicyPath = "/v1/data/playground/vulnerability"
)

type PolicyService struct {
	opaClient *clients.OPAClient
	logger    *slog.Logger
}

type PolicyCheckResult struct {
	Result bool `json:"result"`
}

type HelloInput struct {
	Message string `json:"message"`
}

type VulnerabilityPolicyVuln struct {
	ID           string  `json:"id"`
	Package      string  `json:"package"`
	Version      string  `json:"version"`
	Severity     string  `json:"severity"`
	Score        float64 `json:"score,omitempty"`
	FixedVersion string  `json:"fixed_version,omitempty"`
}

type VulnerabilityPolicyResult struct {
	Compliant                   bool                      `json:"compliant"`
	CompliantCount              int                       `json:"compliant_count"`
	NonCompliantCount           int                       `json:"non_compliant_count"`
	NonCompliantVulnerabilities []VulnerabilityPolicyVuln `json:"non_compliant_vulnerabilities"`
	TotalVulnerabilities        int                       `json:"total_vulnerabilities"`
}

// NewPolicyService initializes a new PolicyService with the provided OPA client and logger.
func NewPolicyService(opaClient *clients.OPAClient, logger *slog.Logger) *PolicyService {
	return &PolicyService{
		opaClient: opaClient,
		logger:    logger,
	}
}

// evaluatePolicy is a helper function to evaluate a policy with the given input.
func evaluatePolicy[T any, R any](ctx context.Context, service *PolicyService, policyPath string, input T) (R, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "policy.evaluate")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.path", policyPath),
	)

	var zero R

	// Wrap input in the format OPA expects: {"input": {...}}
	opaPayload := map[string]interface{}{
		"input": input,
	}

	service.logger.DebugContext(ctx, "Evaluating policy", "path", policyPath, "input", input, "payload", opaPayload)
	resp, err := service.opaClient.EvaluatePolicy(ctx, policyPath, opaPayload)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		service.logger.ErrorContext(ctx, "Failed to evaluate policy",
			"error", err,
			"path", policyPath,
			"input", input)
		return zero, err
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("opa.response_code", resp.StatusCode))
	if resp.StatusCode != http.StatusOK {
		span.SetAttributes(attribute.String("error", "policy evaluation failed"))
		service.logger.ErrorContext(ctx, "Policy evaluation failed",
			"status", resp.Status,
			"path", policyPath,
			"input", input)
		return zero, fmt.Errorf("policy evaluation failed: status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		service.logger.ErrorContext(ctx, "Failed to read response body",
			"error", err,
			"path", policyPath,
			"input", input)
		return zero, err
	}

	var policyResponse struct {
		Result R `json:"result"`
	}
	if err := json.Unmarshal(body, &policyResponse); err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		service.logger.ErrorContext(ctx, "Failed to unmarshal policy response",
			"error", err,
			"path", policyPath,
			"input", input)
		return zero, err
	}

	return policyResponse.Result, nil
}

// CheckHelloPolicy evaluates the hello policy with the given input.
func (s *PolicyService) CheckHelloPolicy(ctx context.Context, input HelloInput) (bool, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "policy.check_hello")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.type", "hello"),
		attribute.String("input.message", input.Message),
	)

	s.logger.DebugContext(ctx, "Checking hello policy", "input", input)

	result, err := evaluatePolicy[HelloInput, bool](ctx, s, helloPolicyPath, input)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to check hello policy", "error", err)
		return false, err
	}

	span.SetAttributes(attribute.Bool("policy.result", result))
	s.logger.InfoContext(ctx, "Hello policy check completed", "result", result)
	return result, nil
}

// CheckVulnerabilityPolicy evaluates the vulnerability policy with the given payload.
func (s *PolicyService) CheckVulnerabilityPolicy(ctx context.Context, input *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "policy.check_vulnerability")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.type", "vulnerability"),
		attribute.Int("input.vulnerability_count", len(input.Vulnerabilities)),
		attribute.String("input.scan_target", input.Metadata.ScanTarget),
		attribute.String("input.tool_name", input.Metadata.ToolName),
	)

	s.logger.DebugContext(ctx, "Checking vulnerability policy",
		"vulnerability_count", len(input.Vulnerabilities),
		"scan_target", input.Metadata.ScanTarget,
		"tool_name", input.Metadata.ToolName)

	result, err := evaluatePolicy[*VulnerabilityPayload, VulnerabilityPolicyResult](ctx, s, vulnerabilityPolicyPath, input)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to check vulnerability policy", "error", err)
		return VulnerabilityPolicyResult{}, err
	}

	span.SetAttributes(
		attribute.Bool("policy.compliant", result.Compliant),
		attribute.Int("policy.total_vulnerabilities", result.TotalVulnerabilities),
		attribute.Int("policy.non_compliant_count", result.NonCompliantCount),
	)
	s.logger.InfoContext(ctx, "Vulnerability policy check completed",
		"compliant", result.Compliant,
		"total_vulnerabilities", result.TotalVulnerabilities,
		"non_compliant_count", result.NonCompliantCount)
	return result, nil
}
