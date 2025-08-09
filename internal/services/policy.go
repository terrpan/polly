package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/telemetry"
)

const (
	licensePolicyPath       = "/v1/data/compliance/license_report"
	vulnerabilityPolicyPath = "/v1/data/compliance/vulnerability_report"
)

// Policy evaluation errors
var (
	ErrUnknownPolicyType = errors.New("unknown policy type")
	ErrPolicyEvaluation  = errors.New("policy evaluation failed")
	ErrSystemUnavailable = errors.New("system unavailable") // OPA connection, network issues
)

// isNetworkError checks if an error is related to network connectivity
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common network error patterns
	errStr := err.Error()
	networkPatterns := []string{
		"dial tcp",
		"connect: connection refused",
		"connect: connection timeout",
		"no such host",
		"network is unreachable",
		"timeout",
	}

	for _, pattern := range networkPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Check for net.Error interface
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	return false
}

// PolicyEvaluator interface for factory pattern
type PolicyEvaluator interface {
	PolicyType() string
	PolicyPath() string
	Evaluate(ctx context.Context, payload any) (any, error)
}

// PolicyService provides methods to evaluate policies using OPA
type PolicyService struct {
	opaClient  *clients.OPAClient
	logger     *slog.Logger
	telemetry  *telemetry.TelemetryHelper
	evaluators map[string]PolicyEvaluator // Factory registry
}

// VulnerabilityPolicyVuln represents a vulnerability in the policy evaluation result
type VulnerabilityPolicyVuln struct {
	ID           string  `json:"id"`
	Package      string  `json:"package"`
	Version      string  `json:"version"`
	Severity     string  `json:"severity"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	Score        float64 `json:"score,omitempty"`
}

// VulnerabilityPolicyResult represents the result of vulnerability policy evaluation
type VulnerabilityPolicyResult struct {
	NonCompliantVulnerabilities []VulnerabilityPolicyVuln `json:"non_compliant_vulnerabilities"`
	CompliantCount              int                       `json:"compliant_count"`
	NonCompliantCount           int                       `json:"non_compliant_count"`
	TotalVulnerabilities        int                       `json:"total_vulnerabilities"`
	Compliant                   bool                      `json:"compliant"`
}

// SBOMPolicyResult represents the result of SBOM policy evaluation
type SBOMPolicyResult struct {
	NonCompliantLicenses   []string              `json:"non_compliant_licenses"`
	NonCompliantComponents []SBOMPolicyComponent `json:"non_compliant_components"`
	ConditionalComponents  []SBOMPolicyComponent `json:"conditional_components"`
	AllowedLicenses        []string              `json:"allowed_licenses"`
	TotalComponents        int                   `json:"total_components"`
	CompliantComponents    int                   `json:"compliant_components"`
	Compliant              bool                  `json:"compliant"`
}

// SBOMPolicyComponent represents a component in the SBOM policy evaluation result
type SBOMPolicyComponent struct {
	SPDXID           string `json:"SPDXID"`
	CopyrightText    string `json:"copyrightText,omitempty"`
	DownloadLocation string `json:"downloadLocation,omitempty"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
	Name             string `json:"name"`
	Supplier         string `json:"supplier"`
	VersionInfo      string `json:"versionInfo"`
	FilesAnalyzed    bool   `json:"filesAnalyzed,omitempty"`
}

// vulnerabilityEvaluator handles vulnerability policy evaluation
type vulnerabilityEvaluator struct {
	service *PolicyService
}

func (v *vulnerabilityEvaluator) PolicyType() string {
	return "vulnerability"
}

func (v *vulnerabilityEvaluator) PolicyPath() string {
	return vulnerabilityPolicyPath
}

// CheckVulnerability evaluates vulnerability policy with type safety
func (v *vulnerabilityEvaluator) CheckVulnerability(
	ctx context.Context,
	payload *VulnerabilityPayload,
) (VulnerabilityPolicyResult, error) {
	ctx, span := v.service.telemetry.StartSpan(ctx, "policy.check_vulnerability")
	defer span.End()

	v.service.telemetry.SetPolicyAttributes(span, "vulnerability")
	span.SetAttributes(
		attribute.Int("input.vulnerability_count", len(payload.Vulnerabilities)),
		attribute.String("input.scan_target", payload.Metadata.ScanTarget),
		attribute.String("input.tool_name", payload.Metadata.ToolName),
	)

	v.service.logger.DebugContext(ctx, "Checking vulnerability policy",
		"vulnerability_count", len(payload.Vulnerabilities),
		"scan_target", payload.Metadata.ScanTarget,
		"tool_name", payload.Metadata.ToolName)

	result, err := evaluatePolicy[*VulnerabilityPayload, VulnerabilityPolicyResult](
		ctx, v.service, v.PolicyPath(), payload,
	)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		v.service.telemetry.SetErrorAttribute(span, err)
		v.service.logger.ErrorContext(ctx, "Failed to check vulnerability policy", "error", err)

		return result, err
	}

	span.SetAttributes(
		attribute.Bool("policy.compliant", result.Compliant),
		attribute.Int("policy.total_vulnerabilities", result.TotalVulnerabilities),
		attribute.Int("policy.non_compliant_count", result.NonCompliantCount),
	)
	v.service.logger.InfoContext(ctx, "Vulnerability policy check completed",
		"compliant", result.Compliant,
		"total_vulnerabilities", result.TotalVulnerabilities,
		"non_compliant_count", result.NonCompliantCount)

	return result, nil
}

// Evaluate implements PolicyEvaluator interface (delegates to type-safe method)
func (v *vulnerabilityEvaluator) Evaluate(ctx context.Context, payload any) (any, error) {
	vulnPayload, ok := payload.(*VulnerabilityPayload)
	if !ok {
		return nil, fmt.Errorf(
			"%w: expected *VulnerabilityPayload, got %T",
			ErrPolicyEvaluation,
			payload,
		)
	}

	return v.CheckVulnerability(ctx, vulnPayload)
}

// sbomEvaluator handles SBOM/license policy evaluation
type sbomEvaluator struct {
	service *PolicyService
}

func (s *sbomEvaluator) PolicyType() string {
	return "sbom"
}

func (s *sbomEvaluator) PolicyPath() string {
	return licensePolicyPath
}

// CheckSBOM evaluates SBOM policy with type safety
func (s *sbomEvaluator) CheckSBOM(
	ctx context.Context,
	payload *SBOMPayload,
) (SBOMPolicyResult, error) {
	ctx, span := s.service.telemetry.StartSpan(ctx, "policy.check_sbom")
	defer span.End()

	s.service.telemetry.SetPolicyAttributes(span, "sbom")
	span.SetAttributes(
		attribute.Int("input.package_count", len(payload.Packages)),
		attribute.String("input.scan_target", payload.Metadata.ScanTarget),
		attribute.String("input.tool_name", payload.Metadata.ToolName),
	)

	s.service.logger.DebugContext(ctx, "Checking SBOM policy",
		"package_count", len(payload.Packages),
		"scan_target", payload.Metadata.ScanTarget,
		"tool_name", payload.Metadata.ToolName)

	result, err := evaluatePolicy[*SBOMPayload, SBOMPolicyResult](
		ctx, s.service, s.PolicyPath(), payload,
	)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		span.RecordError(err)
		s.service.logger.ErrorContext(ctx, "Failed to check SBOM policy", "error", err)

		return result, err
	}

	span.SetAttributes(
		attribute.Bool("policy.compliant", result.Compliant),
		attribute.Int("policy.total_components", result.TotalComponents),
		attribute.Int("policy.compliant_components", result.CompliantComponents),
		attribute.Int("policy.non_compliant_licenses", len(result.NonCompliantLicenses)),
	)
	s.service.logger.InfoContext(ctx, "SBOM policy check completed",
		"compliant", result.Compliant,
		"total_components", result.TotalComponents,
		"compliant_components", result.CompliantComponents,
		"non_compliant_licenses", len(result.NonCompliantLicenses))

	return result, nil
}

// Evaluate implements PolicyEvaluator interface (delegates to type-safe method)
func (s *sbomEvaluator) Evaluate(ctx context.Context, payload any) (any, error) {
	sbomPayload, ok := payload.(*SBOMPayload)
	if !ok {
		return nil, fmt.Errorf("%w: expected *SBOMPayload, got %T", ErrPolicyEvaluation, payload)
	}

	return s.CheckSBOM(ctx, sbomPayload)
}

// NewStandardEvaluators creates the default set of policy evaluators
func NewStandardEvaluators(service *PolicyService) []PolicyEvaluator {
	return []PolicyEvaluator{
		&vulnerabilityEvaluator{service: service},
		&sbomEvaluator{service: service},
	}
}

// NewPolicyService initializes a new PolicyService with the provided OPA client, logger, and evaluators.
func NewPolicyService(
	opaClient *clients.OPAClient,
	logger *slog.Logger,
	telemetry *telemetry.TelemetryHelper,
	evaluators []PolicyEvaluator,
) *PolicyService {
	registry := make(map[string]PolicyEvaluator)
	for _, evaluator := range evaluators {
		registry[evaluator.PolicyType()] = evaluator
	}

	return &PolicyService{
		opaClient:  opaClient,
		logger:     logger,
		telemetry:  telemetry,
		evaluators: registry,
	}
}

// evaluatePolicy is a helper function to evaluate a policy with the given input.
func evaluatePolicy[T any, R any](
	ctx context.Context,
	service *PolicyService,
	policyPath string,
	input T,
) (R, error) {
	ctx, span := service.telemetry.StartSpan(ctx, "policy.evaluate")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.path", policyPath),
	)

	var zero R

	// Wrap input in the format OPA expects: {"input": {...}}
	opaPayload := map[string]interface{}{
		"input": input,
	}

	service.logger.DebugContext(ctx, "Evaluating policy", "path", policyPath)

	resp, err := service.opaClient.EvaluatePolicy(ctx, policyPath, opaPayload)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		span.RecordError(err)
		// Wrap network/connection errors as system unavailable and log at WARN (planned OPA outage friendly)
		if isNetworkError(err) {
			service.logger.WarnContext(ctx, "Policy evaluation system unavailable",
				"error", err,
				"path", policyPath)
			return zero, fmt.Errorf("%w: %v", ErrSystemUnavailable, err)
		}

		// Non-network errors remain ERROR
		service.logger.ErrorContext(ctx, "Failed to evaluate policy",
			"error", err,
			"path", policyPath)
		return zero, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			service.logger.WarnContext(ctx, "Failed to close response body", "error", err)
		}
	}()

	span.SetAttributes(attribute.Int("opa.response_code", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		span.SetAttributes(attribute.String("error", "policy evaluation failed"))
		span.RecordError(fmt.Errorf("policy evaluation failed: status %s", resp.Status))
		service.logger.ErrorContext(ctx, "Policy evaluation failed",
			"status", resp.Status,
			"path", policyPath)

		return zero, fmt.Errorf("policy evaluation failed: status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		span.RecordError(err)
		service.logger.ErrorContext(ctx, "Failed to read response body",
			"error", err,
			"path", policyPath)

		return zero, err
	}

	var policyResponse struct {
		Result R `json:"result"`
	}
	if err := json.Unmarshal(body, &policyResponse); err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		span.RecordError(err)
		service.logger.ErrorContext(ctx, "Failed to unmarshal policy response",
			"error", err,
			"path", policyPath)

		return zero, err
	}

	return policyResponse.Result, nil
}

// Evaluate evaluates a policy using the factory registry
func (s *PolicyService) Evaluate(ctx context.Context, policyType string, payload any) (any, error) {
	ctx, span := s.telemetry.StartSpan(ctx, "policy.evaluate_with_factory")
	defer span.End()

	s.telemetry.SetPolicyAttributes(span, policyType)

	evaluator, exists := s.evaluators[policyType]
	if !exists {
		s.telemetry.SetErrorAttribute(span, ErrUnknownPolicyType)
		return nil, fmt.Errorf("%w: %s", ErrUnknownPolicyType, policyType)
	}

	return evaluator.Evaluate(ctx, payload)
}

// CheckVulnerabilityPolicy evaluates the vulnerability policy with type safety.
func (s *PolicyService) CheckVulnerabilityPolicy(
	ctx context.Context,
	input *VulnerabilityPayload,
) (VulnerabilityPolicyResult, error) {
	evaluator, exists := s.evaluators["vulnerability"]
	if !exists {
		return VulnerabilityPolicyResult{}, fmt.Errorf("%w: vulnerability", ErrUnknownPolicyType)
	}

	vulnEvaluator, ok := evaluator.(*vulnerabilityEvaluator)
	if !ok {
		return VulnerabilityPolicyResult{}, fmt.Errorf(
			"%w: expected *vulnerabilityEvaluator, got %T",
			ErrPolicyEvaluation,
			evaluator,
		)
	}

	return vulnEvaluator.CheckVulnerability(ctx, input)
}

// CheckSBOMPolicy evaluates the SBOM policy with type safety.
func (s *PolicyService) CheckSBOMPolicy(
	ctx context.Context,
	input *SBOMPayload,
) (SBOMPolicyResult, error) {
	evaluator, exists := s.evaluators["sbom"]
	if !exists {
		return SBOMPolicyResult{}, fmt.Errorf("%w: sbom", ErrUnknownPolicyType)
	}

	sbomEvaluator, ok := evaluator.(*sbomEvaluator)
	if !ok {
		return SBOMPolicyResult{}, fmt.Errorf(
			"%w: expected *sbomEvaluator, got %T",
			ErrPolicyEvaluation,
			evaluator,
		)
	}

	return sbomEvaluator.CheckSBOM(ctx, input)
}
