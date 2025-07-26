package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-playground/webhooks/v6/github"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/terrpan/polly/internal/services"
)

// TracingHelper provides a consistent way to create tracing spans across webhook handlers
type TracingHelper struct {
	tracer trace.Tracer
}

// NewTracingHelper creates a new tracing helper for webhook handlers
func NewTracingHelper() *TracingHelper {
	return &TracingHelper{
		tracer: otel.Tracer("polly/handlers"),
	}
}

// StartSpan creates a new tracing span with the given name
func (t *TracingHelper) StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name)
}

// SecurityCheckManager handles the creation and management of security check runs
type SecurityCheckManager struct {
	logger        *slog.Logger
	checkService  *services.CheckService
	stateService  *services.StateService
	tracingHelper *TracingHelper
}

// NewSecurityCheckManager creates a new security check manager
func NewSecurityCheckManager(
	logger *slog.Logger,
	checkService *services.CheckService,
	stateService *services.StateService,
) *SecurityCheckManager {
	return &SecurityCheckManager{
		logger:        logger,
		checkService:  checkService,
		stateService:  stateService,
		tracingHelper: NewTracingHelper(),
	}
}

// BaseWebhookHandler contains the common dependencies for all webhook handlers
type BaseWebhookHandler struct {
	logger           *slog.Logger
	commentService   *services.CommentService
	checkService     *services.CheckService
	policyService    *services.PolicyService
	securityService  *services.SecurityService
	stateService     *services.StateService
	tracingHelper    *TracingHelper
	securityCheckMgr *SecurityCheckManager
}

// NewBaseWebhookHandler creates a new base webhook handler with common dependencies
func NewBaseWebhookHandler(
	logger *slog.Logger,
	commentService *services.CommentService,
	checkService *services.CheckService,
	policyService *services.PolicyService,
	securityService *services.SecurityService,
	stateService *services.StateService,
) *BaseWebhookHandler {
	return &BaseWebhookHandler{
		logger:           logger,
		commentService:   commentService,
		checkService:     checkService,
		policyService:    policyService,
		securityService:  securityService,
		stateService:     stateService,
		tracingHelper:    NewTracingHelper(),
		securityCheckMgr: NewSecurityCheckManager(logger, checkService, stateService),
	}
}

// PolicyProcessingResult holds the result of processing security payloads
type PolicyProcessingResult struct {
	FailureDetails         []string
	NonCompliantVulns      []services.VulnerabilityPolicyVuln
	NonCompliantComponents []services.SBOMPolicyComponent
	ConditionalComponents  []services.SBOMPolicyComponent
	AllPassed              bool
}

// WebhookProcessingConfig holds configuration for processing workflow artifacts
type WebhookProcessingConfig struct {
	Owner         string
	Repo          string
	SHA           string
	WorkflowRunID int64
	PRNumber      int64
	CheckVuln     bool
	CheckLicense  bool
}

// buildCheckRunResult builds the check run result based on policy validation outcome.
func buildCheckRunResult(
	policyPassed bool,
	policyError error,
) (services.CheckRunConclusion, services.CheckRunResult) {
	if policyError != nil {
		return services.ConclusionFailure, services.CheckRunResult{
			Title:   "OPA Policy Check - Error",
			Summary: "Policy validation failed due to error",
			Text:    fmt.Sprintf("Error: %v", policyError),
		}
	}

	if policyPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   "OPA Policy Check - Passed",
			Summary: "All policies passed",
			Text:    "The policy validation succeeded.",
		}
	}

	return services.ConclusionFailure, services.CheckRunResult{
		Title:   "OPA Policy Check - Failed",
		Summary: "Policy validation failed",
		Text:    "The policy validation failed.",
	}
}

// buildVulnerabilityViolationComment generates a markdown comment for vulnerability policy violations.
func buildVulnerabilityViolationComment(vulns []services.VulnerabilityPolicyVuln) string {
	vulnComments := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		comment := fmt.Sprintf("**Package:** `%s@%s`\n**Vulnerability:** %s\n**Severity:** %s",
			vuln.Package, vuln.Version, vuln.ID, vuln.Severity)

		if vuln.Score > 0 {
			comment += fmt.Sprintf("\n**CVSS Score:** %.1f", vuln.Score)
		}

		if vuln.FixedVersion != "" {
			comment += fmt.Sprintf("\n**Fixed Version:** `%s`", vuln.FixedVersion)
		}

		vulnComments = append(vulnComments, comment)
	}

	return fmt.Sprintf(
		"❌ **Vulnerability Policy Violation - %d vulnerabilities blocked**\n\n<details>\n<summary>Click to view policy violation details</summary>\n\n%s\n\n</details>",
		len(vulnComments),
		strings.Join(vulnComments, "\n\n---\n\n"),
	)
}

// buildLicenseComment generates a single markdown comment for both license violations and conditional licenses.
func buildLicenseComment(
	violations []services.SBOMPolicyComponent,
	conditionals []services.SBOMPolicyComponent,
) string {
	var sections []string

	if len(violations) > 0 {
		violationSection := buildLicenseViolationSection(violations)
		sections = append(sections, violationSection)
	}

	if len(conditionals) > 0 {
		conditionalSection := buildLicenseConditionalSection(conditionals)
		sections = append(sections, conditionalSection)
	}

	return strings.Join(sections, "\n\n")
}

// buildLicenseViolationSection creates the violations section of the license comment
func buildLicenseViolationSection(violations []services.SBOMPolicyComponent) string {
	violationComments := make([]string, 0, len(violations))
	for _, component := range violations {
		comment := buildComponentComment(component)
		violationComments = append(violationComments, comment)
	}

	return fmt.Sprintf(
		"❌ **License Violations Found - %d packages**\n\nThe following packages have licenses that violate our policy and must be addressed:\n\n<details>\n<summary>Click to view license violations</summary>\n\n%s\n\n</details>",
		len(violationComments),
		strings.Join(violationComments, "\n\n---\n\n"),
	)
}

// buildLicenseConditionalSection creates the conditional licenses section of the license comment
func buildLicenseConditionalSection(conditionals []services.SBOMPolicyComponent) string {
	conditionalComments := make([]string, 0, len(conditionals))
	for _, component := range conditionals {
		comment := buildComponentComment(component)
		conditionalComments = append(conditionalComments, comment)
	}

	return fmt.Sprintf(
		"ℹ️ **Conditionally Allowed Licenses Found - %d packages require consideration**\n\nThe following packages use licenses that are allowed but should be used with consideration. Please review these packages and their licenses to ensure they meet your project's requirements:\n\n<details>\n<summary>Click to view conditionally allowed licenses</summary>\n\n%s\n\n</details>",
		len(conditionalComments),
		strings.Join(conditionalComments, "\n\n---\n\n"),
	)
}

// buildComponentComment creates a markdown comment for a single SBOM component
func buildComponentComment(component services.SBOMPolicyComponent) string {
	comment := fmt.Sprintf("**Package:** `%s`", component.Name)

	if component.VersionInfo != "" {
		comment += fmt.Sprintf("@%s", component.VersionInfo)
	}

	if component.LicenseDeclared != "" {
		comment += fmt.Sprintf("\n**License Declared:** %s", component.LicenseDeclared)
	} else if component.LicenseConcluded != "" {
		comment += fmt.Sprintf("\n**License Concluded:** %s", component.LicenseConcluded)
	}

	if component.Supplier != "" {
		comment += fmt.Sprintf("\n**Supplier:** %s", component.Supplier)
	}

	if component.SPDXID != "" {
		comment += fmt.Sprintf("\n**SPDX ID:** `%s`", component.SPDXID)
	}

	return comment
}

// processVulnerabilityChecks processes vulnerability payloads, posts comments for violations, and completes the check run.
func processVulnerabilityChecks(
	ctx context.Context,
	logger *slog.Logger,
	policyService *services.PolicyService,
	commentService *services.CommentService,
	checkService *services.CheckService,
	payloads []*services.VulnerabilityPayload,
	owner, repo, sha string,
	prNumber int64,
	checkRunID int64,
) error {
	result := processVulnerabilityPolicies(ctx, logger, policyService, payloads, owner, repo, sha)

	if err := postVulnerabilityComments(ctx, logger, commentService, result.NonCompliantVulns, owner, repo, prNumber); err != nil {
		logger.ErrorContext(ctx, "Failed to post vulnerability comment", "error", err)
	}

	conclusion, checkResult := buildVulnerabilityCheckResult(result, len(payloads))

	return checkService.CompleteVulnerabilityCheck(
		ctx,
		owner,
		repo,
		checkRunID,
		conclusion,
		checkResult,
	)
}

// processLicenseChecks processes SBOM payloads, posts comments for violations, and completes the check run.
func processLicenseChecks(
	ctx context.Context,
	logger *slog.Logger,
	policyService *services.PolicyService,
	commentService *services.CommentService,
	checkService *services.CheckService,
	payloads []*services.SBOMPayload,
	owner, repo, sha string,
	prNumber int64,
	checkRunID int64,
) error {
	result := processLicensePolicies(ctx, logger, policyService, payloads, owner, repo, sha)

	if err := postLicenseComments(ctx, logger, commentService, result.NonCompliantComponents, result.ConditionalComponents, owner, repo, prNumber); err != nil {
		logger.ErrorContext(ctx, "Failed to post license comment", "error", err)
	}

	conclusion, checkResult := buildLicenseCheckResult(result, len(payloads))

	return checkService.CompleteLicenseCheck(ctx, owner, repo, checkRunID, conclusion, checkResult)
}

// processVulnerabilityPolicies evaluates vulnerability policies for all payloads
func processVulnerabilityPolicies(
	ctx context.Context,
	logger *slog.Logger,
	policyService *services.PolicyService,
	payloads []*services.VulnerabilityPayload,
	owner, repo, sha string,
) PolicyProcessingResult {
	result := PolicyProcessingResult{AllPassed: true}

	for _, payload := range payloads {
		logger.DebugContext(ctx, "Processing vulnerability payload",
			"owner", owner, "repo", repo, "sha", sha,
			"payload_vulnerability_summary", payload.Summary,
		)

		policyResult, err := policyService.CheckVulnerabilityPolicy(ctx, payload)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to evaluate vulnerability policy", "error", err)

			if payload.Summary.Critical > 0 || payload.Summary.High > 0 {
				result.AllPassed = false
				result.FailureDetails = append(
					result.FailureDetails,
					fmt.Sprintf(
						"Found %d critical and %d high severity vulnerabilities (policy evaluation failed)",
						payload.Summary.Critical,
						payload.Summary.High,
					),
				)
			}

			continue
		}

		if !policyResult.Compliant {
			result.AllPassed = false
			result.FailureDetails = append(
				result.FailureDetails,
				fmt.Sprintf(
					"Vulnerability policy violation: %d non-compliant vulnerabilities out of %d total",
					policyResult.NonCompliantCount,
					policyResult.TotalVulnerabilities,
				),
			)
			result.NonCompliantVulns = append(
				result.NonCompliantVulns,
				policyResult.NonCompliantVulnerabilities...)
		}
	}

	return result
}

// processLicensePolicies evaluates license policies for all payloads
func processLicensePolicies(
	ctx context.Context,
	logger *slog.Logger,
	policyService *services.PolicyService,
	payloads []*services.SBOMPayload,
	owner, repo, sha string,
) PolicyProcessingResult {
	result := PolicyProcessingResult{AllPassed: true}

	for _, payload := range payloads {
		logger.DebugContext(ctx, "Processing SBOM payload",
			"owner", owner, "repo", repo, "sha", sha,
			"package_count", payload.Summary.TotalPackages,
		)

		policyResult, err := policyService.CheckSBOMPolicy(ctx, payload)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to evaluate SBOM policy", "error", err)

			if payload.Summary.PackagesWithoutLicense > 0 {
				result.AllPassed = false
				result.FailureDetails = append(result.FailureDetails,
					fmt.Sprintf("Found %d packages without license (policy evaluation failed)",
						payload.Summary.PackagesWithoutLicense))
			}

			continue
		}

		if !policyResult.Compliant {
			result.AllPassed = false
			result.FailureDetails = append(result.FailureDetails,
				fmt.Sprintf(
					"SBOM policy violation: %d non-compliant components out of %d total",
					policyResult.TotalComponents-policyResult.CompliantComponents,
					policyResult.TotalComponents,
				))
			result.NonCompliantComponents = append(
				result.NonCompliantComponents,
				policyResult.NonCompliantComponents...)
		}

		result.ConditionalComponents = append(
			result.ConditionalComponents,
			policyResult.ConditionalComponents...)
	}

	return result
}

// postVulnerabilityComments posts vulnerability violation comments if needed
func postVulnerabilityComments(
	ctx context.Context,
	logger *slog.Logger,
	commentService *services.CommentService,
	violations []services.VulnerabilityPolicyVuln,
	owner, repo string,
	prNumber int64,
) error {
	if len(violations) > 0 && prNumber > 0 {
		comment := buildVulnerabilityViolationComment(violations)
		return commentService.WriteComment(ctx, owner, repo, int(prNumber), comment)
	}

	return nil
}

// postLicenseComments posts license violation and conditional comments if needed
func postLicenseComments(
	ctx context.Context,
	logger *slog.Logger,
	commentService *services.CommentService,
	violations, conditionals []services.SBOMPolicyComponent,
	owner, repo string,
	prNumber int64,
) error {
	if (len(violations) > 0 || len(conditionals) > 0) && prNumber > 0 {
		comment := buildLicenseComment(violations, conditionals)
		return commentService.WriteComment(ctx, owner, repo, int(prNumber), comment)
	}

	return nil
}

// buildVulnerabilityCheckResult builds the check run result for vulnerability checks
func buildVulnerabilityCheckResult(
	result PolicyProcessingResult,
	payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult) {
	if result.AllPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   "Vulnerability Check - Passed",
			Summary: fmt.Sprintf("Processed %d vulnerability findings", payloadCount),
			Text:    "All vulnerability policies passed.",
		}
	}

	return services.ConclusionFailure, services.CheckRunResult{
		Title: "Vulnerability Check - Failed",
		Summary: fmt.Sprintf(
			"Found vulnerability violations in %d scan results",
			len(result.FailureDetails),
		),
		Text: fmt.Sprintf(
			"Vulnerability violations found:\n\n%s",
			strings.Join(result.FailureDetails, "\n"),
		),
	}
}

// buildLicenseCheckResult builds the check run result for license checks
func buildLicenseCheckResult(
	result PolicyProcessingResult,
	payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult) {
	if result.AllPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   "License Check - Passed",
			Summary: fmt.Sprintf("Processed %d SBOM findings", payloadCount),
			Text:    "All license policies passed.",
		}
	}

	return services.ConclusionFailure, services.CheckRunResult{
		Title: "License Check - Failed",
		Summary: fmt.Sprintf(
			"Found license violations in %d scan results",
			len(result.FailureDetails),
		),
		Text: fmt.Sprintf(
			"License violations found:\n\n%s",
			strings.Join(result.FailureDetails, "\n"),
		),
	}
}

// getEventInfo extracts common event information for logging using generics
func getEventInfo[T github.PullRequestPayload | github.CheckRunPayload | github.WorkflowRunPayload](
	event T,
) (owner, repo, sha string, eventID int64) {
	// We use type assertion to 'any' here because Go's type switch does not work directly on generic type parameters.
	switch e := any(event).(type) {
	case github.PullRequestPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.PullRequest.Head.Sha, e.PullRequest.ID
	case github.CheckRunPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.CheckRun.HeadSHA, e.CheckRun.ID
	case github.WorkflowRunPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.WorkflowRun.HeadSha, e.WorkflowRun.ID
	default:
		// This should never happen due to type constraints, but just in case
		return "", "", "", 0
	}
}

// storeCheckRunID is a helper method that handles storing check run IDs with consistent error logging
func (h *BaseWebhookHandler) storeCheckRunID(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
	checkType string,
	storeFunc func(context.Context, string, string, string, int64) error,
) {
	if err := storeFunc(ctx, owner, repo, sha, checkRunID); err != nil {
		h.logger.ErrorContext(ctx, "Failed to store check run ID",
			"error", err,
			"check_type", checkType,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_run_id", checkRunID,
		)
	}
}

// storeCheckRunIDWithError is a helper method that handles storing check run IDs with consistent error logging and returns the error
func (h *BaseWebhookHandler) storeCheckRunIDWithError(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
	checkType string,
	storeFunc func(context.Context, string, string, string, int64) error,
) error {
	if err := storeFunc(ctx, owner, repo, sha, checkRunID); err != nil {
		h.logger.ErrorContext(ctx, "Failed to store check run ID",
			"error", err,
			"check_type", checkType,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_run_id", checkRunID,
		)

		return err
	}

	return nil
}

// findVulnerabilityCheckRun finds an existing vulnerability check run for the given SHA
func (h *BaseWebhookHandler) findVulnerabilityCheckRun(
	ctx context.Context,
	owner, repo, sha string,
) (int64, error) {
	checkRunID, exists, err := h.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get vulnerability check run ID",
			"error", err,
			"sha", sha,
		)

		return 0, err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No vulnerability check run found for SHA",
			"sha", sha,
		)

		return 0, nil
	}

	h.logger.DebugContext(ctx, "Found vulnerability check run for SHA",
		"sha", sha,
		"check_run_id", checkRunID,
	)

	return checkRunID, nil
}

// processWorkflowSecurityArtifacts is a shared helper for processing security artifacts from workflows
func (h *BaseWebhookHandler) processWorkflowSecurityArtifacts(
	ctx context.Context,
	config WebhookProcessingConfig,
) error {
	ctx, span := h.tracingHelper.StartSpan(ctx, "webhook.process_security_artifacts")
	defer span.End()

	vulnPayloads, sbomPayloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(
		ctx, config.Owner, config.Repo, config.SHA, config.WorkflowRunID)
	if err != nil {
		return fmt.Errorf("failed to process workflow security artifacts: %w", err)
	}

	// Process vulnerability checks if requested
	if config.CheckVuln && len(vulnPayloads) > 0 {
		if err := h.processVulnerabilityArtifacts(ctx, config, vulnPayloads); err != nil {
			return err
		}
	}

	// Process license checks if requested
	if config.CheckLicense && len(sbomPayloads) > 0 {
		if err := h.processLicenseArtifacts(ctx, config, sbomPayloads); err != nil {
			return err
		}
	}

	return nil
}

// processArtifactsWithCheckRun is a generic helper that eliminates duplication between vulnerability and license processing
// It follows the pattern: check if run ID exists, if not return nil, otherwise call the processor function
func (h *BaseWebhookHandler) processArtifactsWithCheckRun(
	ctx context.Context,
	config WebhookProcessingConfig,
	getCheckRunID func(context.Context, string, string, string) (int64, bool, error),
	checkType string,
	processor func(int64) error,
) error {
	checkRunID, exists, err := getCheckRunID(ctx, config.Owner, config.Repo, config.SHA)
	if err != nil || !exists {
		h.logger.DebugContext(ctx, "No "+checkType+" check run ID found", "sha", config.SHA)
		return nil
	}

	return processor(checkRunID)
}

// processVulnerabilityArtifacts processes vulnerability artifacts
func (h *BaseWebhookHandler) processVulnerabilityArtifacts(
	ctx context.Context,
	config WebhookProcessingConfig,
	payloads []*services.VulnerabilityPayload,
) error {
	return h.processArtifactsWithCheckRun(
		ctx,
		config,
		h.stateService.GetVulnerabilityCheckRunID,
		"vulnerability",
		func(checkRunID int64) error {
			return processVulnerabilityChecks(
				ctx,
				h.logger,
				h.policyService,
				h.commentService,
				h.checkService,
				payloads,
				config.Owner,
				config.Repo,
				config.SHA,
				config.PRNumber,
				checkRunID,
			)
		},
	)
}

// processLicenseArtifacts processes license artifacts
func (h *BaseWebhookHandler) processLicenseArtifacts(
	ctx context.Context,
	config WebhookProcessingConfig,
	payloads []*services.SBOMPayload,
) error {
	return h.processArtifactsWithCheckRun(
		ctx,
		config,
		h.stateService.GetLicenseCheckRunID,
		"license",
		func(checkRunID int64) error {
			return processLicenseChecks(
				ctx,
				h.logger,
				h.policyService,
				h.commentService,
				h.checkService,
				payloads,
				config.Owner,
				config.Repo,
				config.SHA,
				config.PRNumber,
				checkRunID,
			)
		},
	)
}
