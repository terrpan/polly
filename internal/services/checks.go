package services

import (
	"context"
	"log/slog"

	gogithub "github.com/google/go-github/v72/github"
	"github.com/terrpan/polly/internal/clients"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type CheckService struct {
	githubClient clients.GitHubClientInterface
	logger       *slog.Logger
}

type CheckRunStatus string
type CheckRunConclusion string
type CheckRunType string

const (
	//Check Run Statuses
	StatusQueued     CheckRunStatus = "queued"
	StatusInProgress CheckRunStatus = "in_progress"
	StatusCompleted  CheckRunStatus = "completed"

	// Check Run Conclusions
	ConclusionSuccess   CheckRunConclusion = "success"
	ConclusionFailure   CheckRunConclusion = "failure"
	ConclusionNeutral   CheckRunConclusion = "neutral"
	ConclusionCancelled CheckRunConclusion = "cancelled"
	ConclusionSkipped   CheckRunConclusion = "skipped"
	ConclusionTimedOut  CheckRunConclusion = "timed_out"

	// Check Run Types
	CheckRunTypePolicy        CheckRunType = "OPA Policy Check"
	CheckRunTypeVulnerability CheckRunType = "Vulnerability Scan Check"
)

type CheckRunResult struct {
	Success     bool
	Title       string
	Summary     string
	Text        string
	Annotations []gogithub.CheckRunAnnotation
}

// NewCheckService initializes a new CheckService with the provided GitHub client and logger.
func NewCheckService(githubClient clients.GitHubClientInterface, logger *slog.Logger) *CheckService {
	return &CheckService{
		githubClient: githubClient,
		logger:       logger,
	}
}

// Generic method to create any type of check run
func (s *CheckService) CreateCheckRun(ctx context.Context, owner, repo, sha string, checkType CheckRunType) (*gogithub.CheckRun, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "checks.create_check_run")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.String("check.type", string(checkType)),
	)

	checkRun, err := s.githubClient.CreateCheckRun(ctx, owner, repo, sha, string(checkType))
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to create check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_type", checkType,
		)
		return nil, err
	}

	span.SetAttributes(attribute.Int64("github.check_run_id", checkRun.GetID()))
	s.logger.InfoContext(ctx, "Check run created",
		"check_run_id", checkRun.GetID(),
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_type", checkType,
	)

	return checkRun, nil
}

// Generic method to start any type of check run
func (s *CheckService) StartCheckRun(ctx context.Context, owner, repo string, checkRunID int64, checkType CheckRunType) error {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "checks.start_check_run")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int64("github.check_run_id", checkRunID),
		attribute.String("check.type", string(checkType)),
	)

	// Customize output based on check type
	var title, summary, text string
	switch checkType {
	case CheckRunTypePolicy:
		title = "OPA Policy Check - In Progress"
		summary = "OPA Policy validation is in progress"
		text = "The OPA Policy validation is currently being processed. Please wait for the results."
	case CheckRunTypeVulnerability:
		title = "Vulnerability Scan Check - In Progress"
		summary = "Vulnerability scan is in progress"
		text = "The vulnerability scan is currently being processed. Please wait for the results."
	}

	output := &gogithub.CheckRunOutput{
		Title:   gogithub.Ptr(title),
		Summary: gogithub.Ptr(summary),
		Text:    gogithub.Ptr(text),
	}

	err := s.githubClient.UpdateCheckRun(ctx, owner, repo, checkRunID, string(checkType), string(StatusInProgress), nil, output)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to start check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"check_run_id", checkRunID,
			"check_type", checkType,
		)
		return err
	}

	s.logger.InfoContext(ctx, "Check run started",
		"check_run_id", checkRunID,
		"owner", owner,
		"repo", repo,
		"check_type", checkType,
	)
	return nil
}

// Generic method to complete any type of check run
func (s *CheckService) CompleteCheckRun(ctx context.Context, owner, repo string, checkRunID int64, checkType CheckRunType, conclusion CheckRunConclusion, result CheckRunResult) error {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "checks.complete_check_run")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int64("github.check_run_id", checkRunID),
		attribute.String("check.type", string(checkType)),
		attribute.String("check.conclusion", string(conclusion)),
		attribute.Bool("check.success", result.Success),
	)

	var githubConclusion *string
	if conclusion != "" {
		githubConclusion = gogithub.Ptr(string(conclusion))
	}

	output := &gogithub.CheckRunOutput{
		Title:   gogithub.Ptr(result.Title),
		Summary: gogithub.Ptr(result.Summary),
		Text:    gogithub.Ptr(result.Text),
	}

	err := s.githubClient.UpdateCheckRun(ctx, owner, repo, checkRunID, string(checkType), string(StatusCompleted), githubConclusion, output)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to complete check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"check_run_id", checkRunID,
			"check_type", checkType,
			"conclusion", conclusion,
		)
		return err
	}

	s.logger.InfoContext(ctx, "Check run completed",
		"check_run_id", checkRunID,
		"owner", owner,
		"repo", repo,
		"check_type", checkType,
		"conclusion", conclusion,
	)
	return nil
}

// Convenience methods for backward compatibility
func (s *CheckService) CreatePolicyCheck(ctx context.Context, owner, repo, sha string) (*gogithub.CheckRun, error) {
	return s.CreateCheckRun(ctx, owner, repo, sha, CheckRunTypePolicy)
}

func (s *CheckService) CreateVulnerabilityCheck(ctx context.Context, owner, repo, sha string) (*gogithub.CheckRun, error) {
	return s.CreateCheckRun(ctx, owner, repo, sha, CheckRunTypeVulnerability)
}

func (s *CheckService) StartPolicyCheck(ctx context.Context, owner, repo string, checkRunID int64) error {
	return s.StartCheckRun(ctx, owner, repo, checkRunID, CheckRunTypePolicy)
}

func (s *CheckService) StartVulnerabilityCheck(ctx context.Context, owner, repo string, checkRunID int64) error {
	return s.StartCheckRun(ctx, owner, repo, checkRunID, CheckRunTypeVulnerability)
}

func (s *CheckService) CompletePolicyCheck(ctx context.Context, owner, repo string, checkRunID int64, conclusion CheckRunConclusion, result CheckRunResult) error {
	return s.CompleteCheckRun(ctx, owner, repo, checkRunID, CheckRunTypePolicy, conclusion, result)
}

func (s *CheckService) CompleteVulnerabilityCheck(ctx context.Context, owner, repo string, checkRunID int64, conclusion CheckRunConclusion, result CheckRunResult) error {
	return s.CompleteCheckRun(ctx, owner, repo, checkRunID, CheckRunTypeVulnerability, conclusion, result)
}

func (s *CheckService) CompleteVulnerabilityCheckWithNoArtifacts(ctx context.Context, owner, repo string, checkRunID int64) error {
	result := CheckRunResult{
		Title:   "Vulnerability Scan Check - No Reports Found",
		Summary: "No vulnerability scan reports were found to analyze",
		Text:    "The workflow completed successfully but no vulnerability scan reports (Trivy, SARIF, SBOM) were found to analyze. This may indicate that no security scanning tools were configured in the workflow.",
	}
	return s.CompleteCheckRun(ctx, owner, repo, checkRunID, CheckRunTypeVulnerability, ConclusionNeutral, result)
}
