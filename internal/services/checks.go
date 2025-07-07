package services

import (
	"context"
	"log/slog"

	"github.com/google/go-github/v72/github"
	"github.com/terrpan/polly/internal/clients"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type CheckService struct {
	githubClient *clients.GitHubClient
	logger       *slog.Logger
}

type CheckRunStatus string
type CheckRunConclusion string

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
)

type CheckRunResult struct {
	Success     bool
	Title       string
	Summary     string
	Text        string
	Annotations []github.CheckRunAnnotation
}

// NewCheckService initializes a new CheckService with the provided GitHub client and logger.
func NewCheckService(githubClient *clients.GitHubClient, logger *slog.Logger) *CheckService {
	return &CheckService{
		githubClient: githubClient,
		logger:       logger,
	}
}

// CreateCheckRun creates a check run for a given commit SHA in a repository.
func (s *CheckService) CreatePolicyCheck(ctx context.Context, owner, repo, sha string) (*github.CheckRun, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "checks.create_policy_check")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
	)

	checkRun, err := s.githubClient.CreateCheckRun(ctx, owner, repo, sha, "OPA Policy Check")
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to create policy check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha)
		return nil, err
	}

	span.SetAttributes(attribute.Int64("github.check_run_id", checkRun.GetID()))
	s.logger.InfoContext(ctx, "Policy check run created",
		"check_run_id", checkRun.GetID(),
		"owner", owner,
		"repo", repo,
		"sha", sha)

	return checkRun, nil
}

// StartPolicyCheck marks a check run as in-progress for a given commit SHA in a repository.
func (s *CheckService) StartPolicyCheck(ctx context.Context, owner, repo string, checkRunID int64) error {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "checks.start_policy_check")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int64("github.check_run_id", checkRunID),
	)

	output := &github.CheckRunOutput{
		Title:   github.Ptr("OPA Policy Check"),
		Summary: github.Ptr("OPA Policy validation is in progress"),
		Text:    github.Ptr("The OPA Policy validation is currently being processed. Please wait for the results."),
	}

	err := s.githubClient.UpdateCheckRun(ctx, owner, repo, checkRunID, string(StatusInProgress), nil, output)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to start policy check",
			"error", err,
			"owner", owner,
			"repo", repo,
			"check_run_id", checkRunID,
		)
		return err

	}

	s.logger.InfoContext(ctx, "Policy check started",
		"check_run_id", checkRunID,
		"owner", owner,
		"repo", repo,
	)
	return nil
}

// CompletePolicyCheck marks a check run as completed with the given conclusion and result.
func (s *CheckService) CompletePolicyCheck(ctx context.Context, owner, repo string, checkRunID int64, conclusion CheckRunConclusion, result CheckRunResult) error {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "checks.complete_policy_check")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int64("github.check_run_id", checkRunID),
		attribute.String("check.conclusion", string(conclusion)),
		attribute.Bool("check.success", result.Success),
	)

	var githubConclusion *string
	if conclusion != "" {
		githubConclusion = github.Ptr(string(conclusion))
	}

	output := &github.CheckRunOutput{
		Title:   github.Ptr(result.Title),
		Summary: github.Ptr(result.Summary),
		Text:    github.Ptr(result.Text),
	}

	err := s.githubClient.UpdateCheckRun(ctx, owner, repo, checkRunID, string(StatusCompleted), githubConclusion, output)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.ErrorContext(ctx, "Failed to complete policy check",
			"error", err,
			"owner", owner,
			"repo", repo,
			"check_run_id", checkRunID,
			"conclusion", conclusion,
		)
		return err
	}

	s.logger.InfoContext(ctx, "Policy check completed",
		"check_run_id", checkRunID,
		"owner", owner,
		"repo", repo,
		"conclusion", conclusion,
	)
	return nil
}

// RerunPolicyCheck reruns a check run for a given commit SHA in a repository.
func (s *CheckService) RerunPolicyCheck(ctx context.Context, owner, repo, sha string, id int64) error {
	checkRun, err := s.githubClient.GetCheckRun(ctx, owner, repo, id)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to get check run", "error", err, "owner", owner, "repo", repo, "sha", sha)
		return err
	}

	// Rerun the check
	_, err = s.githubClient.CreateCheckRun(ctx, owner, repo, sha, "OPA Policy Check")
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to rerun policy check", "error", err, "owner", owner, "repo", repo, "sha", sha)
		return err
	}

	s.logger.InfoContext(ctx, "Policy check rerun initiated", "check_run_id", checkRun.GetID(), "owner", owner, "repo", repo, "sha", sha)
	return nil
}
