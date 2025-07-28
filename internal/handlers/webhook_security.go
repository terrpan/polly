// Package handlers provides HTTP handlers for health checks and webhook processing.
// This file defines the WebhookSecurityHandler which processes security-related webhook events.
package handlers

import (
	"context"
	"fmt"

	gogithub "github.com/google/go-github/v72/github"
	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/utils"
)

// SecurityCheckType represents a type of security check that can be created
type SecurityCheckType struct {
	create func() (*gogithub.CheckRun, error)
	start  func(checkRunID int64) error
	store  func(checkRunID int64)
	name   string
}

// getSecurityCheckTypes returns the configured security check types for the given context
func (s *SecurityCheckManager) getSecurityCheckTypes(
	ctx context.Context,
	owner, repo, sha string,
) []SecurityCheckType {
	return []SecurityCheckType{
		{
			name: "vulnerability",
			create: func() (*gogithub.CheckRun, error) {
				return s.checkService.CreateVulnerabilityCheck(ctx, owner, repo, sha)
			},
			start: func(checkRunID int64) error {
				return s.checkService.StartVulnerabilityCheck(ctx, owner, repo, checkRunID)
			},
			store: func(checkRunID int64) {
				s.storeCheckRunID(
					ctx,
					owner,
					repo,
					sha,
					checkRunID,
					"vulnerability",
					s.stateService.StoreVulnerabilityCheckRunID,
				)
			},
		},
		{
			name: "license",
			create: func() (*gogithub.CheckRun, error) {
				return s.checkService.CreateLicenseCheck(ctx, owner, repo, sha)
			},
			start: func(checkRunID int64) error {
				return s.checkService.StartLicenseCheck(ctx, owner, repo, checkRunID)
			},
			store: func(checkRunID int64) {
				s.storeCheckRunID(
					ctx,
					owner,
					repo,
					sha,
					checkRunID,
					"license",
					s.stateService.StoreLicenseCheckRunID,
				)
			},
		},
	}
}

// CreateSecurityCheckRuns creates and starts security check runs sequentially
// Note: GitHub API calls are processed sequentially to prevent context cancellation
// and rate limiting issues, while policy processing remains concurrent for performance
func (s *SecurityCheckManager) CreateSecurityCheckRuns(
	ctx context.Context,
	owner, repo, sha string,
	prNumber int64,
) error {
	ctx, span := s.tracingHelper.StartSpan(ctx, "security_check_manager.create_security_check_runs")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.Int64("pr.number", prNumber),
	)

	checkTypes := s.getSecurityCheckTypes(ctx, owner, repo, sha)

	// Process check run creation sequentially to avoid GitHub API rate limits
	// and context cancellation issues
	for _, ct := range checkTypes {
		checkRun, err := ct.create()
		if err != nil {
			s.logger.ErrorContext(ctx, "Failed to create check run",
				"error", err,
				"check_type", ct.name,
				"owner", owner,
				"repo", repo,
				"sha", sha,
			)

			return fmt.Errorf("failed to create %s check: %w", ct.name, err)
		}

		if err := ct.start(checkRun.GetID()); err != nil {
			s.logger.ErrorContext(ctx, "Failed to start check",
				"error", err,
				"check_type", ct.name,
				"check_run_id", checkRun.GetID(),
			)

			return fmt.Errorf("failed to start %s check: %w", ct.name, err)
		}

		ct.store(checkRun.GetID())
		s.logger.InfoContext(ctx, "Created pending check run",
			"check_type", ct.name,
			"check_run_id", checkRun.GetID(),
			"pr_number", prNumber,
		)
	}

	return nil
}

// storeCheckRunID is a helper method that handles storing check run IDs with consistent error logging
func (s *SecurityCheckManager) storeCheckRunID(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
	checkType string,
	storeFunc func(context.Context, string, string, string, int64) error,
) {
	if err := storeFunc(ctx, owner, repo, sha, checkRunID); err != nil {
		s.logger.ErrorContext(ctx, "Failed to store check run ID",
			"error", err,
			"check_type", checkType,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_run_id", checkRunID,
		)
	}
}

// CompleteSecurityChecksAsNeutral completes both vulnerability and license checks as neutral when no artifacts are found
func (s *SecurityCheckManager) CompleteSecurityChecksAsNeutral(
	ctx context.Context,
	owner, repo, sha string,
) error {
	ctx, span := s.tracingHelper.StartSpan(
		ctx,
		"security_check_manager.complete_security_checks_as_neutral",
	)
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
	)

	// Define completion functions
	completionFuncs := []func() error{
		func() error { return s.completeVulnerabilityCheckAsNeutral(ctx, owner, repo, sha) },
		func() error { return s.completeLicenseCheckAsNeutral(ctx, owner, repo, sha) },
	}

	// Complete security checks as neutral concurrently
	tasks := make([]func() error, len(completionFuncs))
	for i, fn := range completionFuncs {
		fn := fn
		tasks[i] = func() error {
			if err := fn(); err != nil {
				s.logger.ErrorContext(
					ctx,
					"Failed to complete security check as neutral",
					"error",
					err,
				)
			}

			return nil
		}
	}

	_ = utils.ExecuteConcurrently(tasks)

	return nil
}

// completeVulnerabilityCheckAsNeutral completes vulnerability checks as neutral when no artifacts are found
func (s *SecurityCheckManager) completeVulnerabilityCheckAsNeutral(
	ctx context.Context,
	owner, repo, sha string,
) error {
	checkRunID, err := s.findVulnerabilityCheckRun(ctx, owner, repo, sha)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to find vulnerability check run",
			"error", err,
			"sha", sha,
		)

		return nil // Don't fail if we can't find the check run
	}

	if checkRunID == 0 {
		return nil // No vulnerability check run to complete
	}

	return s.checkService.CompleteVulnerabilityCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
}

// completeLicenseCheckAsNeutral completes license checks as neutral when no artifacts are found
func (s *SecurityCheckManager) completeLicenseCheckAsNeutral(
	ctx context.Context,
	owner, repo, sha string,
) error {
	checkRunID, err := s.findLicenseCheckRun(ctx, owner, repo, sha)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to find license check run",
			"error", err,
			"sha", sha,
		)

		return nil // Don't fail if we can't find the check run
	}

	if checkRunID == 0 {
		return nil // No license check run to complete
	}

	return s.checkService.CompleteLicenseCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
}

// findVulnerabilityCheckRun finds an existing vulnerability check run for the given SHA
func (s *SecurityCheckManager) findVulnerabilityCheckRun(
	ctx context.Context,
	owner, repo, sha string,
) (int64, error) {
	checkRunID, exists, err := s.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to get vulnerability check run ID",
			"error", err,
			"sha", sha,
		)

		return 0, err
	}

	if !exists {
		s.logger.DebugContext(ctx, "No vulnerability check run found for SHA",
			"sha", sha,
		)

		return 0, nil
	}

	s.logger.DebugContext(ctx, "Found vulnerability check run for SHA",
		"sha", sha,
		"check_run_id", checkRunID,
	)

	return checkRunID, nil
}

// findLicenseCheckRun finds an existing license check run for the given SHA
func (s *SecurityCheckManager) findLicenseCheckRun(
	ctx context.Context,
	owner, repo, sha string,
) (int64, error) {
	checkRunID, exists, err := s.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to get license check run ID",
			"error", err,
			"sha", sha,
		)

		return 0, err
	}

	if !exists {
		s.logger.DebugContext(ctx, "No license check run found for SHA",
			"sha", sha,
		)

		return 0, nil
	}

	s.logger.DebugContext(ctx, "Found license check run for SHA",
		"sha", sha,
		"check_run_id", checkRunID,
	)

	return checkRunID, nil
}
