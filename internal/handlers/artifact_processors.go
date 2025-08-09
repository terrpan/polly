package handlers

import (
	"context"
	"fmt"

	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/utils"
)

// processWorkflowSecurityArtifacts is a shared helper for processing security artifacts from workflows
func (h *BaseWebhookHandler) processWorkflowSecurityArtifacts(
	ctx context.Context,
	config WebhookProcessingConfig,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "webhook.process_security_artifacts")
	defer span.End()

	vulnPayloads, sbomPayloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(
		ctx, config.Owner, config.Repo, config.SHA, config.WorkflowRunID)
	if err != nil {
		return fmt.Errorf("failed to process workflow security artifacts: %w", err)
	}

	// Create concurrent tasks for policy processing
	var tasks []func() error

	// Add vulnerability check task if requested
	if config.CheckVuln && len(vulnPayloads) > 0 {
		tasks = append(tasks, func() error {
			return h.processVulnerabilityArtifacts(ctx, config, vulnPayloads)
		})
	}

	// Add license check task if requested
	if config.CheckLicense && len(sbomPayloads) > 0 {
		tasks = append(tasks, func() error {
			return h.processLicenseArtifacts(ctx, config, sbomPayloads)
		})
	}

	// Execute policy checks concurrently
	if len(tasks) > 0 {
		errs := utils.ExecuteConcurrently(tasks)
		for _, err := range errs {
			if err != nil {
				return fmt.Errorf("concurrent policy processing failed: %w", err)
			}
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
				h.policyCacheService,
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
				h.policyCacheService,
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
