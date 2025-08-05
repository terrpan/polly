package services

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/telemetry"
)

// SecurityService provides methods to process security artifacts from GitHub workflows.
type SecurityService struct {
	githubClient *clients.GitHubClient
	logger       *slog.Logger
	telemetry    *telemetry.TelemetryHelper
	detectors    []ContentDetector // Strategy registry
}

// NewSecurityService initializes a new SecurityService with the provided logger and detectors.
func NewSecurityService(
	githubClient *clients.GitHubClient,
	logger *slog.Logger,
	telemetry *telemetry.TelemetryHelper,
	detectors ...ContentDetector,
) *SecurityService {
	// Sort detectors by priority (lower number = higher priority)
	sort.Slice(detectors, func(i, j int) bool {
		return detectors[i].GetPriority() < detectors[j].GetPriority()
	})

	return &SecurityService{
		githubClient: githubClient,
		logger:       logger,
		telemetry:    telemetry,
		detectors:    detectors,
	}
}

// ProcessWorkflowSecurityArtifacts processes security artifacts and returns normalized payloads
func (s *SecurityService) ProcessWorkflowSecurityArtifacts(
	ctx context.Context,
	owner, repo, sha string,
	workflowID int64,
) ([]*VulnerabilityPayload, []*SBOMPayload, error) {
	ctx, span := s.telemetry.StartSpan(ctx, "security.process_workflow_artifacts")
	defer span.End()

	s.telemetry.SetRepositoryAttributes(span, owner, repo, sha)
	span.SetAttributes(
		attribute.Int64("github.workflow_id", workflowID),
	)

	s.logger.InfoContext(ctx, "Processing security artifacts",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"workflow_id", workflowID,
	)

	// 1. Discover security artifacts
	securityArtifacts, err := s.DiscoverSecurityArtifacts(ctx, owner, repo, workflowID)
	if err != nil {
		s.telemetry.SetErrorAttribute(span, err)
		return nil, nil, fmt.Errorf("failed to discover security artifacts: %w", err)
	}

	if len(securityArtifacts) == 0 {
		span.SetAttributes(attribute.Int("security_artifacts.found", 0))
		s.logger.InfoContext(ctx, "No security artifacts found")

		return nil, nil, nil
	}

	// 2. Build payloads from artifacts
	return s.BuildPayloadsFromArtifacts(ctx, securityArtifacts, owner, repo, sha, workflowID)
}

// DiscoverSecurityArtifacts finds and downloads security-related artifacts
func (s *SecurityService) DiscoverSecurityArtifacts(
	ctx context.Context,
	owner, repo string,
	workflowID int64,
) ([]*SecurityArtifact, error) {
	return s.checkArtifactForSecurityContent(ctx, owner, repo, workflowID)
}

// BuildPayloadsFromArtifacts converts security artifacts into normalized payloads
func (s *SecurityService) BuildPayloadsFromArtifacts(
	ctx context.Context,
	artifacts []*SecurityArtifact,
	owner, repo, sha string,
	workflowID int64,
) ([]*VulnerabilityPayload, []*SBOMPayload, error) {
	vulnPayloads := make([]*VulnerabilityPayload, 0)
	sbomPayloads := make([]*SBOMPayload, 0)

	s.logger.InfoContext(ctx, "Building payloads from security artifacts", "count", len(artifacts))

	for _, artifact := range artifacts {
		s.logger.InfoContext(ctx, "Processing security artifact",
			"type", artifact.Type,
			"filename", artifact.FileName,
			"size", len(artifact.Content),
		)

		switch artifact.Type {
		case ArtifactTypeVulnerabilityJSON:
			payload, err := buildVulnerabilityPayloadFromTrivy(
				artifact,
				owner,
				repo,
				sha,
				0, // prNumber
			)
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to build vulnerability payload",
					"file_name", artifact.FileName,
					"error", err,
				)

				continue
			}

			vulnPayloads = append(vulnPayloads, payload)

		case ArtifactTypeSBOMSPDX:
			payload, err := buildSBOMPayloadFromSPDX(
				artifact,
				owner,
				repo,
				sha,
				0, // prNumber
			)
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to build SBOM payload",
					"artifact_name", artifact.ArtifactName,
					"file_name", artifact.FileName,
					"error", err,
				)

				continue
			}

			sbomPayloads = append(sbomPayloads, payload)

		default:
			s.logger.WarnContext(ctx, "Unsupported artifact type",
				"type", artifact.Type,
				"filename", artifact.FileName,
			)
		}
	}

	s.logger.InfoContext(ctx, "Built payloads from security artifacts",
		"total_artifacts", len(artifacts),
		"vulnerability_payloads", len(vulnPayloads),
		"sbom_payloads", len(sbomPayloads))

	return vulnPayloads, sbomPayloads, nil
}

// checkArtifactForSecurityContent downloads and inspects for security-related content.
func (s *SecurityService) checkArtifactForSecurityContent(
	ctx context.Context,
	owner, repo string,
	workflowID int64,
) ([]*SecurityArtifact, error) {
	ctx, span := s.telemetry.StartSpan(ctx, "security.check_artifact_for_security_content")
	defer span.End()

	span.SetAttributes(
		attribute.String("owner", owner),
		attribute.String("repo", repo),
		attribute.Int64("workflow_id", workflowID),
	)

	// List artifacts for the workflow
	artifacts, err := s.githubClient.ListWorkflowArtifacts(ctx, owner, repo, workflowID)
	if err != nil {
		s.telemetry.SetErrorAttribute(span, err)
		s.logger.ErrorContext(ctx, "Failed to list workflow artifacts",
			"owner", owner,
			"repo", repo,
			"workflow_id", workflowID,
			"error", err)

		return nil, err
	}

	if len(artifacts) == 0 {
		s.logger.InfoContext(ctx, "No artifacts found for workflow",
			"workflow_id", workflowID)

		return nil, nil
	}

	var allSecurityFiles []*SecurityArtifact

	// Check each artifact
	for _, artifact := range artifacts {
		// Download artifact
		zipData, err := s.githubClient.DownloadArtifact(ctx, owner, repo, artifact.GetID())
		if err != nil {
			s.logger.WarnContext(ctx, "Failed to download artifact",
				"artifact", artifact.GetName(),
				"error", err)

			continue
		}

		// Inspect the artifact content for security-related files
		artifactFiles, err := inspectZipContentForSecurity(zipData, artifact.GetName(), s.detectors)
		if err != nil {
			s.telemetry.SetErrorAttribute(span, err)
			s.logger.WarnContext(ctx, "Failed to inspect ZIP content",
				"artifact", artifact.GetName(),
				"error", err)

			continue
		}

		if len(artifactFiles) > 0 {
			s.logger.InfoContext(ctx, "Found security content in artifact",
				"artifact", artifact.GetName(),
				"files", len(artifactFiles))

			allSecurityFiles = append(allSecurityFiles, artifactFiles...)
		}
	}

	span.SetAttributes(
		attribute.Int("artifacts.total", len(artifacts)),
		attribute.Int("security_files.found", len(allSecurityFiles)),
	)

	s.logger.InfoContext(ctx, "Completed artifact security content check",
		"total_artifacts", len(artifacts),
		"security_files_found", len(allSecurityFiles))

	return allSecurityFiles, nil
}
