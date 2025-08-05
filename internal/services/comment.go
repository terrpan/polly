package services

import (
	"context"
	"log/slog"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/telemetry"
)

// CommentService provides methods to interact with comments on GitHub
type CommentService struct {
	githubClient *clients.GitHubClient
	logger       *slog.Logger
	telemetry    *telemetry.TelemetryHelper
}

// NewCommentService initializes a new CommentService with the provided GitHub client and logger.
func NewCommentService(
	githubClient *clients.GitHubClient,
	logger *slog.Logger,
	telemetry *telemetry.TelemetryHelper,
) *CommentService {
	return &CommentService{
		githubClient: githubClient,
		logger:       logger,
		telemetry:    telemetry,
	}
}

// WriteComment writes a comment on a pull request using the GitHub client.
func (s *CommentService) WriteComment(
	ctx context.Context,
	owner, repo string,
	number int,
	comment string,
) error {
	ctx, span := s.telemetry.StartSpan(ctx, "comment.write")
	defer span.End()

	s.telemetry.SetCommentAttributes(span, owner, repo, number, len(comment))

	s.logger.Info("Writing comment", "owner", owner, "repo", repo, "pr_number", number)

	err := s.githubClient.WriteComment(ctx, owner, repo, number, comment)
	if err != nil {
		s.telemetry.SetErrorAttribute(span, err)
		s.logger.Error("Failed to write comment", "error", err)

		return err
	}

	s.logger.Info("Comment written successfully", "owner", owner, "repo", repo, "pr_number", number)

	return nil
}
