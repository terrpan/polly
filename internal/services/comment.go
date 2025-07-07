package services

import (
	"context"
	"log/slog"

	"github.com/terrpan/polly/internal/clients"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type CommentService struct {
	githubClient *clients.GitHubClient
	logger       *slog.Logger
}

// NewCommentService initializes a new CommentService with the provided GitHub client and logger.
func NewCommentService(githubClient *clients.GitHubClient, logger *slog.Logger) *CommentService {
	return &CommentService{
		githubClient: githubClient,
		logger:       logger,
	}
}

// WriteComment writes a comment on a pull request using the GitHub client.
func (s *CommentService) WriteComment(ctx context.Context, owner, repo string, number int, comment string) error {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "comment.write")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int("pr.number", number),
		attribute.Int("comment.length", len(comment)),
	)

	s.logger.Info("Writing comment", "owner", owner, "repo", repo, "pr_number", number)

	err := s.githubClient.WriteComment(ctx, owner, repo, number, comment)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.Error("Failed to write comment", "error", err)
		return err
	}

	s.logger.Info("Comment written successfully", "owner", owner, "repo", repo, "pr_number", number)
	return nil
}
