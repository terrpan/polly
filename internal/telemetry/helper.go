// Package telemetry provides utilities for telemetry and tracing in the application.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Helper centralizes tracing and logging concerns
type Helper struct {
	tracer oteltrace.Tracer
}

// NewTelemetryHelper creates a new Helper with the provided tracer for a component.
func NewTelemetryHelper(component string) *Helper {
	return &Helper{
		tracer: otel.Tracer(component),
	}
}

// StartSpan starts a new span with the given name
func (t *Helper) StartSpan(
	ctx context.Context,
	name string,
) (context.Context, oteltrace.Span) {
	return t.tracer.Start(ctx, name)
}

// SetRepositoryAttributes sets repository attributes on a span
func (t *Helper) SetRepositoryAttributes(span oteltrace.Span, owner, repo, sha string) {
	span.SetAttributes(
		attribute.String("repo.owner", owner),
		attribute.String("repo.name", repo),
		attribute.String("repo.sha", sha),
	)
}

// SetCheckRunAttributes sets check run attributes on a span
func (t *Helper) SetCheckRunAttributes(
	span oteltrace.Span,
	owner, repo string,
	checkRunID int64,
	checkType string,
) {
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int64("github.check_run_id", checkRunID),
		attribute.String("check.type", checkType),
	)
}

// SetPolicyAttributes - for PolicyService
func (t *Helper) SetPolicyAttributes(span oteltrace.Span, policyType string) {
	span.SetAttributes(attribute.String("policy.type", policyType))
}

// SetStorageAttributes - for StateService storage operations
func (t *Helper) SetStorageAttributes(span oteltrace.Span, operation, key string) {
	span.SetAttributes(
		attribute.String("storage.operation", operation),
		attribute.String("storage.key", key),
	)
}

// SetSecurityAttributes - for SecurityService artifact processing
func (t *Helper) SetSecurityAttributes(span oteltrace.Span, artifactType, scanner string) {
	span.SetAttributes(
		attribute.String("security.artifact_type", artifactType),
		attribute.String("security.scanner", scanner),
	)
}

// SetCommentAttributes - for CommentService comment operations
func (t *Helper) SetCommentAttributes(
	span oteltrace.Span,
	owner, repo string,
	prNumber int,
	commentLength int,
) {
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int("pr.number", prNumber),
		attribute.Int("comment.length", commentLength),
	)
}

// SetHealthAttributes - for HealthService dependency checks
func (t *Helper) SetHealthAttributes(span oteltrace.Span, dependency, status string) {
	span.SetAttributes(
		attribute.String("health.dependency", dependency),
		attribute.String("health.status", status),
	)
}

// SetErrorAttribute - universal error handling. Sets error attribute on a span
// and records the error in the span.
func (t *Helper) SetErrorAttribute(span oteltrace.Span, err error) {
	span.SetAttributes(attribute.String("error", err.Error()))
	span.RecordError(err)
}

// SetCacheAttributes sets cache hit/miss attributes on a span
func (t *Helper) SetCacheAttributes(span oteltrace.Span, hit bool) {
	span.SetAttributes(attribute.Bool("cache.hit", hit))
}
