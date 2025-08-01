package otel

import (
	"context"
	"errors"
	"time"

	"github.com/terrpan/polly/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

// TracingHelper provides a consistent way to create tracing spans across the application
type TracingHelper struct {
	tracer oteltrace.Tracer
}

// NewTracingHelper creates a new tracing helper for the specified component
// componentName should be in the format "polly/handlers", "polly/services", etc.
func NewTracingHelper(componentName string) *TracingHelper {
	return &TracingHelper{
		tracer: otel.Tracer(componentName),
	}
}

// StartSpan creates a new tracing span with the given name
func (t *TracingHelper) StartSpan(ctx context.Context, name string) (context.Context, oteltrace.Span) {
	return t.tracer.Start(ctx, name)
}

func SetupOTelSDK(ctx context.Context, serviceName string) (shutdown func(context.Context) error, err error) {
	var shutdownFuncs []func(context.Context) error

	shutdown = func(ctx context.Context) error {
		var err error

		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}

		shutdownFuncs = nil
		return err
	}

	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	tracerProvider, err := newTraceProvider(ctx, serviceName)
	if err != nil {
		handleErr(err)
		return
	}

	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	return
}

func newTraceProvider(ctx context.Context, serviceName string) (*trace.TracerProvider, error) {
	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithInsecure(), // This enables plain HTTP
	)
	if err != nil {
		return nil, err
	}

	var traceStdOut trace.SpanExporter
	if config.AppConfig.OTLP.OTLPStdOut {
		traceStdOut, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, err
		}
	}

	// Merge default resource with service name
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	traceProviderOptions := []trace.TracerProviderOption{
		trace.WithBatcher(traceExporter,
			trace.WithBatchTimeout(time.Second)),
		trace.WithResource(res),
	}

	if traceStdOut != nil {
		traceProviderOptions = append(traceProviderOptions, trace.WithBatcher(traceStdOut))
	}

	traceProvider := trace.NewTracerProvider(traceProviderOptions...)
	return traceProvider, nil
}
