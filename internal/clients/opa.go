package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type OPAClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewOPAClient initializes a new OPA client with the provided base URL and HTTP client.
func NewOPAClient(baseURL string) (*OPAClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("base URL cannot be empty")
	}
	return &OPAClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Transport: otelhttp.NewTransport(http.DefaultTransport),
			Timeout:   30 * time.Second, // Set a timeout for HTTP requests
		},
	}, nil
}

// Do performs an HTTP request with the specified method and URL.
func (c *OPAClient) Do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	return c.HTTPClient.Do(req)
}

func (c *OPAClient) GetOpaHealth(ctx context.Context) (*http.Response, error) {
	// Construct the health check URL
	url := c.BaseURL + "/health"

	// Make a GET request to the OPA health endpoint
	return c.Do(ctx, http.MethodGet, url, nil)
}

// evaluatePolicy evaluates a policy with the given input.
func (c *OPAClient) EvaluatePolicy(ctx context.Context, policyPath string, payload interface{}) (*http.Response, error) {
	// Construct the policy evaluation URL
	url := c.BaseURL + policyPath

	// Convert input to JSON
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	// Make a POST request to evaluate the policy
	return c.Do(ctx, http.MethodPost, url, bytes.NewReader(body))
}
