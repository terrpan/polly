package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoSetsContentType(t *testing.T) {
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := NewOPAClient(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = c.Do(context.Background(), http.MethodPost, server.URL+"/test", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type header = %q, want %q", receivedContentType, "application/json")
	}
}
