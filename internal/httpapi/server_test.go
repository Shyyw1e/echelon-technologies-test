package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Shyyw1e/echelon-technologies-test/internal/analyser"
)

func TestAnalyzeHandlerAcceptsJSONEnvelope(t *testing.T) {
	t.Parallel()

	body := `{"source_name":"test.yaml","content":"storage:\n  digest-algorithm: MD5\n"}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rec := httptest.NewRecorder()

	analyzeHandler(analyser.NewDefault(), 1024)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var response analyzeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(response.Issues) != 1 {
		t.Fatalf("expected one issue, got %#v", response.Issues)
	}
	if response.Issues[0].Source != "test.yaml" {
		t.Fatalf("Source = %q", response.Issues[0].Source)
	}
}

func TestAnalyzeHandlerAcceptsRawConfig(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("log:\n  level: debug\n"))
	rec := httptest.NewRecorder()

	analyzeHandler(analyser.NewDefault(), 1024)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "debug_logging") {
		t.Fatalf("expected debug issue, got %s", rec.Body.String())
	}
}

func TestAnalyzeHandlerRejectsTooLargeRequest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("version: 1"))
	rec := httptest.NewRecorder()

	analyzeHandler(analyser.NewDefault(), 4)(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAnalyzeHandlerRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("- just\n- array\n"))
	rec := httptest.NewRecorder()

	analyzeHandler(analyser.NewDefault(), 1024)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
