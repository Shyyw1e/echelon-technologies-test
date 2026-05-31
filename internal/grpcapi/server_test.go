package grpcapi

import (
	"context"
	"errors"
	"testing"

	"github.com/Shyyw1e/echelon-technologies-test/internal/analyser"
	"google.golang.org/grpc"
)

func TestJSONCodecRoundTrip(t *testing.T) {
	t.Parallel()

	codec := jsonCodec{}
	if codec.Name() != "json" {
		t.Fatalf("Name() = %q", codec.Name())
	}

	encoded, err := codec.Marshal(AnalyzeRequest{Content: []byte("version: 1"), SourceName: "test.yaml"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded AnalyzeRequest
	if err := codec.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if string(decoded.Content) != "version: 1" || decoded.SourceName != "test.yaml" {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestAnalyzerServiceAnalyze(t *testing.T) {
	t.Parallel()

	service := analyzerService{
		analyzer:       analyser.NewDefault(),
		maxConfigBytes: 1024,
	}

	resp, err := service.Analyze(context.Background(), &AnalyzeRequest{
		Content:    []byte("log:\n  level: debug\n"),
		SourceName: "grpc.yaml",
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(resp.Issues) != 1 {
		t.Fatalf("expected one issue, got %#v", resp.Issues)
	}
	if resp.Issues[0].Source != "grpc.yaml" {
		t.Fatalf("Source = %q", resp.Issues[0].Source)
	}
}

func TestAnalyzerServiceRejectsTooLargeConfig(t *testing.T) {
	t.Parallel()

	service := analyzerService{
		analyzer:       analyser.NewDefault(),
		maxConfigBytes: 4,
	}

	if _, err := service.Analyze(context.Background(), &AnalyzeRequest{Content: []byte("version: 1")}); err == nil {
		t.Fatal("expected error for too large config")
	}
}

func TestAnalyzeMethodHandler(t *testing.T) {
	t.Parallel()

	service := &analyzerService{
		analyzer:       analyser.NewDefault(),
		maxConfigBytes: 1024,
	}

	dec := func(value any) error {
		req := value.(*AnalyzeRequest)
		req.Content = []byte("storage:\n  digest-algorithm: MD5\n")
		req.SourceName = "handler.yaml"
		return nil
	}

	resp, err := analyzeMethodHandler(service, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("analyzeMethodHandler() error = %v", err)
	}

	typed := resp.(*AnalyzeResponse)
	if len(typed.Issues) != 1 || typed.Issues[0].Rule != "weak_algorithm" {
		t.Fatalf("unexpected response: %#v", typed)
	}
}

func TestAnalyzeMethodHandlerUsesInterceptor(t *testing.T) {
	t.Parallel()

	service := &analyzerService{
		analyzer:       analyser.NewDefault(),
		maxConfigBytes: 1024,
	}

	called := false
	interceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		called = true
		if info.FullMethod != "/configaudit.AnalyzerService/Analyze" {
			t.Fatalf("FullMethod = %q", info.FullMethod)
		}
		return handler(ctx, req)
	}

	_, err := analyzeMethodHandler(service, context.Background(), func(value any) error {
		value.(*AnalyzeRequest).Content = []byte("version: 1")
		return nil
	}, interceptor)
	if err != nil {
		t.Fatalf("analyzeMethodHandler() error = %v", err)
	}
	if !called {
		t.Fatal("expected interceptor to be called")
	}
}

func TestAnalyzeMethodHandlerPropagatesDecodeError(t *testing.T) {
	t.Parallel()

	service := &analyzerService{
		analyzer:       analyser.NewDefault(),
		maxConfigBytes: 1024,
	}
	want := errors.New("decode failed")

	_, err := analyzeMethodHandler(service, context.Background(), func(any) error {
		return want
	}, nil)
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestConvertIssues(t *testing.T) {
	t.Parallel()

	converted := convertIssues([]analyser.Issue{{
		Severity:       analyser.SeverityHigh,
		RuleID:         "weak_algorithm",
		Message:        "bad algorithm",
		Recommendation: "replace it",
		Path:           "storage.digest",
		Source:         "config.yaml",
	}})

	if len(converted) != 1 {
		t.Fatalf("expected one issue, got %#v", converted)
	}
	if converted[0].Rule != "weak_algorithm" || converted[0].Severity != "HIGH" {
		t.Fatalf("unexpected conversion: %#v", converted[0])
	}
}
