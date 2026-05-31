package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/Shyyw1e/echelon-technologies-test/internal/analyser"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

type AnalyzeRequest struct {
	Content    []byte `json:"content"`
	SourceName string `json:"source_name"`
}

type AnalyzeResponse struct {
	Issues []Issue `json:"issues"`
}

type Issue struct {
	Severity       string `json:"severity"`
	Rule           string `json:"rule"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
	Path           string `json:"path,omitempty"`
	Source         string `json:"source,omitempty"`
}

type analyzerService struct {
	analyzer       analyser.Analyzer
	maxConfigBytes int64
}

func ListenAndServe(addr string, analyzer analyser.Analyzer, maxConfigBytes int64) error {
	encoding.RegisterCodec(jsonCodec{})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	server := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	RegisterAnalyzerService(server, &analyzerService{
		analyzer:       analyzer,
		maxConfigBytes: maxConfigBytes,
	})

	return server.Serve(listener)
}

func (service *analyzerService) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	if int64(len(req.Content)) > service.maxConfigBytes {
		return nil, fmt.Errorf("config is too large")
	}

	source := req.SourceName
	if source == "" {
		source = "grpc-request"
	}

	issues, err := service.analyzer.Analyze(req.Content, analyser.Metadata{SourcePath: source})
	if err != nil {
		return nil, err
	}

	return &AnalyzeResponse{Issues: convertIssues(issues)}, nil
}

func convertIssues(issues []analyser.Issue) []Issue {
	result := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		result = append(result, Issue{
			Severity:       string(issue.Severity),
			Rule:           issue.RuleID,
			Message:        issue.Message,
			Recommendation: issue.Recommendation,
			Path:           issue.Path,
			Source:         issue.Source,
		})
	}
	return result
}

type AnalyzerServer interface {
	Analyze(context.Context, *AnalyzeRequest) (*AnalyzeResponse, error)
}

func RegisterAnalyzerService(server *grpc.Server, service AnalyzerServer) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "configaudit.AnalyzerService",
		HandlerType: (*AnalyzerServer)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Analyze",
			Handler:    analyzeMethodHandler,
		}},
		Streams:  []grpc.StreamDesc{},
		Metadata: "internal/grpcapi/proto/analyser.proto",
	}, service)
}

func analyzeMethodHandler(server any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(AnalyzeRequest)
	if err := dec(req); err != nil {
		return nil, err
	}

	service := server.(AnalyzerServer)
	if interceptor == nil {
		return service.Analyze(ctx, req)
	}

	info := &grpc.UnaryServerInfo{
		Server:     service,
		FullMethod: "/configaudit.AnalyzerService/Analyze",
	}
	handler := func(ctx context.Context, request any) (any, error) {
		return service.Analyze(ctx, request.(*AnalyzeRequest))
	}
	return interceptor(ctx, req, info, handler)
}
