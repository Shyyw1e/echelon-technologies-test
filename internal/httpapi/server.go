package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Shyyw1e/echelon-technologies-test/internal/analyser"
)

type analyzeRequest struct {
	Content    string `json:"content"`
	SourceName string `json:"source_name"`
}

type analyzeResponse struct {
	Issues []analyser.Issue `json:"issues"`
}

func ListenAndServe(addr string, analyzer analyser.Analyzer, maxConfigBytes int64) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /analyze", analyzeHandler(analyzer, maxConfigBytes))

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return server.ListenAndServe()
}

func analyzeHandler(analyzer analyser.Analyzer, maxConfigBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("read request: %v", err))
			return
		}
		if int64(len(body)) > maxConfigBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "config is too large")
			return
		}

		source := "http-request"
		content := body
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			var req analyzeRequest
			if err := json.Unmarshal(body, &req); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode json request: %v", err))
				return
			}
			content = []byte(req.Content)
			if req.SourceName != "" {
				source = req.SourceName
			}
		}

		issues, err := analyzer.Analyze(content, analyser.Metadata{SourcePath: source})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, analyzeResponse{Issues: issues})
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
