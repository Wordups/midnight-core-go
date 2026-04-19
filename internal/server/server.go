package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Wordups/midnight-core-go/internal/compliance"
)

// Server is the HTTP handler for midnight-core-go.
type Server struct {
	agent *compliance.Agent
}

// New creates a Server backed by a Claude compliance agent.
func New(apiKey string) *Server {
	return &Server{agent: compliance.NewAgent(apiKey)}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	corsMiddleware(s.routes()).ServeHTTP(w, r)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /analyze", s.handleAnalyze)
	mux.HandleFunc("POST /analyze/stream", s.handleAnalyzeStream)
	return mux
}

// corsMiddleware adds permissive CORS headers so the Midnight-Core frontend
// and the Python backend can both call this service without a proxy.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleHealth returns service status.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// handleAnalyze runs a synchronous compliance analysis and returns the full result.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}

	log.Printf("analyze: %q against %v", req.Title, req.Frameworks)

	result, err := s.agent.Analyze(r.Context(), req, nil)
	if err != nil {
		log.Printf("analyze error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleAnalyzeStream runs the analysis and pushes SSE progress events to the
// caller in real time, finishing with a "result" or "error" event.
//
// SSE event types:
//
//	event: progress  data: {"type":"framework_start"|"control_assessed", ...}
//	event: result    data: {AnalysisResult JSON}
//	event: error     data: {"error":"..."}
func (s *Server) handleAnalyzeStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
		return
	}

	req, valid := decodeRequest(w, r)
	if !valid {
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	log.Printf("analyze/stream: %q against %v", req.Title, req.Frameworks)

	progress := make(chan compliance.ProgressEvent, 50)
	resultCh := make(chan *compliance.AnalysisResult, 1)
	errCh := make(chan error, 1)

	go func() {
		result, err := s.agent.Analyze(r.Context(), req, progress)
		close(progress) // drain the range loop below before reading result/err
		if err != nil {
			errCh <- err
		} else {
			resultCh <- result
		}
	}()

	// Stream progress events until the agent finishes.
	for event := range progress {
		b, _ := json.Marshal(event)
		fmt.Fprintf(w, "event: progress\ndata: %s\n\n", b)
		flusher.Flush()
	}

	// Send the terminal event.
	select {
	case result := <-resultCh:
		b, _ := json.Marshal(result)
		fmt.Fprintf(w, "event: result\ndata: %s\n\n", b)
	case err := <-errCh:
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", b)
	}
	flusher.Flush()
}

// decodeRequest parses and validates the shared AnalysisRequest body.
func decodeRequest(w http.ResponseWriter, r *http.Request) (*compliance.AnalysisRequest, bool) {
	var req compliance.AnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return nil, false
	}
	if req.Document == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "document is required"})
		return nil, false
	}
	if len(req.Frameworks) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one framework is required"})
		return nil, false
	}
	return &req, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
