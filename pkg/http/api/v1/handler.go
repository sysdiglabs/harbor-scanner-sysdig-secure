package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
)

const (
	DefaultRefreshTimeInSeconds = 60
)

type requestHandler struct {
	adapter scanner.Adapter
}

func NewAPIHandler(adapter scanner.Adapter) http.Handler {
	handler := requestHandler{
		adapter: adapter,
	}

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/health").HandlerFunc(health)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()
	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.metadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.scan)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.getReport)

	return loggingMiddleware(router)
}

func health(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) metadata(res http.ResponseWriter, req *http.Request) {
	metadata, err := h.adapter.GetMetadata()
	if err != nil {
		slog.Error("request error", "method", req.Method, "uri", req.RequestURI, "error", err)
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusInternalServerError)

		if err := json.NewEncoder(res).Encode(errorResponseFromError(err)); err != nil {
			return
		}
		return
	}

	res.Header().Set("Content-Type", harbor.ScannerAdapterMetadataMimeType)
	if err := json.NewEncoder(res).Encode(metadata); err != nil {
		return
	}
}

func (h *requestHandler) scan(res http.ResponseWriter, req *http.Request) {
	var scanRequest harbor.ScanRequest
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		slog.Error("request error", "method", req.Method, "uri", req.RequestURI, "error", err)
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(res).Encode(errorResponseFromError(fmt.Errorf("error parsing scan request: %s", err.Error()))); err != nil {
			return
		}
		return
	}

	scanResponse, err := h.adapter.Scan(scanRequest)
	if err != nil {
		slog.Error("request error", "method", req.Method, "uri", req.RequestURI, "error", err)
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusInternalServerError)
		if err := json.NewEncoder(res).Encode(errorResponseFromError(err)); err != nil {
			return
		}
		return
	}

	res.Header().Set("Content-Type", harbor.ScanResponseMimeType)
	res.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(res).Encode(scanResponse); err != nil {
		return
	}
}

func (h *requestHandler) getReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	vulnerabilityReport, err := h.adapter.GetVulnerabilityReport(harbor.ScanRequestID(vars["scan_request_id"]))
	if err != nil {
		slog.Error("request error", "method", req.Method, "uri", req.RequestURI, "error", err)
		switch {
		case errors.Is(err, scanner.ErrScanRequestIDNotFound):
			res.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(res).Encode(errorResponseFromError(err))
		case errors.Is(err, scanner.ErrVulnerabilityReportNotReady):
			res.Header().Set("Refresh-After", fmt.Sprintf("%d", DefaultRefreshTimeInSeconds))
			res.Header().Set("Location", req.URL.String())
			res.WriteHeader(http.StatusFound)
		default:
			res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
			res.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(res).Encode(errorResponseFromError(err))
		}
		return
	}

	res.Header().Set("Content-Type", harbor.ScanReportMimeType)
	jsonData, err := json.Marshal(vulnerabilityReport)
	if err != nil {
		slog.Error("error marshalling vulnerability report to JSON", "error", err)
		return
	}

	slog.Debug("vulnerability report", "report", string(jsonData))

	_ = json.NewEncoder(res).Encode(vulnerabilityReport)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.RequestURI,
			"status", rec.status,
			"size", rec.size,
			"duration", time.Since(start),
		)
	})
}

func errorResponseFromError(err error) harbor.ErrorResponse {
	return harbor.ErrorResponse{
		Error: &harbor.ModelError{
			Message: err.Error(),
		},
	}
}
