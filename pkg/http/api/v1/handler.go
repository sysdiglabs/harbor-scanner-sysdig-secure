package v1

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
)

type requestHandler struct {
	adapter scanner.Adapter
}

func NewAPIHandler(adapter scanner.Adapter, logger io.Writer) http.Handler {
	handler := requestHandler{
		adapter: adapter,
	}

	// TODO: This smells
	middleware.DefaultLogger = middleware.RequestLogger(&middleware.DefaultLogFormatter{Logger: log.New(logger, "", 0), NoColor: true})

	router := chi.NewRouter()
	router.Use(middleware.Logger)

	router.Get("/health", health)

	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/metadata", handler.metadata)
		r.Post("/scan", handler.scan)
		r.Get("/scan/{scan_request_id}/report", handler.getReport)
	})

	return router
}

func health(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) metadata(res http.ResponseWriter, req *http.Request) {
	metadata, err := h.adapter.GetMetadata()
	if err != nil {
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(res).Encode(errorResponseFromError(err))
		return
	}

	res.Header().Set("Content-Type", harbor.ScannerAdapterMetadataMimeType)
	json.NewEncoder(res).Encode(metadata)
}

func (h *requestHandler) scan(res http.ResponseWriter, req *http.Request) {
	var scanRequest harbor.ScanRequest
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(res).Encode(
			errorResponseFromError(
				fmt.Errorf("Error parsing scan request: %s", err.Error())))
		return
	}

	scanResponse, err := h.adapter.Scan(scanRequest)
	if err != nil {
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(res).Encode(errorResponseFromError(err))
		return
	}

	res.Header().Set("Content-Type", harbor.ScanResponseMimeType)
	res.WriteHeader(http.StatusAccepted)
	json.NewEncoder(res).Encode(scanResponse)
}

func (h *requestHandler) getReport(res http.ResponseWriter, req *http.Request) {
	vulnerabilityReport, err := h.adapter.GetVulnerabilityReport(chi.URLParam(req, "scan_request_id"))
	if err != nil {
		switch err {
		case scanner.ErrScanRequestIDNotFound:
			res.WriteHeader(http.StatusNotFound)
			json.NewEncoder(res).Encode(errorResponseFromError(err))
		case scanner.ErrVulnerabiltyReportNotReady:
			res.Header().Set("Refresh-After", "120")
			res.Header().Set("Location", req.URL.String())
			res.WriteHeader(http.StatusFound)
		default:
			res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
			res.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(res).Encode(errorResponseFromError(err))
		}
		return
	}

	res.Header().Set("Content-Type", harbor.ScanReportMimeType)
	json.NewEncoder(res).Encode(vulnerabilityReport)
}

func errorResponseFromError(err error) harbor.ErrorResponse {
	return harbor.ErrorResponse{
		Error: &harbor.ModelError{
			Message: err.Error(),
		},
	}
}
