package v1

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

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

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/health").HandlerFunc(health)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()
	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.metadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.scan)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.getReport)

	return handlers.LoggingHandler(logger, router)
}

func health(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) metadata(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", harbor.ScannerAdapterMetadataMimeType)

	json.NewEncoder(res).Encode(h.adapter.GetMetadata())
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
	vars := mux.Vars(req)

	vulnerabilityReport, err := h.adapter.GetVulnerabilityReport(vars["scan_request_id"])
	if err != nil {
		switch err {
		case scanner.ErrScanRequestIDNotFound:
			res.WriteHeader(http.StatusNotFound)
			json.NewEncoder(res).Encode(errorResponseFromError(err))
		case scanner.ErrVulnerabiltyReportNotReady:
			res.Header().Set("Refresh-After", "120")
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
