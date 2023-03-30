package v1

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
)

const (
	DefaultRefreshTimeInSeconds = 60
)

type requestHandler struct {
	adapter scanner.Adapter
	logger  Logger
}

type Logger interface {
	Writer() *io.PipeWriter
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

func NewAPIHandler(adapter scanner.Adapter, logger Logger) http.Handler {
	handler := requestHandler{
		adapter: adapter,
		logger:  logger,
	}

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/health").HandlerFunc(health)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()
	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.metadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.scan)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.getReport)

	return handlers.LoggingHandler(logger.Writer(), router)
}

func health(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) metadata(res http.ResponseWriter, req *http.Request) {
	metadata, err := h.adapter.GetMetadata()
	if err != nil {
		h.logRequestError(req, err)
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
		h.logRequestError(req, err)
		res.Header().Set("Content-Type", harbor.ScanAdapterErrorMimeType)
		res.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(res).Encode(
			errorResponseFromError(
				fmt.Errorf("Error parsing scan request: %s", err.Error())))
		return
	}

	scanResponse, err := h.adapter.Scan(scanRequest)
	if err != nil {
		h.logRequestError(req, err)
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

	vulnerabilityReport, err := h.adapter.GetVulnerabilityReport(harbor.ScanRequestID(vars["scan_request_id"]))
	if err != nil {
		h.logRequestError(req, err)
		switch err {
		case scanner.ErrScanRequestIDNotFound:
			res.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(res).Encode(errorResponseFromError(err))
		case scanner.ErrVulnerabilityReportNotReady:
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
	_ = json.NewEncoder(res).Encode(vulnerabilityReport)
}

func (h *requestHandler) logRequestError(req *http.Request, err error) {
	ts := time.Now()
	h.logger.Errorf("[%s] \"%s %s %s\" request ERROR: %s",
		ts.Format("02/Jan/2006:15:04:05 -0700"),
		req.Method,
		req.RequestURI,
		req.Proto,
		err)
}

func errorResponseFromError(err error) harbor.ErrorResponse {
	return harbor.ErrorResponse{
		Error: &harbor.ModelError{
			Message: err.Error(),
		},
	}
}
