package v1

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
)

type requestHandler struct {
	adapter scanner.Adapter
}

func NewAPIHandler(adapter scanner.Adapter) http.Handler {
	handler := requestHandler{
		adapter: adapter,
	}

	router := mux.NewRouter()

	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.metadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.scan)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.getReport)

	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func (h *requestHandler) metadata(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", harbor.ScannerAdapterMetadataMimeType)

	err := json.NewEncoder(res).Encode(h.adapter.GetMetadata())
	if err != nil {
		log.WithError(err).Error("Error while serializing JSON")
	}
}

func (h *requestHandler) scan(res http.ResponseWriter, req *http.Request) {
	var scanRequest harbor.ScanRequest
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)

		errorResponse := harbor.ErrorResponse{
			Error: &harbor.ModelError{
				Message: fmt.Sprintf("Error parsing scan request: %s", err.Error()),
			},
		}
		err := json.NewEncoder(res).Encode(errorResponse)
		if err != nil {
			log.WithError(err).Error("Error while serializing JSON")
		}

		return
	}

	res.WriteHeader(http.StatusAccepted)
}

func (h *requestHandler) getReport(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", harbor.ScanReportMimeType)

	vars := mux.Vars(req)
	vulnerabilityReport, err := h.adapter.GetVulnerabilityReport(vars["scan_request_id"])

	if err != nil {
		if err == scanner.ScanRequestIDNotFoundErr {
			res.WriteHeader(http.StatusNotFound)

			errorResponse := harbor.ErrorResponse{
				Error: &harbor.ModelError{
					Message: err.Error(),
				},
			}
			err := json.NewEncoder(res).Encode(errorResponse)
			if err != nil {
				log.WithError(err).Error("Error while serializing JSON")
			}

			return
		}

		if err == scanner.VulnerabiltyReportNotReadyErr {
			res.Header().Set("Refresh-After", "120")
			res.WriteHeader(http.StatusFound)
			return
		}
	}

	json.NewEncoder(res).Encode(vulnerabilityReport)
}
