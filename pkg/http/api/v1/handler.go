package v1

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

func NewAPIHandler() http.Handler {
	router := mux.NewRouter()

	router.Use(logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(metadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(scan)

	return router
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func metadata(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", harbor.ScannerAdapterMetadataMimeType)

	result := harbor.ScannerAdapterMetadata{
		Scanner: &harbor.Scanner{
			Name:    "Sysdig Secure",
			Vendor:  "Sysdig",
			Version: "3.2", // TODO: Query backend to get version information
		},
		Capabilities: []harbor.ScannerCapability{
			{
				ConsumesMimeTypes: []string{
					harbor.OCIImageManifestMimeType,
					harbor.DockerDistributionManifestMimeType,
				},
				ProducesMimeTypes: []string{
					harbor.ScanReportMimeType,
				},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type":                "os-package-vulnerability",
			"harbor.scanner-adapter/registry-authorization-type": "Bearer",
		},
	}

	err := json.NewEncoder(res).Encode(result)

	if err != nil {
		log.WithError(err).Error("Error while serializing JSON")
	}
}

func scan(res http.ResponseWriter, req *http.Request) {
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
