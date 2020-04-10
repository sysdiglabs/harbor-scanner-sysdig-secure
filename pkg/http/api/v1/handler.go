package v1

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

const (
	scannerAdapterMetadataMimeType     = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	ociImageManifestMimeType           = "application/vnd.oci.image.manifest.v1+json"
	dockerDistributionManifestMimeType = "application/vnd.docker.distribution.manifest.v2+json"
	scanReportMimeType                 = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
)

func NewAPIHandler() http.Handler {
	router := mux.NewRouter()

	router.Use(logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(metadata)

	return router
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func metadata(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", scannerAdapterMetadataMimeType)

	result := harbor.ScannerAdapterMetadata{
		Scanner: &harbor.Scanner{
			Name:    "Sysdig Secure",
			Vendor:  "Sysdig",
			Version: "3.2", // TODO: Query backend to get version information
		},
		Capabilities: []harbor.ScannerCapability{
			{
				ConsumesMimeTypes: []string{
					ociImageManifestMimeType,
					dockerDistributionManifestMimeType,
				},
				ProducesMimeTypes: []string{
					scanReportMimeType,
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
