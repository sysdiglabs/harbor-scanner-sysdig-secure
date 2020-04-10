package v1_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
)

var _ = Describe("Harbor Scanner Sysdig Secure API Adapter", func() {
	Context("GET /api/v1/metadata", func() {
		It("returns OK", func() {
			response := doGetRequest("/api/v1/metadata")

			Expect(response.StatusCode).To(Equal(http.StatusOK))
		})

		It("returns scanner.adapter.metadata Mime Type", func() {
			response := doGetRequest("/api/v1/metadata")

			Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.metadata+json; version=1.0"))
		})

		It("returns a valid scanner.adapter.metadata encoded as JSON", func() {
			response := doGetRequest("/api/v1/metadata")

			var result harbor.ScannerAdapterMetadata
			json.NewDecoder(response.Body).Decode(&result)

			Expect(result).To(Equal(sysdigSecureScannerAdapterMetadata()))
		})
	})

})

func doGetRequest(path string) *http.Response {
	request, _ := http.NewRequest("GET", path, nil)

	recorder := httptest.NewRecorder()

	handler := v1.NewAPIHandler()
	handler.ServeHTTP(recorder, request)

	return recorder.Result()
}

func sysdigSecureScannerAdapterMetadata() harbor.ScannerAdapterMetadata {
	return harbor.ScannerAdapterMetadata{
		Scanner: &harbor.Scanner{
			Name:    "Sysdig Secure",
			Vendor:  "Sysdig",
			Version: "3.2",
		},
		Capabilities: []harbor.ScannerCapability{
			{
				ConsumesMimeTypes: []string{
					"application/vnd.oci.image.manifest.v1+json",
					"application/vnd.docker.distribution.manifest.v2+json",
				},
				ProducesMimeTypes: []string{
					"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
				},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type":                "os-package-vulnerability",
			"harbor.scanner-adapter/registry-authorization-type": "Bearer",
		},
	}
}
