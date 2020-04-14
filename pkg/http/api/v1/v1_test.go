package v1_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	v1 "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner/mocks"
)

var _ = Describe("Harbor Scanner Sysdig Secure API Adapter", func() {
	var (
		controller *gomock.Controller
		adapter    *mocks.MockAdapter
		handler    http.Handler
	)

	BeforeEach(func() {
		controller = gomock.NewController(GinkgoT())
		adapter = mocks.NewMockAdapter(controller)
		handler = v1.NewAPIHandler(adapter)
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("GET /api/v1/metadata", func() {
		BeforeEach(func() {
			adapter.EXPECT().GetMetadata().Return(sysdigSecureScannerAdapterMetadata())
		})

		It("returns OK", func() {
			response := doGetRequest(handler, "/api/v1/metadata")

			Expect(response.StatusCode).To(Equal(http.StatusOK))
		})

		It("returns scanner.adapter.metadata Mime Type", func() {
			response := doGetRequest(handler, "/api/v1/metadata")

			Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.metadata+json; version=1.0"))
		})

		It("returns a valid scanner.adapter.metadata encoded as JSON", func() {
			response := doGetRequest(handler, "/api/v1/metadata")

			var result harbor.ScannerAdapterMetadata
			json.NewDecoder(response.Body).Decode(&result)

			Expect(result).To(Equal(sysdigSecureScannerAdapterMetadata()))
		})
	})

	Context("POST /api/v1/scan", func() {
		It("returns ACCEPTED", func() {
			scanRequest := harbor.ScanRequest{
				Registry: &harbor.Registry{
					Url:           "https://core.harbor.domain",
					Authorization: "Basic BASE64_ENCODED_CREDENTIALS",
				},
				Artifact: &harbor.Artifact{
					Repository: "library/mongo",
					Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
					Tag:        "3.14-xenial",
					MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
				},
			}
			payload, _ := json.Marshal(scanRequest)

			response := doPostRequest(handler, "/api/v1/scan", string(payload))

			Expect(response.StatusCode).To(Equal(http.StatusAccepted))
		})

		Context("when receiving a not valid scan.request representation", func() {
			It("returns BAD_REQUEST", func() {
				scanRequest := ""

				response := doPostRequest(handler, "/api/v1/scan", scanRequest)

				Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
			})

			It("returns a an error encoded as JSON", func() {
				scanRequest := "invalid json"

				response := doPostRequest(handler, "/api/v1/scan", scanRequest)

				var result harbor.ErrorResponse
				json.NewDecoder(response.Body).Decode(&result)

				Expect(result).To(Equal(harborInvalidScanResponse()))
			})
		})
	})
})

func doGetRequest(handler http.Handler, path string) *http.Response {
	request, _ := http.NewRequest(http.MethodGet, path, nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder.Result()
}

func doPostRequest(handler http.Handler, path string, payload string) *http.Response {
	request, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(payload))

	recorder := httptest.NewRecorder()
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

func harborInvalidScanResponse() harbor.ErrorResponse {
	return harbor.ErrorResponse{
		Error: &harbor.ModelError{
			Message: "Error parsing scan request: invalid character 'i' looking for beginning of value",
		},
	}
}
