package v1_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	v1 "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner/mocks"
)

var (
	ErrUnexpected = errors.New("an unexpected error")
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
		handler = v1.NewAPIHandler(adapter, GinkgoWriter)
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("GET /health", func() {
		It("returns OK", func() {
			response := doGetRequest(handler, "/health")

			Expect(response.StatusCode).To(Equal(http.StatusOK))
		})
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
			adapter.EXPECT().Scan(harborScanRequest()).Return(harborScanResponse(), nil)

			payload, _ := json.Marshal(harborScanRequest())
			response := doPostRequest(handler, "/api/v1/scan", string(payload))

			Expect(response.StatusCode).To(Equal(http.StatusAccepted))
		})

		It("returns scanner.adapter.scan.response mime type", func() {
			adapter.EXPECT().Scan(harborScanRequest()).Return(harborScanResponse(), nil)

			payload, _ := json.Marshal(harborScanRequest())
			response := doPostRequest(handler, "/api/v1/scan", string(payload))

			Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.scan.response+json; version=1.0"))
		})

		It("returns a valid scanner.adapter.scan.response as JSON", func() {
			adapter.EXPECT().Scan(harborScanRequest()).Return(harborScanResponse(), nil)

			payload, _ := json.Marshal(harborScanRequest())
			response := doPostRequest(handler, "/api/v1/scan", string(payload))

			var result harbor.ScanResponse
			json.NewDecoder(response.Body).Decode(&result)
			Expect(result).To(Equal(harborScanResponse()))
		})

		Context("when receiving a not valid JSON", func() {
			It("returns BAD_REQUEST", func() {
				scanRequest := "invalid json"
				response := doPostRequest(handler, "/api/v1/scan", scanRequest)

				Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
			})

			It("returns scanner.adapter.error mime type", func() {
				scanRequest := "invalid json"
				response := doPostRequest(handler, "/api/v1/scan", scanRequest)

				Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.error+json; version=1.0"))
			})

			It("returns a an error encoded as JSON", func() {
				scanRequest := "invalid json"
				response := doPostRequest(handler, "/api/v1/scan", scanRequest)

				var result harbor.ErrorResponse
				json.NewDecoder(response.Body).Decode(&result)

				Expect(result).To(Equal(harborErrorResponseFor("Error parsing scan request: invalid character 'i' looking for beginning of value")))
			})
		})

		Context("when other unexpected errors happen", func() {
			BeforeEach(func() {
				adapter.EXPECT().Scan(harborScanRequest()).Return(harbor.ScanResponse{}, ErrUnexpected)
			})

			It("returns INTERNAL_SERVER_ERROR", func() {
				payload, _ := json.Marshal(harborScanRequest())
				response := doPostRequest(handler, "/api/v1/scan", string(payload))

				Expect(response.StatusCode).To(Equal(http.StatusInternalServerError))
			})

			It("returns scanner.adapter.error mime type", func() {
				payload, _ := json.Marshal(harborScanRequest())
				response := doPostRequest(handler, "/api/v1/scan", string(payload))

				Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.error+json; version=1.0"))
			})

			It("returns a the error encoded as JSON", func() {
				payload, _ := json.Marshal(harborScanRequest())
				response := doPostRequest(handler, "/api/v1/scan", string(payload))

				var result harbor.ErrorResponse
				json.NewDecoder(response.Body).Decode(&result)

				Expect(result).To(Equal(harborErrorResponseFor(ErrUnexpected.Error())))
			})
		})
	})

	Context("POST /api/v1/scan/{scan_request_id}/report", func() {
		It("returns OK", func() {
			adapter.EXPECT().GetVulnerabilityReport("scan-request-id").Return(vulnerabilityReport(), nil)

			response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

			Expect(response.StatusCode).To(Equal(http.StatusOK))
		})

		It("returns scanner.adapter.vuln.report.harbor Mime Type", func() {
			adapter.EXPECT().GetVulnerabilityReport("scan-request-id").Return(vulnerabilityReport(), nil)

			response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

			Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"))
		})

		It("returns a valid scanner.vuln.report.harbor as JSON", func() {
			adapter.EXPECT().GetVulnerabilityReport("scan-request-id").Return(vulnerabilityReport(), nil)
			response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

			var result harbor.VulnerabilityReport
			json.NewDecoder(response.Body).Decode(&result)

			Expect(result).To(Equal(vulnerabilityReport()))
		})

		Context("when scan_request_id doesn't exist", func() {
			BeforeEach(func() {
				adapter.EXPECT().GetVulnerabilityReport("scan-request-id").Return(vulnerabilityReport(), scanner.ErrScanRequestIDNotFound)
			})

			It("returns NOT_FOUND", func() {
				response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

				Expect(response.StatusCode).To(Equal(http.StatusNotFound))
			})
		})

		Context("when image is still being scanned", func() {
			BeforeEach(func() {
				adapter.EXPECT().GetVulnerabilityReport("scan-request-id").Return(vulnerabilityReport(), scanner.ErrVulnerabiltyReportNotReady)
			})

			It("returns FOUND", func() {
				response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

				Expect(response.StatusCode).To(Equal(http.StatusFound))
			})

			It("returns the interval after request should be retried", func() {
				response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

				Expect(response.Header.Get("Refresh-After")).To(Equal("120"))
			})
		})

		Context("when other unexpected errors happen", func() {
			BeforeEach(func() {
				adapter.EXPECT().GetVulnerabilityReport("scan-request-id").Return(vulnerabilityReport(), ErrUnexpected)
			})

			It("returns INTERNAL_SERVER_ERROR", func() {
				response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

				Expect(response.StatusCode).To(Equal(http.StatusInternalServerError))
			})

			It("returns scanner.adapter.error mime type", func() {
				response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

				Expect(response.Header.Get("Content-Type")).To(Equal("application/vnd.scanner.adapter.error+json; version=1.0"))
			})

			It("returns a the error encoded as JSON", func() {
				response := doGetRequest(handler, "/api/v1/scan/scan-request-id/report")

				var result harbor.ErrorResponse
				json.NewDecoder(response.Body).Decode(&result)

				Expect(result).To(Equal(harborErrorResponseFor(ErrUnexpected.Error())))
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

func harborScanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: &harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Basic BASE64_ENCODED_CREDENTIALS",
		},
		Artifact: &harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
			Tag:        "3.14-xenial",
			MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
		},
	}
}

func harborScanResponse() harbor.ScanResponse {
	return harbor.ScanResponse{ID: "an scan response id"}
}

func harborErrorResponseFor(message string) harbor.ErrorResponse {
	return harbor.ErrorResponse{
		Error: &harbor.ModelError{
			Message: message,
		},
	}
}

func vulnerabilityReport() harbor.VulnerabilityReport {
	return harbor.VulnerabilityReport{
		Vulnerabilities: []harbor.VulnerabilityItem{
			harbor.VulnerabilityItem{
				ID:          "CVE-2019-9948",
				Package:     "Python",
				Version:     "2.7.16",
				FixVersion:  "None",
				Severity:    harbor.CRITICAL,
				Description: "",
				Links: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2019-9948",
				},
			},
		},
	}
}
