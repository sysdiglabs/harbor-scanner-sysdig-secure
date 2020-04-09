package v1_test

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
)

var _ = Describe("Harbor Scanner Sysdig Secure API Adapter", func() {
	Context("GET /api/v1/metadata", func() {
		It("returns OK", func() {
			response := doGetRequest("/api/v1/metadata")

			Expect(response.StatusCode).To(Equal(http.StatusOK))
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
