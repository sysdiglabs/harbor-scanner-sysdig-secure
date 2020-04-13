package scanner_test

import (
	"errors"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure/mocks"
)

const (
	imageDigest = "an image digest"
)

var (
	secureError = errors.New("an error from Sysdig Secure")
)

var _ = Describe("BackendAdapter", func() {
	var (
		controller     *gomock.Controller
		client         *mocks.MockClient
		backendAdapter scanner.Adapter
	)

	BeforeEach(func() {
		controller = gomock.NewController(GinkgoT())
		client = mocks.NewMockClient(controller)
		backendAdapter = scanner.NewBackendAdapter(client)
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("when scanning an image", func() {
		It("sends the repository and tag to Sysdig Secure", func() {
			secureResponse := secure.ScanResponse{ImageDigest: imageDigest}
			client.EXPECT().AddImage("sysdig/agent:9.7.0").Return(secureResponse, nil)

			scanResponse, _ := backendAdapter.Scan(scanRequest())

			Expect(scanResponse).To(Equal(harbor.ScanResponse{Id: imageDigest}))
		})

		Context("when Secure returns an error", func() {
			It("returns the error", func() {
				client.EXPECT().AddImage("sysdig/agent:9.7.0").Return(secure.ScanResponse{}, secureError)

				_, err := backendAdapter.Scan(scanRequest())

				Expect(err).To(MatchError(secureError))
			})
		})
	})
})

func scanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: &harbor.Registry{
			Url:           "",
			Authorization: "",
		},
		Artifact: &harbor.Artifact{
			Repository: "sysdig/agent",
			//Digest:     "",
			Tag:      "9.7.0",
			MimeType: "application/vnd.docker.distribution.manifest.v2+json",
		},
	}
}
