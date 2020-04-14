package secure_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

var _ = Describe("Sysdig Secure Client", func() {
	var (
		client secure.Client
	)

	BeforeEach(func() {
		client = secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"))
	})

	Context("when adding an image to scanning queue", func() {
		It("adds image to scanning queue", func() {
			response, _ := client.AddImage("sysdig/agent:9.7.0")

			Expect(response).NotTo(Equal(secure.ScanResponse{}))
			Expect(response.ImageContent).NotTo(BeNil())
			Expect(response.ImageContent.Metadata).NotTo(BeNil())
			Expect(len(response.ImageDetail)).To(BeNumerically(">", 0))
		})

		Context("when an error happens", func() {
			It("returns the error", func() {
				_, err := client.AddImage("sysdiglabs/non-existent")

				Expect(err).To(MatchError("cannot fetch image digest/manifest from registry"))
			})
		})
	})

	Context("when retrieving vulnerabilities for an image", func() {
		It("gets the report for a SHA", func() {
			response, _ := client.GetVulnerabilities("sha256:49d142e1e11ff9ab2bcaf5fb4408f55eec2a037a66281a16aede375b8e47a789")

			Expect(response).NotTo(Equal(secure.VulnerabilityReport{}))
		})
		Context("when an error happens", func() {
			It("returns the error", func() {
				_, err := client.GetVulnerabilities("non-existent")

				Expect(err).To(MatchError("image not found in DB"))
			})
		})
	})
})
