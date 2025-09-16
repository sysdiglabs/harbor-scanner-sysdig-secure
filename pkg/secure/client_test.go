package secure_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

var _ = Describe("Sysdig Secure Client", func() {
	var client secure.Client

	BeforeEach(func() {
		client = secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"), true)
	})

	Context("when retrieving vulnerabilities for an image", func() {
		It("gets the report for a SHA", func() {
			Skip("skipping this so we don't need to maintain the existence of this image")
			response, err := client.GetVulnerabilities("sha256:a97a153152fcd6410bdf4fb64f5622ecf97a753f07dcc89dab14509d059736cf")

			Expect(err).To(Succeed())
			Expect(response).NotTo(Equal(secure.VulnerabilityReport{}))
			Expect(len(response.Vulnerabilities)).To(BeNumerically(">", 0))
		})

		Context("when an error happens", func() {
			It("returns a ImageNotFoundErr if the image does not exists on Secure", func() {
				_, err := client.GetVulnerabilities("non-existent")

				Expect(err).To(MatchError(secure.ErrImageNotFound))
			})
		})

		Context("when getting an image information", func() {
			It("returns the image information", func() {
				image, _ := client.GetImage("sha256:a97a153152fcd6410bdf4fb64f5622ecf97a753f07dcc89dab14509d059736cf")

				Expect(image).NotTo(Equal(secure.V2VulnerabilityData{}))
			})
		})
	})
})
