package secure_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

var _ = Describe("Sysdig Secure Client", func() {
	Context("when adding an image to scanning queue", func() {
		It("adds image to scanning queue", func() {
			client := secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"))

			response, _ := client.AddImage("nginx")

			Expect(response).NotTo(Equal(secure.ScanResponse{}))
			Expect(response.ImageContent).NotTo(BeNil())
			Expect(response.ImageContent.Metadata).NotTo(BeNil())
			Expect(len(response.ImageDetail)).To(BeNumerically(">", 0))
		})

		Context("when an error happens", func() {
			It("returns the error", func() {
				client := secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"))

				_, err := client.AddImage("sysdiglabs/non-existent")

				Expect(err).To(MatchError("cannot fetch image digest/manifest from registry"))
			})
		})
	})
})
