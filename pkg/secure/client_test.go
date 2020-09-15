package secure_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

const (
	user     = "a user"
	password = "a password"
)

var _ = Describe("Sysdig Secure Client", func() {
	var (
		client secure.Client
	)

	BeforeEach(func() {
		client = secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"), true)
	})

	Context("when adding an image to scanning queue", func() {
		It("adds image to scanning queue", func() {
			response, _ := client.AddImage("sysdig/agent:9.8.0", false)

			Expect(response).NotTo(Equal(secure.ScanResponse{}))
			Expect(response.ImageContent).NotTo(BeNil())
			Expect(response.ImageContent.Metadata).NotTo(BeNil())
			Expect(len(response.ImageDetail)).To(BeNumerically(">", 0))
		})

		Context("when an error happens", func() {
			It("returns the error", func() {
				_, err := client.AddImage("sysdiglabs/non-existent", false)

				Expect(err).To(MatchError("cannot fetch image digest/manifest from registry"))
			})
		})
	})

	Context("when retrieving vulnerabilities for an image", func() {
		It("gets the report for a SHA", func() {
			response, _ := client.GetVulnerabilities("sha256:fda6b046981f5dab88aad84c6cebed4e47a0d6ad1c8ff7f58b5f0e6a95a5b2c1")

			Expect(response).NotTo(Equal(secure.VulnerabilityReport{}))
			Expect(len(response.Vulnerabilities)).To(BeNumerically(">", 0))
		})

		Context("when an error happens", func() {
			It("returns a ImageNotFoundErr if the image does not exists on Secure", func() {
				_, err := client.GetVulnerabilities("non-existent")

				Expect(err).To(MatchError(secure.ErrImageNotFound))
			})

			It("returns a ReportNotReadyErr if the image is being analyzed", func() {
				response, _ := client.AddImage("sysdig/agent:9.9.0", true)

				_, err := client.GetVulnerabilities(response.ImageDigest)

				Expect(err).To(MatchError(secure.ErrVulnerabiltyReportNotReady))
			})
		})
	})

	Context("when adding registry credentials", func() {
		It("registers the credentials in Secure", func() {
			err := client.AddRegistry("foo.sysdig-demo.zone", user, password)
			defer client.DeleteRegistry("foo.sysdig-demo.zone")

			Expect(err).To(Succeed())
		})

		Context("when adding twice a registry", func() {
			It("returns an ErrRegistryAlreadyExists", func() {
				client.AddRegistry("foo.sysdig-demo.zone", user, password)
				defer client.DeleteRegistry("foo.sysdig-demo.zone")

				err := client.AddRegistry("foo.sysdig-demo.zone", user, password)

				Expect(err).To(MatchError(secure.ErrRegistryAlreadyExists))
			})
		})
	})

	Context("when updating registry credentials", func() {
		It("updates an existing registry", func() {
			client.AddRegistry("foo.sysdig-demo.zone", user, password)
			defer client.DeleteRegistry("foo.sysdig-demo.zone")

			err := client.UpdateRegistry("foo.sysdig-demo.zone", "otherUser", "otherPassword")

			Expect(err).To(Succeed())
		})

		Context("when registry does not exist", func() {
			It("returns the error", func() {
				err := client.UpdateRegistry("foo.sysdig-demo.zone", user, password)

				Expect(err).To(MatchError(HavePrefix("unknown error (status 404): ")))
			})
		})
	})

	Context("when getting an image information", func() {
		It("returns the image information", func() {
			image, _ := client.GetImage("sha256:7cd23a94051e17b191b5cc5b4682ed9f3ece26b8283dc39b8a5b894462cec696")

			Expect(image).NotTo(Equal(secure.ScanResponse{}))
		})

		Context("when image does not exist", func() {
			It("returns ErrImageNotFound", func() {
				_, err := client.GetImage("sha256:non-existent")

				Expect(err).To(MatchError(secure.ErrImageNotFound))
			})
		})
	})

	Context("when getting the feeds", func() {
		It("returns the feed list", func() {
			image, _ := client.GetFeeds()

			Expect(image).NotTo(Equal([]secure.Feed{}))
		})
	})

	Context("when retrieving vulnerabilities description", func() {
		It("returns a map with the id as key", func() {
			descriptions, _ := client.GetVulnerabilityDescription("CVE-2016-2779", "VULNDB-229217")

			Expect(descriptions).To(HaveKeyWithValue("CVE-2016-2779", "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."))

			Expect(descriptions).To(HaveKeyWithValue("VULNDB-229217", "pip PyPI (Python Packaging Index) contains a flaw that allows traversing outside of a restricted path. The issue is due to the PipXmlrpcTransport._download_http_url() function in _internal/download.py not properly sanitizing input, specifically path traversal style attacks (e.g. '../') supplied via the HTTP Content-Disposition header when downloading a remote package. With a specially crafted server, a remote attacker can write to arbitrary files."))
		})
	})
})
