package secure_test

import (
	"errors"
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
			Expect(len(response.Vulnerabilities[0].NVDData)).To(BeNumerically(">", 0))
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

	FContext("when adding registry credentials", func() {
		It("registers the credentials in Secure", func() {
			user := "robot$9f6711d1-834d-11ea-867f-76103d08dca8"
			password := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTAwMDk5OTksImlhdCI6MTU4NzQxNzk5OSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6OSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoic2Nhbm5lci1wdWxsIiwiRWZmZWN0IjoiIn1dfQ.A3_aTzvxqSTvl26pQKa97ay15zRPC9K55NE0WbEyOsY3m0KFz-HuSDatncWLSYvOlcGVdysKlF3JXYWIjQ7tEI4V76WA9UMoi-fr9vEEdWLF5C1uWZJOz_S72sQ3G1BzsLp3HyWe9ZN5EBK9mhXzYNv2rONYrr0UJeBmNnMf2mU3sH71OO_G6JvRl5fwFSLSYx8nQs82PhfVhx50wRuWl_zyeCCDy_ytLzjRBvZwKuI9iVIxgM1pRfKG15NWMHfl0lcYnjm7f1_WFGKtVddkLOTICK0_FPtef1L8A16ozo_2NA32WD9PstdcTuD37XbZ6AFXUAZFoZLfCEW97mtIZBY2uYMwDQtc6Nme4o3Ya-MnBEIAs9Vi9d5a4pkf7Two-xjI-9ESgVz79YqL-_OnecQPNJ9yAFtJuxQ7StfsCIZx84hh5VdcZmW9jlezRHh4hTAjsNmrOBFTAjPyaXk98Se3Fj0Ev3bChod63og4frE7_fE7HnoBKVPHRAdBhJ2yrAiPymfij_kD4ke1Vb0AxmGGOwRP2K3TZNqEdKcq89lU6lHYV2UfrWchuF3u4ieNEC1BGu1_m_c55f0YZH1FAq6evCyA0JnFuXzO4cCxC7WHzXXRGSC9Lm3LF7cbaZAgFj5d34gbgUQmJst8nPlpW-KtwRL-pHC6mipunCBv9bU"
			err := client.AddRegistry("harbor.sysdig-demo.zone", user, password)
			defer client.DeleteRegistry("harbor.sysdig-demo.zone")

			Expect(err).To(Succeed())
		})

		Context("when adding twice a registry", func() {
			It("returns an ErrRegistryAlreadyExists", func() {
				user := "robot$9f6711d1-834d-11ea-867f-76103d08dca8"
				password := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTAwMDk5OTksImlhdCI6MTU4NzQxNzk5OSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6OSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoic2Nhbm5lci1wdWxsIiwiRWZmZWN0IjoiIn1dfQ.A3_aTzvxqSTvl26pQKa97ay15zRPC9K55NE0WbEyOsY3m0KFz-HuSDatncWLSYvOlcGVdysKlF3JXYWIjQ7tEI4V76WA9UMoi-fr9vEEdWLF5C1uWZJOz_S72sQ3G1BzsLp3HyWe9ZN5EBK9mhXzYNv2rONYrr0UJeBmNnMf2mU3sH71OO_G6JvRl5fwFSLSYx8nQs82PhfVhx50wRuWl_zyeCCDy_ytLzjRBvZwKuI9iVIxgM1pRfKG15NWMHfl0lcYnjm7f1_WFGKtVddkLOTICK0_FPtef1L8A16ozo_2NA32WD9PstdcTuD37XbZ6AFXUAZFoZLfCEW97mtIZBY2uYMwDQtc6Nme4o3Ya-MnBEIAs9Vi9d5a4pkf7Two-xjI-9ESgVz79YqL-_OnecQPNJ9yAFtJuxQ7StfsCIZx84hh5VdcZmW9jlezRHh4hTAjsNmrOBFTAjPyaXk98Se3Fj0Ev3bChod63og4frE7_fE7HnoBKVPHRAdBhJ2yrAiPymfij_kD4ke1Vb0AxmGGOwRP2K3TZNqEdKcq89lU6lHYV2UfrWchuF3u4ieNEC1BGu1_m_c55f0YZH1FAq6evCyA0JnFuXzO4cCxC7WHzXXRGSC9Lm3LF7cbaZAgFj5d34gbgUQmJst8nPlpW-KtwRL-pHC6mipunCBv9bU"
				client.AddRegistry("harbor.sysdig-demo.zone", user, password)
				defer client.DeleteRegistry("harbor.sysdig-demo.zone")
				err := client.AddRegistry("harbor.sysdig-demo.zone", user, password)

				Expect(err).To(MatchError(secure.ErrRegistryAlreadyExists))
			})
		})

		Context("when an error happens", func() {
			It("returns the error", func() {
				user := "someUser"
				password := "somePassword"

				err := client.AddRegistry("harbor.sysdig-demo.zone", user, password)

				Expect(err).To(MatchError(errors.New("cannot ping supplied registry with supplied credentials - exception: failed check to access registry (https://harbor.sysdig-demo.zone,someUser) - exception: cannot login to registry user=someUser registry=https://harbor.sysdig-demo.zone - invalid username/password")))
			})
		})
	})
})
