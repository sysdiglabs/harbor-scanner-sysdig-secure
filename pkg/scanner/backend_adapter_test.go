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
	user        = "robot$9f6711d1-834d-11ea-867f-76103d08dca8"
	password    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTAwMDk5OTksImlhdCI6MTU4NzQxNzk5OSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6OSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoic2Nhbm5lci1wdWxsIiwiRWZmZWN0IjoiIn1dfQ.A3_aTzvxqSTvl26pQKa97ay15zRPC9K55NE0WbEyOsY3m0KFz-HuSDatncWLSYvOlcGVdysKlF3JXYWIjQ7tEI4V76WA9UMoi-fr9vEEdWLF5C1uWZJOz_S72sQ3G1BzsLp3HyWe9ZN5EBK9mhXzYNv2rONYrr0UJeBmNnMf2mU3sH71OO_G6JvRl5fwFSLSYx8nQs82PhfVhx50wRuWl_zyeCCDy_ytLzjRBvZwKuI9iVIxgM1pRfKG15NWMHfl0lcYnjm7f1_WFGKtVddkLOTICK0_FPtef1L8A16ozo_2NA32WD9PstdcTuD37XbZ6AFXUAZFoZLfCEW97mtIZBY2uYMwDQtc6Nme4o3Ya-MnBEIAs9Vi9d5a4pkf7Two-xjI-9ESgVz79YqL-_OnecQPNJ9yAFtJuxQ7StfsCIZx84hh5VdcZmW9jlezRHh4hTAjsNmrOBFTAjPyaXk98Se3Fj0Ev3bChod63og4frE7_fE7HnoBKVPHRAdBhJ2yrAiPymfij_kD4ke1Vb0AxmGGOwRP2K3TZNqEdKcq89lU6lHYV2UfrWchuF3u4ieNEC1BGu1_m_c55f0YZH1FAq6evCyA0JnFuXzO4cCxC7WHzXXRGSC9Lm3LF7cbaZAgFj5d34gbgUQmJst8nPlpW-KtwRL-pHC6mipunCBv9bU"
)

var (
	errSecure = errors.New("an error from Sysdig Secure")
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
			client.EXPECT().AddRegistry("harbor.sysdig-demo.zone", user, password).Return(nil)

			secureResponse := secure.ScanResponse{ImageDigest: imageDigest}
			client.EXPECT().AddImage("harbor.sysdig-demo.zone/sysdig/agent:9.7.0", false).Return(secureResponse, nil)

			result, _ := backendAdapter.Scan(scanRequest())

			Expect(result).To(Equal(harbor.ScanResponse{ID: imageDigest}))
		})

		Context("when registry already exists in Secure", func() {
			It("ignores the error and queues the image", func() {
				client.EXPECT().AddRegistry("harbor.sysdig-demo.zone", user, password).Return(secure.ErrRegistryAlreadyExists)
				secureResponse := secure.ScanResponse{ImageDigest: imageDigest}
				client.EXPECT().AddImage("harbor.sysdig-demo.zone/sysdig/agent:9.7.0", false).Return(secureResponse, nil)

				result, _ := backendAdapter.Scan(scanRequest())

				Expect(result).To(Equal(harbor.ScanResponse{ID: imageDigest}))
			})
		})

		Context("when Secure cannot verify registry credentials", func() {
			It("returns the error", func() {
				client.EXPECT().AddRegistry("harbor.sysdig-demo.zone", user, password).Return(errSecure)

				_, err := backendAdapter.Scan(scanRequest())

				Expect(err).To(MatchError(errSecure))
			})
		})

		Context("when Secure fails to add the image to the scanning queue", func() {
			It("returns the error", func() {
				client.EXPECT().AddRegistry("harbor.sysdig-demo.zone", user, password).Return(nil)
				client.EXPECT().AddImage("harbor.sysdig-demo.zone/sysdig/agent:9.7.0", false).Return(secure.ScanResponse{}, errSecure)

				_, err := backendAdapter.Scan(scanRequest())

				Expect(err).To(MatchError(errSecure))
			})
		})
	})

	Context("when getting the vulnerability report for an image", func() {
		It("queries Secure for the vulnerability list", func() {
			client.EXPECT().GetVulnerabilities(imageDigest).Return(secureVulnerabilityReport(), nil)

			result, _ := backendAdapter.GetVulnerabilityReport(imageDigest)

			Expect(result).To(Equal(vulnerabilityReport()))
		})

		Context("when Secure returns an error", func() {
			Context("when Secure cannot find the image scanned", func() {
				It("returns a ScanRequestID Not Found Error", func() {
					client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, secure.ErrImageNotFound)

					_, err := backendAdapter.GetVulnerabilityReport(imageDigest)

					Expect(err).To(MatchError(scanner.ErrScanRequestIDNotFound))
				})
			})

			Context("when Secure is still scanning the image", func() {
				It("returns a VulnerabilityReport is not Ready Error", func() {
					client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, secure.ErrVulnerabiltyReportNotReady)

					_, err := backendAdapter.GetVulnerabilityReport(imageDigest)

					Expect(err).To(MatchError(scanner.ErrVulnerabiltyReportNotReady))
				})
			})

			It("returns the error", func() {
				client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, errSecure)

				_, err := backendAdapter.GetVulnerabilityReport(imageDigest)

				Expect(err).To(MatchError(errSecure))
			})
		})
	})
})

func scanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: &harbor.Registry{
			URL:           "https://harbor.sysdig-demo.zone",
			Authorization: "Basic cm9ib3QkOWY2NzExZDEtODM0ZC0xMWVhLTg2N2YtNzYxMDNkMDhkY2E4OmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpsZUhBaU9qRTFPVEF3TURrNU9Ua3NJbWxoZENJNk1UVTROelF4TnprNU9Td2lhWE56SWpvaWFHRnlZbTl5TFhSdmEyVnVMV1JsWm1GMWJIUkpjM04xWlhJaUxDSnBaQ0k2T1N3aWNHbGtJam95TENKaFkyTmxjM01pT2x0N0lsSmxjMjkxY21ObElqb2lMM0J5YjJwbFkzUXZNaTl5WlhCdmMybDBiM0o1SWl3aVFXTjBhVzl1SWpvaWMyTmhibTVsY2kxd2RXeHNJaXdpUldabVpXTjBJam9pSW4xZGZRLkEzX2FUenZ4cVNUdmwyNnBRS2E5N2F5MTV6UlBDOUs1NU5FMFdiRXlPc1kzbTBLRnotSHVTRGF0bmNXTFNZdk9sY0dWZHlzS2xGM0pYWVdJalE3dEVJNFY3NldBOVVNb2ktZnI5dkVFZFdMRjVDMXVXWkpPel9TNzJzUTNHMUJ6c0xwM0h5V2U5Wk41RUJLOW1oWHpZTnYyck9OWXJyMFVKZUJtTm5NZjJtVTNzSDcxT09fRzZKdlJsNWZ3RlNMU1l4OG5RczgyUGhmVmh4NTB3UnVXbF96eWVDQ0R5X3l0THpqUkJ2WndLdUk5aVZJeGdNMXBSZktHMTVOV01IZmwwbGNZbmptN2YxX1dGR0t0VmRka0xPVElDSzBfRlB0ZWYxTDhBMTZvem9fMk5BMzJXRDlQc3RkY1R1RDM3WGJaNkFGWFVBWkZvWkxmQ0VXOTdtdElaQlkydVlNd0RRdGM2Tm1lNG8zWWEtTW5CRUlBczlWaTlkNWE0cGtmN1R3by14akktOUVTZ1Z6NzlZcUwtX09uZWNRUE5KOXlBRnRKdXhRN1N0ZnNDSVp4ODRoaDVWZGNabVc5amxlelJIaDRoVEFqc05tck9CRlRBalB5YVhrOThTZTNGajBFdjNiQ2hvZDYzb2c0ZnJFN19mRTdIbm9CS1ZQSFJBZEJoSjJ5ckFpUHltZmlqX2tENGtlMVZiMEF4bUdHT3dSUDJLM1RaTnFFZEtjcTg5bFU2bEhZVjJVZnJXY2h1RjN1NGllTkVDMUJHdTFfbV9jNTVmMFlaSDFGQXE2ZXZDeUEwSm5GdVh6TzRjQ3hDN1dIelhYUkdTQzlMbTNMRjdjYmFaQWdGajVkMzRnYmdVUW1Kc3Q4blBscFctS3R3UkwtcEhDNm1pcHVuQ0J2OWJV",
		},
		Artifact: &harbor.Artifact{
			Repository: "sysdig/agent",
			//Digest:     "",
			Tag:      "9.7.0",
			MimeType: "application/vnd.docker.distribution.manifest.v2+json",
		},
	}
}

func secureVulnerabilityReport() secure.VulnerabilityReport {
	return secure.VulnerabilityReport{
		ImageDigest:       imageDigest,
		VulnerabilityType: "all",
		Vulnerabilities: []*secure.Vulnerability{
			&secure.Vulnerability{
				Vuln:           "CVE-2019-9948",
				PackageName:    "Python",
				PackageVersion: "2.7.16",
				Fix:            "None",
				Severity:       "Critical",
				URL:            "https://nvd.nist.gov/vuln/detail/CVE-2019-9948",
			},
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
