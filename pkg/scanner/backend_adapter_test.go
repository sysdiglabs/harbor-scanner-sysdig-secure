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
			secureResponse := secure.ScanResponse{ImageDigest: imageDigest}
			client.EXPECT().AddImage("sysdig/agent:9.7.0").Return(secureResponse, nil)

			result, _ := backendAdapter.Scan(scanRequest())

			Expect(result).To(Equal(harbor.ScanResponse{Id: imageDigest}))
		})

		Context("when Secure returns an error", func() {
			It("returns the error", func() {
				client.EXPECT().AddImage("sysdig/agent:9.7.0").Return(secure.ScanResponse{}, errSecure)

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
