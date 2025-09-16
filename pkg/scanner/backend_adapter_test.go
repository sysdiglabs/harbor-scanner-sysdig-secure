package scanner

import (
	"errors"
	"fmt"
	"os"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

const (
	imageDigest = "an image digest"
	scanID      = harbor.ScanRequestID("c3lzZGlnL2FnZW50fGFuIGltYWdlIGRpZ2VzdA==")
	user        = "robot$9f6711d1-834d-11ea-867f-76103d08dca8"
	password    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTAwMDk5OTksImlhdCI6MTU4NzQxNzk5OSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6OSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoic2Nhbm5lci1wdWxsIiwiRWZmZWN0IjoiIn1dfQ.A3_aTzvxqSTvl26pQKa97ay15zRPC9K55NE0WbEyOsY3m0KFz-HuSDatncWLSYvOlcGVdysKlF3JXYWIjQ7tEI4V76WA9UMoi-fr9vEEdWLF5C1uWZJOz_S72sQ3G1BzsLp3HyWe9ZN5EBK9mhXzYNv2rONYrr0UJeBmNnMf2mU3sH71OO_G6JvRl5fwFSLSYx8nQs82PhfVhx50wRuWl_zyeCCDy_ytLzjRBvZwKuI9iVIxgM1pRfKG15NWMHfl0lcYnjm7f1_WFGKtVddkLOTICK0_FPtef1L8A16ozo_2NA32WD9PstdcTuD37XbZ6AFXUAZFoZLfCEW97mtIZBY2uYMwDQtc6Nme4o3Ya-MnBEIAs9Vi9d5a4pkf7Two-xjI-9ESgVz79YqL-_OnecQPNJ9yAFtJuxQ7StfsCIZx84hh5VdcZmW9jlezRHh4hTAjsNmrOBFTAjPyaXk98Se3Fj0Ev3bChod63og4frE7_fE7HnoBKVPHRAdBhJ2yrAiPymfij_kD4ke1Vb0AxmGGOwRP2K3TZNqEdKcq89lU6lHYV2UfrWchuF3u4ieNEC1BGu1_m_c55f0YZH1FAq6evCyA0JnFuXzO4cCxC7WHzXXRGSC9Lm3LF7cbaZAgFj5d34gbgUQmJst8nPlpW-KtwRL-pHC6mipunCBv9bU"
)

var (
	errSecure = errors.New("an error from Sysdig Secure")
	createdAt = generatedAt
)

func scanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: &harbor.Registry{
			URL:           "https://harbor.sysdig-demo.zone",
			Authorization: "Basic cm9ib3QkOWY2NzExZDEtODM0ZC0xMWVhLTg2N2YtNzYxMDNkMDhkY2E4OmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpsZUhBaU9qRTFPVEF3TURrNU9Ua3NJbWxoZENJNk1UVTROelF4TnprNU9Td2lhWE56SWpvaWFHRnlZbTl5TFhSdmEyVnVMV1JsWm1GMWJIUkpjM04xWlhJaUxDSnBaQ0k2T1N3aWNHbGtJam95TENKaFkyTmxjM01pT2x0N0lsSmxjMjkxY21ObElqb2lMM0J5YjJwbFkzUXZNaTl5WlhCdmMybDBiM0o1SWl3aVFXTjBhVzl1SWpvaWMyTmhibTVsY2kxd2RXeHNJaXdpUldabVpXTjBJam9pSW4xZGZRLkEzX2FUenZ4cVNUdmwyNnBRS2E5N2F5MTV6UlBDOUs1NU5FMFdiRXlPc1kzbTBLRnotSHVTRGF0bmNXTFNZdk9sY0dWZHlzS2xGM0pYWVdJalE3dEVJNFY3NldBOVVNb2ktZnI5dkVFZFdMRjVDMXVXWkpPel9TNzJzUTNHMUJ6c0xwM0h5V2U5Wk41RUJLOW1oWHpZTnYyck9OWXJyMFVKZUJtTm5NZjJtVTNzSDcxT09fRzZKdlJsNWZ3RlNMU1l4OG5RczgyUGhmVmh4NTB3UnVXbF96eWVDQ0R5X3l0THpqUkJ2WndLdUk5aVZJeGdNMXBSZktHMTVOV01IZmwwbGNZbmptN2YxX1dGR0t0VmRka0xPVElDSzBfRlB0ZWYxTDhBMTZvem9fMk5BMzJXRDlQc3RkY1R1RDM3WGJaNkFGWFVBWkZvWkxmQ0VXOTdtdElaQlkydVlNd0RRdGM2Tm1lNG8zWWEtTW5CRUlBczlWaTlkNWE0cGtmN1R3by14akktOUVTZ1Z6NzlZcUwtX09uZWNRUE5KOXlBRnRKdXhRN1N0ZnNDSVp4ODRoaDVWZGNabVc5amxlelJIaDRoVEFqc05tck9CRlRBalB5YVhrOThTZTNGajBFdjNiQ2hvZDYzb2c0ZnJFN19mRTdIbm9CS1ZQSFJBZEJoSjJ5ckFpUHltZmlqX2tENGtlMVZiMEF4bUdHT3dSUDJLM1RaTnFFZEtjcTg5bFU2bEhZVjJVZnJXY2h1RjN1NGllTkVDMUJHdTFfbV9jNTVmMFlaSDFGQXE2ZXZDeUEwSm5GdVh6TzRjQ3hDN1dIelhYUkdTQzlMbTNMRjdjYmFaQWdGajVkMzRnYmdVUW1Kc3Q4blBscFctS3R3UkwtcEhDNm1pcHVuQ0J2OWJV",
		},
		Artifact: &harbor.Artifact{
			Repository: "sysdig/agent",
			Digest:     imageDigest,
			Tag:        "9.7.0",
			MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
		},
	}
}

func scanResponse() secure.V2VulnerabilityReport {
	return secure.V2VulnerabilityReport{
		Data: []secure.V2VulnerabilityData{
			{
				CreatedAt:     createdAt,
				MainAssetName: fmt.Sprintf("sysdig/agent:%s@%s", "9.7", imageDigest),
			},
		},
	}
}

func secureVulnerabilityReport() secure.VulnerabilityReport {
	return secure.VulnerabilityReport{
		ImageDigest:       imageDigest,
		VulnerabilityType: "all",
		Vulnerabilities: []*secure.Vulnerability{
			{
				Vuln:           "CVE-2019-9948",
				PackageName:    "Python",
				PackageVersion: "2.7.16",
				Fix:            "None",
				Severity:       "Critical",
				URL:            "https://nvd.nist.gov/vuln/detail/CVE-2019-9948",
				NVDData: []*secure.NVDData{
					{
						ID: "NVD-1234",
						CVSSV2: &secure.CVSS{
							BaseScore:           7.5,
							ExploitabilityScore: 8.6,
							ImpactScore:         6.4,
						},
						CVSSV3: &secure.CVSS{
							BaseScore:           9.8,
							ExploitabilityScore: 10.0,
							ImpactScore:         8.9,
						},
					},
				},
			},
			{
				Vuln:           "CVE-2019-9946",
				PackageName:    "Python",
				PackageVersion: "2.7.16",
				Fix:            "None",
				Severity:       "High",
				URL:            "https://nvd.nist.gov/vuln/detail/CVE-2019-9946",
				NVDData: []*secure.NVDData{
					{
						ID: "NVD-1234",
						CVSSV2: &secure.CVSS{
							BaseScore:           7.5,
							ExploitabilityScore: 8.6,
							ImpactScore:         6.4,
						},
						CVSSV3: &secure.CVSS{
							BaseScore:           9.8,
							ExploitabilityScore: 10.0,
							ImpactScore:         8.9,
						},
					},
				},
			},
		},
	}
}

func vulnerabilityReport() harbor.VulnerabilityReport {
	return harbor.VulnerabilityReport{
		GeneratedAt: createdAt,
		Severity:    harbor.CRITICAL,
		Scanner: &harbor.Scanner{
			Name:    "Sysdig Secure",
			Vendor:  "Sysdig",
			Version: secure.BackendVersion,
		},
		Artifact: nil,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{
				ID:          "CVE-2019-9948",
				Package:     "Python",
				Version:     "2.7.16",
				FixVersion:  "",
				Severity:    harbor.CRITICAL,
				Description: "Disclosure Date: '', Exploitable: 'false' ",
				Links: []string{
					fmt.Sprintf("%s/secure/#/vulnerabilities/results//overview", os.Getenv("SECURE_URL")),
					"https://nvd.nist.gov/vuln/detail/CVE-2019-9948",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9948",
				},
				CVSS: harbor.CVSSData{
					ScoreV3:  9.8,
					ScoreV2:  7.5,
					VectorV3: "",
					VectorV2: "",
				},
				VendorAttributes: harbor.CVSS{
					CvssKey: harbor.NVDKey{
						NVD: harbor.CVSSDataVendor{
							ScoreV3:  9.8,
							VectorV3: "",
							ScoreV2:  7.5,
							VectorV2: "",
						},
					},
				},
			},
			{
				ID:          "CVE-2019-9946",
				Package:     "Python",
				Version:     "2.7.16",
				FixVersion:  "",
				Severity:    harbor.HIGH,
				Description: "Disclosure Date: '', Exploitable: 'false' ",
				Links: []string{
					fmt.Sprintf("%s/secure/#/vulnerabilities/results//overview", os.Getenv("SECURE_URL")),
					"https://nvd.nist.gov/vuln/detail/CVE-2019-9946",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946",
				},
				CVSS: harbor.CVSSData{
					ScoreV3:  9.8,
					ScoreV2:  7.5,
					VectorV3: "",
					VectorV2: "",
				},
				VendorAttributes: harbor.CVSS{
					CvssKey: harbor.NVDKey{
						NVD: harbor.CVSSDataVendor{
							ScoreV3:  9.8,
							VectorV3: "",
							ScoreV2:  7.5,
							VectorV2: "",
						},
					},
				},
			},
		},
	}
}
