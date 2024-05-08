package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
	"strings"
	"time"
)

type BaseAdapter struct {
	secureClient secure.Client

	scanner                *harbor.Scanner
	scannerAdapterMetadata *harbor.ScannerAdapterMetadata
	logger                 Logger
}

func (b *BaseAdapter) getScanner() *harbor.Scanner {
	if b.scanner == nil {
		b.scanner = &harbor.Scanner{
			Name:    "Sysdig Secure",
			Vendor:  "Sysdig",
			Version: secure.BackendVersion,
		}
	}
	return b.scanner
}

func (b *BaseAdapter) GetMetadata() (harbor.ScannerAdapterMetadata, error) {
	if b.scannerAdapterMetadata == nil {
		feeds, err := b.secureClient.GetFeeds()
		if err != nil {
			return harbor.ScannerAdapterMetadata{}, err
		}

		b.scannerAdapterMetadata = &harbor.ScannerAdapterMetadata{
			Scanner: b.getScanner(),
			Capabilities: []harbor.ScannerCapability{
				{
					ConsumesMimeTypes: []string{
						harbor.OCIImageManifestMimeType,
						harbor.DockerDistributionManifestMimeType,
					},
					ProducesMimeTypes: []string{
						harbor.ScanReportMimeType,
					},
				},
			},
			Properties: map[string]string{
				"harbor.scanner-adapter/scanner-type":                      "os-package-vulnerability",
				"harbor.scanner-adapter/vulnerability-database-updated-at": lastSync(feeds).Format(time.RFC3339),
			},
		}
	}

	return *b.scannerAdapterMetadata, nil
}

func lastSync(feeds []secure.Feed) time.Time {
	var result time.Time

	for _, feed := range feeds {
		for _, group := range feed.Groups {
			if result.Before(group.LastSync) {
				result = group.LastSync
			}
		}
	}

	return result
}

func (b *BaseAdapter) CreateScanResponse(repository string, shaDigest string) harbor.ScanResponse {
	return harbor.ScanResponse{
		ID: harbor.ScanRequestID(base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%s", repository, shaDigest)))),
	}
}

func (b *BaseAdapter) DecodeScanResponseID(scanResponseID harbor.ScanRequestID) (repository string, shaDigest string) {
	plain, _ := base64.URLEncoding.DecodeString(string(scanResponseID))
	splitted := strings.Split(string(plain), "|")

	return splitted[0], splitted[1]
}

func (b *BaseAdapter) ToHarborVulnerabilityReport(repository string, shaDigest string, vulnerabilityReport *secure.VulnerabilityReport) (harbor.VulnerabilityReport, error) {
	result := harbor.VulnerabilityReport{
		Scanner:     b.getScanner(),
		Severity:    harbor.UNKNOWN,
		GeneratedAt: time.Now(),
	}

	vulnerabilitiesDescription, _ := b.getVulnerabilitiesDescriptionFrom(vulnerabilityReport.Vulnerabilities)

	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		vulnerabilityItem := toHarborVulnerabilityItem(vulnerability, vulnerabilitiesDescription)
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilityItem)

		if severities[result.Severity] < severities[vulnerabilityItem.Severity] {
			result.Severity = vulnerabilityItem.Severity
		}
		vulnJSON, _ := json.MarshalIndent(vulnerabilityItem, "", "    ")
		// Echoing out the payload we are sending to Harbor
		b.logger.Debugf("ToHarborVulnerabilityReport:: %s\n", string(vulnJSON))
	}

	scanResponse, _ := b.secureClient.GetImage(shaDigest)

	for _, imageDetail := range scanResponse.Data {
		parts := strings.Split(imageDetail.ImagePullString, "@")
		repoWithTag := parts[0]
		hash := parts[1]
		firstSlash := strings.Index(repoWithTag, "/")
		lastColon := strings.LastIndex(repoWithTag, ":")
		repo := repoWithTag[firstSlash+1 : lastColon]
		tag := repoWithTag[lastColon+1:]
		if repo == repository {
			result.GeneratedAt = imageDetail.StoredAt
			result.Artifact = &harbor.Artifact{
				Repository: repo,
				Digest:     hash,
				Tag:        tag,
				MimeType:   harbor.DockerDistributionManifestMimeType,
			}
			return result, nil
		}
	}

	return result, nil
}

func (b *BaseAdapter) getVulnerabilitiesDescriptionFrom(vulnerabilities []*secure.Vulnerability) (map[string]string, error) {
	result := make(map[string]string)

	// Query the descriptions (and URL) from the v2 endpoint instead
	for idx, vulnerability := range vulnerabilities {
		b.logger.Debugf("getVulnerabilitiesDescriptionFrom:: Processing %d/%d", idx, len(vulnerabilities))
		/*v2, err := b.secureClient.GetVulnerabilityDescriptionV2(vulnerability.ResultId, vulnerability.VulnId)
		if err != nil {
			return nil, err
		}
		b.logger.Debugf("getVulnerabilitiesDescriptionFrom:: Vuln: '%s', URL: '%s', Description '%s", vulnerability.Vuln, v2.URL, v2.Description)
		vulnerabilities[idx].URL = v2.URL
		result[vulnerability.Vuln] = v2.Description
		*/
		vulnerabilities[idx].URL = "https://www.sysdig.com"
		result[vulnerability.Vuln] = "Full Image Scan: https://www.sysdig.com"

	}
	b.logger.Debugf("getVulnerabilitiesDescriptionFrom:: Finished getting descriptions")
	return result, nil
}

func toHarborVulnerabilityItem(vulnerability *secure.Vulnerability, descriptions map[string]string) harbor.VulnerabilityItem {
	return harbor.VulnerabilityItem{
		ID:          vulnerability.Vuln,
		Description: descriptions[vulnerability.Vuln],
		Package:     vulnerability.PackageName,
		Version:     vulnerability.PackageVersion,
		FixVersion:  fixVersionFor(vulnerability),
		Severity:    harbor.Severity(vulnerability.Severity),
		Links:       []string{vulnerability.URL},
		CVSS: harbor.CVSSData{
			ScoreV3:  vulnerability.NVDData[0].CVSSV3.BaseScore,
			VectorV3: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			ScoreV2:  vulnerability.NVDData[0].CVSSV2.BaseScore,
			VectorV2: "AV:L/AC:M/Au:N/C:P/I:N/A:N",
		},
		VendorAttributes: harbor.CVSS{
			CvssKey: harbor.NVDKey{
				NVD: harbor.CVSSDataVendor{
					ScoreV3:  vulnerability.NVDData[0].CVSSV3.BaseScore,
					VectorV3: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
					ScoreV2:  vulnerability.NVDData[0].CVSSV2.BaseScore,
					VectorV2: "AV:L/AC:M/Au:N/C:P/I:N/A:N",
				},
			},
		},
	}
}

func fixVersionFor(vulnerability *secure.Vulnerability) string {
	if vulnerability.Fix == "None" {
		return ""
	}
	return vulnerability.Fix
}
