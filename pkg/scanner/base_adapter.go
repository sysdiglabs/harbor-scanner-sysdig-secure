package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

type BaseAdapter struct {
	secureClient secure.Client

	scanner                *harbor.Scanner
	scannerAdapterMetadata *harbor.ScannerAdapterMetadata
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
		Scanner:  b.getScanner(),
		Severity: harbor.UNKNOWN,
	}

	vulnerabilitiesDescription, _ := b.getVulnerabilitiesDescriptionFrom(vulnerabilityReport.Vulnerabilities)

	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		vulnerabilityItem := toHarborVulnerabilityItem(vulnerability, vulnerabilitiesDescription)
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilityItem)

		if severities[result.Severity] < severities[vulnerabilityItem.Severity] {
			result.Severity = vulnerabilityItem.Severity
		}
	}

	scanResponse, _ := b.secureClient.GetImage(shaDigest)
	for _, imageDetail := range scanResponse.ImageDetail {
		if imageDetail.Repository == repository {
			result.GeneratedAt = imageDetail.CreatedAt
			result.Artifact = &harbor.Artifact{
				Repository: imageDetail.Repository,
				Digest:     imageDetail.Digest,
				Tag:        imageDetail.Tag,
				MimeType:   harbor.DockerDistributionManifestMimeType,
			}
			return result, nil
		}
	}

	return result, nil
}

func (b *BaseAdapter) getVulnerabilitiesDescriptionFrom(vulnerabilities []*secure.Vulnerability) (map[string]string, error) {
	ids := make([]string, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		ids = append(ids, vulnerability.Vuln)
	}

	return b.secureClient.GetVulnerabilityDescription(ids...)
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
	}
}

func fixVersionFor(vulnerability *secure.Vulnerability) string {
	if vulnerability.Fix == "None" {
		return ""
	}
	return vulnerability.Fix
}
