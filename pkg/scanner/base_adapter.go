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

func (b *BaseAdapter) GetMetadata() harbor.ScannerAdapterMetadata {
	if b.scannerAdapterMetadata == nil {
		feeds, _ := b.secureClient.GetFeeds()

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
				"harbor.scanner-adapter/vulnerability-database-updated-at": lastSync(feeds).String(),
			},
		}
	}

	return *b.scannerAdapterMetadata
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
		ID: base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%s", repository, shaDigest))),
	}
}

func (b *BaseAdapter) DecodeScanResponseID(scanResponseID string) (repository string, shaDigest string) {
	plain, _ := base64.URLEncoding.DecodeString(scanResponseID)
	splitted := strings.Split(string(plain), "|")

	return splitted[0], splitted[1]
}

func (b *BaseAdapter) ToHarborVulnerabilityReport(repository string, shaDigest string, vulnerabilityReport *secure.VulnerabilityReport) (harbor.VulnerabilityReport, error) {
	result := harbor.VulnerabilityReport{
		Scanner:  b.getScanner(),
		Severity: harbor.UNKNOWN,
	}

	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		vulnerabilityItem := toHarborVulnerabilityItem(vulnerability)
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

func toHarborVulnerabilityItem(vulnerability *secure.Vulnerability) harbor.VulnerabilityItem {
	return harbor.VulnerabilityItem{
		ID:         vulnerability.Vuln,
		Package:    vulnerability.PackageName,
		Version:    vulnerability.PackageVersion,
		FixVersion: fixVersionFor(vulnerability),
		Severity:   harbor.Severity(vulnerability.Severity),
		Links:      []string{vulnerability.URL},
	}
}

func fixVersionFor(vulnerability *secure.Vulnerability) string {
	if vulnerability.Fix == "None" {
		return ""
	}
	return vulnerability.Fix
}
