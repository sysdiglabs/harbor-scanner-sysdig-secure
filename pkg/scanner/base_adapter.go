package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

type BaseAdapter struct {
	secureClient secure.Client
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
		Scanner:  scanner,
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
