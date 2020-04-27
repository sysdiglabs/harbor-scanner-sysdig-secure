package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

var (
	scanner = &harbor.Scanner{
		Name:    "Sysdig Secure",
		Vendor:  "Sysdig",
		Version: secure.BackendVersion,
	}
	scannerAdapterMetadata = harbor.ScannerAdapterMetadata{
		Scanner: scanner,
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
			"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
		},
	}
)

type backendAdapter struct {
	secureClient secure.Client
}

func NewBackendAdapter(client secure.Client) Adapter {
	return &backendAdapter{
		secureClient: client,
	}
}

func (s *backendAdapter) GetMetadata() harbor.ScannerAdapterMetadata {
	return scannerAdapterMetadata
}

func (s *backendAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	var result harbor.ScanResponse

	registry := getRegistryFrom(req.Registry.URL)
	user, password := getUserAndPasswordFrom(req.Registry.Authorization)
	err := s.secureClient.AddRegistry(registry, user, password)
	if err != nil && err != secure.ErrRegistryAlreadyExists {
		// TODO: is this way the better to check against secure.ErrVulnerabiltyReportNotReady ?
		return result, err
	}

	response, err := s.secureClient.AddImage(
		fmt.Sprintf("%s/%s:%s", registry, req.Artifact.Repository, req.Artifact.Tag), false)
	if err != nil {
		return result, err
	}

	result.ID = createScanResponseID(req.Artifact.Repository, response.ImageDigest)
	return result, nil
}

func getRegistryFrom(url string) string {
	return strings.ReplaceAll(url, "https://", "")
}

func getUserAndPasswordFrom(authorization string) (string, string) {
	payload := strings.ReplaceAll(authorization, "Basic ", "")
	plain, _ := base64.StdEncoding.DecodeString(payload)
	splitted := strings.Split(string(plain), ":")

	return splitted[0], splitted[1]
}

func createScanResponseID(repository string, shaDigest string) string {
	return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%s", repository, shaDigest)))
}

func (s *backendAdapter) GetVulnerabilityReport(scanResponseID string) (harbor.VulnerabilityReport, error) {
	var result harbor.VulnerabilityReport
	repository, shaDigest := parseScanResponseID(scanResponseID)

	vulnerabilityReport, err := s.secureClient.GetVulnerabilities(shaDigest)
	if err != nil {
		if err == secure.ErrImageNotFound {
			return result, ErrScanRequestIDNotFound
		}

		if err == secure.ErrVulnerabiltyReportNotReady {
			return result, ErrVulnerabiltyReportNotReady
		}

		return result, err
	}

	scanResponse, _ := s.secureClient.GetImage(shaDigest)
	for _, imageDetail := range scanResponse.ImageDetail {
		if imageDetail.Repository == repository {
			result.GeneratedAt = imageDetail.CreatedAt
			result.Artifact = &harbor.Artifact{
				Repository: imageDetail.Repository,
				Digest:     imageDetail.Digest,
				Tag:        imageDetail.Tag,
				MimeType:   harbor.DockerDistributionManifestMimeType,
			}
			break
		}
	}

	result.Scanner = scanner
	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, toHarborVulnerabilityItem(vulnerability))
	}

	return result, nil
}

func parseScanResponseID(scanResponseID string) (string, string) {
	plain, _ := base64.URLEncoding.DecodeString(scanResponseID)
	splitted := strings.Split(string(plain), "|")

	return splitted[0], splitted[1]
}

func toHarborVulnerabilityItem(vulnerability *secure.Vulnerability) harbor.VulnerabilityItem {
	return harbor.VulnerabilityItem{
		ID:         vulnerability.Vuln,
		Package:    vulnerability.PackageName,
		Version:    vulnerability.PackageVersion,
		FixVersion: vulnerability.Fix,
		Severity:   harbor.Severity(vulnerability.Severity),
		Links:      []string{vulnerability.URL},
	}
}
