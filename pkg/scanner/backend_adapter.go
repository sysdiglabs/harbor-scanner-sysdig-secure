package scanner

import (
	"fmt"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

type backendAdapter struct {
	secureClient secure.Client
}

func NewBackendAdapter(client secure.Client) Adapter {
	return &backendAdapter{
		secureClient: client,
	}
}

func (s *backendAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	var result harbor.ScanResponse

	response, err := s.secureClient.AddImage(fmt.Sprintf("%s:%s", req.Artifact.Repository, req.Artifact.Tag))
	if err != nil {
		return result, err
	}

	result.Id = response.ImageDigest
	return result, nil
}

func (s *backendAdapter) GetVulnerabilityReport(scanRequestID string) (harbor.VulnerabilityReport, error) {
	var result harbor.VulnerabilityReport

	vulnerabilityReport, err := s.secureClient.GetVulnerabilities(scanRequestID)
	if err != nil {
		return result, err
	}

	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, toHarborVulnerabilityItem(vulnerability))
	}

	return result, nil
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
