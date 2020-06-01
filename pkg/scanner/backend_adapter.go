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

	severities = map[harbor.Severity]int{
		harbor.UNKNOWN:    0,
		harbor.NEGLIGIBLE: 1,
		harbor.LOW:        2,
		harbor.MEDIUM:     3,
		harbor.HIGH:       4,
		harbor.CRITICAL:   5,
	}
)

type backendAdapter struct {
	BaseAdapter
}

func NewBackendAdapter(client secure.Client) Adapter {
	return &backendAdapter{
		BaseAdapter: BaseAdapter{secureClient: client},
	}
}

func (b *backendAdapter) GetMetadata() harbor.ScannerAdapterMetadata {
	return scannerAdapterMetadata
}

func (b *backendAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	if err := b.setupCredentials(req); err != nil {
		return harbor.ScanResponse{}, err
	}

	response, err := b.secureClient.AddImage(getImageFrom(req), false)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	return b.CreateScanResponse(req.Artifact.Repository, response.ImageDigest), nil
}

func (b *backendAdapter) setupCredentials(req harbor.ScanRequest) error {
	registry := getRegistryFrom(req)
	user, password := getUserAndPasswordFrom(req.Registry.Authorization)

	if err := b.secureClient.AddRegistry(registry, user, password); err != nil {
		if err != secure.ErrRegistryAlreadyExists {
			return err
		}

		if err = b.secureClient.UpdateRegistry(registry, user, password); err != nil {
			return err
		}
	}
	return nil
}

func getRegistryFrom(req harbor.ScanRequest) string {
	return strings.ReplaceAll(req.Registry.URL, "https://", "")
}

func getUserAndPasswordFrom(authorization string) (string, string) {
	payload := strings.ReplaceAll(authorization, "Basic ", "")
	plain, _ := base64.StdEncoding.DecodeString(payload)
	splitted := strings.Split(string(plain), ":")

	return splitted[0], splitted[1]
}

func getImageFrom(req harbor.ScanRequest) string {
	return fmt.Sprintf("%s/%s:%s", getRegistryFrom(req), req.Artifact.Repository, req.Artifact.Tag)
}

func (b *backendAdapter) GetVulnerabilityReport(scanResponseID string) (harbor.VulnerabilityReport, error) {
	repository, shaDigest := b.DecodeScanResponseID(scanResponseID)

	vulnerabilityReport, err := b.secureClient.GetVulnerabilities(shaDigest)
	if err != nil {
		switch err {
		case secure.ErrImageNotFound:
			return harbor.VulnerabilityReport{}, ErrScanRequestIDNotFound
		case secure.ErrVulnerabiltyReportNotReady:
			return harbor.VulnerabilityReport{}, ErrVulnerabiltyReportNotReady
		}
		return harbor.VulnerabilityReport{}, err
	}

	return b.ToHarborVulnerabilityReport(repository, shaDigest, &vulnerabilityReport)
}
