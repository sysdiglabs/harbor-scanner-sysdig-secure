package scanner

import (
	"errors"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

type inlineAdapter struct {
	secureClient secure.Client
}

func NewInlineAdapter(client secure.Client) Adapter {
	return &inlineAdapter{
		secureClient: client,
	}
}

func (s *inlineAdapter) GetMetadata() harbor.ScannerAdapterMetadata {
	return scannerAdapterMetadata
}

func (s *inlineAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	return harbor.ScanResponse{}, errors.New("Not implemented")
}

func (s *inlineAdapter) GetVulnerabilityReport(scanResponseID string) (harbor.VulnerabilityReport, error) {
	return harbor.VulnerabilityReport{}, errors.New("Not implemented")
}
