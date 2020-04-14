package scanner

import (
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

type Adapter interface {
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetVulnerabilityReport(scanRequestID string) (harbor.VulnerabilityReport, error)
}
