package scanner

import (
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

//go:generate mockgen -source=$GOFILE -destination=./mocks/${GOFILE} -package=mocks
type Adapter interface {
	GetMetadata() harbor.ScannerAdapterMetadata
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetVulnerabilityReport(scanRequestID string) (harbor.VulnerabilityReport, error)
}
