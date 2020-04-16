package scanner

import (
	"errors"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

var (
	ScanRequestIDNotFoundErr      = errors.New("scanRequestID cannot be found")
	VulnerabiltyReportNotReadyErr = errors.New("image is being scanned and report is still not ready")
)

//go:generate mockgen -source=$GOFILE -destination=./mocks/${GOFILE} -package=mocks
type Adapter interface {
	GetMetadata() harbor.ScannerAdapterMetadata
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetVulnerabilityReport(scanRequestID string) (harbor.VulnerabilityReport, error)
}
