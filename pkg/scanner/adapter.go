package scanner

import (
	"errors"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

var (
	ErrScanRequestIDNotFound       = errors.New("scanRequestID cannot be found")
	ErrVulnerabilityReportNotReady = errors.New("image is being scanned and report is still not ready")
)

//go:generate mockgen -source=$GOFILE -destination=./mocks/${GOFILE} -package=mocks
type Adapter interface {
	GetMetadata() (harbor.ScannerAdapterMetadata, error)
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetVulnerabilityReport(scanResponseID harbor.ScanRequestID) (harbor.VulnerabilityReport, error)
}
