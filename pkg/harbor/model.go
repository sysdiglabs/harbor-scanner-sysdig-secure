package harbor

import "time"

const (
	ScannerAdapterMetadataMimeType     = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	OCIImageManifestMimeType           = "application/vnd.oci.image.manifest.v1+json"
	DockerDistributionManifestMimeType = "application/vnd.docker.distribution.manifest.v2+json"
	ScanResponseMimeType               = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	ScanReportMimeType                 = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	ScanAdapterErrorMimeType           = "application/vnd.scanner.adapter.error+json; version=1.0"
)

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}
type ScannerCapability struct {
	ConsumesMimeTypes []string `json:"consumes_mime_types"`
	ProducesMimeTypes []string `json:"produces_mime_types"`
}

type ScannerAdapterMetadata struct {
	Scanner      *Scanner            `json:"scanner"`
	Capabilities []ScannerCapability `json:"capabilities"`
	Properties   map[string]string   `json:"properties"`
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag"`
	MimeType   string `json:"mime_type"`
}

type ScanRequest struct {
	Registry *Registry `json:"registry"`
	Artifact *Artifact `json:"artifact"`
}

type ModelError struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error *ModelError `json:"error"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type VulnerabilityReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Artifact        *Artifact           `json:"artifact"`
	Scanner         *Scanner            `json:"scanner"`
	Severity        *Severity           `json:"severity"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type Severity string

const (
	UNKNOWN    Severity = "Unknown"
	NEGLIGIBLE Severity = "Negligible"
	LOW        Severity = "Low"
	MEDIUM     Severity = "Medium"
	HIGH       Severity = "High"
	CRITICAL   Severity = "Critical"
)

type VulnerabilityItem struct {
	ID          string   `json:"id"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
}
