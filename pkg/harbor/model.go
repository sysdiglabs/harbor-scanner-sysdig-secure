package harbor

import "time"

const (
	ScannerAdapterMetadataMimeType     = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	OCIImageManifestMimeType           = "application/vnd.oci.image.manifest.v1+json"
	DockerDistributionManifestMimeType = "application/vnd.docker.distribution.manifest.v2+json"
	ScanResponseMimeType               = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	ScanReportMimeType                 = "application/vnd.security.vulnerability.report; version=1.1"
	ScanAdapterErrorMimeType           = "application/vnd.scanner.adapter.error+json; version=1.0"
)

type ScanRequestID string

type Scanner struct {
	Name    string `json:"name,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
}
type ScannerCapability struct {
	ConsumesMimeTypes []string `json:"consumes_mime_types"`
	ProducesMimeTypes []string `json:"produces_mime_types"`
}

type ScannerAdapterMetadata struct {
	Scanner      *Scanner            `json:"scanner"`
	Capabilities []ScannerCapability `json:"capabilities"`
	Properties   map[string]string   `json:"properties,omitempty"`
}

type Registry struct {
	URL           string `json:"url,omitempty"`
	Authorization string `json:"authorization,omitempty"`
}

type Artifact struct {
	Repository string `json:"repository,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Tag        string `json:"tag,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
}

type ScanRequest struct {
	Registry *Registry `json:"registry"`
	Artifact *Artifact `json:"artifact"`
}

type ModelError struct {
	Message string `json:"message,omitempty"`
}

type ErrorResponse struct {
	Error *ModelError `json:"error,omitempty"`
}

type ScanResponse struct {
	ID ScanRequestID `json:"id"`
}

type VulnerabilityReport struct {
	GeneratedAt     time.Time           `json:"generated_at,omitempty"`
	Artifact        *Artifact           `json:"artifact,omitempty"`
	Scanner         *Scanner            `json:"scanner,omitempty"`
	Severity        Severity            `json:"severity,omitempty"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities,omitempty"`
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
	ID               string   `json:"id,omitempty"`
	Package          string   `json:"package,omitempty"`
	Version          string   `json:"version,omitempty"`
	FixVersion       string   `json:"fix_version,omitempty"`
	Severity         Severity `json:"severity,omitempty"`
	Description      string   `json:"description,omitempty"`
	Links            []string `json:"links,omitempty"`
	CVSS             CVSSData `json:"preferred_cvss"`
	VendorAttributes CVSS     `json:"vendor_attributes"`
}

type CVSS struct {
	CvssKey NVDKey `json:"CVSS"`
}

type NVDKey struct {
	NVD CVSSData `json:"Base_Score"`
}

type CVSSData struct {
	ScoreV3  float32 `json:"V3Score"`
	ScoreV2  float32 `json:"V2Score"`
	VectorV3 string  `json:"V3Vector"`
	VectorV2 string  `json:"V2Vector"`
}
