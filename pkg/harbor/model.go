package harbor

import "time"

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
	Url           string `json:"url,omitempty"`
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
	Id string `json:"id"`
}

type VulnerabilityReport struct {
	GeneratedAt     time.Time           `json:"generated_at,omitempty"`
	Artifact        *Artifact           `json:"artifact,omitempty"`
	Scanner         *Scanner            `json:"scanner,omitempty"`
	Severity        *Severity           `json:"severity,omitempty"`
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
	ID          string    `json:"id,omitempty"`
	Package     string    `json:"package,omitempty"`
	Version     string    `json:"version,omitempty"`
	FixVersion  string    `json:"fix_version,omitempty"`
	Severity    *Severity `json:"severity,omitempty"`
	Description string    `json:"description,omitempty"`
	Links       []string  `json:"links,omitempty"`
}
