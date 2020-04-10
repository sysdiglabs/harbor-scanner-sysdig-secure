package harbor

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
