package secure

import "time"

type ScanResponse struct {
	AnalysisStatus string         `json:"analysis_status"`
	CreatedAt      time.Time      `json:"created_at"`
	ImageDigest    string         `json:"imageDigest"`
	ImageStatus    string         `json:"image_status"`
	LastUpdated    time.Time      `json:"last_updated"`
	ParentDigest   string         `json:"parentDigest"`
	UserID         string         `json:"userId"`
	ImageContent   *ImageContent  `json:"image_content"`
	ImageDetail    []*ImageDetail `json:"image_detail"`
}

type ImageContent struct {
	Metadata *Metadata `json:"metadata"`
}

type Metadata struct {
	Arch           string `json:"arch"`
	Distro         string `json:"distro"`
	DistroVersion  string `json:"distro_version"`
	DockerfileMode string `json:"dockerfile_mode"`
	ImageSize      int    `json:"image_size"`
	LayerCount     int    `json:"layer_count"`
}

type ImageDetail struct {
	CreatedAt   time.Time `json:"created_at"`
	Dockerfile  string    `json:"dockerfile"`
	FullDigest  string    `json:"full_digest"`
	FullTag     string    `json:"full_tag"`
	ImageDigest string    `json:"image_digest"`
	ImageID     string    `json:"imageId"`
	LastUpdated time.Time `json:"last_updated"`
	Registry    string    `json:"registry"`
	Repository  string    `json:"repo"`
	UserID      string    `json:"userId"`
	// TODO: I have some doubts about if these fields should be right here or
	// create a new value for GetImage operations
	Digest        string    `json:"digest"`
	Tag           string    `json:"tag"`
	TagDetectedAt time.Time `json:"tag_detected_at"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type VulnerabilityReport struct {
	ImageDigest       string           `json:"imageDigest"`
	VulnerabilityType string           `json:"vtype"`
	Vulnerabilities   []*Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	Exploitable    bool       `json:"exploitable"`
	Feed           string     `json:"feed"`
	FeedGroup      string     `json:"feed_group"`
	Fix            string     `json:"fix"`
	NVDData        []*NVDData `json:"nvd_data"`
	Package        string     `json:"package"`
	PackageCPE     string     `json:"package_cpe"`
	PackageName    string     `json:"package_name"`
	PackagePath    string     `json:"package_path"`
	PackageType    string     `json:"package_type"`
	PackageVersion string     `json:"package_version"`
	ResultId       string     // Not serialised (Notice the S not Z, we use 'proper' english :)
	Severity       string     `json:"severity"`
	URL            string     `json:"url"`
	Vuln           string     `json:"vuln"`
	DisclosureDate string     `json:"disclosureDate"`
	// VulnId         string     // Not serialised either, used for description querying
}

type NVDData struct {
	ID     string `json:"id"`
	CVSSV2 *CVSS  `json:"cvss_v2"`
	CVSSV3 *CVSS  `json:"cvss_v3"`
}

type CVSS struct {
	BaseScore           float32 `json:"base_score"`
	ExploitabilityScore float32 `json:"exploitability_score"`
	ImpactScore         float32 `json:"impact_score"`
}

type FeedGroup struct {
	Name        string    `json:"name"`
	RecordCount int       `json:"record_count"`
	CreatedAt   time.Time `json:"created_at"`
	LastSync    time.Time `json:"last_sync"`
}

type Feed struct {
	Name         string      `json:"name"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	LastFullSync time.Time   `json:"last_full_sync"`
	Groups       []FeedGroup `json:"groups"`
}
