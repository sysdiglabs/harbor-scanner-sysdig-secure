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
	Repo        string    `json:"repo"`
	UserID      string    `json:"userId"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}
