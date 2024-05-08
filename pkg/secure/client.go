package secure

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	BackendVersion = "SaaS"
)

var (
	ErrImageNotFound               = errors.New("image not found in Sysdig Secure")
	ErrVulnerabilityReportNotReady = errors.New("image is being analyzed by Sysdig Secure")
	ErrRegistryAlreadyExists       = errors.New("registry already exists in DB")
)

//go:generate mockgen -source=$GOFILE -destination=./mocks/${GOFILE} -package=mocks
type Client interface {
	AddImage(image string, force bool) (ScanResponse, error)
	GetImage(shaDigest string) (V2VulnerabilityReport, error)

	GetVulnerabilities(shaDigest string) (VulnerabilityReport, error)

	GetFeeds() ([]Feed, error)

	AddRegistry(registry string, user string, password string) error
	UpdateRegistry(registry string, user string, password string) error
	DeleteRegistry(registry string) error

	GetVulnerabilityDescription(vulnerabilityIDs ...string) (map[string]string, error)
	GetVulnerabilityDescriptionV2(resultId string, VulnId string) (*UrlVuln, error)
}

func NewClient(apiToken string, secureURL string, verifySSL bool) Client {
	// Clone DefaultTransport to use proxy settings and default timeouts
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if !verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &client{
		apiToken:  apiToken,
		secureURL: secureURL,
		client:    http.Client{Transport: transport},
	}
}

type client struct {
	apiToken  string
	secureURL string
	client    http.Client
}

func (s *client) AddImage(image string, force bool) (ScanResponse, error) {
	var emptyResult ScanResponse

	params := map[string]string{
		"tag": image,
	}
	payload, _ := json.Marshal(params)
	response, body, err := s.doRequest(
		http.MethodPost,
		fmt.Sprintf("/api/scanning/v1/anchore/images?force=%t", force),
		payload)
	if err != nil {
		return emptyResult, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return emptyResult, err
	}

	var result []ScanResponse
	if err = json.Unmarshal(body, &result); err != nil {
		return emptyResult, err
	}
	return result[0], nil
}

func (s *client) doRequest(method string, url string, payload []byte) (*http.Response, []byte, error) {
	var emptyBody []byte
	baseDelay := 1 * time.Second

	for attempt := 0; attempt < 7; attempt++ {
		request, err := http.NewRequest(method, fmt.Sprintf("%s%s", s.secureURL, url), strings.NewReader(string(payload)))
		if err != nil {
			return nil, emptyBody, err
		}

		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("Authorization", "Bearer "+s.apiToken)

		response, err := s.client.Do(request)
		if err != nil {
			return nil, emptyBody, err
		}
		if response.Body != nil {
			body, err := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if err != nil {
				return nil, nil, err
			}
			if closeErr != nil {
				return nil, nil, closeErr
			}

			if response.StatusCode != http.StatusTooManyRequests {
				return response, body, nil
			}
		} else {
			return nil, emptyBody, fmt.Errorf("response body is nil")
		}
		fmt.Printf("doRequest:: Got '%d'\n", response.StatusCode)
		backoff := time.Duration(int64(math.Pow(2, float64(attempt)))) * baseDelay

		time.Sleep(backoff)
		fmt.Printf("doRequest sleeping for '%d'\n", backoff)
	}
	fmt.Printf("Out of retries, exiting...\n")
	return nil, emptyBody, fmt.Errorf("too many requests, all retries failed")
}

func (s *client) checkErrorInSecureAPI(response *http.Response, body []byte) error {
	if response.StatusCode <= 300 {
		return nil
	}

	var secureError ErrorResponse
	if err := json.Unmarshal(body, &secureError); err != nil {
		return err
	}
	return errors.New(secureError.Message)
}

type V2VulnerabilityScanResult struct {
	Page V2PageDetail     `json:"page"`
	Data []V2ScanDataItem `json:"data"`
}

type V2PageDetail struct {
	Total int `json:"total"`
}

type V2ScanDataItem struct {
	ResultID                string `json:"resultId"`
	ImageID                 string `json:"imageId"`
	PolicyEvaluationsResult string `json:"policyEvaluationsResult"`
}

type imageScanResultResponse struct {
	Results []*imageScanResult `json:"results"`
}

type imageScanResult struct {
	AnalysisStatus string `json:"analysisStatus"`
	AnalyzedAt     int    `json:"analyzedAt"`
	CreatedAt      int    `json:"createdAt"`
	ImageDigest    string `json:"imageDigest"`
	ImageId        string `json:"imageId"`
	FullTag        string `json:"fullTag"`
}

type V2VulnerabilityResponse struct {
	Page V2PageData   `json:"page"`
	Data []V2DataItem `json:"data"`
}

type V2PageData struct {
	Returned int `json:"returned"`
	Offset   int `json:"offset"`
	Matched  int `json:"matched"`
}

type V2DataItem struct {
	ID             string          `json:"id"`
	Vuln           V2Vulnerability `json:"vuln"`
	Package        V2Package       `json:"package"`
	FixedInVersion string          `json:"fixedInVersion"`
}

type V2Vulnerability struct {
	Name           string        `json:"name"`
	Severity       int           `json:"severity"`
	CvssVersion    string        `json:"cvssVersion"`
	CvssScore      float32       `json:"cvssScore"`
	Exploitable    bool          `json:"exploitable"`
	Cisakev        bool          `json:"cisakev"`
	DisclosureDate time.Time     `json:"disclosureDate"`
	AcceptedRisks  []interface{} `json:"acceptedRisks"` // Use []interface{} if the risks vary in type or are unknown.
}

type V2Package struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Running bool   `json:"running"`
}

func (s *client) retrieveFullVulnerabilityReport(resultID string) (*V2VulnerabilityResponse, error) {
	var result V2VulnerabilityResponse
	var partialResult V2VulnerabilityResponse

	offset := 0
	limit := 100
	baseUrl := fmt.Sprintf("/api/scanning/scanresults/v2/results/%s/vulnPkgs", resultID)
	queryParams := url.Values{}
	queryParams.Set("limit", strconv.Itoa(limit))
	queryParams.Set("order", "asc")
	queryParams.Set("sort", "vulnSeverity")

	var allData []V2DataItem
	for {
		queryParams.Set("offset", strconv.Itoa(offset))
		fullUrl := fmt.Sprintf("%s?%s", baseUrl, queryParams.Encode())
		response, body, err := s.doRequest(http.MethodGet, fullUrl, nil)
		if err != nil {
			return nil, err
		}

		if err := s.checkErrorInSecureAPI(response, body); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(body, &partialResult); err != nil {
			return nil, err
		}

		allData = append(allData, partialResult.Data...)
		if partialResult.Page.Returned < limit {
			break
		}

		offset += limit
	}

	result.Data = allData
	return &result, nil
}

func (s *client) GetVulnerabilities(shaDigest string) (VulnerabilityReport, error) {
	//var checkScanResultResponse imageScanResultResponse
	var checkScanResultResponse V2VulnerabilityScanResult

	var result VulnerabilityReport

	baseUrl := "/secure/vulnerability/v1beta1/pipeline-results"
	queryParams := url.Values{}
	queryParams.Set("filter", fmt.Sprintf("freeText in (\"%s\")", shaDigest))
	queryParams.Set("limit", "1")

	fullUrl := fmt.Sprintf("%s?%s", baseUrl, queryParams.Encode())

	response, body, err := s.doRequest(
		http.MethodGet,
		//fmt.Sprintf("/api/scanning/v1/results?filter=%s&limit=%d", shaDigest, 1),
		fullUrl, nil)

	if err != nil {
		return result, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return result, err
	}
	if err = json.Unmarshal(body, &checkScanResultResponse); err != nil {
		return result, err
	}

	statusMap := map[string]bool{
		"passed": true,
		"failed": true,
	}

	if checkScanResultResponse.Page.Total == 0 {
		return result, ErrImageNotFound
	} else if _, img := statusMap[checkScanResultResponse.Data[0].PolicyEvaluationsResult]; !img {
		return result, ErrVulnerabilityReportNotReady
	}

	resultId := checkScanResultResponse.Data[0].ResultID

	V2VulnResponse, err := s.retrieveFullVulnerabilityReport(resultId)
	// Convert data into the v1 legacy format as best as possible
	result = VulnerabilityReport{
		ImageDigest:       checkScanResultResponse.Data[0].ImageID,
		VulnerabilityType: "all",
		Vulnerabilities:   []*Vulnerability{},
	}
	severityMap := map[int]string{
		2: "Critical",
		3: "High",
		5: "Medium",
		6: "Low",
		7: "Negligible",
	}

	for _, row := range V2VulnResponse.Data {
		var cvssV2ValueFloat float32
		var cvssV3ValueFloat float32
		if strings.HasPrefix(row.Vuln.CvssVersion, "3") {
			cvssV3ValueFloat = row.Vuln.CvssScore
		} else if strings.HasPrefix(row.Vuln.CvssVersion, "2") {
			cvssV2ValueFloat = row.Vuln.CvssScore
		}
		cvssV3 := CVSS{
			BaseScore:           cvssV3ValueFloat,
			ExploitabilityScore: 0,
			ImpactScore:         0,
		}
		cvssV2 := CVSS{
			BaseScore:           cvssV2ValueFloat,
			ExploitabilityScore: 0,
			ImpactScore:         0,
		}
		nvd := NVDData{
			ID:     row.Vuln.Name,
			CVSSV2: &cvssV2,
			CVSSV3: &cvssV3,
		}

		vuln := Vulnerability{
			Feed:           "vulnerabilities",
			FeedGroup:      "",
			Fix:            row.FixedInVersion,
			NVDData:        []*NVDData{&nvd},
			Package:        fmt.Sprintf("%s-%s", row.Package.Name, row.Package.Version),
			PackageCPE:     "None",
			PackageName:    row.Package.Name,
			PackagePath:    "",
			PackageType:    row.Package.Type,
			PackageVersion: row.Package.Version,
			ResultId:       resultId,
			Severity:       severityMap[row.Vuln.Severity],
			URL:            "",
			Vuln:           row.Vuln.Name,
			VulnId:         row.ID,
		}
		result.Vulnerabilities = append(result.Vulnerabilities, &vuln)
	}

	return result, nil
}

type registryRequest struct {
	Registry string `json:"registry"`
	User     string `json:"registry_user"`
	Password string `json:"registry_pass"`
	Type     string `json:"registry_type"`
	Verify   bool   `json:"registry_verify"`
}

func (s *client) AddRegistry(registry string, user string, password string) error {
	request := registryRequest{
		Registry: registry,
		User:     user,
		Password: password,
		Type:     "docker_v2",
		Verify:   false,
	}
	payload, _ := json.Marshal(request)
	response, body, err := s.doRequest(
		http.MethodPost,
		// We don't validate credentials provided by Harbor, we assume they are valid
		fmt.Sprintf("/api/scanning/v1/anchore/registries?validate=%t", false),
		payload)
	if err != nil {
		return err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		if err.Error() == "registry already exists in DB" {
			return ErrRegistryAlreadyExists
		}
		return err
	}

	return nil
}

func (s *client) UpdateRegistry(registry string, user string, password string) error {
	request := registryRequest{
		Registry: registry,
		User:     user,
		Password: password,
		Type:     "docker_v2",
		Verify:   false,
	}
	payload, _ := json.Marshal(request)
	response, body, err := s.doRequest(
		http.MethodPut,
		fmt.Sprintf("/api/scanning/v1/anchore/registries/registry/%s?validate=%t", registry, false),
		payload)
	if err != nil {
		return err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return err
	}
	return nil
}

func (s *client) DeleteRegistry(registry string) error {
	response, body, err := s.doRequest(
		http.MethodDelete,
		fmt.Sprintf("/api/scanning/v1/anchore/registries/%s", registry),
		nil)
	if err != nil {
		return err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return err
	}

	return nil
}

type V2PageDetails struct {
	Returned int    `json:"returned"`
	Matched  int    `json:"matched"`
	Next     string `json:"next"`
}

type V2VulnerabilityData struct {
	ID                      string    `json:"id"`
	StoredAt                time.Time `json:"storedAt"`
	ImageID                 string    `json:"imageId"`
	ImagePullString         string    `json:"imagePullString"`
	VulnsBySev              []int     `json:"vulnsBySev"`
	ExploitCount            int       `json:"exploitCount"`
	PolicyEvaluationsResult string    `json:"policyEvaluationsResult"`
	HasAcceptedRisk         bool      `json:"hasAcceptedRisk"`
}

type V2VulnerabilityReport struct {
	Page V2PageDetails         `json:"page"`
	Data []V2VulnerabilityData `json:"data"`
}

func (s *client) GetImage(shaDigest string) (V2VulnerabilityReport, error) {
	var emptyResult V2VulnerabilityReport

	baseUrl := "/api/scanning/scanresults/v2/results"
	queryParams := url.Values{}
	queryParams.Set("limit", "1")
	queryParams.Set("filter", fmt.Sprintf("freeText in (\"%s\")", shaDigest))
	fullUrl := fmt.Sprintf("%s?%s", baseUrl, queryParams.Encode())

	response, body, err := s.doRequest(http.MethodGet, fullUrl, nil)
	if err != nil {
		return emptyResult, err
	}
	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		if err.Error() == "image not found in DB" {
			return emptyResult, ErrImageNotFound
		}
		return emptyResult, err
	}

	var result V2VulnerabilityReport
	if err = json.Unmarshal(body, &result); err != nil {
		return emptyResult, err
	}

	return result, nil
}

func (s *client) GetFeeds() ([]Feed, error) {
	var emptyResult []Feed

	response, body, err := s.doRequest(
		http.MethodGet,
		"/api/scanning/v1/system/feeds",
		nil)
	if err != nil {
		return emptyResult, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return emptyResult, err
	}

	var result []Feed
	if err = json.Unmarshal(body, &result); err != nil {
		return emptyResult, err
	}
	return result, nil
}

type vulnerabilityDescription struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type vulnerabilityResponse struct {
	Vulnerabilities []vulnerabilityDescription `json:"vulnerabilities"`
}

type VulnerabilityDetail struct {
	Vuln VulnDetail `json:"vuln"`
}

type VulnDetail struct {
	CvssScore   CvssScoreDetail `json:"cvssScore"`
	Description string          `json:"description"`
}

type CvssScoreDetail struct {
	Reporter URLDetail `json:"reporter"`
}

type URLDetail struct {
	URL string `json:"url"`
}

type UrlVuln struct {
	URL         string
	Description string
}

func (s *client) GetVulnerabilityDescriptionV2(resultId string, VulnId string) (*UrlVuln, error) {
	result := UrlVuln{}

	response, body, err := s.doRequest(
		http.MethodGet,
		fmt.Sprintf("/api/scanning/scanresults/v2/results/%s/vulnPkgs/%s", resultId, VulnId),
		nil)
	if err != nil {
		return &result, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return &result, err
	}

	var res VulnerabilityDetail
	if err = json.Unmarshal(body, &res); err != nil {
		return &result, err
	}

	result.Description = res.Vuln.Description
	result.URL = res.Vuln.CvssScore.Reporter.URL

	return &result, nil
}

func (s *client) GetVulnerabilityDescription(vulnerabilitiesIDs ...string) (map[string]string, error) {
	result := make(map[string]string)

	response, body, err := s.doRequest(
		http.MethodGet,
		fmt.Sprintf("/api/scanning/v1/anchore/query/vulnerabilities?id=%s&namespace=nvdv2:cves,vulndb:vulnerabilities", strings.Join(vulnerabilitiesIDs, ",")),
		nil)
	if err != nil {
		return result, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		return result, err
	}

	var res vulnerabilityResponse
	if err = json.Unmarshal(body, &res); err != nil {
		return result, err
	}

	for _, current := range res.Vulnerabilities {
		result[current.ID] = current.Description
	}

	return result, nil
}
