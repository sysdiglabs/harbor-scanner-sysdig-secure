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
	//AddImage(image string, force bool) (ScanResponse, error)
	GetImage(shaDigest string) (V2VulnerabilityReport, error)

	GetVulnerabilities(shaDigest string) (VulnerabilityReport, error)

	GetFeeds() ([]Feed, error)

	//AddRegistry(registry string, user string, password string) error
	//UpdateRegistry(registry string, user string, password string) error
	//DeleteRegistry(registry string) error

	//GetVulnerabilityDescription(vulnerabilityIDs ...string) (map[string]string, error)
	//GetVulnerabilityDescriptionV2(resultId string, VulnId string) (*UrlVuln, error)
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

/*
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
*/

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

type V1BetaScanResult struct {
	Result V1BetaImageScanResult `json:"result"`
}

type V1BetaImageScanResult struct {
	Type                 string          `json:"type"`
	Metadata             V1BetaMetadata  `json:"metadata"`
	ExploitsCount        int             `json:"exploitsCount"`
	RiskSpotlightEnabled bool            `json:"riskSpotlightEnabled"`
	Packages             []V1BetaPackage `json:"packages"`
}

type V1BetaMetadata struct {
	PullString   string            `json:"pullString"`
	ImageID      string            `json:"imageId"`
	Digest       string            `json:"digest"`
	BaseOs       string            `json:"baseOs"`
	Size         int               `json:"size"`
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	Labels       map[string]string `json:"labels"`
	LayersCount  int               `json:"layersCount"`
	CreatedAt    time.Time         `json:"createdAt"`
}

type V1BetaPackage struct {
	Type         string        `json:"type"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Path         string        `json:"path"`
	SuggestedFix string        `json:"suggestedFix"`
	InUse        bool          `json:"inUse"`
	Vulns        []V1BetaVulns `json:"vulns"`
}

type V1BetaVulns struct {
	Name                string             `json:"name"`
	Severity            V1BetaSeverityInfo `json:"severity"`
	CvssScore           V1BetaCvss         `json:"cvssScore"`
	DisclosureDate      string             `json:"disclosureDate"`
	Exploitable         bool               `json:"exploitable"`
	PublishDateByVendor map[string]string  `json:"publishDateByVendor"`
	FixedInVersion      string             `json:"fixedInVersion,omitempty"`
	SolutionDate        string             `json:"solutionDate,omitempty"`
}

type V1BetaSeverityInfo struct {
	Value      string `json:"value"`
	SourceName string `json:"sourceName"`
}

type V1BetaCvss struct {
	Value      V1BetaCvssValue `json:"value"`
	SourceName string          `json:"sourceName"`
}

type V1BetaCvssValue struct {
	Version string  `json:"version"`
	Score   float32 `json:"score"`
	Vector  string  `json:"vector"`
}

func (s *client) retrieveFullVulnerabilityReport(resultID string) (*V1BetaScanResult, error) {
	var result V1BetaScanResult
	response, body, err := s.doRequest(http.MethodGet, fmt.Sprintf("/secure/vulnerability/v1beta1/results/%s", resultID), nil)
	if err != nil {
		return nil, err
	}

	if err := s.checkErrorInSecureAPI(response, body); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *client) GetVulnerabilities(shaDigest string) (VulnerabilityReport, error) {
	var checkScanResultResponse V2VulnerabilityScanResult

	var result VulnerabilityReport

	baseUrl := "/secure/vulnerability/v1beta1/pipeline-results"
	queryParams := url.Values{}
	queryParams.Set("filter", fmt.Sprintf("freeText in (\"%s\")", shaDigest))
	queryParams.Set("limit", "1")

	fullUrl := fmt.Sprintf("%s?%s", baseUrl, queryParams.Encode())

	response, body, err := s.doRequest(http.MethodGet, fullUrl, nil)

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
	var V1BetaScanResult *V1BetaScanResult
	V1BetaScanResult, err = s.retrieveFullVulnerabilityReport(resultId)
	// Convert data into the v1 legacy format as best as possible
	result = VulnerabilityReport{
		ImageDigest:       checkScanResultResponse.Data[0].ImageID,
		VulnerabilityType: "all",
		Vulnerabilities:   []*Vulnerability{},
	}

	for _, packageRow := range V1BetaScanResult.Result.Packages {
		for _, vulnRow := range packageRow.Vulns {
			var cvssV2ValueFloat float32
			var cvssV3ValueFloat float32
			if strings.HasPrefix(vulnRow.CvssScore.Value.Version, "3") {
				cvssV3ValueFloat = vulnRow.CvssScore.Value.Score
			} else if strings.HasPrefix(vulnRow.CvssScore.Value.Version, "2") {
				cvssV2ValueFloat = vulnRow.CvssScore.Value.Score
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
				ID:     vulnRow.Name,
				CVSSV2: &cvssV2,
				CVSSV3: &cvssV3,
			}

			vuln := Vulnerability{
				Feed:           "vulnerabilities",
				FeedGroup:      "",
				Fix:            packageRow.SuggestedFix,
				NVDData:        []*NVDData{&nvd},
				Package:        fmt.Sprintf("%s-%s", packageRow.Name, packageRow.Version),
				PackageCPE:     "None",
				PackageName:    packageRow.Name,
				PackagePath:    "",
				PackageType:    packageRow.Type,
				PackageVersion: packageRow.Version,
				ResultId:       resultId,
				Severity:       vulnRow.Severity.Value,
				URL:            "",
				Vuln:           vulnRow.Name,
				Exploitable:    vulnRow.Exploitable,
				DisclosureDate: vulnRow.DisclosureDate,
				//VulnId:         "",
			}
			result.Vulnerabilities = append(result.Vulnerabilities, &vuln)
		}
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

/*
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
*/

/*
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
*/

/*
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
*/

type V2PageDetails struct {
	Returned int    `json:"returned"`
	Matched  int    `json:"matched"`
	Next     string `json:"next"`
}

type V2VulnerabilityData struct {
	//ID                      string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	//ImageID                 string    `json:"imageId"`
	MainAssetName string `json:"mainAssetName"`
	//VulnsBySev              []int  `json:"vulnsBySev"`
	//ExploitCount            int    `json:"exploitCount"`
	//PolicyEvaluationsResult string `json:"policyEvaluationsResult"`
	//HasAcceptedRisk         bool   `json:"hasAcceptedRisk"`
}

type V2VulnerabilityReport struct {
	//Page V2PageDetails         `json:"page"`
	Data []V2VulnerabilityData `json:"data"`
}

func (s *client) GetImage(shaDigest string) (V2VulnerabilityReport, error) {
	var emptyResult V2VulnerabilityReport

	baseUrl := "/secure/vulnerability/v1beta1/pipeline-results"
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

/*
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
*/
/*
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
*/
