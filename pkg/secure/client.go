package secure

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	BackendVersion = "3.x"
)

var (
	ErrImageNotFound              = errors.New("image not found in Sysdig Secure")
	ErrVulnerabiltyReportNotReady = errors.New("image is being analyzed by Sysdig Secure")

	ErrRegistryAlreadyExists = errors.New("registry already exists in DB")
)

//go:generate mockgen -source=$GOFILE -destination=./mocks/${GOFILE} -package=mocks
type Client interface {
	AddImage(image string, force bool) (ScanResponse, error)
	GetImage(shaDigest string) (ScanResponse, error)

	GetVulnerabilities(shaDigest string) (VulnerabilityReport, error)

	GetFeeds() ([]Feed, error)

	AddRegistry(registry string, user string, password string) error
	UpdateRegistry(registry string, user string, password string) error
	DeleteRegistry(registry string) error

	GetVulnerabilityDescription(vulnerabilityIDs ...string) (map[string]string, error)
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

	request, err := http.NewRequest(
		method,
		fmt.Sprintf("%s%s", s.secureURL, url),
		strings.NewReader(string(payload)))
	if err != nil {
		return nil, emptyBody, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+s.apiToken)

	response, err := s.client.Do(request)
	if err != nil {
		return nil, emptyBody, err
	}

	body, err := ioutil.ReadAll(response.Body)
	defer response.Body.Close()
	if err != nil {
		return nil, emptyBody, err
	}

	return response, body, nil
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

func (s *client) GetVulnerabilities(shaDigest string) (VulnerabilityReport, error) {
	var result VulnerabilityReport
	response, body, err := s.doRequest(
		http.MethodGet,
		fmt.Sprintf("/api/scanning/v1/images/%s/vulnDirect/all?includeVulnExceptions=%t", shaDigest, false),
		nil)
	if err != nil {
		return result, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		if response.StatusCode == http.StatusNotFound {
			if err.Error() == "image not found in DB" {
				return result, ErrImageNotFound
			}

			if strings.HasPrefix(err.Error(), "image is not analyzed - analysis_status:") {
				return result, ErrVulnerabiltyReportNotReady
			}
		}
		return result, err
	}

	if err = json.Unmarshal(body, &result); err != nil {
		return result, err
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

func (s *client) GetImage(shaDigest string) (ScanResponse, error) {
	var emptyResult ScanResponse

	response, body, err := s.doRequest(
		http.MethodGet,
		fmt.Sprintf("/api/scanning/v1/anchore/images/%s", shaDigest),
		nil)
	if err != nil {
		return emptyResult, err
	}

	if err = s.checkErrorInSecureAPI(response, body); err != nil {
		if err.Error() == "image not found in DB" {
			return emptyResult, ErrImageNotFound
		}
		return emptyResult, err
	}

	var result []ScanResponse
	if err = json.Unmarshal(body, &result); err != nil {
		return emptyResult, err
	}

	return result[0], nil
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
