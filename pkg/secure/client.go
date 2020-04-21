package secure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

var (
	ErrImageNotFound              = errors.New("image not found in Sysdig Secure")
	ErrVulnerabiltyReportNotReady = errors.New("image is being analzyed by Sysdig Secure")
)

//go:generate mockgen -source=$GOFILE -destination=./mocks/${GOFILE} -package=mocks
type Client interface {
	AddImage(image string, force bool) (ScanResponse, error)
	GetVulnerabilities(shaDigest string) (VulnerabilityReport, error)
	AddRegistry(registry string, user string, password string) error
}

func NewClient(apiToken string, secureURL string) Client {
	return &client{
		apiToken:  apiToken,
		secureURL: secureURL,
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
	response, err := s.doRequest(
		http.MethodPost,
		fmt.Sprintf("/api/scanning/v1/anchore/images?force=%t", force),
		payload)
	if err != nil {
		return emptyResult, err
	}

	body, err := ioutil.ReadAll(response.Body)
	defer response.Body.Close()
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

func (s *client) doRequest(method string, url string, payload []byte) (*http.Response, error) {
	request, err := http.NewRequest(
		method,
		fmt.Sprintf("%s%s", s.secureURL, url),
		strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+s.apiToken)

	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
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

	response, err := s.doRequest(
		http.MethodGet,
		fmt.Sprintf("/api/scanning/v1/anchore/images/%s/vuln/all", shaDigest),
		nil)
	if err != nil {
		return result, err
	}

	body, err := ioutil.ReadAll(response.Body)
	defer response.Body.Close()
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

func (s *client) AddRegistry(registry string, user string, password string) error {
	return errors.New("Not Implemented")
}
