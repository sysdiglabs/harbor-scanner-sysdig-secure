package secure

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

type Client interface {
	AddImage(image string) (ScanResponse, error)
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

func (s *client) AddImage(image string) (ScanResponse, error) {
	var emptyResult ScanResponse

	params := map[string]string{
		"tag": image,
	}
	payload, _ := json.Marshal(params)
	request, err := s.buildPostRequest("/api/scanning/v1/anchore/images", payload)
	if err != nil {
		return emptyResult, err
	}

	response, err := s.client.Do(request)
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

func (s *client) buildPostRequest(url string, payload []byte) (*http.Request, error) {
	request, err := http.NewRequest(
		"POST",
		s.secureURL+"/api/scanning/v1/anchore/images",
		strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+s.apiToken)

	return request, nil
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
