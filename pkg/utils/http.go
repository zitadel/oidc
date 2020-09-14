package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
)

var (
	DefaultHTTPClient = &http.Client{
		Timeout: time.Duration(30 * time.Second),
	}
)

type Decoder interface {
	Decode(dst interface{}, src map[string][]string) error
}
type Encoder interface {
	Encode(src interface{}, dst map[string][]string) error
}

func FormRequest(endpoint string, request interface{}, clientID, clientSecret string, header bool) (*http.Request, error) {
	form := make(map[string][]string)
	encoder := schema.NewEncoder()
	if err := encoder.Encode(request, form); err != nil {
		return nil, err
	}
	if !header {
		form["client_id"] = []string{clientID}
		form["client_secret"] = []string{clientSecret}
	}
	body := strings.NewReader(url.Values(form).Encode())
	req, err := http.NewRequest("POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	if header {
		req.SetBasicAuth(clientID, clientSecret)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

func HttpRequest(client *http.Client, req *http.Request, response interface{}) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status not ok: %s %s", resp.Status, body)
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v %s", err, body)
	}
	return nil
}

func URLEncodeResponse(resp interface{}, encoder Encoder) (string, error) {
	values := make(map[string][]string)
	err := encoder.Encode(resp, values)
	if err != nil {
		return "", err
	}
	v := url.Values(values)
	return v.Encode(), nil
}
