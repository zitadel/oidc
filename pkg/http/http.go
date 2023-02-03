package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var DefaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

type Decoder interface {
	Decode(dst interface{}, src map[string][]string) error
}

type Encoder interface {
	Encode(src interface{}, dst map[string][]string) error
}

type FormAuthorization func(url.Values)
type RequestAuthorization func(*http.Request)

func AuthorizeBasic(user, password string) RequestAuthorization {
	return func(req *http.Request) {
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(password))
	}
}

func FormRequest(endpoint string, request interface{}, encoder Encoder, authFn interface{}) (*http.Request, error) {
	form := url.Values{}
	if err := encoder.Encode(request, form); err != nil {
		return nil, err
	}
	if fn, ok := authFn.(FormAuthorization); ok {
		fn(form)
	}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequest("POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	if fn, ok := authFn.(RequestAuthorization); ok {
		fn(req)
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

	body, err := io.ReadAll(resp.Body)
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

func URLEncodeParams(resp interface{}, encoder Encoder) (url.Values, error) {
	values := make(map[string][]string)
	err := encoder.Encode(resp, values)
	if err != nil {
		return nil, err
	}
	return values, nil
}

func StartServer(ctx context.Context, port string) {
	server := &http.Server{Addr: port}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		err := server.Shutdown(ctxShutdown)
		if err != nil {
			log.Fatalf("Shutdown(): %v", err)
		}
	}()
}
