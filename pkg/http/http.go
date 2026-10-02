package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var DefaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

type Decoder interface {
	Decode(dst any, src map[string][]string) error
}

type Encoder interface {
	Encode(src any, dst map[string][]string) error
}

type (
	FormAuthorization    func(url.Values)
	RequestAuthorization func(*http.Request)
)

func AuthorizeBasic(user, password string) RequestAuthorization {
	return func(req *http.Request) {
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(password))
	}
}

func FormRequest(ctx context.Context, endpoint string, request any, encoder Encoder, authFn any) (*http.Request, error) {
	form := url.Values{}
	if err := encoder.Encode(request, form); err != nil {
		return nil, err
	}
	if fn, ok := authFn.(FormAuthorization); ok && fn != nil {
		fn(form)
	}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	if fn, ok := authFn.(RequestAuthorization); ok && fn != nil {
		fn(req)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// HttpRequest sends req using client and unmarshals a successful JSON response
// body into response. The Content-Type of the response is not checked;
// use [HttpJSONRequest] when the server is required to respond with
// application/json.
func HttpRequest(client *http.Client, req *http.Request, response any) error {
	return httpRequest(client, req, response, false)
}

// HttpJSONRequest works like [HttpRequest], but additionally requires a
// successful response to carry an application/json Content-Type header.
// If it does not, an error wrapping [ErrInvalidContentType] is returned.
func HttpJSONRequest(client *http.Client, req *http.Request, response any) error {
	return httpRequest(client, req, response, true)
}

func httpRequest(client *http.Client, req *http.Request, response any, requireJSON bool) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodySize+1))
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oidcErr oidc.Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil || oidcErr.ErrorType == "" {
			return fmt.Errorf("http status not ok: %s %s", resp.Status, body)
		}
		return &oidcErr
	}

	if int64(len(body)) > MaxResponseBodySize {
		return ErrResponseBodyTooLarge
	}

	if requireJSON {
		if err := checkJSONContentType(resp.Header.Get("Content-Type")); err != nil {
			return err
		}
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v %s", err, body)
	}
	return nil
}

func URLEncodeParams(resp any, encoder Encoder) (url.Values, error) {
	values := make(map[string][]string)
	err := encoder.Encode(resp, values)
	if err != nil {
		return nil, err
	}
	return values, nil
}

func StartServer(ctx context.Context, address string) {
	server := &http.Server{Addr: address}
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

func checkJSONContentType(contentType string) error {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: expected application/json, got %q", ErrInvalidContentType, contentType)
	}
	return nil
}
