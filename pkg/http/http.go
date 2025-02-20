package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

type FormAuthorization func(url.Values)
type RequestAuthorization func(*http.Request)

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
	if fn, ok := authFn.(FormAuthorization); ok {
		fn(form)
	}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	if fn, ok := authFn.(RequestAuthorization); ok {
		fn(req)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

func HttpRequest(client *http.Client, req *http.Request, response any) error {
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
		var oidcErr oidc.Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil || oidcErr.ErrorType == "" {
			return fmt.Errorf("http status not ok: %s %s", resp.Status, body)
		}
		return &oidcErr
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

func StartServer(ctx context.Context, port string) {
	c := make(chan error)
	StartServer2(ctx, port, WithStartServerErrorChannel(&c))
	err := <-c
	if err != nil {
		log.Fatal(err)
	}
}

type startServerOpts struct {
	errorChannel *chan error
	timeout      time.Duration
}

func WithStartServerErrorChannel(errorChannel *chan error) func(*startServerOpts) {
	return func(opts *startServerOpts) {
		opts.errorChannel = errorChannel
	}
}

func WithTimeout(timeout time.Duration) func(*startServerOpts) {
	return func(opts *startServerOpts) {
		opts.timeout = timeout
	}
}

var ErrStartServerListenAndServe = errors.New("server.ListenAndServe():")
var ErrStartServerShutdown = errors.New("server.Shutdown():")

func StartServer2(ctx context.Context, port string, opts ...func(*startServerOpts)) {
	options := &startServerOpts{
		timeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(options)
	}

	server := &http.Server{Addr: port}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			if options.errorChannel != nil {
				*options.errorChannel <- fmt.Errorf("%w %v", ErrStartServerListenAndServe, err)
			}
		}
	}()

	go func() {
		<-ctx.Done()
		ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), options.timeout)
		defer cancelShutdown()
		err := server.Shutdown(ctxShutdown)
		if err != nil {
			if options.errorChannel != nil {
				*options.errorChannel <- fmt.Errorf("%w %v", ErrStartServerShutdown, err)
			}
		}
	}()
}
