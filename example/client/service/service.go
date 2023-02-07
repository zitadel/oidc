package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v2/pkg/client/profile"
)

var client = http.DefaultClient

func main() {
	keyPath := os.Getenv("KEY_PATH")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")

	if keyPath != "" {
		ts, err := profile.NewJWTProfileTokenSourceFromKeyFile(issuer, keyPath, scopes)
		if err != nil {
			logrus.Fatalf("error creating token source %s", err.Error())
		}
		client = oauth2.NewClient(context.Background(), ts)
	}

	http.HandleFunc("/jwt-profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tpl := `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Login</title>
		</head>
		<body>
			<form method="POST" action="/jwt-profile" enctype="multipart/form-data">
				<label for="key">Select a key file:</label>
				<input type="file" accept=".json" id="key" name="key">
				<button type="submit">Get Token</button>
			</form>
		</body>
	</html>`
			t, err := template.New("login").Parse(tpl)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = t.Execute(w, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else {
			err := r.ParseMultipartForm(4 << 10)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			file, _, err := r.FormFile("key")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer file.Close()

			key, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ts, err := profile.NewJWTProfileTokenSourceFromKeyFileData(issuer, key, scopes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			client = oauth2.NewClient(context.Background(), ts)
			token, err := ts.Token()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			data, err := json.Marshal(token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(data)
		}
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		tpl := `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Test</title>
		</head>
		<body>
			<form method="POST" action="/test">
				<label for="url">URL for test:</label>
				<input type="text" id="url" name="url" width="200px">
				<button type="submit">Test Token</button>
			</form>
			{{if .URL}}
			<p>
				Result for {{.URL}}: {{.Response}}
			</p>
			{{end}}
		</body>
	</html>`
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		testURL := r.Form.Get("url")
		var data struct {
			URL      string
			Response interface{}
		}
		if testURL != "" {
			data.URL = testURL
			data.Response, err = callExampleEndpoint(client, testURL)
			if err != nil {
				data.Response = err
			}
		}
		t, err := template.New("login").Parse(tpl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	lis := fmt.Sprintf("127.0.0.1:%s", port)
	logrus.Infof("listening on http://%s/", lis)
	logrus.Fatal(http.ListenAndServe("127.0.0.1:"+port, nil))
}

func callExampleEndpoint(client *http.Client, testURL string) (interface{}, error) {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http status not ok: %s %s", resp.Status, body)
	}

	if strings.HasPrefix(resp.Header.Get("content-type"), "text/plain") {
		return string(body), nil
	}
	return body, err
}
