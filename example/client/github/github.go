package main

import (
	"context"
	"fmt"
	"os"

	"github.com/caos/oidc/pkg/cli"
	"github.com/caos/oidc/pkg/rp"
	"github.com/google/go-github/v31/github"
	githubOAuth "golang.org/x/oauth2/github"
)

var (
	callbackPath string = "/orbctl/github/callback"
	key          []byte = []byte("test1234test1234")
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	port := os.Getenv("PORT")

	rpConfig := &rp.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CallbackURL:  fmt.Sprintf("http://localhost:%v%v", port, callbackPath),
		Scopes:       []string{"repo", "repo_deployment"},
		Endpoints:    githubOAuth.Endpoint,
	}

	oauth2Client := cli.CodeFlowForClient(rpConfig, key, callbackPath, port)

	client := github.NewClient(oauth2Client)

	ctx := context.Background()
	_, _, err := client.Users.Get(ctx, "")
	if err != nil {
		fmt.Println("OAuth flow failed")
	} else {
		fmt.Println("OAuth flow success")
	}
}
