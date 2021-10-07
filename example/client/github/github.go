package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-github/v31/github"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/caos/oidc/pkg/client/rp/cli"
	"github.com/caos/oidc/pkg/utils"
)

var (
	callbackPath string = "/orbctl/github/callback"
	key          []byte = []byte("test1234test1234")
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	port := os.Getenv("PORT")

	rpConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%v%v", port, callbackPath),
		Scopes:       []string{"repo", "repo_deployment"},
		Endpoint:     githubOAuth.Endpoint,
	}

	ctx := context.Background()
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	relyingParty, err := rp.NewRelyingPartyOAuth(rpConfig, rp.WithCookieHandler(cookieHandler))
	if err != nil {
		fmt.Printf("error creating relaying party: %v", err)
		return
	}
	state := func() string {
		return uuid.New().String()
	}
	token := cli.CodeFlow(ctx, relyingParty, callbackPath, port, state)

	client := github.NewClient(relyingParty.OAuthConfig().Client(ctx, token.Token))

	_, _, err = client.Users.Get(ctx, "")
	if err != nil {
		fmt.Printf("error %v", err)
		return
	}
	fmt.Println("call succeeded")
}
