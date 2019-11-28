package main

import (
	"context"
	"log"

	"github.com/caos/oidc/example/internal/mock"
	server "github.com/caos/oidc/pkg/op"
)

func main() {
	ctx := context.Background()
	config := &server.Config{
		Issuer: "http://localhost:9998/",

		Port: "9998",
	}
	storage := &mock.Storage{}
	signer := &mock.Signer{}
	handler, err := server.NewDefaultOP(config, storage, signer, server.WithCustomTokenEndpoint("test"))
	if err != nil {
		log.Fatal(err)
	}
	server.Start(ctx, handler)
	<-ctx.Done()

}
