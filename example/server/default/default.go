package main

import (
	"context"
	"log"

	"github.com/caos/oidc/example/internal/mock"
	"github.com/caos/oidc/pkg/op"
)

func main() {
	ctx := context.Background()
	config := &op.Config{
		Issuer: "http://localhost:9998/",

		Port: "9998",
	}
	storage := mock.NewStorage()
	handler, err := op.NewDefaultOP(config, storage, op.WithCustomTokenEndpoint("test"))
	if err != nil {
		log.Fatal(err)
	}
	op.Start(ctx, handler)
	<-ctx.Done()

}
