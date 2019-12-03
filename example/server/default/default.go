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
	authStorage := mock.NewAuthStorage()
	opStorage := &mock.OPStorage{}
	handler, err := op.NewDefaultOP(config, authStorage, opStorage, op.WithCustomTokenEndpoint("test"))
	if err != nil {
		log.Fatal(err)
	}
	op.Start(ctx, handler)
	<-ctx.Done()

}
