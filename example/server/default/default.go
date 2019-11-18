package main

import (
	"context"

	"github.com/caos/oidc/example/internal/mock"
	"github.com/caos/oidc/pkg/server"
)

func main() {
	ctx := context.Background()
	config := &server.Config{
		Issuer: "test",
	}
	storage := &mock.Storage{}
	handler := server.NewDefaultHandler(config, storage)
	server.Start(ctx, handler)
}
