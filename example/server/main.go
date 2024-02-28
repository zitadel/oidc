package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/zitadel/oidc/v3/example/server/exampleop"
	"github.com/zitadel/oidc/v3/example/server/storage"
)

func main() {
	//we will run on :9998
	port := "9998"
	//which gives us the issuer: http://localhost:9998/
	issuer := fmt.Sprintf("http://localhost:%s/", port)

	// the OpenIDProvider interface needs a Storage interface handling various checks and state manipulations
	// this might be the layer for accessing your database
	// in this example it will be handled in-memory
	storage := storage.NewStorage(storage.NewUserStore(issuer))

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)
	router := exampleop.SetupServer(issuer, storage, logger, false)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}
	logger.Info("server listening, press ctrl+c to stop", "addr", fmt.Sprintf("http://localhost:%s/", port))
	err := server.ListenAndServe()
	if err != http.ErrServerClosed {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
