package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/zitadel/oidc/v2/example/server/exampleop"
	"github.com/zitadel/oidc/v2/example/server/storage"
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

	router := exampleop.SetupServer(issuer, storage)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}
	log.Printf("server listening on http://localhost:%s/", port)
	log.Println("press ctrl+c to stop")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
