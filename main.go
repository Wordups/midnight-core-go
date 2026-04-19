package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Wordups/midnight-core-go/internal/server"
)

func main() {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		log.Fatal("ANTHROPIC_API_KEY is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := server.New(apiKey)
	log.Printf("midnight-core-go listening on :%s", port)
	if err := http.ListenAndServe(":"+port, srv); err != nil {
		log.Fatal(err)
	}
}
