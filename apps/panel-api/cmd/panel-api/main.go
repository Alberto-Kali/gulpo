package main

import (
	"context"
	"log"

	"github.com/fear/gulpo/apps/panel-api/internal/app"
	"github.com/fear/gulpo/apps/panel-api/internal/config"
)

func main() {
	cfg := config.Load()
	application, err := app.New(context.Background(), cfg)
	if err != nil {
		log.Fatalf("build app: %v", err)
	}

	log.Printf("panel-api listening on %s", cfg.HTTPAddr)
	if err := application.Run(); err != nil {
		log.Fatalf("run app: %v", err)
	}
}

