package main

import (
	"context"
	"log"

	"github.com/fear/gulpo/apps/node-agent/internal/agent"
	"github.com/fear/gulpo/apps/node-agent/internal/config"
)

func main() {
	cfg := config.Load()
	a, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("build agent: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		log.Fatalf("run agent: %v", err)
	}
}

