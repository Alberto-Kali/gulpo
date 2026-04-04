package config

import (
	"os"
	"time"
)

type Config struct {
	PanelBaseURL    string
	EnrollToken     string
	NodeAPIKey      string
	AgentVersion    string
	SingboxVersion  string
	StateDir        string
	PollInterval    time.Duration
	HeartbeatEvery  time.Duration
}

func Load() Config {
	return Config{
		PanelBaseURL:   env("NODE_PANEL_BASE_URL", "http://localhost:8080"),
		EnrollToken:    env("NODE_ENROLL_TOKEN", ""),
		NodeAPIKey:     env("NODE_API_KEY", ""),
		AgentVersion:   env("NODE_AGENT_VERSION", "0.1.0"),
		SingboxVersion: env("NODE_SINGBOX_VERSION", "unknown"),
		StateDir:       env("NODE_STATE_DIR", "/var/lib/gulpo-node"),
		PollInterval:   duration("NODE_POLL_INTERVAL", 30*time.Second),
		HeartbeatEvery: duration("NODE_HEARTBEAT_EVERY", 15*time.Second),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func duration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

