package config

import (
	"os"
	"time"
)

type Config struct {
	HTTPAddr           string
	DatabaseURL        string
	AdminLogin         string
	AdminEmail         string
	AdminPassword      string
	JWTSecret          string
	SSSecretKey        string
	NodeOfflineTimeout time.Duration
}

func Load() Config {
	jwtSecret := env("PANEL_JWT_SECRET", "dev-secret")
	return Config{
		HTTPAddr:           env("PANEL_HTTP_ADDR", ":8080"),
		DatabaseURL:        env("PANEL_DATABASE_URL", "postgres://gulpo:gulpo@localhost:5432/gulpo?sslmode=disable"),
		AdminLogin:         env("PANEL_ADMIN_LOGIN", "axalotctl"),
		AdminEmail:         env("PANEL_ADMIN_EMAIL", "axalotctl@local"),
		AdminPassword:      env("PANEL_ADMIN_PASSWORD", "Mars.Bmas.Bias.0"),
		JWTSecret:          jwtSecret,
		SSSecretKey:        env("PANEL_SS_SECRET_KEY", jwtSecret),
		NodeOfflineTimeout: duration("PANEL_NODE_OFFLINE_TIMEOUT", 60*time.Second),
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
	if parsed < time.Second {
		return fallback
	}
	return parsed
}
