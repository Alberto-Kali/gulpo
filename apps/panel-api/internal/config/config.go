package config

import "os"

type Config struct {
	HTTPAddr      string
	DatabaseURL   string
	AdminEmail    string
	AdminPassword string
	JWTSecret     string
}

func Load() Config {
	return Config{
		HTTPAddr:      env("PANEL_HTTP_ADDR", ":8080"),
		DatabaseURL:   env("PANEL_DATABASE_URL", "postgres://gulpo:gulpo@localhost:5432/gulpo?sslmode=disable"),
		AdminEmail:    env("PANEL_ADMIN_EMAIL", "admin@example.com"),
		AdminPassword: env("PANEL_ADMIN_PASSWORD", "change-me"),
		JWTSecret:     env("PANEL_JWT_SECRET", "dev-secret"),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

