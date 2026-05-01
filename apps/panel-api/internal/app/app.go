package app

import (
	"context"
	"net/http"

	"github.com/fear/gulpo/apps/panel-api/internal/config"
	"github.com/fear/gulpo/apps/panel-api/internal/handlers"
	"github.com/fear/gulpo/apps/panel-api/internal/store"
)

type App struct {
	cfg    config.Config
	server *http.Server
	store  *store.PostgresStore
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.SSSecretKey)
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		return nil, err
	}
	if err := st.SeedAdmin(ctx, cfg.AdminLogin, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		return nil, err
	}
	handler := handlers.New(cfg, st)
	return &App{
		cfg:   cfg,
		store: st,
		server: &http.Server{
			Addr:    cfg.HTTPAddr,
			Handler: handler,
		},
	}, nil
}

func (a *App) Run() error {
	defer a.store.Close()
	return a.server.ListenAndServe()
}
