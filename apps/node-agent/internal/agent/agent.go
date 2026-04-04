package agent

import (
	"context"
	"log"
	"time"

	"github.com/fear/gulpo/apps/node-agent/internal/client"
	"github.com/fear/gulpo/apps/node-agent/internal/config"
	"github.com/fear/gulpo/apps/node-agent/internal/driver"
	"github.com/fear/gulpo/apps/node-agent/internal/state"
)

type Agent struct {
	cfg    config.Config
	client *client.Client
	driver driver.Driver
	state  state.RuntimeState
}

func New(cfg config.Config) (*Agent, error) {
	st, err := state.Load(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg:    cfg,
		client: client.New(cfg.PanelBaseURL),
		driver: driver.New(cfg.StateDir + "/sing-box.json"),
		state:  st,
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if a.state.NodeAPIKey == "" {
		if err := a.bootstrap(ctx); err != nil {
			return err
		}
	}

	heartbeatTicker := time.NewTicker(a.cfg.HeartbeatEvery)
	defer heartbeatTicker.Stop()
	syncTicker := time.NewTicker(a.cfg.PollInterval)
	defer syncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeatTicker.C:
			if err := a.client.Heartbeat(ctx, a.state.NodeAPIKey, a.cfg.AgentVersion, a.cfg.SingboxVersion); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}
		case <-syncTicker.C:
			if err := a.sync(ctx); err != nil {
				log.Printf("sync failed: %v", err)
			}
		}
	}
}

func (a *Agent) bootstrap(ctx context.Context) error {
	resp, err := a.client.Enroll(ctx, a.cfg.EnrollToken, a.cfg.AgentVersion, a.cfg.SingboxVersion)
	if err != nil {
		return err
	}
	a.state.NodeID = resp.NodeID
	a.state.NodeAPIKey = resp.NodeAPIKey
	a.state.DesiredConfig = resp.DesiredConfig
	if err := a.applyDesired(ctx); err != nil {
		return err
	}
	return state.Save(a.cfg.StateDir, a.state)
}

func (a *Agent) sync(ctx context.Context) error {
	resultPayloads := make([]map[string]any, 0)
	resp, err := a.client.Sync(ctx, a.state.NodeAPIKey, a.cfg.AgentVersion, a.cfg.SingboxVersion, resultPayloads)
	if err != nil {
		return err
	}
	a.state.DesiredConfig = resp.DesiredConfig
	commandResults := make([]map[string]any, 0, len(resp.Commands))
	for _, cmd := range resp.Commands {
		commandResults = append(commandResults, a.runCommand(ctx, cmd))
	}
	if err := a.applyDesired(ctx); err != nil {
		log.Printf("apply desired failed: %v", err)
	}
	a.state.DesiredConfig = resp.DesiredConfig
	if err := state.Save(a.cfg.StateDir, a.state); err != nil {
		return err
	}
	if len(commandResults) > 0 {
		_, err = a.client.Sync(ctx, a.state.NodeAPIKey, a.cfg.AgentVersion, a.cfg.SingboxVersion, commandResults)
	}
	return err
}

func (a *Agent) applyDesired(ctx context.Context) error {
	if a.state.DesiredConfig == nil {
		return nil
	}
	if err := a.driver.Validate(ctx, a.state.DesiredConfig); err != nil {
		if a.state.LastKnownGood != nil {
			_ = a.driver.Apply(ctx, a.state.LastKnownGood)
		}
		return err
	}
	if err := a.driver.Apply(ctx, a.state.DesiredConfig); err != nil {
		if a.state.LastKnownGood != nil {
			_ = a.driver.Apply(ctx, a.state.LastKnownGood)
		}
		return err
	}
	a.state.LastAppliedConfig = a.state.DesiredConfig
	a.state.LastKnownGood = a.state.DesiredConfig
	return nil
}

func (a *Agent) runCommand(ctx context.Context, cmd client.Command) map[string]any {
	result := map[string]any{
		"id": cmd.ID,
		"status": "done",
		"result": "ok",
	}
	var err error
	switch cmd.Type {
	case "restart":
		err = a.driver.Restart(ctx)
	case "reload", "apply_config":
		err = a.applyDesired(ctx)
	case "disable":
		err = a.driver.Restart(ctx)
	case "rotate_credentials", "ping":
	default:
		result["status"] = "failed"
		result["result"] = "unknown command"
		return result
	}
	if err != nil {
		result["status"] = "failed"
		result["result"] = err.Error()
	}
	return result
}

