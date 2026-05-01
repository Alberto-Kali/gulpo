package agent

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fear/gulpo/apps/node-agent/internal/client"
	"github.com/fear/gulpo/apps/node-agent/internal/config"
	"github.com/fear/gulpo/apps/node-agent/internal/driver"
	"github.com/fear/gulpo/apps/node-agent/internal/runtimeapi"
	"github.com/fear/gulpo/apps/node-agent/internal/state"
)

type Agent struct {
	cfg                    config.Config
	client                 *client.Client
	driver                 driver.Driver
	runtime                *runtimeapi.Client
	state                  state.RuntimeState
	hadConnectivityFailure bool
}

func New(cfg config.Config) (*Agent, error) {
	st, err := state.Load(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg:     cfg,
		client:  client.New(cfg.PanelBaseURL),
		driver:  driver.New(cfg.StateDir + "/sing-box.json"),
		runtime: runtimeapi.New(cfg.V2RayAPIListen, cfg.ClashAPIURL),
		state:   st,
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if a.state.NodeAPIKey == "" {
		if err := a.bootstrap(ctx); err != nil {
			return err
		}
	}
	if err := a.applyDesired(ctx); err != nil {
		log.Printf("initial desired config apply failed: %v", err)
	}

	heartbeatTicker := time.NewTicker(a.cfg.HeartbeatEvery)
	defer heartbeatTicker.Stop()
	syncTicker := time.NewTicker(a.cfg.PollInterval)
	defer syncTicker.Stop()
	telemetryTicker := time.NewTicker(a.cfg.TelemetryEvery)
	defer telemetryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeatTicker.C:
			if err := a.client.Heartbeat(ctx, a.state.NodeAPIKey, a.cfg.AgentVersion, a.cfg.SingboxVersion); err != nil {
				a.hadConnectivityFailure = true
				log.Printf("heartbeat failed: %v", err)
			} else if a.hadConnectivityFailure {
				a.reportEvents(ctx, []client.NodeEvent{{
					Level:   "info",
					Type:    "node_heartbeat_restored",
					Message: "Connectivity to panel restored after heartbeat failure.",
					Source:  "agent",
				}})
				a.hadConnectivityFailure = false
			}
		case <-syncTicker.C:
			if err := a.sync(ctx); err != nil {
				a.hadConnectivityFailure = true
				log.Printf("sync failed: %v", err)
			}
		case <-telemetryTicker.C:
			if err := a.collectTelemetry(ctx); err != nil {
				log.Printf("telemetry collection failed: %v", err)
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
		a.reportEvents(ctx, []client.NodeEvent{{
			Level:   "error",
			Type:    "config_apply_failed",
			Message: err.Error(),
			Source:  "agent",
		}})
		return err
	}
	a.reportEvents(ctx, []client.NodeEvent{
		{
			Level:   "info",
			Type:    "node_connected",
			Message: "Node enrolled and connected to panel.",
			Source:  "agent",
		},
		{
			Level:   "info",
			Type:    "singbox_started",
			Message: "sing-box started successfully after bootstrap.",
			Source:  "agent",
		},
	})
	_ = a.collectTelemetry(ctx)
	return state.Save(a.cfg.StateDir, a.state)
}

func (a *Agent) sync(ctx context.Context) error {
	resultPayloads := make([]map[string]any, 0)
	resp, err := a.client.Sync(ctx, a.state.NodeAPIKey, a.cfg.AgentVersion, a.cfg.SingboxVersion, resultPayloads)
	if err != nil {
		return err
	}
	if a.hadConnectivityFailure {
		a.reportEvents(ctx, []client.NodeEvent{{
			Level:   "info",
			Type:    "node_heartbeat_restored",
			Message: "Connectivity to panel restored after sync failure.",
			Source:  "agent",
		}})
		a.hadConnectivityFailure = false
	}
	normalizedDesired := a.normalizeDesiredConfig(resp.DesiredConfig)
	configChanged := !configsEqual(a.state.LastAppliedConfig, normalizedDesired)
	a.state.DesiredConfig = resp.DesiredConfig
	commandResults := make([]map[string]any, 0, len(resp.Commands))
	for _, cmd := range resp.Commands {
		commandResults = append(commandResults, a.runCommand(ctx, cmd))
	}
	if configChanged {
		if err := a.applyDesired(ctx); err != nil {
			a.reportEvents(ctx, []client.NodeEvent{{
				Level:   "error",
				Type:    "config_apply_failed",
				Message: err.Error(),
				Source:  "agent",
			}})
			log.Printf("apply desired failed: %v", err)
		} else {
			a.reportEvents(ctx, []client.NodeEvent{{
				Level:   "info",
				Type:    "singbox_reloaded",
				Message: "Desired config applied successfully.",
				Source:  "agent",
			}})
		}
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
	resolved := a.normalizeDesiredConfig(a.state.DesiredConfig)
	if configsEqual(a.state.LastAppliedConfig, resolved) {
		return a.driver.EnsureRunning(ctx, resolved)
	}
	if err := a.driver.Validate(ctx, resolved); err != nil {
		if a.state.LastKnownGood != nil {
			_ = a.driver.Apply(ctx, a.state.LastKnownGood)
		}
		return err
	}
	if err := a.driver.Apply(ctx, resolved); err != nil {
		if a.state.LastKnownGood != nil {
			_ = a.driver.Apply(ctx, a.state.LastKnownGood)
		}
		return err
	}
	a.state.LastAppliedConfig = resolved
	a.state.LastKnownGood = resolved
	return nil
}

func (a *Agent) applyDesiredWithReporting(ctx context.Context) error {
	if err := a.applyDesired(ctx); err != nil {
		a.reportEvents(ctx, []client.NodeEvent{{
			Level:   "error",
			Type:    "config_apply_failed",
			Message: err.Error(),
			Source:  "agent",
		}})
		return err
	}
	return nil
}

func (a *Agent) collectTelemetry(ctx context.Context) error {
	if a.state.NodeAPIKey == "" {
		return nil
	}
	if err := a.flushPendingUsage(ctx); err != nil {
		log.Printf("pending usage flush failed: %v", err)
	}
	trafficCtx, cancelTraffic := context.WithTimeout(ctx, 8*time.Second)
	traffic, trafficErr := a.runtime.FetchTrafficCounters(trafficCtx)
	cancelTraffic()
	var trafficActiveUsers []string
	if trafficErr == nil {
		var err error
		trafficActiveUsers, err = a.handleTrafficSnapshot(ctx, traffic)
		if err != nil {
			log.Printf("traffic snapshot handling failed: %v", err)
		}
	} else {
		log.Printf("traffic counters fetch failed: %v", trafficErr)
	}
	sessionCtx, cancelSessions := context.WithTimeout(ctx, 8*time.Second)
	sessions, sessionsErr := a.runtime.FetchSessionSnapshot(sessionCtx)
	cancelSessions()
	if sessionsErr != nil {
		return sessionsErr
	}
	if len(sessions) == 0 && len(trafficActiveUsers) > 0 {
		sessions = trafficPresenceSnapshot(trafficActiveUsers)
	}
	if len(sessions) == 0 {
		return nil
	}
	return a.pushSessionSnapshot(ctx, sessions)
}

func (a *Agent) handleTrafficSnapshot(ctx context.Context, snapshot map[string]runtimeapi.UserTrafficSample) ([]string, error) {
	if a.state.LastTrafficCounters == nil {
		a.state.LastTrafficCounters = map[string]state.UserTrafficSample{}
	}
	records := make([]client.UsageRecord, 0, len(snapshot))
	activeUsers := make([]string, 0, len(snapshot))
	collectedAt := time.Now().UTC().Format(time.RFC3339)
	for userID, current := range snapshot {
		previous := a.state.LastTrafficCounters[userID]
		uplinkDelta := current.UplinkBytes - previous.UplinkBytes
		downlinkDelta := current.DownlinkBytes - previous.DownlinkBytes
		if uplinkDelta < 0 {
			uplinkDelta = current.UplinkBytes
		}
		if downlinkDelta < 0 {
			downlinkDelta = current.DownlinkBytes
		}
		if uplinkDelta > 0 || downlinkDelta > 0 {
			records = append(records, client.UsageRecord{
				UserID:        userID,
				UplinkBytes:   uplinkDelta,
				DownlinkBytes: downlinkDelta,
				CollectedAt:   collectedAt,
			})
			activeUsers = append(activeUsers, userID)
		}
		a.state.LastTrafficCounters[userID] = state.UserTrafficSample{
			UplinkBytes:   current.UplinkBytes,
			DownlinkBytes: current.DownlinkBytes,
		}
	}
	for userID := range a.state.LastTrafficCounters {
		if _, ok := snapshot[userID]; !ok {
			delete(a.state.LastTrafficCounters, userID)
		}
	}
	for _, record := range records {
		a.state.PendingUsageRecords = append(a.state.PendingUsageRecords, state.PendingUsageRecord(record))
	}
	if err := state.Save(a.cfg.StateDir, a.state); err != nil {
		return activeUsers, err
	}
	return activeUsers, a.flushPendingUsage(ctx)
}

func (a *Agent) flushPendingUsage(ctx context.Context) error {
	if a.state.NodeAPIKey == "" || len(a.state.PendingUsageRecords) == 0 {
		return nil
	}
	batch := make([]client.UsageRecord, 0, len(a.state.PendingUsageRecords))
	for _, record := range a.state.PendingUsageRecords {
		batch = append(batch, client.UsageRecord{
			UserID:        record.UserID,
			UplinkBytes:   record.UplinkBytes,
			DownlinkBytes: record.DownlinkBytes,
			CollectedAt:   record.CollectedAt,
		})
	}
	if err := a.client.UsageBatch(ctx, a.state.NodeAPIKey, batch); err != nil {
		return err
	}
	a.state.PendingUsageRecords = nil
	return state.Save(a.cfg.StateDir, a.state)
}

func (a *Agent) pushSessionSnapshot(ctx context.Context, snapshot []runtimeapi.SessionPresence) error {
	payload := make([]client.SessionPresence, 0, len(snapshot))
	for _, session := range snapshot {
		if session.UserID == "" || session.Protocol == "" || session.Connections <= 0 {
			continue
		}
		payload = append(payload, client.SessionPresence{
			UserID:      session.UserID,
			Protocol:    session.Protocol,
			Connections: session.Connections,
		})
	}
	return a.client.SessionsSnapshot(ctx, a.state.NodeAPIKey, payload)
}

func trafficPresenceSnapshot(userIDs []string) []runtimeapi.SessionPresence {
	seen := map[string]bool{}
	snapshot := make([]runtimeapi.SessionPresence, 0, len(userIDs))
	for _, userID := range userIDs {
		if userID == "" || seen[userID] {
			continue
		}
		seen[userID] = true
		snapshot = append(snapshot, runtimeapi.SessionPresence{
			UserID:      userID,
			Protocol:    "traffic",
			Connections: 1,
		})
	}
	return snapshot
}

func (a *Agent) normalizeDesiredConfig(cfg map[string]any) map[string]any {
	cloned := cloneMap(cfg)
	if a.cfg.V2RayAPIListen != "" || a.cfg.ClashAPIURL != "" {
		experimental, _ := cloned["experimental"].(map[string]any)
		if experimental == nil {
			experimental = map[string]any{}
			cloned["experimental"] = experimental
		}
		if a.cfg.V2RayAPIListen != "" {
			if _, ok := experimental["v2ray_api"]; !ok {
				experimental["v2ray_api"] = map[string]any{
					"listen": a.cfg.V2RayAPIListen,
					"stats": map[string]any{
						"enabled": true,
						"users":   collectRuntimeUsers(cloned),
					},
				}
			}
		}
		if a.cfg.ClashAPIURL != "" {
			if _, ok := experimental["clash_api"]; !ok {
				externalController := a.cfg.ClashAPIURL
				externalController = strings.TrimPrefix(externalController, "http://")
				externalController = strings.TrimPrefix(externalController, "https://")
				experimental["clash_api"] = map[string]any{
					"external_controller": externalController,
				}
			}
		}
	}
	rawInbounds, ok := cloned["inbounds"].([]any)
	if !ok {
		return cloned
	}
	acmeDir := filepath.Join(a.cfg.StateDir, "acme")
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tlsConfig, ok := inbound["tls"].(map[string]any)
		if !ok {
			continue
		}
		acmeConfig, ok := tlsConfig["acme"].(map[string]any)
		if !ok {
			continue
		}
		if asString(acmeConfig["data_directory"]) == "__GULPO_ACME_DATA_DIR__" || asString(acmeConfig["data_directory"]) == "" {
			acmeConfig["data_directory"] = acmeDir
		}
	}
	_ = os.MkdirAll(acmeDir, 0o755)
	return cloned
}

func collectRuntimeUsers(cfg map[string]any) []string {
	rawInbounds, ok := cfg["inbounds"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	users := make([]string, 0)
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		rawUsers, ok := inbound["users"].([]any)
		if !ok {
			continue
		}
		for _, rawUser := range rawUsers {
			user, ok := rawUser.(map[string]any)
			if !ok {
				continue
			}
			name := asString(user["name"])
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			users = append(users, name)
		}
	}
	return users
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for key, value := range src {
		switch nested := value.(type) {
		case map[string]any:
			out[key] = cloneMap(nested)
		case []any:
			copied := make([]any, len(nested))
			for i, item := range nested {
				if nestedMap, ok := item.(map[string]any); ok {
					copied[i] = cloneMap(nestedMap)
				} else {
					copied[i] = item
				}
			}
			out[key] = copied
		default:
			out[key] = value
		}
	}
	return out
}

func asString(value any) string {
	typed, _ := value.(string)
	return typed
}

func (a *Agent) runCommand(ctx context.Context, cmd client.Command) map[string]any {
	result := map[string]any{
		"id":     cmd.ID,
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
		a.reportEvents(ctx, []client.NodeEvent{{
			Level:   "error",
			Type:    "command_failed",
			Message: cmd.Type + ": " + err.Error(),
			Source:  "agent",
		}})
		result["status"] = "failed"
		result["result"] = err.Error()
	} else {
		switch cmd.Type {
		case "restart":
			a.reportEvents(ctx, []client.NodeEvent{{
				Level:   "info",
				Type:    "singbox_restarted",
				Message: "sing-box restarted successfully.",
				Source:  "agent",
			}})
		case "reload", "apply_config":
			a.reportEvents(ctx, []client.NodeEvent{{
				Level:   "info",
				Type:    "singbox_reloaded",
				Message: "sing-box reloaded successfully.",
				Source:  "agent",
			}})
		}
	}
	return result
}

func (a *Agent) reportEvents(ctx context.Context, events []client.NodeEvent) {
	if a.state.NodeAPIKey == "" || len(events) == 0 {
		return
	}
	if err := a.client.EventsBatch(ctx, a.state.NodeAPIKey, events); err != nil {
		log.Printf("events batch failed: %v", err)
	}
}

func configsEqual(left, right map[string]any) bool {
	if left == nil && right == nil {
		return true
	}
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return string(leftJSON) == string(rightJSON)
}
