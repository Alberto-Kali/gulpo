package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type RuntimeState struct {
	NodeID              string                       `json:"node_id"`
	NodeAPIKey          string                       `json:"node_api_key"`
	DesiredConfig       map[string]any               `json:"desired_config"`
	LastAppliedConfig   map[string]any               `json:"last_applied_config"`
	LastKnownGood       map[string]any               `json:"last_known_good"`
	LastTrafficCounters map[string]UserTrafficSample `json:"last_traffic_counters"`
	PendingUsageRecords []PendingUsageRecord         `json:"pending_usage_records"`
}

type UserTrafficSample struct {
	UplinkBytes   int64 `json:"uplink_bytes"`
	DownlinkBytes int64 `json:"downlink_bytes"`
}

type PendingUsageRecord struct {
	UserID        string `json:"user_id"`
	UplinkBytes   int64  `json:"uplink_bytes"`
	DownlinkBytes int64  `json:"downlink_bytes"`
	CollectedAt   string `json:"collected_at"`
}

func Load(dir string) (RuntimeState, error) {
	path := filepath.Join(dir, "state.json")
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RuntimeState{}, nil
		}
		return RuntimeState{}, err
	}
	var st RuntimeState
	if err := json.Unmarshal(body, &st); err != nil {
		return RuntimeState{}, err
	}
	return st, nil
}

func Save(dir string, st RuntimeState) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "state.json"), body, 0o644)
}
