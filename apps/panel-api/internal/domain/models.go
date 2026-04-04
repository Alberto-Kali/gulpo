package domain

import (
	"encoding/json"
	"time"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusExpired  UserStatus = "expired"
)

type NodeStatus string

const (
	NodeStatusPending  NodeStatus = "pending"
	NodeStatusOnline   NodeStatus = "online"
	NodeStatusOffline  NodeStatus = "offline"
	NodeStatusDisabled NodeStatus = "disabled"
)

type NodeAccessMode string

const (
	NodeAccessModeTags     NodeAccessMode = "tags"
	NodeAccessModeExplicit NodeAccessMode = "explicit"
)

type DefaultAccessPolicy string

const (
	DefaultAccessPolicyNobody  DefaultAccessPolicy = "nobody"
	DefaultAccessPolicyByTag   DefaultAccessPolicy = "tag"
	DefaultAccessPolicyOpen    DefaultAccessPolicy = "open"
)

type CommandType string

const (
	CommandApplyConfig       CommandType = "apply_config"
	CommandRestart           CommandType = "restart"
	CommandReload            CommandType = "reload"
	CommandDisable           CommandType = "disable"
	CommandRotateCredential  CommandType = "rotate_credentials"
	CommandPing              CommandType = "ping"
)

type CommandStatus string

const (
	CommandStatusPending CommandStatus = "pending"
	CommandStatusDone    CommandStatus = "done"
	CommandStatusFailed  CommandStatus = "failed"
)

type Admin struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	PasswordHash   string    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
}

type User struct {
	ID                 string         `json:"id"`
	ExternalID         *string        `json:"external_id,omitempty"`
	Name               string         `json:"name"`
	Status             UserStatus     `json:"status"`
	TrafficLimitBytes  int64          `json:"traffic_limit_bytes"`
	TrafficUsedBytes   int64          `json:"traffic_used_bytes"`
	SubscriptionToken  string         `json:"subscription_token"`
	NodeAccessMode     NodeAccessMode `json:"node_access_mode"`
	Tags               []Tag          `json:"tags,omitempty"`
	AllowedNodeIDs     []string       `json:"allowed_node_ids,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type Tag struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Node struct {
	ID                    string              `json:"id"`
	Name                  string              `json:"name"`
	Domain                string              `json:"domain"`
	Status                NodeStatus          `json:"status"`
	DefaultAccessPolicy   DefaultAccessPolicy `json:"default_access_policy"`
	DefaultAccessTag      *string             `json:"default_access_tag,omitempty"`
	EnrollToken           string              `json:"-"`
	APIKey                string              `json:"-"`
	AgentVersion          string              `json:"agent_version"`
	SingboxVersion        string              `json:"singbox_version"`
	LastSeenAt            *time.Time          `json:"last_seen_at,omitempty"`
	ConfigOverride        json.RawMessage     `json:"config_override,omitempty"`
	CreatedAt             time.Time           `json:"created_at"`
	UpdatedAt             time.Time           `json:"updated_at"`
}

type GlobalConfig struct {
	ID          string    `json:"id"`
	ConfigJSON  json.RawMessage `json:"config_json"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type NodeCommand struct {
	ID         string        `json:"id"`
	NodeID     string        `json:"node_id"`
	Type       CommandType   `json:"type"`
	Payload    json.RawMessage `json:"payload"`
	Status     CommandStatus `json:"status"`
	Result     *string       `json:"result,omitempty"`
	IssuedAt   time.Time     `json:"issued_at"`
	AppliedAt  *time.Time    `json:"applied_at,omitempty"`
}

type UsageRecord struct {
	ID            string    `json:"id"`
	NodeID        string    `json:"node_id"`
	UserID        string    `json:"user_id"`
	UplinkBytes   int64     `json:"uplink_bytes"`
	DownlinkBytes int64     `json:"downlink_bytes"`
	CollectedAt   time.Time `json:"collected_at"`
}

type SubscriptionEnvelope struct {
	Version string                 `json:"version"`
	Nodes   []SubscriptionNode     `json:"nodes"`
	Meta    map[string]interface{} `json:"meta"`
}

type SubscriptionNode struct {
	NodeID  string                 `json:"node_id"`
	Name    string                 `json:"name"`
	Domain  string                 `json:"domain"`
	Config  map[string]interface{} `json:"config"`
}

type EnrollResponse struct {
	NodeID         string          `json:"node_id"`
	NodeAPIKey     string          `json:"node_api_key"`
	DesiredConfig  map[string]any  `json:"desired_config"`
	Commands       []NodeCommand   `json:"commands"`
}
