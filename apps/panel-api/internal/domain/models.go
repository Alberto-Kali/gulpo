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
	DefaultAccessPolicyNobody DefaultAccessPolicy = "nobody"
	DefaultAccessPolicyByTag  DefaultAccessPolicy = "tag"
	DefaultAccessPolicyOpen   DefaultAccessPolicy = "open"
)

type CommandType string

const (
	CommandApplyConfig      CommandType = "apply_config"
	CommandRestart          CommandType = "restart"
	CommandReload           CommandType = "reload"
	CommandDisable          CommandType = "disable"
	CommandRotateCredential CommandType = "rotate_credentials"
	CommandPing             CommandType = "ping"
)

type CommandStatus string

const (
	CommandStatusPending CommandStatus = "pending"
	CommandStatusDone    CommandStatus = "done"
	CommandStatusFailed  CommandStatus = "failed"
)

type NodeEventLevel string

const (
	NodeEventLevelInfo  NodeEventLevel = "info"
	NodeEventLevelWarn  NodeEventLevel = "warn"
	NodeEventLevelError NodeEventLevel = "error"
)

type NodeEventSource string

const (
	NodeEventSourcePanel NodeEventSource = "panel"
	NodeEventSourceAgent NodeEventSource = "agent"
)

type NodeEventType string

const (
	NodeEventTypeConnected         NodeEventType = "node_connected"
	NodeEventTypeDisconnected      NodeEventType = "node_disconnected"
	NodeEventTypeHeartbeatRestored NodeEventType = "node_heartbeat_restored"
	NodeEventTypeSingboxStarted    NodeEventType = "singbox_started"
	NodeEventTypeSingboxRestarted  NodeEventType = "singbox_restarted"
	NodeEventTypeSingboxReloaded   NodeEventType = "singbox_reloaded"
	NodeEventTypeConfigApplyFailed NodeEventType = "config_apply_failed"
	NodeEventTypeCommandFailed     NodeEventType = "command_failed"
)

type CertificateMode string

const (
	CertificateModeDisabled CertificateMode = "disabled"
	CertificateModeACME     CertificateMode = "acme"
	CertificateModeManual   CertificateMode = "manual"
)

type CertificateStatus string

const (
	CertificateStatusUnknown CertificateStatus = "unknown"
	CertificateStatusReady   CertificateStatus = "ready"
	CertificateStatusWarning CertificateStatus = "warning"
	CertificateStatusError   CertificateStatus = "error"
)

type ProtocolType string

const (
	ProtocolShadowsocks ProtocolType = "shadowsocks"
	ProtocolTrojan      ProtocolType = "trojan"
	ProtocolVLESS       ProtocolType = "vless"
	ProtocolHysteria2   ProtocolType = "hysteria2"
	ProtocolTUIC        ProtocolType = "tuic"
)

type Admin struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type User struct {
	ID                         string         `json:"id"`
	ExternalID                 *string        `json:"external_id,omitempty"`
	Name                       string         `json:"name"`
	Status                     UserStatus     `json:"status"`
	TrafficLimitBytes          int64          `json:"traffic_limit_bytes"`
	TrafficUsedBytes           int64          `json:"traffic_used_bytes"`
	SubscriptionToken          string         `json:"subscription_token"`
	NodeAccessMode             NodeAccessMode `json:"node_access_mode"`
	SubscriptionDeviceLimit    int            `json:"subscription_device_limit"`
	SSPasswordEncrypted        string         `json:"-"`
	TrojanPasswordEncrypted    string         `json:"-"`
	VLESSUUID                  string         `json:"-"`
	Hysteria2PasswordEncrypted string         `json:"-"`
	TUICUUID                   string         `json:"-"`
	TUICPasswordEncrypted      string         `json:"-"`
	Tags                       []Tag          `json:"tags,omitempty"`
	AllowedNodeIDs             []string       `json:"allowed_node_ids,omitempty"`
	IsOnline                   bool           `json:"is_online"`
	ActiveSessions             int            `json:"active_sessions"`
	CreatedAt                  time.Time      `json:"created_at"`
	UpdatedAt                  time.Time      `json:"updated_at"`
}

type Tag struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Node struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Domain              string              `json:"domain"`
	Port                int                 `json:"port"`
	Status              NodeStatus          `json:"status"`
	DefaultAccessPolicy DefaultAccessPolicy `json:"default_access_policy"`
	DefaultAccessTag    *string             `json:"default_access_tag,omitempty"`
	EnrollToken         string              `json:"-"`
	APIKey              string              `json:"-"`
	AgentVersion        string              `json:"agent_version"`
	SingboxVersion      string              `json:"singbox_version"`
	CertificateMode     CertificateMode     `json:"certificate_mode"`
	CertificateStatus   CertificateStatus   `json:"certificate_status"`
	CertificateMessage  string              `json:"certificate_message"`
	HostKind            string              `json:"host_kind,omitempty"`
	SupportedProtocols  []string            `json:"supported_protocols,omitempty"`
	LastSeenAt          *time.Time          `json:"last_seen_at,omitempty"`
	IsOnline            bool                `json:"is_online"`
	ActiveUsers         int                 `json:"active_users"`
	ConfigOverride      json.RawMessage     `json:"config_override,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type GlobalConfig struct {
	ID         string          `json:"id"`
	ConfigJSON json.RawMessage `json:"config_json"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type NodeCommand struct {
	ID        string          `json:"id"`
	NodeID    string          `json:"node_id"`
	Type      CommandType     `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Status    CommandStatus   `json:"status"`
	Result    *string         `json:"result,omitempty"`
	IssuedAt  time.Time       `json:"issued_at"`
	AppliedAt *time.Time      `json:"applied_at,omitempty"`
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
	NodeID string                 `json:"node_id"`
	Name   string                 `json:"name"`
	Domain string                 `json:"domain"`
	Config map[string]interface{} `json:"config"`
}

type ProfilePageResponse struct {
	UserName     string        `json:"user_name"`
	UserStatus   UserStatus    `json:"user_status"`
	Subscription string        `json:"subscription_token"`
	Profiles     []ProfileItem `json:"profiles"`
	Message      string        `json:"message,omitempty"`
}

type DashboardSummary struct {
	TotalUsers              int   `json:"total_users"`
	TotalTrafficUsedBytes   int64 `json:"total_traffic_used_bytes"`
	AverageNodeLoad24HBytes int64 `json:"average_node_load_24h_bytes"`
	OnlineUsers             int   `json:"online_users"`
	OnlineNodes             int   `json:"online_nodes"`
}

type UserNodeSessionPresence struct {
	UserID      string       `json:"user_id"`
	NodeID      string       `json:"node_id"`
	Protocol    ProtocolType `json:"protocol"`
	Connections int          `json:"connections"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type PresenceSummary struct {
	OnlineUsers int `json:"online_users"`
	OnlineNodes int `json:"online_nodes"`
}

type ProfileItem struct {
	NodeID         string     `json:"node_id"`
	Name           string     `json:"name"`
	Protocol       string     `json:"protocol"`
	Label          string     `json:"label"`
	TransportMode  string     `json:"transport_mode,omitempty"`
	Server         string     `json:"server"`
	Port           int        `json:"port"`
	Method         string     `json:"method,omitempty"`
	SNI            string     `json:"sni,omitempty"`
	ALPN           []string   `json:"alpn,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	Flow           string     `json:"flow,omitempty"`
	PublicKey      string     `json:"public_key,omitempty"`
	ShortID        string     `json:"short_id,omitempty"`
	Obfs           string     `json:"obfs,omitempty"`
	MaskHost       string     `json:"mask_host,omitempty"`
	UUID           string     `json:"uuid,omitempty"`
	ClientPassword string     `json:"client_password,omitempty"`
	PasswordMasked string     `json:"password_masked,omitempty"`
	URI            string     `json:"uri"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	Status         string     `json:"status"`
}

type EnrollResponse struct {
	NodeID        string         `json:"node_id"`
	NodeAPIKey    string         `json:"node_api_key"`
	DesiredConfig map[string]any `json:"desired_config"`
	Commands      []NodeCommand  `json:"commands"`
}

type NodeEvent struct {
	ID        string          `json:"id"`
	NodeID    string          `json:"node_id"`
	Level     NodeEventLevel  `json:"level"`
	Type      NodeEventType   `json:"type"`
	Message   string          `json:"message"`
	Source    NodeEventSource `json:"source"`
	CreatedAt time.Time       `json:"created_at"`
}

type UserNodeProtocolAccess struct {
	UserID   string       `json:"user_id"`
	NodeID   string       `json:"node_id"`
	Protocol ProtocolType `json:"protocol"`
	Enabled  bool         `json:"enabled"`
}

type SubscriptionDevice struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	DeviceKey        string     `json:"device_key"`
	DeviceIdentifier string     `json:"device_identifier,omitempty"`
	DeviceSource     string     `json:"device_source"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	LastClientIP     string     `json:"last_client_ip,omitempty"`
	LastUserAgent    string     `json:"last_user_agent,omitempty"`
	RequestCount     int64      `json:"request_count"`
	Blocked          bool       `json:"blocked"`
	BlockedAt        *time.Time `json:"blocked_at,omitempty"`
}

type SubscriptionRequestEvent struct {
	ID                 string          `json:"id"`
	UserID             string          `json:"user_id"`
	Endpoint           string          `json:"endpoint"`
	ClientIP           string          `json:"client_ip,omitempty"`
	UserAgent          string          `json:"user_agent,omitempty"`
	DeviceKey          string          `json:"device_key"`
	DeviceIdentifier   string          `json:"device_identifier,omitempty"`
	DeviceSource       string          `json:"device_source"`
	RequestFingerprint string          `json:"request_fingerprint"`
	QueryParams        json.RawMessage `json:"query_params,omitempty"`
	Headers            json.RawMessage `json:"headers,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
}
