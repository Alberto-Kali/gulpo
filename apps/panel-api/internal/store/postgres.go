package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/fear/gulpo/apps/panel-api/internal/auth"
	"github.com/fear/gulpo/apps/panel-api/internal/domain"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db *sql.DB
}

func Open(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *PostgresStore) SeedAdmin(ctx context.Context, email, password string) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx, `select exists(select 1 from admins where email = $1)`, email).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		insert into admins (id, email, password_hash, created_at)
		values ($1, $2, $3, now())`,
		uuid.NewString(), email, auth.HashPassword(password),
	)
	return err
}

func (s *PostgresStore) GetAdminByEmail(ctx context.Context, email string) (domain.Admin, error) {
	row := s.db.QueryRowContext(ctx, `select id, email, password_hash, created_at from admins where email = $1`, email)
	var admin domain.Admin
	err := row.Scan(&admin.ID, &admin.Email, &admin.PasswordHash, &admin.CreatedAt)
	return admin, err
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		select id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, created_at, updated_at
		from users
		order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var user domain.User
		if err := rows.Scan(&user.ID, &user.ExternalID, &user.Name, &user.Status, &user.TrafficLimitBytes, &user.TrafficUsedBytes, &user.SubscriptionToken, &user.NodeAccessMode, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		tags, _ := s.ListUserTags(ctx, user.ID)
		user.Tags = tags
		user.AllowedNodeIDs, _ = s.ListUserAllowedNodes(ctx, user.ID)
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *PostgresStore) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.SubscriptionToken == "" {
		token, err := auth.RandomToken(24)
		if err != nil {
			return domain.User{}, err
		}
		user.SubscriptionToken = token
	}
	err := s.db.QueryRowContext(ctx, `
		insert into users (id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, created_at, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		returning created_at, updated_at`,
		user.ID, user.ExternalID, user.Name, user.Status, user.TrafficLimitBytes, user.TrafficUsedBytes, user.SubscriptionToken, user.NodeAccessMode,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func (s *PostgresStore) UpdateUser(ctx context.Context, id string, user domain.User) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		update users
		set external_id = $2, name = $3, status = $4, traffic_limit_bytes = $5, node_access_mode = $6, updated_at = now()
		where id = $1
		returning id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, created_at, updated_at`,
		id, user.ExternalID, user.Name, user.Status, user.TrafficLimitBytes, user.NodeAccessMode,
	)
	var out domain.User
	err := row.Scan(&out.ID, &out.ExternalID, &out.Name, &out.Status, &out.TrafficLimitBytes, &out.TrafficUsedBytes, &out.SubscriptionToken, &out.NodeAccessMode, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return domain.User{}, err
	}
	out.Tags, _ = s.ListUserTags(ctx, out.ID)
	out.AllowedNodeIDs, _ = s.ListUserAllowedNodes(ctx, out.ID)
	return out, nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `delete from users where id = $1`, id)
	return err
}

func (s *PostgresStore) GetUserBySubscriptionToken(ctx context.Context, token string) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		select id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, created_at, updated_at
		from users where subscription_token = $1`, token)
	var user domain.User
	err := row.Scan(&user.ID, &user.ExternalID, &user.Name, &user.Status, &user.TrafficLimitBytes, &user.TrafficUsedBytes, &user.SubscriptionToken, &user.NodeAccessMode, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return domain.User{}, err
	}
	user.Tags, _ = s.ListUserTags(ctx, user.ID)
	user.AllowedNodeIDs, _ = s.ListUserAllowedNodes(ctx, user.ID)
	return user, nil
}

func (s *PostgresStore) RotateSubscriptionToken(ctx context.Context, userID string) (string, error) {
	token, err := auth.RandomToken(24)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `update users set subscription_token = $2, updated_at = now() where id = $1`, userID, token)
	return token, err
}

func (s *PostgresStore) ListUserTags(ctx context.Context, userID string) ([]domain.Tag, error) {
	rows, err := s.db.QueryContext(ctx, `
		select t.id, t.name, t.created_at
		from tags t
		join user_tags ut on ut.tag_id = t.id
		where ut.user_id = $1
		order by t.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []domain.Tag
	for rows.Next() {
		var tag domain.Tag
		if err := rows.Scan(&tag.ID, &tag.Name, &tag.CreatedAt); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, rows.Err()
}

func (s *PostgresStore) AttachTagsToUser(ctx context.Context, userID string, tagNames []string) ([]domain.Tag, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `delete from user_tags where user_id = $1`, userID); err != nil {
		return nil, err
	}
	var tags []domain.Tag
	for _, name := range tagNames {
		var tag domain.Tag
		err := tx.QueryRowContext(ctx, `
			insert into tags (id, name, created_at)
			values ($1, $2, now())
			on conflict (name) do update set name = excluded.name
			returning id, name, created_at`,
			uuid.NewString(), name,
		).Scan(&tag.ID, &tag.Name, &tag.CreatedAt)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `insert into user_tags (user_id, tag_id) values ($1, $2) on conflict do nothing`, userID, tag.ID); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return tags, nil
}

func (s *PostgresStore) ReplaceAllowedNodes(ctx context.Context, userID string, nodeIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `delete from user_node_access where user_id = $1`, userID); err != nil {
		return err
	}
	for _, nodeID := range nodeIDs {
		if _, err := tx.ExecContext(ctx, `insert into user_node_access (user_id, node_id) values ($1, $2)`, userID, nodeID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ListUserAllowedNodes(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `select node_id from user_node_access where user_id = $1 order by node_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodeIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		nodeIDs = append(nodeIDs, id)
	}
	return nodeIDs, rows.Err()
}

func (s *PostgresStore) ListNodes(ctx context.Context) ([]domain.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		select id, name, domain, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, last_seen_at, config_override, created_at, updated_at
		from nodes order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []domain.Node
	for rows.Next() {
		var node domain.Node
		if err := rows.Scan(&node.ID, &node.Name, &node.Domain, &node.Status, &node.DefaultAccessPolicy, &node.DefaultAccessTag, &node.EnrollToken, &node.APIKey, &node.AgentVersion, &node.SingboxVersion, &node.LastSeenAt, &node.ConfigOverride, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *PostgresStore) CreateNode(ctx context.Context, node domain.Node) (domain.Node, error) {
	if node.ID == "" {
		node.ID = uuid.NewString()
	}
	if node.EnrollToken == "" {
		token, err := auth.RandomToken(24)
		if err != nil {
			return domain.Node{}, err
		}
		node.EnrollToken = token
	}
	if node.APIKey == "" {
		key, err := auth.RandomToken(24)
		if err != nil {
			return domain.Node{}, err
		}
		node.APIKey = key
	}
	err := s.db.QueryRowContext(ctx, `
		insert into nodes (id, name, domain, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, config_override, created_at, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),now())
		returning created_at, updated_at`,
		node.ID, node.Name, node.Domain, node.Status, node.DefaultAccessPolicy, node.DefaultAccessTag, node.EnrollToken, node.APIKey, node.AgentVersion, node.SingboxVersion, node.ConfigOverride,
	).Scan(&node.CreatedAt, &node.UpdatedAt)
	return node, err
}

func (s *PostgresStore) UpdateNode(ctx context.Context, id string, node domain.Node) (domain.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		update nodes set name = $2, domain = $3, status = $4, default_access_policy = $5, default_access_tag = $6, agent_version = $7, singbox_version = $8, updated_at = now()
		where id = $1
		returning id, name, domain, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, last_seen_at, config_override, created_at, updated_at`,
		id, node.Name, node.Domain, node.Status, node.DefaultAccessPolicy, node.DefaultAccessTag, node.AgentVersion, node.SingboxVersion,
	)
	var out domain.Node
	err := row.Scan(&out.ID, &out.Name, &out.Domain, &out.Status, &out.DefaultAccessPolicy, &out.DefaultAccessTag, &out.EnrollToken, &out.APIKey, &out.AgentVersion, &out.SingboxVersion, &out.LastSeenAt, &out.ConfigOverride, &out.CreatedAt, &out.UpdatedAt)
	return out, err
}

func (s *PostgresStore) DeleteNode(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `delete from nodes where id = $1`, id)
	return err
}

func (s *PostgresStore) RotateEnrollToken(ctx context.Context, nodeID string) (string, error) {
	token, err := auth.RandomToken(24)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `update nodes set enroll_token = $2, updated_at = now() where id = $1`, nodeID, token)
	return token, err
}

func (s *PostgresStore) GetGlobalConfig(ctx context.Context) (domain.GlobalConfig, error) {
	row := s.db.QueryRowContext(ctx, `select id, config_json, updated_at from global_config limit 1`)
	var cfg domain.GlobalConfig
	err := row.Scan(&cfg.ID, &cfg.ConfigJSON, &cfg.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		cfg = domain.GlobalConfig{ID: uuid.NewString(), ConfigJSON: []byte(`{"inbounds":[],"outbounds":[]}`)}
		_, insertErr := s.db.ExecContext(ctx, `insert into global_config (id, config_json, updated_at) values ($1, $2, now())`, cfg.ID, cfg.ConfigJSON)
		return cfg, insertErr
	}
	return cfg, err
}

func (s *PostgresStore) UpdateGlobalConfig(ctx context.Context, data []byte) (domain.GlobalConfig, error) {
	cfg, err := s.GetGlobalConfig(ctx)
	if err != nil {
		return domain.GlobalConfig{}, err
	}
	_, err = s.db.ExecContext(ctx, `update global_config set config_json = $2, updated_at = now() where id = $1`, cfg.ID, data)
	if err != nil {
		return domain.GlobalConfig{}, err
	}
	cfg.ConfigJSON = data
	cfg.UpdatedAt = time.Now()
	return cfg, nil
}

func (s *PostgresStore) GetNodeConfig(ctx context.Context, nodeID string) ([]byte, error) {
	var cfg []byte
	err := s.db.QueryRowContext(ctx, `select config_override from nodes where id = $1`, nodeID).Scan(&cfg)
	return cfg, err
}

func (s *PostgresStore) UpdateNodeConfig(ctx context.Context, nodeID string, data []byte) error {
	_, err := s.db.ExecContext(ctx, `update nodes set config_override = $2, updated_at = now() where id = $1`, nodeID, data)
	return err
}

func (s *PostgresStore) CreateNodeCommand(ctx context.Context, cmd domain.NodeCommand) (domain.NodeCommand, error) {
	if cmd.ID == "" {
		cmd.ID = uuid.NewString()
	}
	err := s.db.QueryRowContext(ctx, `
		insert into node_commands (id, node_id, type, payload, status, result, issued_at)
		values ($1,$2,$3,$4,$5,$6,now())
		returning issued_at`,
		cmd.ID, cmd.NodeID, cmd.Type, cmd.Payload, domain.CommandStatusPending, cmd.Result,
	).Scan(&cmd.IssuedAt)
	cmd.Status = domain.CommandStatusPending
	return cmd, err
}

func (s *PostgresStore) ListPendingNodeCommands(ctx context.Context, nodeID string) ([]domain.NodeCommand, error) {
	rows, err := s.db.QueryContext(ctx, `
		select id, node_id, type, payload, status, result, issued_at, applied_at
		from node_commands
		where node_id = $1 and status = 'pending'
		order by issued_at`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var commands []domain.NodeCommand
	for rows.Next() {
		var cmd domain.NodeCommand
		if err := rows.Scan(&cmd.ID, &cmd.NodeID, &cmd.Type, &cmd.Payload, &cmd.Status, &cmd.Result, &cmd.IssuedAt, &cmd.AppliedAt); err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}
	return commands, rows.Err()
}

func (s *PostgresStore) CompleteNodeCommand(ctx context.Context, id string, status domain.CommandStatus, result string) error {
	_, err := s.db.ExecContext(ctx, `update node_commands set status = $2, result = $3, applied_at = now() where id = $1`, id, status, result)
	return err
}

func (s *PostgresStore) EnrollNode(ctx context.Context, enrollToken, agentVersion, singboxVersion string) (domain.Node, error) {
	var node domain.Node
	row := s.db.QueryRowContext(ctx, `
		update nodes
		set agent_version = $2, singbox_version = $3, status = 'online', last_seen_at = now(), updated_at = now()
		where enroll_token = $1
		returning id, name, domain, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, last_seen_at, config_override, created_at, updated_at`,
		enrollToken, agentVersion, singboxVersion,
	)
	err := row.Scan(&node.ID, &node.Name, &node.Domain, &node.Status, &node.DefaultAccessPolicy, &node.DefaultAccessTag, &node.EnrollToken, &node.APIKey, &node.AgentVersion, &node.SingboxVersion, &node.LastSeenAt, &node.ConfigOverride, &node.CreatedAt, &node.UpdatedAt)
	return node, err
}

func (s *PostgresStore) GetNodeByAPIKey(ctx context.Context, apiKey string) (domain.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		select id, name, domain, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, last_seen_at, config_override, created_at, updated_at
		from nodes where api_key = $1`, apiKey)
	var node domain.Node
	err := row.Scan(&node.ID, &node.Name, &node.Domain, &node.Status, &node.DefaultAccessPolicy, &node.DefaultAccessTag, &node.EnrollToken, &node.APIKey, &node.AgentVersion, &node.SingboxVersion, &node.LastSeenAt, &node.ConfigOverride, &node.CreatedAt, &node.UpdatedAt)
	return node, err
}

func (s *PostgresStore) TouchNodeHeartbeat(ctx context.Context, nodeID, agentVersion, singboxVersion string) error {
	_, err := s.db.ExecContext(ctx, `
		update nodes
		set last_seen_at = now(), status = 'online', agent_version = $2, singbox_version = $3, updated_at = now()
		where id = $1`, nodeID, agentVersion, singboxVersion)
	return err
}

func (s *PostgresStore) SaveUsageBatch(ctx context.Context, nodeID string, records []domain.UsageRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, record := range records {
		if record.ID == "" {
			record.ID = uuid.NewString()
		}
		if _, err := tx.ExecContext(ctx, `
			insert into usage_records (id, node_id, user_id, uplink_bytes, downlink_bytes, collected_at)
			values ($1,$2,$3,$4,$5,$6)`,
			record.ID, nodeID, record.UserID, record.UplinkBytes, record.DownlinkBytes, record.CollectedAt,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			update users
			set traffic_used_bytes = traffic_used_bytes + $2 + $3, updated_at = now()
			where id = $1`,
			record.UserID, record.UplinkBytes, record.DownlinkBytes,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) BuildSubscription(ctx context.Context, user domain.User) (domain.SubscriptionEnvelope, error) {
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return domain.SubscriptionEnvelope{}, err
	}
	tagSet := map[string]bool{}
	for _, tag := range user.Tags {
		tagSet[tag.Name] = true
	}
	allowed := map[string]bool{}
	for _, id := range user.AllowedNodeIDs {
		allowed[id] = true
	}
	globalCfg, err := s.GetGlobalConfig(ctx)
	if err != nil {
		return domain.SubscriptionEnvelope{}, err
	}
	var globalMap map[string]any
	if err := json.Unmarshal(globalCfg.ConfigJSON, &globalMap); err != nil {
		return domain.SubscriptionEnvelope{}, err
	}

	envelope := domain.SubscriptionEnvelope{
		Version: "1",
		Meta: map[string]interface{}{
			"user_id": user.ID,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	if user.Status != domain.UserStatusActive || (user.TrafficLimitBytes > 0 && user.TrafficUsedBytes >= user.TrafficLimitBytes) {
		return envelope, nil
	}

	for _, node := range nodes {
		if node.Status == domain.NodeStatusDisabled {
			continue
		}
		include := false
		switch user.NodeAccessMode {
		case domain.NodeAccessModeExplicit:
			include = allowed[node.ID]
		default:
			switch node.DefaultAccessPolicy {
			case domain.DefaultAccessPolicyOpen:
				include = true
			case domain.DefaultAccessPolicyByTag:
				include = node.DefaultAccessTag != nil && tagSet[*node.DefaultAccessTag]
			case domain.DefaultAccessPolicyNobody:
				include = false
			}
		}
		if !include {
			continue
		}
		nodeConfig := cloneMap(globalMap)
		if len(node.ConfigOverride) > 0 {
			var override map[string]any
			if err := json.Unmarshal(node.ConfigOverride, &override); err == nil {
				nodeConfig = mergeMap(nodeConfig, override)
			}
		}
		nodeConfig["domain"] = node.Domain
		nodeConfig["user"] = map[string]any{
			"id": user.ID,
			"name": user.Name,
			"subscription_token": user.SubscriptionToken,
		}
		envelope.Nodes = append(envelope.Nodes, domain.SubscriptionNode{
			NodeID: node.ID,
			Name: node.Name,
			Domain: node.Domain,
			Config: nodeConfig,
		})
	}
	return envelope, nil
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		if nested, ok := v.(map[string]any); ok {
			out[k] = cloneMap(nested)
			continue
		}
		out[k] = v
	}
	return out
}

func mergeMap(base, overlay map[string]any) map[string]any {
	for key, value := range overlay {
		if nestedOverlay, ok := value.(map[string]any); ok {
			if nestedBase, ok := base[key].(map[string]any); ok {
				base[key] = mergeMap(nestedBase, nestedOverlay)
				continue
			}
		}
		base[key] = value
	}
	return base
}

const schemaSQL = `
create table if not exists admins (
	id text primary key,
	email text not null unique,
	password_hash text not null,
	created_at timestamptz not null
);

create table if not exists users (
	id text primary key,
	external_id text,
	name text not null,
	status text not null,
	traffic_limit_bytes bigint not null default 0,
	traffic_used_bytes bigint not null default 0,
	subscription_token text not null unique,
	node_access_mode text not null,
	created_at timestamptz not null,
	updated_at timestamptz not null
);

create table if not exists tags (
	id text primary key,
	name text not null unique,
	created_at timestamptz not null
);

create table if not exists user_tags (
	user_id text not null references users(id) on delete cascade,
	tag_id text not null references tags(id) on delete cascade,
	primary key (user_id, tag_id)
);

create table if not exists nodes (
	id text primary key,
	name text not null,
	domain text not null,
	status text not null,
	default_access_policy text not null,
	default_access_tag text,
	enroll_token text not null unique,
	api_key text not null unique,
	agent_version text not null default '',
	singbox_version text not null default '',
	last_seen_at timestamptz,
	config_override jsonb not null default '{}'::jsonb,
	created_at timestamptz not null,
	updated_at timestamptz not null
);

create table if not exists user_node_access (
	user_id text not null references users(id) on delete cascade,
	node_id text not null references nodes(id) on delete cascade,
	primary key (user_id, node_id)
);

create table if not exists node_commands (
	id text primary key,
	node_id text not null references nodes(id) on delete cascade,
	type text not null,
	payload jsonb not null default '{}'::jsonb,
	status text not null,
	result text,
	issued_at timestamptz not null,
	applied_at timestamptz
);

create table if not exists global_config (
	id text primary key,
	config_json jsonb not null,
	updated_at timestamptz not null
);

create table if not exists usage_records (
	id text primary key,
	node_id text not null references nodes(id) on delete cascade,
	user_id text not null references users(id) on delete cascade,
	uplink_bytes bigint not null default 0,
	downlink_bytes bigint not null default 0,
	collected_at timestamptz not null
);
`

