package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/fear/gulpo/apps/panel-api/internal/auth"
	secretcrypto "github.com/fear/gulpo/apps/panel-api/internal/crypto"
	"github.com/fear/gulpo/apps/panel-api/internal/domain"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/curve25519"
)

type PostgresStore struct {
	db      *sql.DB
	secrets *secretcrypto.SecretBox
}

func Open(ctx context.Context, databaseURL, ssSecretKey string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	return &PostgresStore{
		db:      db,
		secrets: secretcrypto.NewSecretBox(ssSecretKey),
	}, nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *PostgresStore) SeedAdmin(ctx context.Context, username, email, password string) error {
	var existingID string
	err := s.db.QueryRowContext(ctx, `select id from admins order by created_at asc limit 1`).Scan(&existingID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.ExecContext(ctx, `
			insert into admins (id, username, email, password_hash, created_at)
			values ($1, $2, $3, $4, now())`,
			uuid.NewString(), username, email, auth.HashPassword(password),
		)
		return err
	case err != nil:
		return err
	default:
		_, err = s.db.ExecContext(ctx, `
			update admins
			set username = $2, email = $3, password_hash = $4
			where id = $1`,
			existingID, username, email, auth.HashPassword(password),
		)
		return err
	}
}

func (s *PostgresStore) GetAdminByLogin(ctx context.Context, login string) (domain.Admin, error) {
	row := s.db.QueryRowContext(ctx, `select id, username, email, password_hash, created_at from admins where username = $1 or email = $1 limit 1`, login)
	var admin domain.Admin
	err := row.Scan(&admin.ID, &admin.Username, &admin.Email, &admin.PasswordHash, &admin.CreatedAt)
	return admin, err
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		select id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, ss_password_encrypted, trojan_password_encrypted, vless_uuid, hysteria2_password_encrypted, tuic_uuid, tuic_password_encrypted, created_at, updated_at
		from users
		order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var user domain.User
		if err := rows.Scan(
			&user.ID,
			&user.ExternalID,
			&user.Name,
			&user.Status,
			&user.TrafficLimitBytes,
			&user.TrafficUsedBytes,
			&user.SubscriptionToken,
			&user.NodeAccessMode,
			&user.SSPasswordEncrypted,
			&user.TrojanPasswordEncrypted,
			&user.VLESSUUID,
			&user.Hysteria2PasswordEncrypted,
			&user.TUICUUID,
			&user.TUICPasswordEncrypted,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if err := s.ensureUserSecrets(ctx, &user); err != nil {
			return nil, err
		}
		user.Tags, _ = s.ListUserTags(ctx, user.ID)
		user.AllowedNodeIDs, _ = s.ListUserAllowedNodes(ctx, user.ID)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.attachUserPresence(ctx, users, 60*time.Second)
}

func (s *PostgresStore) GetDashboardSummary(ctx context.Context) (domain.DashboardSummary, error) {
	var summary domain.DashboardSummary
	if err := s.db.QueryRowContext(ctx, `select count(*)::bigint, coalesce(sum(traffic_used_bytes), 0)::bigint from users`).Scan(&summary.TotalUsers, &summary.TotalTrafficUsedBytes); err != nil {
		return summary, err
	}
	if err := s.db.QueryRowContext(ctx, `
		with recent as (
			select node_id, sum(uplink_bytes + downlink_bytes)::bigint as total_bytes
			from usage_records
			where collected_at >= now() - interval '24 hours'
			group by node_id
		)
		select coalesce((sum(total_bytes) / nullif(count(*), 0))::bigint, 0)
		from recent`).Scan(&summary.AverageNodeLoad24HBytes); err != nil {
		return summary, err
	}
	presence, err := s.GetPresenceSummary(ctx, 60*time.Second)
	if err != nil {
		return summary, err
	}
	summary.OnlineUsers = presence.OnlineUsers
	summary.OnlineNodes = presence.OnlineNodes
	return summary, nil
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
	if err := s.ensureSecretFields(&user); err != nil {
		return domain.User{}, err
	}
	err := s.db.QueryRowContext(ctx, `
		insert into users (id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, ss_password_encrypted, trojan_password_encrypted, vless_uuid, hysteria2_password_encrypted, tuic_uuid, tuic_password_encrypted, created_at, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now(),now())
		returning created_at, updated_at`,
		user.ID,
		user.ExternalID,
		user.Name,
		user.Status,
		user.TrafficLimitBytes,
		user.TrafficUsedBytes,
		user.SubscriptionToken,
		user.NodeAccessMode,
		user.SSPasswordEncrypted,
		user.TrojanPasswordEncrypted,
		user.VLESSUUID,
		user.Hysteria2PasswordEncrypted,
		user.TUICUUID,
		user.TUICPasswordEncrypted,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func (s *PostgresStore) UpdateUser(ctx context.Context, id string, user domain.User) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		update users
		set external_id = $2, name = $3, status = $4, traffic_limit_bytes = $5, node_access_mode = $6, updated_at = now()
		where id = $1
		returning id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, ss_password_encrypted, trojan_password_encrypted, vless_uuid, hysteria2_password_encrypted, tuic_uuid, tuic_password_encrypted, created_at, updated_at`,
		id, user.ExternalID, user.Name, user.Status, user.TrafficLimitBytes, user.NodeAccessMode,
	)
	var out domain.User
	err := row.Scan(
		&out.ID,
		&out.ExternalID,
		&out.Name,
		&out.Status,
		&out.TrafficLimitBytes,
		&out.TrafficUsedBytes,
		&out.SubscriptionToken,
		&out.NodeAccessMode,
		&out.SSPasswordEncrypted,
		&out.TrojanPasswordEncrypted,
		&out.VLESSUUID,
		&out.Hysteria2PasswordEncrypted,
		&out.TUICUUID,
		&out.TUICPasswordEncrypted,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
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
		select id, external_id, name, status, traffic_limit_bytes, traffic_used_bytes, subscription_token, node_access_mode, ss_password_encrypted, trojan_password_encrypted, vless_uuid, hysteria2_password_encrypted, tuic_uuid, tuic_password_encrypted, created_at, updated_at
		from users where subscription_token = $1`, token)
	var user domain.User
	err := row.Scan(
		&user.ID,
		&user.ExternalID,
		&user.Name,
		&user.Status,
		&user.TrafficLimitBytes,
		&user.TrafficUsedBytes,
		&user.SubscriptionToken,
		&user.NodeAccessMode,
		&user.SSPasswordEncrypted,
		&user.TrojanPasswordEncrypted,
		&user.VLESSUUID,
		&user.Hysteria2PasswordEncrypted,
		&user.TUICUUID,
		&user.TUICPasswordEncrypted,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return domain.User{}, err
	}
	if err := s.ensureUserSecrets(ctx, &user); err != nil {
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

func (s *PostgresStore) ListUserProtocolAccess(ctx context.Context, userID string) ([]domain.UserNodeProtocolAccess, error) {
	rows, err := s.db.QueryContext(ctx, `
		select user_id, node_id, protocol, enabled
		from user_node_protocol_access
		where user_id = $1
		order by node_id, protocol`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []domain.UserNodeProtocolAccess
	for rows.Next() {
		var entry domain.UserNodeProtocolAccess
		if err := rows.Scan(&entry.UserID, &entry.NodeID, &entry.Protocol, &entry.Enabled); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *PostgresStore) ReplaceUserProtocolAccess(ctx context.Context, userID string, entries []domain.UserNodeProtocolAccess) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `delete from user_node_protocol_access where user_id = $1`, userID); err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := tx.ExecContext(ctx, `
			insert into user_node_protocol_access (user_id, node_id, protocol, enabled)
			values ($1, $2, $3, $4)`,
			userID, entry.NodeID, entry.Protocol, entry.Enabled,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ListNodes(ctx context.Context) ([]domain.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		select id, name, domain, port, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, certificate_mode, certificate_status, certificate_message, last_seen_at, config_override, created_at, updated_at
		from nodes order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []domain.Node
	for rows.Next() {
		var node domain.Node
		if err := rows.Scan(&node.ID, &node.Name, &node.Domain, &node.Port, &node.Status, &node.DefaultAccessPolicy, &node.DefaultAccessTag, &node.EnrollToken, &node.APIKey, &node.AgentVersion, &node.SingboxVersion, &node.CertificateMode, &node.CertificateStatus, &node.CertificateMessage, &node.LastSeenAt, &node.ConfigOverride, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, err
		}
		normalizeLegacyNodeAddress(&node)
		node.HostKind = detectHostKind(node.Domain)
		if supported, supportedErr := s.supportedProtocolsForNode(ctx, node); supportedErr == nil {
			node.SupportedProtocols = supported
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.attachNodePresence(ctx, nodes, 60*time.Second)
}

func (s *PostgresStore) UpsertSessionSnapshot(ctx context.Context, nodeID string, entries []domain.UserNodeSessionPresence) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `delete from user_node_session_presence where node_id = $1`, nodeID); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.UserID == "" || entry.Connections <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			insert into user_node_session_presence (user_id, node_id, protocol, connections, updated_at)
			values ($1, $2, $3, $4, now())
			on conflict (user_id, node_id, protocol)
			do update set connections = excluded.connections, updated_at = excluded.updated_at`,
			entry.UserID, nodeID, entry.Protocol, entry.Connections,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) GetPresenceSummary(ctx context.Context, freshness time.Duration) (domain.PresenceSummary, error) {
	if freshness <= 0 {
		freshness = 60 * time.Second
	}
	var summary domain.PresenceSummary
	if err := s.db.QueryRowContext(ctx, `
		select count(*)
		from nodes
		where status = 'online'`).Scan(&summary.OnlineNodes); err != nil {
		return summary, err
	}
	if err := s.db.QueryRowContext(ctx, `
		select count(distinct p.user_id)
		from user_node_session_presence p
		join nodes n on n.id = p.node_id
		where n.status = 'online' and p.updated_at >= now() - $1::interval and p.connections > 0`,
		durationInterval(freshness),
	).Scan(&summary.OnlineUsers); err != nil {
		return summary, err
	}
	return summary, nil
}

func (s *PostgresStore) attachUserPresence(ctx context.Context, users []domain.User, freshness time.Duration) ([]domain.User, error) {
	if len(users) == 0 {
		return users, nil
	}
	if freshness <= 0 {
		freshness = 60 * time.Second
	}
	rows, err := s.db.QueryContext(ctx, `
		select p.user_id, coalesce(sum(p.connections), 0) as active_sessions
		from user_node_session_presence p
		join nodes n on n.id = p.node_id
		where n.status = 'online' and p.updated_at >= now() - $1::interval and p.connections > 0
		group by p.user_id`,
		durationInterval(freshness),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessionCounts := make(map[string]int, len(users))
	for rows.Next() {
		var userID string
		var activeSessions int
		if err := rows.Scan(&userID, &activeSessions); err != nil {
			return nil, err
		}
		sessionCounts[userID] = activeSessions
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range users {
		users[i].ActiveSessions = sessionCounts[users[i].ID]
		users[i].IsOnline = users[i].ActiveSessions > 0
	}
	return users, nil
}

func (s *PostgresStore) attachNodePresence(ctx context.Context, nodes []domain.Node, freshness time.Duration) ([]domain.Node, error) {
	if len(nodes) == 0 {
		return nodes, nil
	}
	if freshness <= 0 {
		freshness = 60 * time.Second
	}
	rows, err := s.db.QueryContext(ctx, `
		select p.node_id, count(distinct p.user_id) as active_users
		from user_node_session_presence p
		join nodes n on n.id = p.node_id
		where n.status = 'online' and p.updated_at >= now() - $1::interval and p.connections > 0
		group by p.node_id`,
		durationInterval(freshness),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	activeUsersByNode := make(map[string]int, len(nodes))
	for rows.Next() {
		var nodeID string
		var activeUsers int
		if err := rows.Scan(&nodeID, &activeUsers); err != nil {
			return nil, err
		}
		activeUsersByNode[nodeID] = activeUsers
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range nodes {
		nodes[i].IsOnline = nodes[i].Status == domain.NodeStatusOnline
		nodes[i].ActiveUsers = activeUsersByNode[nodes[i].ID]
	}
	return nodes, nil
}

func (s *PostgresStore) ListNodeEvents(ctx context.Context, nodeID string, limit int) ([]domain.NodeEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		select id, node_id, level, type, message, source, created_at
		from node_events
		where node_id = $1
		order by created_at desc
		limit $2`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []domain.NodeEvent
	for rows.Next() {
		var event domain.NodeEvent
		if err := rows.Scan(&event.ID, &event.NodeID, &event.Level, &event.Type, &event.Message, &event.Source, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *PostgresStore) CreateNodeEvent(ctx context.Context, event domain.NodeEvent) (domain.NodeEvent, error) {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.Level == "" {
		event.Level = domain.NodeEventLevelInfo
	}
	if event.Source == "" {
		event.Source = domain.NodeEventSourceAgent
	}
	err := s.db.QueryRowContext(ctx, `
		insert into node_events (id, node_id, level, type, message, source, created_at)
		values ($1, $2, $3, $4, $5, $6, now())
		returning created_at`,
		event.ID, event.NodeID, event.Level, event.Type, event.Message, event.Source,
	).Scan(&event.CreatedAt)
	return event, err
}

func (s *PostgresStore) CreateNodeEvents(ctx context.Context, nodeID string, events []domain.NodeEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range events {
		if event.ID == "" {
			event.ID = uuid.NewString()
		}
		if event.Level == "" {
			event.Level = domain.NodeEventLevelInfo
		}
		if event.Source == "" {
			event.Source = domain.NodeEventSourceAgent
		}
		if _, err := tx.ExecContext(ctx, `
			insert into node_events (id, node_id, level, type, message, source, created_at)
			values ($1, $2, $3, $4, $5, $6, now())`,
			event.ID, nodeID, event.Level, event.Type, event.Message, event.Source,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	normalizeNodeCertificate(&node)
	err := s.db.QueryRowContext(ctx, `
		insert into nodes (id, name, domain, port, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, certificate_mode, certificate_status, certificate_message, config_override, created_at, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now(),now())
		returning created_at, updated_at`,
		node.ID, node.Name, node.Domain, node.Port, node.Status, node.DefaultAccessPolicy, node.DefaultAccessTag, node.EnrollToken, node.APIKey, node.AgentVersion, node.SingboxVersion, node.CertificateMode, node.CertificateStatus, node.CertificateMessage, node.ConfigOverride,
	).Scan(&node.CreatedAt, &node.UpdatedAt)
	node.HostKind = detectHostKind(node.Domain)
	if supported, supportedErr := s.supportedProtocolsForNode(ctx, node); supportedErr == nil {
		node.SupportedProtocols = supported
	}
	return node, err
}

func (s *PostgresStore) UpdateNode(ctx context.Context, id string, node domain.Node) (domain.Node, error) {
	normalizeNodeCertificate(&node)
	row := s.db.QueryRowContext(ctx, `
		update nodes set name = $2, domain = $3, port = $4, status = $5, default_access_policy = $6, default_access_tag = $7, agent_version = $8, singbox_version = $9, certificate_mode = $10, certificate_status = $11, certificate_message = $12, updated_at = now()
		where id = $1
		returning id, name, domain, port, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, certificate_mode, certificate_status, certificate_message, last_seen_at, config_override, created_at, updated_at`,
		id, node.Name, node.Domain, node.Port, node.Status, node.DefaultAccessPolicy, node.DefaultAccessTag, node.AgentVersion, node.SingboxVersion, node.CertificateMode, node.CertificateStatus, node.CertificateMessage,
	)
	var out domain.Node
	err := row.Scan(&out.ID, &out.Name, &out.Domain, &out.Port, &out.Status, &out.DefaultAccessPolicy, &out.DefaultAccessTag, &out.EnrollToken, &out.APIKey, &out.AgentVersion, &out.SingboxVersion, &out.CertificateMode, &out.CertificateStatus, &out.CertificateMessage, &out.LastSeenAt, &out.ConfigOverride, &out.CreatedAt, &out.UpdatedAt)
	normalizeLegacyNodeAddress(&out)
	out.HostKind = detectHostKind(out.Domain)
	if supported, supportedErr := s.supportedProtocolsForNode(ctx, out); supportedErr == nil {
		out.SupportedProtocols = supported
	}
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
		cfg = domain.GlobalConfig{ID: uuid.NewString(), ConfigJSON: defaultGlobalConfigJSON()}
		_, insertErr := s.db.ExecContext(ctx, `insert into global_config (id, config_json, updated_at) values ($1, $2, now())`, cfg.ID, cfg.ConfigJSON)
		return cfg, insertErr
	}
	if err != nil {
		return cfg, err
	}
	normalized, normalizeErr := normalizeGlobalConfigJSON(cfg.ConfigJSON)
	if normalizeErr != nil {
		return cfg, nil
	}
	if string(normalized) != string(cfg.ConfigJSON) {
		cfg.ConfigJSON = normalized
		cfg.UpdatedAt = time.Now()
		_, _ = s.db.ExecContext(ctx, `update global_config set config_json = $2, updated_at = now() where id = $1`, cfg.ID, cfg.ConfigJSON)
	}
	return cfg, nil
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
	if err != nil {
		return nil, err
	}
	return sanitizeNodeOverrideJSON(cfg)
}

func (s *PostgresStore) UpdateNodeConfig(ctx context.Context, nodeID string, data []byte) error {
	sanitized, err := sanitizeNodeOverrideJSON(data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `update nodes set config_override = $2, updated_at = now() where id = $1`, nodeID, sanitized)
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
	var previousStatus domain.NodeStatus
	_ = s.db.QueryRowContext(ctx, `select status from nodes where enroll_token = $1`, enrollToken).Scan(&previousStatus)
	var node domain.Node
	row := s.db.QueryRowContext(ctx, `
		update nodes
		set agent_version = $2, singbox_version = $3, status = 'online', last_seen_at = now(), updated_at = now()
		where enroll_token = $1
		returning id, name, domain, port, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, certificate_mode, certificate_status, certificate_message, last_seen_at, config_override, created_at, updated_at`,
		enrollToken, agentVersion, singboxVersion,
	)
	err := row.Scan(&node.ID, &node.Name, &node.Domain, &node.Port, &node.Status, &node.DefaultAccessPolicy, &node.DefaultAccessTag, &node.EnrollToken, &node.APIKey, &node.AgentVersion, &node.SingboxVersion, &node.CertificateMode, &node.CertificateStatus, &node.CertificateMessage, &node.LastSeenAt, &node.ConfigOverride, &node.CreatedAt, &node.UpdatedAt)
	normalizeLegacyNodeAddress(&node)
	node.HostKind = detectHostKind(node.Domain)
	if supported, supportedErr := s.supportedProtocolsForNode(ctx, node); supportedErr == nil {
		node.SupportedProtocols = supported
	}
	if err == nil && previousStatus != domain.NodeStatusOnline {
		message := "Node connected to panel."
		eventType := domain.NodeEventTypeConnected
		if previousStatus == domain.NodeStatusOffline {
			message = "Node reconnected after offline state."
			eventType = domain.NodeEventTypeHeartbeatRestored
		}
		_, _ = s.CreateNodeEvent(ctx, domain.NodeEvent{
			NodeID:  node.ID,
			Level:   domain.NodeEventLevelInfo,
			Type:    eventType,
			Message: message,
			Source:  domain.NodeEventSourcePanel,
		})
	}
	return node, err
}

func (s *PostgresStore) GetNodeByAPIKey(ctx context.Context, apiKey string) (domain.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		select id, name, domain, port, status, default_access_policy, default_access_tag, enroll_token, api_key, agent_version, singbox_version, certificate_mode, certificate_status, certificate_message, last_seen_at, config_override, created_at, updated_at
		from nodes where api_key = $1`, apiKey)
	var node domain.Node
	err := row.Scan(&node.ID, &node.Name, &node.Domain, &node.Port, &node.Status, &node.DefaultAccessPolicy, &node.DefaultAccessTag, &node.EnrollToken, &node.APIKey, &node.AgentVersion, &node.SingboxVersion, &node.CertificateMode, &node.CertificateStatus, &node.CertificateMessage, &node.LastSeenAt, &node.ConfigOverride, &node.CreatedAt, &node.UpdatedAt)
	normalizeLegacyNodeAddress(&node)
	node.HostKind = detectHostKind(node.Domain)
	if supported, supportedErr := s.supportedProtocolsForNode(ctx, node); supportedErr == nil {
		node.SupportedProtocols = supported
	}
	return node, err
}

func (s *PostgresStore) TouchNodeHeartbeat(ctx context.Context, nodeID, agentVersion, singboxVersion string) error {
	var previousStatus domain.NodeStatus
	_ = s.db.QueryRowContext(ctx, `select status from nodes where id = $1`, nodeID).Scan(&previousStatus)
	_, err := s.db.ExecContext(ctx, `
		update nodes
		set last_seen_at = now(), status = 'online', agent_version = $2, singbox_version = $3, updated_at = now()
		where id = $1`, nodeID, agentVersion, singboxVersion)
	if err == nil && previousStatus != domain.NodeStatusOnline {
		_, _ = s.CreateNodeEvent(ctx, domain.NodeEvent{
			NodeID:  nodeID,
			Level:   domain.NodeEventLevelInfo,
			Type:    domain.NodeEventTypeHeartbeatRestored,
			Message: "Heartbeat restored and node is online again.",
			Source:  domain.NodeEventSourcePanel,
		})
	}
	return err
}

func (s *PostgresStore) ReconcileStaleNodes(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	rows, err := s.db.QueryContext(ctx, `
		update nodes
		set status = 'offline', updated_at = now()
		where status = 'online' and last_seen_at is not null and last_seen_at < now() - $1::interval
		returning id`, durationInterval(timeout))
	if err != nil {
		return err
	}
	defer rows.Close()
	var nodeIDs []string
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return err
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, nodeID := range nodeIDs {
		_, _ = s.CreateNodeEvent(ctx, domain.NodeEvent{
			NodeID:  nodeID,
			Level:   domain.NodeEventLevelWarn,
			Type:    domain.NodeEventTypeDisconnected,
			Message: "Node heartbeat timed out and node was marked offline.",
			Source:  domain.NodeEventSourcePanel,
		})
	}
	return nil
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
	nodes, err := s.AccessibleNodesForUser(ctx, user)
	if err != nil {
		return domain.SubscriptionEnvelope{}, err
	}
	protocolAccess, err := s.protocolAccessMap(ctx, user.ID)
	if err != nil {
		return domain.SubscriptionEnvelope{}, err
	}
	envelope := domain.SubscriptionEnvelope{
		Version: "1",
		Meta: map[string]interface{}{
			"user_id":      user.ID,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"transport":    "multi",
			"subscription": user.SubscriptionToken,
		},
	}
	if !isUserEligible(user) {
		return envelope, nil
	}
	for _, node := range nodes {
		nodeConfig, err := s.BuildMergedNodeConfig(ctx, node)
		if err != nil {
			return domain.SubscriptionEnvelope{}, err
		}
		nodeConfig["domain"] = node.Domain
		nodeConfig["user"] = map[string]any{
			"id":                 user.ID,
			"name":               user.Name,
			"subscription_token": user.SubscriptionToken,
		}
		nodeConfig["subscription_profiles"] = buildNodeProfileSummaries(node, nodeConfig, user, protocolAccess, s.secrets)
		envelope.Nodes = append(envelope.Nodes, domain.SubscriptionNode{
			NodeID: node.ID,
			Name:   node.Name,
			Domain: node.Domain,
			Config: nodeConfig,
		})
	}
	return envelope, nil
}

func (s *PostgresStore) BuildProfilePage(ctx context.Context, user domain.User) (domain.ProfilePageResponse, error) {
	response := domain.ProfilePageResponse{
		UserName:     user.Name,
		UserStatus:   user.Status,
		Subscription: user.SubscriptionToken,
		Profiles:     []domain.ProfileItem{},
	}
	if !isUserEligible(user) {
		response.Message = "This subscription is inactive or traffic limit is exhausted."
		return response, nil
	}
	nodes, err := s.AccessibleNodesForUser(ctx, user)
	if err != nil {
		return response, err
	}
	protocolAccess, err := s.protocolAccessMap(ctx, user.ID)
	if err != nil {
		return response, err
	}
	for _, node := range nodes {
		mergedConfig, err := s.BuildMergedNodeConfig(ctx, node)
		if err != nil {
			return response, err
		}
		for _, profile := range buildNodeProfilesForUser(node, mergedConfig, user, protocolAccess, s.secrets) {
			response.Profiles = append(response.Profiles, profile)
		}
	}
	if len(response.Profiles) == 0 {
		response.Message = "No eligible protocol profiles are available for this subscription."
	}
	return response, nil
}

func (s *PostgresStore) BuildNodeDesiredConfig(ctx context.Context, node domain.Node) (map[string]any, error) {
	merged, err := s.BuildMergedNodeConfig(ctx, node)
	if err != nil {
		return nil, err
	}
	users, err := s.ListEligibleUsersForNode(ctx, node)
	if err != nil {
		return nil, err
	}
	return s.resolveNodeRuntimeConfig(node, merged, users)
}

func (s *PostgresStore) BuildMergedNodeConfig(ctx context.Context, node domain.Node) (map[string]any, error) {
	globalCfg, err := s.GetGlobalConfig(ctx)
	if err != nil {
		return nil, err
	}
	var persistedGlobal map[string]any
	if err := json.Unmarshal(globalCfg.ConfigJSON, &persistedGlobal); err != nil {
		return nil, err
	}
	merged := cloneMap(persistedGlobal)
	if merged == nil {
		merged = map[string]any{}
	}
	if len(node.ConfigOverride) > 0 {
		sanitizedOverride, err := sanitizeNodeOverrideJSON(node.ConfigOverride)
		if err != nil {
			return nil, err
		}
		var override map[string]any
		if err := json.Unmarshal(sanitizedOverride, &override); err == nil && override != nil {
			merged = mergeMap(merged, override)
		}
	}
	return cloneMap(merged), nil
}

func (s *PostgresStore) AccessibleNodesForUser(ctx context.Context, user domain.User) ([]domain.Node, error) {
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	var allowed []domain.Node
	for _, node := range nodes {
		if userCanAccessNode(user, node) {
			allowed = append(allowed, node)
		}
	}
	return allowed, nil
}

func (s *PostgresStore) ListEligibleUsersForNode(ctx context.Context, node domain.Node) ([]domain.User, error) {
	users, err := s.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := s.ListUserProtocolAccessByNode(ctx, node.ID)
	if err != nil {
		return nil, err
	}
	var eligible []domain.User
	for _, user := range users {
		if isUserEligible(user) && userCanAccessNode(user, node) && userHasAnyEnabledProtocol(user.ID, node.ID, entries) {
			eligible = append(eligible, user)
		}
	}
	return eligible, nil
}

func (s *PostgresStore) resolveNodeRuntimeConfig(node domain.Node, cfg map[string]any, users []domain.User) (map[string]any, error) {
	rawInbounds, ok := cfg["inbounds"].([]any)
	if !ok {
		return cfg, nil
	}
	var entries []domain.UserNodeProtocolAccess
	if s.db != nil && node.ID != "" {
		var err error
		entries, err = s.ListUserProtocolAccessByNode(context.Background(), node.ID)
		if err != nil {
			return nil, err
		}
	}
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		protocol := domain.ProtocolType(asString(inbound["type"]))
		applyInboundListenDefaults(inbound)
		applyNodeTLSDefaults(inbound, node)
		runtimeUsers := make([]map[string]any, 0, len(users))
		for _, user := range users {
			if !protocolEnabledForUser(entries, user.ID, node.ID, protocol) {
				continue
			}
			switch protocol {
			case domain.ProtocolShadowsocks:
				method := asString(inbound["method"])
				if method == "" {
					continue
				}
				password, err := s.secrets.Decrypt(user.SSPasswordEncrypted)
				if err != nil {
					return nil, err
				}
				runtimeUsers = append(runtimeUsers, map[string]any{
					"name":     user.ID,
					"password": password,
				})
			case domain.ProtocolTrojan:
				password, err := s.secrets.Decrypt(user.TrojanPasswordEncrypted)
				if err != nil {
					return nil, err
				}
				runtimeUsers = append(runtimeUsers, map[string]any{
					"name":     user.ID,
					"password": password,
				})
			case domain.ProtocolVLESS:
				if user.VLESSUUID == "" {
					continue
				}
				runtimeUsers = append(runtimeUsers, map[string]any{
					"name": user.ID,
					"uuid": user.VLESSUUID,
					"flow": "xtls-rprx-vision",
				})
			case domain.ProtocolHysteria2:
				password, err := s.secrets.Decrypt(user.Hysteria2PasswordEncrypted)
				if err != nil {
					return nil, err
				}
				runtimeUsers = append(runtimeUsers, map[string]any{
					"name":     user.ID,
					"password": password,
				})
			case domain.ProtocolTUIC:
				password, err := s.secrets.Decrypt(user.TUICPasswordEncrypted)
				if err != nil {
					return nil, err
				}
				if user.TUICUUID == "" {
					continue
				}
				runtimeUsers = append(runtimeUsers, map[string]any{
					"name":     user.ID,
					"uuid":     user.TUICUUID,
					"password": password,
				})
			case "shadowtls":
				password, err := s.secrets.Decrypt(user.SSPasswordEncrypted)
				if err != nil {
					return nil, err
				}
				runtimeUsers = append(runtimeUsers, map[string]any{
					"name":     user.ID,
					"password": password,
				})
			}
		}
		switch protocol {
		case "shadowsocks":
			inbound["users"] = runtimeUsers
			inbound["tag"] = coalesceString(asString(inbound["tag"]), "ss-in")
		case "trojan":
			inbound["users"] = runtimeUsers
			inbound["tag"] = coalesceString(asString(inbound["tag"]), "trojan-in")
		case "vless":
			inbound["users"] = runtimeUsers
			inbound["tag"] = coalesceString(asString(inbound["tag"]), "vless-in")
		case "hysteria2":
			inbound["users"] = runtimeUsers
			inbound["tag"] = coalesceString(asString(inbound["tag"]), "hysteria2-in")
		case "tuic":
			inbound["users"] = runtimeUsers
			inbound["tag"] = coalesceString(asString(inbound["tag"]), "tuic-in")
		case "shadowtls":
			inbound["tag"] = coalesceString(asString(inbound["tag"]), "shadowtls-in")
			version := 3
			if parsedVersion, ok := asInt(inbound["version"]); ok {
				version = parsedVersion
			}
			inbound["version"] = version
			if version >= 3 {
				inbound["users"] = runtimeUsers
				delete(inbound, "password")
			} else {
				delete(inbound, "users")
			}
			handshake, ok := inbound["handshake"].(map[string]any)
			if !ok {
				handshake = map[string]any{}
				inbound["handshake"] = handshake
			}
			if asString(handshake["server"]) == "" {
				handshake["server"] = "www.gosuslugi.ru"
			}
			if _, ok := handshake["server_port"]; !ok {
				handshake["server_port"] = 443
			}
		}
	}
	return cfg, nil
}

func (s *PostgresStore) ensureSecretFields(user *domain.User) error {
	if user.SSPasswordEncrypted == "" {
		plainPassword, err := auth.RandomBase64Key(32)
		if err != nil {
			return err
		}
		encrypted, err := s.secrets.Encrypt(plainPassword)
		if err != nil {
			return err
		}
		user.SSPasswordEncrypted = encrypted
	}
	if user.TrojanPasswordEncrypted == "" {
		plainPassword, err := auth.RandomToken(24)
		if err != nil {
			return err
		}
		encrypted, err := s.secrets.Encrypt(plainPassword)
		if err != nil {
			return err
		}
		user.TrojanPasswordEncrypted = encrypted
	}
	if user.VLESSUUID == "" {
		user.VLESSUUID = uuid.NewString()
	}
	if user.Hysteria2PasswordEncrypted == "" {
		plainPassword, err := auth.RandomToken(24)
		if err != nil {
			return err
		}
		encrypted, err := s.secrets.Encrypt(plainPassword)
		if err != nil {
			return err
		}
		user.Hysteria2PasswordEncrypted = encrypted
	}
	if user.TUICUUID == "" {
		user.TUICUUID = uuid.NewString()
	}
	if user.TUICPasswordEncrypted == "" {
		plainPassword, err := auth.RandomToken(24)
		if err != nil {
			return err
		}
		encrypted, err := s.secrets.Encrypt(plainPassword)
		if err != nil {
			return err
		}
		user.TUICPasswordEncrypted = encrypted
	}
	return nil
}

func (s *PostgresStore) ensureUserSecrets(ctx context.Context, user *domain.User) error {
	if user.SSPasswordEncrypted != "" && s.ssSecretNeedsRotation(user.SSPasswordEncrypted) {
		user.SSPasswordEncrypted = ""
	}
	if user.SSPasswordEncrypted != "" && user.TrojanPasswordEncrypted != "" && user.VLESSUUID != "" && user.Hysteria2PasswordEncrypted != "" && user.TUICUUID != "" && user.TUICPasswordEncrypted != "" {
		return nil
	}
	if err := s.ensureSecretFields(user); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		update users
		set ss_password_encrypted = $2, trojan_password_encrypted = $3, vless_uuid = $4, hysteria2_password_encrypted = $5, tuic_uuid = $6, tuic_password_encrypted = $7, updated_at = now()
		where id = $1`,
		user.ID, user.SSPasswordEncrypted, user.TrojanPasswordEncrypted, user.VLESSUUID, user.Hysteria2PasswordEncrypted, user.TUICUUID, user.TUICPasswordEncrypted,
	); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) ssSecretNeedsRotation(encrypted string) bool {
	if encrypted == "" {
		return true
	}
	plain, err := s.secrets.Decrypt(encrypted)
	if err != nil {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(plain)
	if err != nil {
		return true
	}
	return len(raw) != 32
}

func isUserEligible(user domain.User) bool {
	if user.Status != domain.UserStatusActive {
		return false
	}
	return user.TrafficLimitBytes <= 0 || user.TrafficUsedBytes < user.TrafficLimitBytes
}

func userCanAccessNode(user domain.User, node domain.Node) bool {
	if node.Status == domain.NodeStatusDisabled {
		return false
	}
	switch user.NodeAccessMode {
	case domain.NodeAccessModeExplicit:
		for _, id := range user.AllowedNodeIDs {
			if id == node.ID {
				return true
			}
		}
		return false
	default:
		tagSet := map[string]bool{}
		for _, tag := range user.Tags {
			tagSet[tag.Name] = true
		}
		switch node.DefaultAccessPolicy {
		case domain.DefaultAccessPolicyOpen:
			return true
		case domain.DefaultAccessPolicyByTag:
			return node.DefaultAccessTag != nil && tagSet[*node.DefaultAccessTag]
		default:
			return false
		}
	}
}

type shadowsocksInbound struct {
	Port     int
	Method   string
	Password string
}

func firstInboundByType(config map[string]any, inboundType string) (map[string]any, bool) {
	rawInbounds, ok := config["inbounds"].([]any)
	if !ok {
		return nil, false
	}
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if asString(inbound["type"]) == inboundType {
			return inbound, true
		}
	}
	return nil, false
}

func firstShadowsocksInbound(config map[string]any) (map[string]any, shadowsocksInbound, bool) {
	rawInbounds, ok := config["inbounds"].([]any)
	if !ok {
		return nil, shadowsocksInbound{}, false
	}
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if asString(inbound["type"]) != "shadowsocks" {
			continue
		}
		port, ok := asInt(inbound["listen_port"])
		if !ok {
			continue
		}
		method := asString(inbound["method"])
		if method == "" {
			continue
		}
		return inbound, shadowsocksInbound{
			Port:     port,
			Method:   method,
			Password: asString(inbound["password"]),
		}, true
	}
	return nil, shadowsocksInbound{}, false
}

func asInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		i, err := typed.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func (s *PostgresStore) ListUserProtocolAccessByNode(ctx context.Context, nodeID string) ([]domain.UserNodeProtocolAccess, error) {
	rows, err := s.db.QueryContext(ctx, `
		select user_id, node_id, protocol, enabled
		from user_node_protocol_access
		where node_id = $1
		order by user_id, protocol`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []domain.UserNodeProtocolAccess
	for rows.Next() {
		var entry domain.UserNodeProtocolAccess
		if err := rows.Scan(&entry.UserID, &entry.NodeID, &entry.Protocol, &entry.Enabled); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *PostgresStore) protocolAccessMap(ctx context.Context, userID string) (map[string]bool, error) {
	entries, err := s.ListUserProtocolAccess(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(entries))
	for _, entry := range entries {
		result[protocolAccessKey(entry.NodeID, entry.Protocol)] = entry.Enabled
	}
	return result, nil
}

func protocolAccessKey(nodeID string, protocol domain.ProtocolType) string {
	return nodeID + ":" + string(protocol)
}

func protocolEnabledForUser(entries []domain.UserNodeProtocolAccess, userID, nodeID string, protocol domain.ProtocolType) bool {
	for _, entry := range entries {
		if entry.UserID == userID && entry.NodeID == nodeID && entry.Protocol == protocol {
			return entry.Enabled
		}
	}
	return true
}

func userHasAnyEnabledProtocol(userID, nodeID string, entries []domain.UserNodeProtocolAccess) bool {
	hasEntry := false
	for _, entry := range entries {
		if entry.UserID == userID && entry.NodeID == nodeID {
			hasEntry = true
			if entry.Enabled {
				return true
			}
		}
	}
	return !hasEntry
}

func asString(value any) string {
	typed, _ := value.(string)
	return typed
}

func coalesceString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func applyNodeTLSDefaults(inbound map[string]any, node domain.Node) {
	protocol := domain.ProtocolType(asString(inbound["type"]))
	tlsConfig, ok := inbound["tls"].(map[string]any)
	if !ok && node.CertificateMode != domain.CertificateModeDisabled && protocolUsesTLS(protocol) {
		tlsConfig = map[string]any{}
		inbound["tls"] = tlsConfig
	}
	if !ok && tlsConfig == nil {
		return
	}
	if node.CertificateMode != domain.CertificateModeDisabled {
		tlsConfig["enabled"] = true
	}
	serverName := normalizeServer(node.Domain)
	if serverName == "" {
		return
	}
	if protocol == domain.ProtocolVLESS {
		if realityConfig, hasReality := tlsConfig["reality"].(map[string]any); hasReality {
			handshake, ok := realityConfig["handshake"].(map[string]any)
			if !ok {
				handshake = map[string]any{}
				realityConfig["handshake"] = handshake
			}
			if asString(handshake["server"]) == "" {
				handshake["server"] = "www.gosuslugi.ru"
			}
			if _, ok := handshake["server_port"]; !ok {
				handshake["server_port"] = 443
			}
			return
		}
	}
	if asString(tlsConfig["server_name"]) == "" {
		tlsConfig["server_name"] = serverName
	}
	if protocol == domain.ProtocolTrojan {
		if _, exists := tlsConfig["alpn"]; !exists {
			tlsConfig["alpn"] = []string{"h2", "http/1.1"}
		}
	}
	if node.CertificateMode != domain.CertificateModeACME {
		if acmeConfig, ok := tlsConfig["acme"].(map[string]any); ok {
			if enabled, ok := acmeConfig["enabled"].(bool); ok && !enabled {
				delete(tlsConfig, "acme")
			}
		}
		return
	}
	acmeConfig, ok := tlsConfig["acme"].(map[string]any)
	if !ok {
		acmeConfig = map[string]any{}
		tlsConfig["acme"] = acmeConfig
	}
	if enabled, ok := acmeConfig["enabled"].(bool); ok && !enabled {
		delete(acmeConfig, "enabled")
		return
	}
	delete(acmeConfig, "enabled")
	if _, ok := acmeConfig["domain"]; !ok {
		acmeConfig["domain"] = []string{serverName}
	} else if domainName := asString(acmeConfig["domain"]); domainName != "" {
		acmeConfig["domain"] = []string{domainName}
	}
	if asString(acmeConfig["data_directory"]) == "" {
		acmeConfig["data_directory"] = "__GULPO_ACME_DATA_DIR__"
	}
}

func applyInboundListenDefaults(inbound map[string]any) {
	inboundType := strings.ToLower(asString(inbound["type"]))
	if inboundType == "" {
		return
	}
	if asString(inbound["listen"]) != "" {
		return
	}
	switch inboundType {
	case "shadowsocks":
		if asString(inbound["tag"]) == "ss-in" {
			inbound["listen"] = "127.0.0.1"
			return
		}
	case "shadowtls", "vless", "trojan", "hysteria2", "tuic":
		inbound["listen"] = "::"
		return
	}
}

func composeClientPassword(method, serverPassword, userPassword string) string {
	if strings.HasPrefix(method, "2022-blake3-") && serverPassword != "" {
		return serverPassword + ":" + userPassword
	}
	return userPassword
}

func buildSSURI(method, password, server string, port int, name string) string {
	credential := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	return fmt.Sprintf("ss://%s@%s:%d#%s", credential, server, port, url.QueryEscape(name))
}

func buildShadowTLSSSURI(method, ssPassword, shadowTLSPassword, server string, port int, label string, inbound map[string]any) string {
	credential := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + ssPassword))
	query := url.Values{}
	version := 3
	if parsedVersion, ok := asInt(inbound["version"]); ok {
		version = parsedVersion
	}
	pluginParts := []string{fmt.Sprintf("version=%d", version)}
	if host := coalesceString(shadowTLSHandshakeServer(inbound), "www.gosuslugi.ru"); host != "" {
		pluginParts = append(pluginParts, "host="+host)
	}
	if shadowTLSPassword != "" {
		pluginParts = append(pluginParts, "password="+shadowTLSPassword)
	}
	query.Set("plugin", "shadow-tls;"+strings.Join(pluginParts, ";"))
	return fmt.Sprintf("ss://%s@%s:%d/?%s#%s", credential, server, port, query.Encode(), url.QueryEscape(label))
}

func buildTrojanURI(password, server string, port int, label string, inbound map[string]any) string {
	query := url.Values{}
	query.Set("security", "tls")
	if sni := coalesceString(serverNameFromInbound(inbound), server); sni != "" {
		query.Set("sni", sni)
	}
	return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(password), server, port, query.Encode(), url.QueryEscape(label))
}

func buildVLESSRealityURI(uuidValue, server string, port int, label string, inbound map[string]any) string {
	query := url.Values{}
	transportType, serviceName, host, path := vlessTransportDetails(inbound)
	query.Set("type", transportType)
	if transportType == "grpc" {
		if serviceName != "" {
			query.Set("serviceName", serviceName)
		}
	} else {
		query.Set("headerType", "none")
		query.Set("spx", "/")
		if host != "" {
			query.Set("host", host)
		}
		if path != "" {
			query.Set("path", path)
		}
	}
	query.Set("encryption", "none")
	query.Set("flow", "xtls-rprx-vision")
	tlsConfig, _ := inbound["tls"].(map[string]any)
	if reality, ok := tlsConfig["reality"].(map[string]any); ok {
		query.Set("security", "reality")
		if sni := coalesceString(realityHandshakeServer(reality), coalesceString(firstString(reality["server_name"]), asString(tlsConfig["server_name"]))); sni != "" {
			query.Set("sni", sni)
		}
		if pbk := coalesceString(asString(reality["public_key"]), realityPublicKeyFromPrivate(asString(reality["private_key"]))); pbk != "" {
			query.Set("pbk", pbk)
		}
		if sid := firstString(reality["short_id"]); sid != "" {
			query.Set("sid", sid)
		}
		query.Set("fp", coalesceString(asString(reality["fingerprint"]), "chrome"))
	} else {
		query.Set("security", "none")
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuidValue, server, port, query.Encode(), url.QueryEscape(label))
}

func vlessTransportDetails(inbound map[string]any) (transportType, serviceName, host, path string) {
	transport, ok := inbound["transport"].(map[string]any)
	if !ok {
		return "tcp", "", "", ""
	}
	switch asString(transport["type"]) {
	case "grpc":
		return "grpc", coalesceString(asString(transport["service_name"]), "gulpo-grpc"), "", ""
	case "http":
		return "xhttp", "", firstString(transport["host"]), coalesceString(asString(transport["path"]), "/")
	default:
		return coalesceString(asString(transport["type"]), "tcp"), "", firstString(transport["host"]), asString(transport["path"])
	}
}

func buildHysteria2URI(password, server string, port int, label string, inbound map[string]any) string {
	query := url.Values{}
	if sni := coalesceString(serverNameFromInbound(inbound), server); sni != "" {
		query.Set("sni", sni)
	}
	if alpn := firstString(tlsALPNFromInbound(inbound)); alpn != "" {
		query.Set("alpn", alpn)
	}
	if obfsType, obfsPassword := hysteria2ObfsFromInbound(inbound); obfsType != "" {
		query.Set("obfs", obfsType)
		if obfsPassword != "" {
			query.Set("obfs-password", obfsPassword)
		}
	}
	query.Set("insecure", "0")
	return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", url.QueryEscape(password), server, port, query.Encode(), url.QueryEscape(label))
}

func buildTUICURI(uuidValue, password, server string, port int, label string, inbound map[string]any) string {
	query := url.Values{}
	if sni := coalesceString(serverNameFromInbound(inbound), server); sni != "" {
		query.Set("sni", sni)
	}
	if cc := asString(inbound["congestion_control"]); cc != "" {
		query.Set("congestion_control", cc)
	}
	return fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s", uuidValue, url.QueryEscape(password), server, port, query.Encode(), url.QueryEscape(label))
}

func normalizeServer(domain string) string {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		return host
	}
	return domain
}

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func durationInterval(value time.Duration) string {
	seconds := int(value / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%d seconds", seconds)
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		switch nested := v.(type) {
		case map[string]any:
			out[k] = cloneMap(nested)
		case []any:
			copied := make([]any, len(nested))
			for i, item := range nested {
				if nestedMap, ok := item.(map[string]any); ok {
					copied[i] = cloneMap(nestedMap)
				} else {
					copied[i] = item
				}
			}
			out[k] = copied
		default:
			out[k] = v
		}
	}
	return out
}

func detectHostKind(domain string) string {
	host := normalizeServer(strings.TrimSpace(domain))
	if host == "" {
		return "unknown"
	}
	if net.ParseIP(host) != nil {
		return "ip"
	}
	return "domain"
}

func normalizeNodeCertificate(node *domain.Node) {
	normalizeLegacyNodeAddress(node)
	if node.CertificateMode == "" {
		node.CertificateMode = domain.CertificateModeDisabled
	}
	node.HostKind = detectHostKind(node.Domain)
	switch node.CertificateMode {
	case domain.CertificateModeACME:
		if node.HostKind == "ip" {
			node.CertificateStatus = domain.CertificateStatusWarning
			node.CertificateMessage = "ACME requires a real domain name. Bare IP addresses are not eligible."
			return
		}
		node.CertificateStatus = domain.CertificateStatusReady
		node.CertificateMessage = "ACME can be attempted when DNS resolves to this node and ports 80/443 are reachable."
	case domain.CertificateModeManual:
		node.CertificateStatus = domain.CertificateStatusReady
		node.CertificateMessage = "Manual TLS mode expects certificate handling outside the panel."
	default:
		node.CertificateStatus = domain.CertificateStatusUnknown
		node.CertificateMessage = "Certificate automation is disabled for this node."
	}
}

func supportedProtocolsFromRaw(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil
	}
	return supportedProtocolsFromConfig(cfg)
}

func normalizeLegacyNodeAddress(node *domain.Node) {
	host := strings.TrimSpace(node.Domain)
	if host == "" {
		if node.Port == 0 {
			node.Port = 443
		}
		return
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		node.Domain = parsedHost
		if node.Port == 0 {
			node.Port = parseNodePort(parsedPort, 443)
		}
	}
	if node.Port == 0 {
		node.Port = 443
	}
}

func parseNodePort(value string, fallback int) int {
	var port int
	if _, err := fmt.Sscanf(value, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}

func supportedProtocolsFromConfig(cfg map[string]any) []string {
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var protocols []string
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		protocol := asString(inbound["type"])
		switch domain.ProtocolType(protocol) {
		case domain.ProtocolShadowsocks, domain.ProtocolTrojan, domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolTUIC:
			if !seen[protocol] {
				seen[protocol] = true
				protocols = append(protocols, protocol)
			}
		default:
			if protocol == "shadowtls" && !seen[string(domain.ProtocolShadowsocks)] {
				seen[string(domain.ProtocolShadowsocks)] = true
				protocols = append(protocols, string(domain.ProtocolShadowsocks))
			}
		}
	}
	sort.Strings(protocols)
	return protocols
}

func protocolUsesTLS(protocol domain.ProtocolType) bool {
	switch protocol {
	case domain.ProtocolTrojan, domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolTUIC:
		return true
	default:
		return false
	}
}

func serverNameFromInbound(inbound map[string]any) string {
	tlsConfig, _ := inbound["tls"].(map[string]any)
	return asString(tlsConfig["server_name"])
}

func tlsALPNFromInbound(inbound map[string]any) []string {
	tlsConfig, _ := inbound["tls"].(map[string]any)
	if tlsConfig == nil {
		return nil
	}
	return stringsFromAny(tlsConfig["alpn"])
}

func shadowTLSHandshakeServer(inbound map[string]any) string {
	handshake, _ := inbound["handshake"].(map[string]any)
	if handshake == nil {
		return ""
	}
	return asString(handshake["server"])
}

func hysteria2ObfsFromInbound(inbound map[string]any) (string, string) {
	obfs, _ := inbound["obfs"].(map[string]any)
	if obfs == nil {
		return "", ""
	}
	return asString(obfs["type"]), asString(obfs["password"])
}

func firstString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		for _, item := range typed {
			if item != "" {
				return item
			}
		}
	case []any:
		for _, item := range typed {
			if asString(item) != "" {
				return asString(item)
			}
		}
	}
	return ""
}

func stringsFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := asString(item); value != "" {
				result = append(result, value)
			}
		}
		return result
	default:
		if value := asString(value); value != "" {
			return []string{value}
		}
		return nil
	}
}

func realityHandshakeServer(value map[string]any) string {
	handshake, ok := value["handshake"].(map[string]any)
	if !ok {
		return ""
	}
	return asString(handshake["server"])
}

func realityPublicKeyFromPrivate(privateKey string) string {
	if privateKey == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil || len(raw) != 32 {
		return ""
	}
	var priv [32]byte
	copy(priv[:], raw)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

func buildNodeProfilesForUser(node domain.Node, cfg map[string]any, user domain.User, protocolAccess map[string]bool, box *secretcrypto.SecretBox) []domain.ProfileItem {
	rawInbounds, ok := cfg["inbounds"].([]any)
	if !ok {
		return nil
	}
	server := normalizeServer(node.Domain)
	if server == "" {
		return nil
	}
	shadowTLSInbound, hasShadowTLS := firstInboundByType(cfg, "shadowtls")
	_, ssInbound, hasSSBackend := firstShadowsocksInbound(cfg)
	var profiles []domain.ProfileItem
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		protocol := domain.ProtocolType(asString(inbound["type"]))
		if hasShadowTLS && protocol == domain.ProtocolShadowsocks {
			continue
		}
		if !isSupportedProfileProtocol(protocol) {
			if asString(inbound["type"]) != "shadowtls" {
				continue
			}
			protocol = domain.ProtocolShadowsocks
			if !hasSSBackend {
				continue
			}
			inbound = shadowTLSInbound
		}
		if !isSupportedProfileProtocol(protocol) {
			continue
		}
		if protocolAccess != nil {
			if enabled, ok := protocolAccess[protocolAccessKey(node.ID, protocol)]; ok && !enabled {
				continue
			}
		}
		port, ok := asInt(inbound["listen_port"])
		if !ok {
			continue
		}
		label := fmt.Sprintf("%s %s %s", user.Name, node.Name, strings.ToUpper(string(protocol)))
		item := domain.ProfileItem{
			NodeID:     node.ID,
			Name:       node.Name,
			Label:      label,
			Protocol:   string(protocol),
			Server:     server,
			Port:       port,
			SNI:        serverNameFromInbound(inbound),
			ALPN:       tlsALPNFromInbound(inbound),
			LastSeenAt: node.LastSeenAt,
			Status:     string(node.Status),
		}
		switch protocol {
		case domain.ProtocolShadowsocks:
			method := asString(inbound["method"])
			if asString(inbound["type"]) == "shadowtls" {
				method = ssInbound.Method
			}
			if method == "" {
				continue
			}
			password, err := box.Decrypt(user.SSPasswordEncrypted)
			if err != nil {
				continue
			}
			serverPassword := asString(inbound["password"])
			if asString(inbound["type"]) == "shadowtls" {
				version := 3
				if parsedVersion, ok := asInt(inbound["version"]); ok {
					version = parsedVersion
				}
				if version >= 3 {
					serverPassword = ssInbound.Password
				}
			}
			clientPassword := composeClientPassword(method, serverPassword, password)
			item.Method = method
			item.ClientPassword = clientPassword
			item.PasswordMasked = maskSecret(clientPassword)
			if asString(inbound["type"]) == "shadowtls" {
				item.TransportMode = "shadowtls"
				item.MaskHost = coalesceString(shadowTLSHandshakeServer(inbound), "www.gosuslugi.ru")
				shadowTLSPassword := password
				version := 3
				if parsedVersion, ok := asInt(inbound["version"]); ok {
					version = parsedVersion
				}
				if version <= 2 {
					shadowTLSPassword = asString(inbound["password"])
				}
				item.URI = buildShadowTLSSSURI(method, clientPassword, shadowTLSPassword, server, port, label, inbound)
			} else {
				item.TransportMode = "raw"
				item.URI = buildSSURI(method, clientPassword, server, port, label)
			}
		case domain.ProtocolTrojan:
			password, err := box.Decrypt(user.TrojanPasswordEncrypted)
			if err != nil {
				continue
			}
			item.TransportMode = "tls"
			item.ClientPassword = password
			item.PasswordMasked = maskSecret(password)
			item.URI = buildTrojanURI(password, server, port, label, inbound)
		case domain.ProtocolVLESS:
			if user.VLESSUUID == "" {
				continue
			}
			transportType, _, _, _ := vlessTransportDetails(inbound)
			item.TransportMode = transportType
			item.Flow = "xtls-rprx-vision"
			tlsConfig, _ := inbound["tls"].(map[string]any)
			realityConfig, _ := tlsConfig["reality"].(map[string]any)
			item.Fingerprint = coalesceString(asString(realityConfig["fingerprint"]), "chrome")
			item.PublicKey = coalesceString(asString(realityConfig["public_key"]), realityPublicKeyFromPrivate(asString(realityConfig["private_key"])))
			item.ShortID = firstString(realityConfig["short_id"])
			item.MaskHost = coalesceString(realityHandshakeServer(realityConfig), "www.gosuslugi.ru")
			item.UUID = user.VLESSUUID
			item.URI = buildVLESSRealityURI(user.VLESSUUID, server, port, label, inbound)
		case domain.ProtocolHysteria2:
			password, err := box.Decrypt(user.Hysteria2PasswordEncrypted)
			if err != nil {
				continue
			}
			item.TransportMode = "quic-tls"
			item.Obfs, _ = hysteria2ObfsFromInbound(inbound)
			item.ClientPassword = password
			item.PasswordMasked = maskSecret(password)
			item.URI = buildHysteria2URI(password, server, port, label, inbound)
		case domain.ProtocolTUIC:
			password, err := box.Decrypt(user.TUICPasswordEncrypted)
			if err != nil {
				continue
			}
			if user.TUICUUID == "" {
				continue
			}
			item.TransportMode = "quic-tls"
			item.UUID = user.TUICUUID
			item.ClientPassword = password
			item.PasswordMasked = maskSecret(password)
			item.URI = buildTUICURI(user.TUICUUID, password, server, port, label, inbound)
		default:
			continue
		}
		if item.URI != "" {
			profiles = append(profiles, item)
		}
	}
	return profiles
}

func buildNodeProfileSummaries(node domain.Node, cfg map[string]any, user domain.User, protocolAccess map[string]bool, box *secretcrypto.SecretBox) []map[string]any {
	profiles := buildNodeProfilesForUser(node, cfg, user, protocolAccess, box)
	result := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, map[string]any{
			"protocol": profile.Protocol,
			"server":   profile.Server,
			"port":     profile.Port,
			"uri":      profile.URI,
		})
	}
	return result
}

func isSupportedProfileProtocol(protocol domain.ProtocolType) bool {
	switch protocol {
	case domain.ProtocolShadowsocks, domain.ProtocolTrojan, domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolTUIC:
		return true
	default:
		return false
	}
}

func mergeMap(base, overlay map[string]any) map[string]any {
	for key, value := range overlay {
		if key == "inbounds" {
			if overlayInbounds, ok := value.([]any); ok {
				baseInbounds, _ := base[key].([]any)
				base[key] = mergeInboundArrays(baseInbounds, overlayInbounds)
				continue
			}
		}
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

func mergeInboundArrays(base, overlay []any) []any {
	if len(base) == 0 {
		return cloneSlice(overlay)
	}
	result := cloneSlice(base)
	indexByKey := make(map[string]int, len(result))
	for i, raw := range result {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if key := inboundMergeKey(inbound); key != "" {
			indexByKey[key] = i
		}
	}
	for _, raw := range overlay {
		inbound, ok := raw.(map[string]any)
		if !ok {
			result = append(result, raw)
			continue
		}
		key := inboundMergeKey(inbound)
		if index, exists := indexByKey[key]; exists && key != "" {
			if existing, ok := result[index].(map[string]any); ok {
				result[index] = mergeMap(existing, cloneMap(inbound))
				continue
			}
		}
		indexByKey[key] = len(result)
		result = append(result, cloneMap(inbound))
	}
	return result
}

func inboundMergeKey(inbound map[string]any) string {
	if tag := asString(inbound["tag"]); tag != "" {
		return "tag:" + tag
	}
	if inboundType := asString(inbound["type"]); inboundType != "" {
		return "type:" + inboundType
	}
	return ""
}

func cloneSlice(src []any) []any {
	out := make([]any, len(src))
	for i, item := range src {
		if nested, ok := item.(map[string]any); ok {
			out[i] = cloneMap(nested)
			continue
		}
		out[i] = item
	}
	return out
}

func defaultGlobalConfig() map[string]any {
	return map[string]any{
		"log":       map[string]any{"level": "info"},
		"route":     map[string]any{"final": "direct"},
		"outbounds": []any{},
		"inbounds": []any{
			map[string]any{
				"tag":         "shadowtls-in",
				"type":        "shadowtls",
				"listen_port": 2080,
				"version":     2,
				"password":    "shadowtls-default-password",
				"handshake": map[string]any{
					"server":      "www.gosuslugi.ru",
					"server_port": 443,
				},
			},
			map[string]any{
				"tag":         "ss-in",
				"type":        "shadowsocks",
				"listen":      "127.0.0.1",
				"listen_port": 2081,
				"method":      "2022-blake3-aes-128-gcm",
			},
			map[string]any{
				"tag":         "vless-in",
				"type":        "vless",
				"listen_port": 9443,
				"transport": map[string]any{
					"type":         "grpc",
					"service_name": "gulpo-grpc",
				},
				"tls": map[string]any{
					"enabled": true,
					"reality": map[string]any{
						"handshake": map[string]any{
							"server":      "www.gosuslugi.ru",
							"server_port": 443,
						},
					},
				},
			},
		},
	}
}

func defaultGlobalConfigJSON() []byte {
	body, _ := json.Marshal(defaultGlobalConfig())
	return body
}

func normalizeGlobalConfigJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return defaultGlobalConfigJSON(), nil
	}
	var current map[string]any
	if err := json.Unmarshal(raw, &current); err != nil {
		return nil, err
	}
	normalized := mergeMap(defaultGlobalConfig(), current)
	if rawInbounds, exists := current["inbounds"]; exists {
		if inbounds, ok := rawInbounds.([]any); ok {
			normalized["inbounds"] = cloneSlice(inbounds)
		} else {
			normalized["inbounds"] = rawInbounds
		}
	}
	return json.Marshal(normalized)
}

func sanitizeNodeOverrideJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return []byte(`{}`), nil
	}
	var current map[string]any
	if err := json.Unmarshal(raw, &current); err != nil {
		return nil, err
	}
	rawInbounds, ok := current["inbounds"].([]any)
	if !ok {
		return json.Marshal(current)
	}
	filtered := make([]any, 0, len(rawInbounds))
	for _, rawInbound := range rawInbounds {
		inbound, ok := rawInbound.(map[string]any)
		if !ok {
			filtered = append(filtered, rawInbound)
			continue
		}
		inboundType := strings.ToLower(asString(inbound["type"]))
		tag := strings.TrimSpace(asString(inbound["tag"]))
		if inboundType == "" {
			filtered = append(filtered, inbound)
			continue
		}
		switch inboundType {
		case "shadowsocks", "shadowtls", "vless":
			// Global config owns the full inbound definitions for these protocols.
			// Node overrides may still patch them via tag-only fragments, so only
			// strip full protocol redefinitions here.
			if tag == "shadowtls-in" || tag == "ss-in" || tag == "vless-in" {
				continue
			}
			continue
		}
		filtered = append(filtered, inbound)
	}
	current["inbounds"] = filtered
	return json.Marshal(current)
}

func (s *PostgresStore) supportedProtocolsForNode(ctx context.Context, node domain.Node) ([]string, error) {
	cfg, err := s.BuildMergedNodeConfig(ctx, node)
	if err != nil {
		return nil, err
	}
	return supportedProtocolsFromConfig(cfg), nil
}

const schemaSQL = `
create table if not exists admins (
	id text primary key,
	username text not null unique,
	email text not null unique,
	password_hash text not null,
	created_at timestamptz not null
);

alter table admins add column if not exists username text;
update admins set username = split_part(email, '@', 1) where coalesce(username, '') = '';
create unique index if not exists idx_admins_username on admins (username);

create table if not exists users (
	id text primary key,
	external_id text,
	name text not null,
	status text not null,
	traffic_limit_bytes bigint not null default 0,
	traffic_used_bytes bigint not null default 0,
	subscription_token text not null unique,
	node_access_mode text not null,
	ss_password_encrypted text not null default '',
	trojan_password_encrypted text not null default '',
	vless_uuid text not null default '',
	hysteria2_password_encrypted text not null default '',
	tuic_uuid text not null default '',
	tuic_password_encrypted text not null default '',
	created_at timestamptz not null,
	updated_at timestamptz not null
);

alter table users add column if not exists ss_password_encrypted text not null default '';
alter table users add column if not exists trojan_password_encrypted text not null default '';
alter table users add column if not exists vless_uuid text not null default '';
alter table users add column if not exists hysteria2_password_encrypted text not null default '';
alter table users add column if not exists tuic_uuid text not null default '';
alter table users add column if not exists tuic_password_encrypted text not null default '';

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
	port integer not null default 443,
	status text not null,
	default_access_policy text not null,
	default_access_tag text,
	enroll_token text not null unique,
	api_key text not null unique,
	agent_version text not null default '',
	singbox_version text not null default '',
	certificate_mode text not null default 'disabled',
	certificate_status text not null default 'unknown',
	certificate_message text not null default '',
	last_seen_at timestamptz,
	config_override jsonb not null default '{}'::jsonb,
	created_at timestamptz not null,
	updated_at timestamptz not null
);

alter table nodes add column if not exists certificate_mode text not null default 'disabled';
alter table nodes add column if not exists certificate_status text not null default 'unknown';
alter table nodes add column if not exists certificate_message text not null default '';
alter table nodes add column if not exists port integer not null default 443;

create table if not exists user_node_access (
	user_id text not null references users(id) on delete cascade,
	node_id text not null references nodes(id) on delete cascade,
	primary key (user_id, node_id)
);

create table if not exists user_node_protocol_access (
	user_id text not null references users(id) on delete cascade,
	node_id text not null references nodes(id) on delete cascade,
	protocol text not null,
	enabled boolean not null default true,
	primary key (user_id, node_id, protocol)
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

create table if not exists user_node_session_presence (
	user_id text not null references users(id) on delete cascade,
	node_id text not null references nodes(id) on delete cascade,
	protocol text not null,
	connections integer not null default 0,
	updated_at timestamptz not null,
	primary key (user_id, node_id, protocol)
);

create index if not exists idx_user_node_session_presence_node_updated_at on user_node_session_presence (node_id, updated_at desc);
create index if not exists idx_user_node_session_presence_user_updated_at on user_node_session_presence (user_id, updated_at desc);

create table if not exists node_events (
	id text primary key,
	node_id text not null references nodes(id) on delete cascade,
	level text not null,
	type text not null,
	message text not null default '',
	source text not null,
	created_at timestamptz not null
);

create index if not exists idx_node_events_node_created_at on node_events (node_id, created_at desc);
`
