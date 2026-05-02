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
	subscription_device_limit integer not null default 0,
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
alter table users add column if not exists subscription_device_limit integer not null default 0;

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

create table if not exists user_subscription_devices (
	id text primary key,
	user_id text not null references users(id) on delete cascade,
	device_key text not null,
	device_identifier text not null default '',
	device_source text not null default '',
	first_seen_at timestamptz not null,
	last_seen_at timestamptz not null,
	last_client_ip text not null default '',
	last_user_agent text not null default '',
	request_count bigint not null default 0,
	blocked boolean not null default false,
	blocked_at timestamptz,
	unique (user_id, device_key)
);

create index if not exists idx_user_subscription_devices_user_last_seen on user_subscription_devices (user_id, last_seen_at desc);

create table if not exists subscription_request_events (
	id text primary key,
	user_id text not null references users(id) on delete cascade,
	endpoint text not null,
	client_ip text not null default '',
	user_agent text not null default '',
	device_key text not null,
	device_identifier text not null default '',
	device_source text not null default '',
	request_fingerprint text not null,
	query_params jsonb not null default '{}'::jsonb,
	headers jsonb not null default '{}'::jsonb,
	created_at timestamptz not null
);

create index if not exists idx_subscription_request_events_user_created on subscription_request_events (user_id, created_at desc);
create index if not exists idx_subscription_request_events_user_device on subscription_request_events (user_id, device_key, created_at desc);
