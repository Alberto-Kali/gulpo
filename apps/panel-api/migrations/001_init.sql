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
