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
