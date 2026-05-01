# Gulpo

Monorepo for a sing-box control panel MVP and a pull-based node agent.

## Apps

- `apps/panel-api`: Go REST API for admin, subscriptions, and node sync.
- `apps/panel-web`: Next.js admin UI.
- `apps/node-agent`: Go agent that enrolls, syncs configuration, and manages local `sing-box`.

## Local Development

The repository ships with Dockerfiles and a `compose.yaml` for the panel side:

- Postgres
- panel API
- panel web

The node agent is packaged as a standalone image and is expected to be deployed separately per node/domain.

## Test Node

For a same-server test node, use `compose.node.yaml`.

1. Create a node in the panel.
2. Rotate its enroll token.
3. Replace `CHANGE_ME_ENROLL_TOKEN` in `compose.node.yaml`.
4. Start the node stack.

The test node compose publishes port `2080` and is intended for MVP connectivity checks on the same host.

## Main MVP Features

- User CRUD with tag-based and explicit node access.
- Stable rotatable subscription token per user.
- Global node config plus per-node overrides.
- Node enrollment with independent default policy.
- Pull-based node sync, command queue, heartbeat, and traffic usage reporting.
