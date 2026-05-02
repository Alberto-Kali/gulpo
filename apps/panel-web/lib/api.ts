function normalizeBasePath(value?: string) {
  if (!value || value === "/") return "";
  return value.startsWith("/") ? value.replace(/\/$/, "") : `/${value.replace(/\/$/, "")}`;
}

function resolveApiBase() {
  return normalizeBasePath(process.env.NEXT_PUBLIC_PANEL_BASE_PATH || "/panel");
}

const API_BASE = resolveApiBase();

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = response.statusText;
    try {
      const body = await response.json();
      message = body.error ?? message;
    } catch {}
    throw new Error(message);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json();
}

type Tag = {
  id: string;
  name: string;
};

export type User = {
  id: string;
  external_id?: string | null;
  name: string;
  status: string;
  traffic_limit_bytes: number;
  traffic_used_bytes: number;
  subscription_token: string;
  node_access_mode: string;
  subscription_device_limit: number;
  tags?: Tag[] | null;
  allowed_node_ids?: string[] | null;
  is_online?: boolean;
  active_sessions?: number;
};

export type Node = {
  id: string;
  name: string;
  domain: string;
  port: number;
  status: string;
  default_access_policy: string;
  default_access_tag?: string | null;
  agent_version?: string;
  singbox_version?: string;
  certificate_mode?: string;
  certificate_status?: string;
  certificate_message?: string;
  host_kind?: string;
  supported_protocols?: string[] | null;
  last_seen_at?: string | null;
  is_online?: boolean;
  active_users?: number;
};

export type UserNodeProtocolAccess = {
  user_id: string;
  node_id: string;
  protocol: string;
  enabled: boolean;
};

export type SubscriptionDevice = {
  id: string;
  user_id: string;
  device_key: string;
  device_identifier?: string;
  device_source: string;
  first_seen_at: string;
  last_seen_at: string;
  last_client_ip?: string;
  last_user_agent?: string;
  request_count: number;
  blocked: boolean;
  blocked_at?: string | null;
};

export type SubscriptionRequestEvent = {
  id: string;
  user_id: string;
  endpoint: string;
  client_ip?: string;
  user_agent?: string;
  device_key: string;
  device_identifier?: string;
  device_source: string;
  request_fingerprint: string;
  query_params?: Record<string, string[]>;
  headers?: Record<string, string>;
  created_at: string;
};

export type NodeEvent = {
  id: string;
  node_id: string;
  level: string;
  type: string;
  message: string;
  source: string;
  created_at: string;
};

export type DashboardSummary = {
  total_users: number;
  total_traffic_used_bytes: number;
  average_node_load_24h_bytes: number;
  online_users: number;
  online_nodes: number;
};

function normalizeUser(user: User): User {
  return {
    ...user,
    external_id: user.external_id ?? null,
    tags: Array.isArray(user.tags) ? user.tags : [],
    allowed_node_ids: Array.isArray(user.allowed_node_ids) ? user.allowed_node_ids : [],
    subscription_device_limit: Number(user.subscription_device_limit ?? 0),
    is_online: Boolean(user.is_online),
    active_sessions: Number(user.active_sessions ?? 0),
  };
}

function normalizeNode(node: Node): Node {
  return {
    ...node,
    default_access_tag: node.default_access_tag ?? null,
    port: Number(node.port ?? 443),
    last_seen_at: node.last_seen_at ?? null,
    agent_version: node.agent_version ?? "",
    singbox_version: node.singbox_version ?? "",
    certificate_mode: node.certificate_mode ?? "disabled",
    certificate_status: node.certificate_status ?? "unknown",
    certificate_message: node.certificate_message ?? "",
    host_kind: node.host_kind ?? "unknown",
    supported_protocols: Array.isArray(node.supported_protocols) ? node.supported_protocols : [],
    is_online: Boolean(node.is_online),
    active_users: Number(node.active_users ?? 0),
  };
}

export async function login(loginValue: string, password: string) {
  return parse<{ token: string }>(
    await fetch(`${API_BASE}/api/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login: loginValue, password }),
    }),
  );
}

export async function getDashboardSummary(token: string) {
  return parse<DashboardSummary>(
    await fetch(`${API_BASE}/api/admin/dashboard/summary`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
}

export async function listUsers(token: string) {
  const data = await parse<User[] | null>(
    await fetch(`${API_BASE}/api/admin/users`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
  return (Array.isArray(data) ? data : []).map(normalizeUser);
}

export async function createUser(token: string, payload: Record<string, unknown>) {
  return normalizeUser(
    await parse<User>(
      await fetch(`${API_BASE}/api/admin/users`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }),
    ),
  );
}

export async function updateUser(token: string, userId: string, payload: Record<string, unknown>) {
  return normalizeUser(
    await parse<User>(
      await fetch(`${API_BASE}/api/admin/users/${userId}`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }),
    ),
  );
}

export async function deleteUser(token: string, userId: string) {
  await parse<unknown>(
    await fetch(`${API_BASE}/api/admin/users/${userId}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),
  );
}

export async function updateUserTags(token: string, userId: string, tags: string[]) {
  return parse<Tag[]>(
    await fetch(`${API_BASE}/api/admin/users/${userId}/tags`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ tags }),
    }),
  );
}

export async function rotateUserSubscription(token: string, userId: string) {
  return parse<{ subscription_token: string }>(
    await fetch(`${API_BASE}/api/admin/users/${userId}/subscription/rotate`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),
  );
}

export async function listNodes(token: string) {
  const data = await parse<Node[] | null>(
    await fetch(`${API_BASE}/api/admin/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
  return (Array.isArray(data) ? data : []).map(normalizeNode);
}

export async function createNode(token: string, payload: Record<string, unknown>) {
  return normalizeNode(
    await parse<Node>(
      await fetch(`${API_BASE}/api/admin/nodes`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }),
    ),
  );
}

export async function updateNode(token: string, nodeId: string, payload: Record<string, unknown>) {
  return normalizeNode(
    await parse<Node>(
      await fetch(`${API_BASE}/api/admin/nodes/${nodeId}`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }),
    ),
  );
}

export async function getUserProtocolAccess(token: string, userId: string) {
  const data = await parse<UserNodeProtocolAccess[] | null>(
    await fetch(`${API_BASE}/api/admin/users/${userId}/protocol-access`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
  return Array.isArray(data) ? data : [];
}

export async function updateUserProtocolAccess(token: string, userId: string, entries: UserNodeProtocolAccess[]) {
  return parse<{ status: string }>(
    await fetch(`${API_BASE}/api/admin/users/${userId}/protocol-access`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ entries }),
    }),
  );
}

export async function listUserSubscriptionDevices(token: string, userId: string) {
  const data = await parse<SubscriptionDevice[] | null>(
    await fetch(`${API_BASE}/api/admin/users/${userId}/subscription/devices`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
  return Array.isArray(data) ? data : [];
}

export async function listUserSubscriptionRequests(token: string, userId: string, limit = 50) {
  const data = await parse<SubscriptionRequestEvent[] | null>(
    await fetch(`${API_BASE}/api/admin/users/${userId}/subscription/requests?limit=${limit}`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
  return Array.isArray(data) ? data : [];
}

export async function deleteNode(token: string, nodeId: string) {
  await parse<unknown>(
    await fetch(`${API_BASE}/api/admin/nodes/${nodeId}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),
  );
}

export async function rotateNodeEnrollToken(token: string, nodeId: string) {
  return parse<{ enroll_token: string }>(
    await fetch(`${API_BASE}/api/admin/nodes/${nodeId}/enroll-token/rotate`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),
  );
}

export async function sendNodeCommand(token: string, nodeId: string, type: string, payload: Record<string, unknown> = {}) {
  return parse<{ id: string; status: string }>(
    await fetch(`${API_BASE}/api/admin/nodes/${nodeId}/commands`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ type, payload }),
    }),
  );
}

export async function getNodeConfig(token: string, nodeId: string) {
  return parse<Record<string, unknown>>(
    await fetch(`${API_BASE}/api/admin/nodes/${nodeId}/config`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
}

export async function listNodeEvents(token: string, nodeId: string, limit = 100) {
  const data = await parse<NodeEvent[] | null>(
    await fetch(`${API_BASE}/api/admin/nodes/${nodeId}/events?limit=${limit}`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
  return Array.isArray(data) ? data : [];
}

export async function updateNodeConfig(token: string, nodeId: string, payload: Record<string, unknown>) {
  return parse<{ status: string }>(
    await fetch(`${API_BASE}/api/admin/nodes/${nodeId}/config`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }),
  );
}

export async function getGlobalConfig(token: string) {
  return parse<Record<string, unknown>>(
    await fetch(`${API_BASE}/api/admin/config/global`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
}

export async function updateGlobalConfig(token: string, payload: Record<string, unknown>) {
  return parse<Record<string, unknown>>(
    await fetch(`${API_BASE}/api/admin/config/global`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }),
  );
}
