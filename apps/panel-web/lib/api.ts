const API_BASE =
  process.env.NEXT_PUBLIC_PANEL_API_BASE_URL || "http://localhost:8080";

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = response.statusText;
    try {
      const body = await response.json();
      message = body.error ?? message;
    } catch {}
    throw new Error(message);
  }
  return response.json();
}

export type User = {
  id: string;
  name: string;
  status: string;
  traffic_limit_bytes: number;
  traffic_used_bytes: number;
  subscription_token: string;
  node_access_mode: string;
  tags?: { id: string; name: string }[];
  allowed_node_ids?: string[];
};

export type Node = {
  id: string;
  name: string;
  domain: string;
  status: string;
  default_access_policy: string;
  default_access_tag?: string | null;
  last_seen_at?: string | null;
};

export async function login(email: string, password: string) {
  return parse<{ token: string }>(
    await fetch(`${API_BASE}/api/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    }),
  );
}

export async function listUsers(token: string) {
  return parse<User[]>(
    await fetch(`${API_BASE}/api/admin/users`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
}

export async function createUser(token: string, payload: Record<string, unknown>) {
  return parse<User>(
    await fetch(`${API_BASE}/api/admin/users`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }),
  );
}

export async function listNodes(token: string) {
  return parse<Node[]>(
    await fetch(`${API_BASE}/api/admin/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }),
  );
}

export async function createNode(token: string, payload: Record<string, unknown>) {
  return parse<Node>(
    await fetch(`${API_BASE}/api/admin/nodes`, {
      method: "POST",
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

