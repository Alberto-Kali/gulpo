"use client";

import { FormEvent, useEffect, useState } from "react";
import {
  createNode,
  createUser,
  getGlobalConfig,
  listNodes,
  listUsers,
  login,
  Node,
  updateGlobalConfig,
  User,
} from "../lib/api";

type Props = {
  defaultEmail: string;
};

const initialConfig = {
  log: { level: "info" },
  inbounds: [],
  outbounds: [],
  transport_profile: "vless-reality",
};

export function Dashboard({ defaultEmail }: Props) {
  const [token, setToken] = useState<string>("");
  const [email, setEmail] = useState(defaultEmail);
  const [password, setPassword] = useState("change-me");
  const [users, setUsers] = useState<User[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [configText, setConfigText] = useState(JSON.stringify(initialConfig, null, 2));
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) return;
    void refresh(token);
  }, [token]);

  async function refresh(authToken: string) {
    try {
      const [userList, nodeList, globalConfig] = await Promise.all([
        listUsers(authToken),
        listNodes(authToken),
        getGlobalConfig(authToken),
      ]);
      setUsers(userList);
      setNodes(nodeList);
      setConfigText(JSON.stringify(globalConfig, null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    }
  }

  async function onLogin(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await login(email, password);
      setToken(response.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  async function onCreateUser() {
    if (!token) return;
    setBusy(true);
    setError("");
    try {
      await createUser(token, {
        name: `user-${users.length + 1}`,
        status: "active",
        traffic_limit_bytes: 10737418240,
        node_access_mode: "tags",
        tags: ["default"],
      });
      await refresh(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create user");
    } finally {
      setBusy(false);
    }
  }

  async function onCreateNode() {
    if (!token) return;
    setBusy(true);
    setError("");
    try {
      await createNode(token, {
        name: `node-${nodes.length + 1}`,
        domain: `node-${nodes.length + 1}.example.com`,
        status: "pending",
        default_access_policy: "tag",
        default_access_tag: "default",
        agent_version: "",
        singbox_version: "",
      });
      await refresh(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create node");
    } finally {
      setBusy(false);
    }
  }

  async function onSaveConfig() {
    if (!token) return;
    setBusy(true);
    setError("");
    try {
      await updateGlobalConfig(token, JSON.parse(configText));
      await refresh(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save config");
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <section className="panel">
        <h2>Admin Login</h2>
        <form className="form" onSubmit={onLogin}>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
          <button disabled={busy} type="submit">
            {busy ? "Signing in..." : "Sign in"}
          </button>
          {error ? <div className="pill warn">{error}</div> : null}
        </form>
      </section>
    );
  }

  return (
    <div className="grid">
      <section className="panel">
        <div className="toolbar">
          <button onClick={onCreateUser} disabled={busy}>Create Demo User</button>
          <button className="secondary" onClick={() => void refresh(token)} disabled={busy}>Refresh</button>
        </div>
        <h2>Users</h2>
        <div className="stack">
          {users.map((user) => (
            <article className="card" key={user.id}>
              <div className="meta">
                <span className="pill">{user.status}</span>
                <span>{user.traffic_used_bytes} / {user.traffic_limit_bytes} bytes</span>
              </div>
              <h3>{user.name}</h3>
              <p>Subscription token: <code>{user.subscription_token}</code></p>
              <div className="meta">
                {(user.tags ?? []).map((tag) => (
                  <span className="pill" key={tag.id}>{tag.name}</span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="toolbar">
          <button onClick={onCreateNode} disabled={busy}>Create Demo Node</button>
        </div>
        <h2>Nodes</h2>
        <div className="stack">
          {nodes.map((node) => (
            <article className="card" key={node.id}>
              <div className="meta">
                <span className="pill">{node.status}</span>
                <span>{node.default_access_policy}</span>
              </div>
              <h3>{node.name}</h3>
              <p>{node.domain}</p>
              <div className="meta">
                <span>Last seen: {node.last_seen_at ?? "never"}</span>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Global Node Config</h2>
        <div className="form">
          <textarea value={configText} onChange={(e) => setConfigText(e.target.value)} />
          <button onClick={onSaveConfig} disabled={busy}>Save Global Config</button>
          {error ? <div className="pill warn">{error}</div> : null}
        </div>
      </section>
    </div>
  );
}

