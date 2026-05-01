"use client";

import { FormEvent, useEffect, useState } from "react";
import {
  createNode,
  createUser,
  DashboardSummary,
  deleteNode,
  deleteUser,
  getDashboardSummary,
  getGlobalConfig,
  getNodeConfig,
  getUserProtocolAccess,
  listNodes,
  listNodeEvents,
  listUsers,
  login,
  Node,
  NodeEvent,
  rotateNodeEnrollToken,
  rotateUserSubscription,
  sendNodeCommand,
  updateGlobalConfig,
  updateNode,
  updateNodeConfig,
  updateUserProtocolAccess,
  updateUser,
  updateUserTags,
  User,
  UserNodeProtocolAccess,
} from "../lib/api";

type Props = {
  defaultLogin: string;
};

type DashboardTab = "users" | "nodes" | "config";

type UserForm = {
  externalID: string;
  name: string;
  status: string;
  trafficLimitBytes: string;
  nodeAccessMode: string;
  tagsText: string;
  allowedNodeIDs: string[];
};

type NodeForm = {
  name: string;
  domain: string;
  port: string;
  status: string;
  defaultAccessPolicy: string;
  defaultAccessTag: string;
  certificateMode: string;
};

const initialConfig = {
  log: { level: "info" },
  outbounds: [],
  route: { final: "direct" },
};

const initialSummary: DashboardSummary = {
  total_users: 0,
  total_traffic_used_bytes: 0,
  average_node_load_24h_bytes: 0,
  online_users: 0,
  online_nodes: 0,
};

function tagsToText(tags: User["tags"]) {
  return (tags ?? []).map((tag) => tag.name).join(", ");
}

function buildUserForm(user: User): UserForm {
  return {
    externalID: user.external_id ?? "",
    name: user.name,
    status: user.status,
    trafficLimitBytes: String(user.traffic_limit_bytes ?? 0),
    nodeAccessMode: user.node_access_mode || "tags",
    tagsText: tagsToText(user.tags),
    allowedNodeIDs: Array.isArray(user.allowed_node_ids) ? user.allowed_node_ids : [],
  };
}

function buildNodeForm(node: Node): NodeForm {
  return {
    name: node.name,
    domain: node.domain,
    port: String(node.port ?? 443),
    status: node.status,
    defaultAccessPolicy: node.default_access_policy,
    defaultAccessTag: node.default_access_tag ?? "",
    certificateMode: node.certificate_mode ?? "disabled",
  };
}

function protocolLabel(protocol: string) {
  switch (protocol) {
    case "vless":
      return "VLESS + Reality";
    case "hysteria2":
      return "Hysteria2";
    case "tuic":
      return "TUIC";
    default:
      return protocol;
  }
}

function isIPAddressHost(value: string) {
  const host = value.includes(":") ? value.split(":")[0] : value;
  return /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  const digits = size >= 100 || index === 0 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[index]}`;
}

function formatDateTime(value?: string | null) {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatRelativeTime(value?: string | null) {
  if (!value) return "never";
  const date = new Date(value);
  const diffMs = Date.now() - date.getTime();
  if (!Number.isFinite(diffMs)) return "never";
  const diffSeconds = Math.max(0, Math.round(diffMs / 1000));
  if (diffSeconds < 60) return `${diffSeconds}s ago`;
  if (diffSeconds < 3600) return `${Math.round(diffSeconds / 60)}m ago`;
  if (diffSeconds < 86400) return `${Math.round(diffSeconds / 3600)}h ago`;
  return `${Math.round(diffSeconds / 86400)}d ago`;
}

function statusTone(value: string) {
  switch (value) {
    case "online":
    case "active":
      return "success";
    case "offline":
    case "expired":
      return "subtle";
    case "disabled":
      return "warn";
    default:
      return "subtle";
  }
}

function hostWithPort(node: Node) {
  return `${node.domain}:${node.port}`;
}

export function Dashboard({ defaultLogin }: Props) {
  const [token, setToken] = useState<string>("");
  const [loginValue, setLoginValue] = useState(defaultLogin);
  const [password, setPassword] = useState("");
  const [users, setUsers] = useState<User[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [summary, setSummary] = useState<DashboardSummary>(initialSummary);
  const [activeTab, setActiveTab] = useState<DashboardTab>("users");
  const [configText, setConfigText] = useState(JSON.stringify(initialConfig, null, 2));
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [userDialog, setUserDialog] = useState<User | null>(null);
  const [userForm, setUserForm] = useState<UserForm | null>(null);
  const [userDialogBusy, setUserDialogBusy] = useState(false);
  const [userDialogNotice, setUserDialogNotice] = useState("");
  const [userProtocolAccess, setUserProtocolAccess] = useState<UserNodeProtocolAccess[]>([]);
  const [nodeDialog, setNodeDialog] = useState<Node | null>(null);
  const [nodeForm, setNodeForm] = useState<NodeForm | null>(null);
  const [nodeConfigText, setNodeConfigText] = useState("{}");
  const [nodeEvents, setNodeEvents] = useState<NodeEvent[]>([]);
  const [nodeDialogBusy, setNodeDialogBusy] = useState(false);
  const [nodeDialogNotice, setNodeDialogNotice] = useState("");

  useEffect(() => {
    if (!token) return;
    void refresh(token);
  }, [token]);

  async function refresh(authToken: string) {
    try {
      const [userList, nodeList, globalConfig, dashboardSummary] = await Promise.all([
        listUsers(authToken),
        listNodes(authToken),
        getGlobalConfig(authToken),
        getDashboardSummary(authToken),
      ]);
      setUsers(userList);
      setNodes(nodeList);
      setSummary(dashboardSummary);
      setConfigText(JSON.stringify(globalConfig, null, 2));
      if (nodeDialog) {
        await refreshNodeDialogData(nodeDialog.id, authToken);
      }
      return { userList, nodeList, dashboardSummary };
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
      return null;
    }
  }

  async function onLogin(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await login(loginValue, password);
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
      const createdUser = await createUser(token, {
        name: `user-${users.length + 1}`,
        status: "active",
        traffic_limit_bytes: 10737418240,
        node_access_mode: "tags",
        tags: ["default"],
      });
      const refreshed = await refresh(token);
      setActiveTab("users");
      openUserDialog(refreshed?.userList.find((item) => item.id === createdUser.id) ?? createdUser);
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
      const createdNode = await createNode(token, {
        name: `node-${nodes.length + 1}`,
        domain: "replace-me.invalid",
        port: 443,
        status: "pending",
        default_access_policy: "tag",
        default_access_tag: "default",
        agent_version: "",
        singbox_version: "",
        certificate_mode: "disabled",
      });
      const refreshed = await refresh(token);
      setActiveTab("nodes");
      await openNodeDialog(refreshed?.nodeList.find((item) => item.id === createdNode.id) ?? createdNode);
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
      setActiveTab("config");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save config");
    } finally {
      setBusy(false);
    }
  }

  function openUserDialog(user: User) {
    setUserDialog(user);
    setUserForm(buildUserForm(user));
    setUserDialogNotice("");
    setUserProtocolAccess([]);
    if (!token) return;
    void getUserProtocolAccess(token, user.id)
      .then(setUserProtocolAccess)
      .catch((err) => setUserDialogNotice(err instanceof Error ? err.message : "Could not load protocol access"));
  }

  async function openNodeDialog(node: Node) {
    setNodeDialog(node);
    setNodeForm(buildNodeForm(node));
    setNodeDialogNotice("");
    setNodeConfigText("{}");
    setNodeEvents([]);
    if (!token) return;
    setNodeDialogBusy(true);
    try {
      const [config, events] = await Promise.all([
        getNodeConfig(token, node.id),
        listNodeEvents(token, node.id, 100),
      ]);
      setNodeConfigText(JSON.stringify(config, null, 2));
      setNodeEvents(events);
    } catch (err) {
      setNodeDialogNotice(err instanceof Error ? err.message : "Could not load node config");
    } finally {
      setNodeDialogBusy(false);
    }
  }

  function closeUserDialog() {
    setUserDialog(null);
    setUserForm(null);
    setUserDialogBusy(false);
    setUserDialogNotice("");
  }

  function closeNodeDialog() {
    setNodeDialog(null);
    setNodeForm(null);
    setNodeConfigText("{}");
    setNodeEvents([]);
    setNodeDialogBusy(false);
    setNodeDialogNotice("");
  }

  async function refreshNodeDialogData(nodeId: string, authToken: string) {
    const [config, events] = await Promise.all([
      getNodeConfig(authToken, nodeId),
      listNodeEvents(authToken, nodeId, 100),
    ]);
    setNodeConfigText(JSON.stringify(config, null, 2));
    setNodeEvents(events);
  }

  async function submitUserDialog() {
    if (!token || !userDialog || !userForm) return;
    setUserDialogBusy(true);
    setUserDialogNotice("");
    try {
      const updatedUser = await updateUser(token, userDialog.id, {
        external_id: userForm.externalID || null,
        name: userForm.name,
        status: userForm.status,
        traffic_limit_bytes: Number(userForm.trafficLimitBytes) || 0,
        node_access_mode: userForm.nodeAccessMode,
        allowed_node_ids: userForm.nodeAccessMode === "explicit" ? userForm.allowedNodeIDs : [],
      });
      await updateUserTags(
        token,
        userDialog.id,
        userForm.tagsText
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
      );
      await updateUserProtocolAccess(token, userDialog.id, userProtocolAccess);
      const refreshed = await refresh(token);
      const freshUser = refreshed?.userList.find((item) => item.id === updatedUser.id);
      setUserDialog(freshUser ?? updatedUser);
      setUserForm(buildUserForm(freshUser ?? updatedUser));
      setUserDialogNotice("User updated.");
    } catch (err) {
      setUserDialogNotice(err instanceof Error ? err.message : "Could not update user");
    } finally {
      setUserDialogBusy(false);
    }
  }

  async function rotateSubscription() {
    if (!token || !userDialog) return;
    setUserDialogBusy(true);
    setUserDialogNotice("");
    try {
      const result = await rotateUserSubscription(token, userDialog.id);
      await refresh(token);
      setUserDialog({
        ...userDialog,
        subscription_token: result.subscription_token,
      });
      setUserDialogNotice("Subscription token rotated.");
    } catch (err) {
      setUserDialogNotice(err instanceof Error ? err.message : "Could not rotate subscription token");
    } finally {
      setUserDialogBusy(false);
    }
  }

  async function submitNodeDialog() {
    if (!token || !nodeDialog || !nodeForm) return;
    setNodeDialogBusy(true);
    setNodeDialogNotice("");
    try {
      const updatedNode = await updateNode(token, nodeDialog.id, {
        name: nodeForm.name,
        domain: nodeForm.domain,
        port: Number(nodeForm.port) || 443,
        status: nodeForm.status,
        default_access_policy: nodeForm.defaultAccessPolicy,
        default_access_tag: nodeForm.defaultAccessPolicy === "tag" ? nodeForm.defaultAccessTag || null : null,
        agent_version: nodeDialog.agent_version ?? "",
        singbox_version: nodeDialog.singbox_version ?? "",
        certificate_mode: nodeForm.certificateMode,
      });
      await updateNodeConfig(token, nodeDialog.id, JSON.parse(nodeConfigText));
      await refresh(token);
      await refreshNodeDialogData(nodeDialog.id, token);
      setNodeDialog(updatedNode);
      setNodeForm(buildNodeForm(updatedNode));
      setNodeDialogNotice("Node and node-local config updated.");
    } catch (err) {
      setNodeDialogNotice(err instanceof Error ? err.message : "Could not update node");
    } finally {
      setNodeDialogBusy(false);
    }
  }

  async function rotateEnrollToken() {
    if (!token || !nodeDialog) return;
    setNodeDialogBusy(true);
    setNodeDialogNotice("");
    try {
      const result = await rotateNodeEnrollToken(token, nodeDialog.id);
      setNodeDialogNotice(`New enroll token: ${result.enroll_token}`);
    } catch (err) {
      setNodeDialogNotice(err instanceof Error ? err.message : "Could not rotate enroll token");
    } finally {
      setNodeDialogBusy(false);
    }
  }

  async function runNodeCommand(type: "ping" | "reload" | "restart") {
    if (!token || !nodeDialog) return;
    setNodeDialogBusy(true);
    setNodeDialogNotice("");
    try {
      await sendNodeCommand(token, nodeDialog.id, type, {});
      await refreshNodeDialogData(nodeDialog.id, token);
      setNodeDialogNotice(`Command queued: ${type}.`);
    } catch (err) {
      setNodeDialogNotice(err instanceof Error ? err.message : `Could not queue ${type}`);
    } finally {
      setNodeDialogBusy(false);
    }
  }

  async function removeUser() {
    if (!token || !userDialog) return;
    if (!window.confirm(`Delete user "${userDialog.name}" permanently?`)) return;
    setUserDialogBusy(true);
    setUserDialogNotice("");
    try {
      await deleteUser(token, userDialog.id);
      closeUserDialog();
      await refresh(token);
    } catch (err) {
      setUserDialogNotice(err instanceof Error ? err.message : "Could not delete user");
    } finally {
      setUserDialogBusy(false);
    }
  }

  async function removeNode() {
    if (!token || !nodeDialog) return;
    if (!window.confirm(`Delete node "${nodeDialog.name}" permanently?`)) return;
    setNodeDialogBusy(true);
    setNodeDialogNotice("");
    try {
      await deleteNode(token, nodeDialog.id);
      closeNodeDialog();
      await refresh(token);
    } catch (err) {
      setNodeDialogNotice(err instanceof Error ? err.message : "Could not delete node");
    } finally {
      setNodeDialogBusy(false);
    }
  }

  if (!token) {
    return (
      <section className="panel login-panel">
          <h2>Admin Login</h2>
        <form className="form" onSubmit={onLogin}>
          <input value={loginValue} onChange={(event) => setLoginValue(event.target.value)} placeholder="Login" />
          <input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" />
          <button disabled={busy} type="submit">
            {busy ? "Signing in..." : "Sign in"}
          </button>
          {error ? <div className="pill warn">{error}</div> : null}
        </form>
      </section>
    );
  }

  return (
    <>
      <section className="summary-grid">
        <article className="summary-card">
          <span className="summary-label">Total Usage</span>
          <strong className="summary-value">{formatBytes(summary.total_traffic_used_bytes)}</strong>
          <span className="summary-copy">All-time user traffic across the control plane.</span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Users</span>
          <strong className="summary-value">{summary.total_users}</strong>
          <span className="summary-copy">Currently provisioned users in the panel.</span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Online Now</span>
          <strong className="summary-value">{summary.online_users}</strong>
          <span className="summary-copy">{summary.online_nodes} nodes online with fresh live session presence.</span>
        </article>
        <article className="summary-card">
          <span className="summary-label">Average Network Load</span>
          <strong className="summary-value">{formatBytes(summary.average_node_load_24h_bytes)}</strong>
          <span className="summary-copy">Average node traffic over the last 24 hours.</span>
        </article>
      </section>

      <section className="panel dashboard-shell">
        <div className="section-head">
          <div>
            <h2>Control Surface</h2>
            <p className="section-copy">Manage users, nodes and the global node config from one workspace.</p>
          </div>
          <div className="toolbar">
            <button className={activeTab === "users" ? "" : "secondary"} onClick={() => setActiveTab("users")}>Users</button>
            <button className={activeTab === "nodes" ? "" : "secondary"} onClick={() => setActiveTab("nodes")}>Nodes</button>
            <button className={activeTab === "config" ? "" : "secondary"} onClick={() => setActiveTab("config")}>Global Config</button>
            <button className="secondary" onClick={() => void refresh(token)} disabled={busy}>Refresh</button>
          </div>
        </div>

        {error ? <div className="notice warn-box">{error}</div> : null}

        {activeTab === "users" ? (
          <div className="table-panel">
            <div className="table-toolbar">
              <div>
                <h3>Users</h3>
                <p className="section-copy">Traffic, tags, subscription access and lifecycle in a single table.</p>
              </div>
              <button onClick={onCreateUser} disabled={busy}>Create User</button>
            </div>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Status</th>
                    <th>Online Now</th>
                    <th>Traffic</th>
                    <th>Access</th>
                    <th>Tags</th>
                    <th>Subscription</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.length === 0 ? (
                    <tr>
                      <td colSpan={8}>
                        <div className="empty-state">No users yet.</div>
                      </td>
                    </tr>
                  ) : null}
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td>
                        <div className="table-primary">
                          <strong>{user.name}</strong>
                          <span className="muted-text wrap-anywhere">External ID: {user.external_id || "none"}</span>
                        </div>
                      </td>
                      <td><span className={`pill ${statusTone(user.status)}`}>{user.status}</span></td>
                      <td>
                        <div className="table-primary">
                          <strong>{user.is_online ? "online" : "offline"}</strong>
                          <span className="muted-text">{user.active_sessions ?? 0} active sessions</span>
                        </div>
                      </td>
                      <td>
                        <div className="table-primary">
                          <strong>{formatBytes(user.traffic_used_bytes)}</strong>
                          <span className="muted-text">of {formatBytes(user.traffic_limit_bytes)}</span>
                        </div>
                      </td>
                      <td><span className="pill subtle">{user.node_access_mode}</span></td>
                      <td>
                        <div className="table-tags">
                          {(user.tags ?? []).length ? (user.tags ?? []).map((tag) => (
                            <span className="pill subtle" key={tag.id}>{tag.name}</span>
                          )) : <span className="muted-text">none</span>}
                        </div>
                      </td>
                      <td>
                        <div className="code-link-stack">
                          <code className="token-inline wrap-anywhere">{user.subscription_token}</code>
                          <a className="inline-link wrap-anywhere" href={`/sub/${user.subscription_token}`} target="_blank" rel="noreferrer">
                            Open raw /sub
                          </a>
                          <a className="inline-link wrap-anywhere" href={`/subj/${user.subscription_token}`} target="_blank" rel="noreferrer">
                            Open legacy /subj
                          </a>
                        </div>
                      </td>
                      <td>
                        <div className="table-actions">
                          <button className="secondary" onClick={() => openUserDialog(user)}>Edit</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        {activeTab === "nodes" ? (
          <div className="table-panel">
            <div className="table-toolbar">
              <div>
                <h3>Nodes</h3>
                <p className="section-copy">Inspect domains, certificates, protocols and runtime health.</p>
              </div>
              <button onClick={onCreateNode} disabled={busy}>Create Node</button>
            </div>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Node</th>
                    <th>Status</th>
                    <th>Endpoint</th>
                    <th>Protocols</th>
                    <th>Active Users</th>
                    <th>Certificates</th>
                    <th>Last Seen</th>
                    <th>Versions</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.length === 0 ? (
                    <tr>
                      <td colSpan={9}>
                        <div className="empty-state">No nodes yet.</div>
                      </td>
                    </tr>
                  ) : null}
                  {nodes.map((node) => (
                    <tr key={node.id}>
                      <td>
                        <div className="table-primary">
                          <strong>{node.name}</strong>
                          <span className="muted-text wrap-anywhere">{node.default_access_policy}</span>
                        </div>
                      </td>
                      <td><span className={`pill ${statusTone(node.status)}`}>{node.status}</span></td>
                      <td>
                        <div className="table-primary">
                          <strong className="wrap-anywhere">{hostWithPort(node)}</strong>
                          <span className="muted-text">{node.host_kind || (isIPAddressHost(node.domain) ? "ip" : "domain")}</span>
                        </div>
                      </td>
                      <td>
                        <div className="table-tags">
                          {(node.supported_protocols ?? []).length ? (node.supported_protocols ?? []).map((protocol) => (
                            <span className="pill subtle" key={protocol}>{protocolLabel(protocol)}</span>
                          )) : <span className="muted-text">none</span>}
                        </div>
                      </td>
                      <td>
                        <div className="table-primary">
                          <strong>{node.active_users ?? 0}</strong>
                          <span className="muted-text">{node.is_online ? "live" : "stale"}</span>
                        </div>
                      </td>
                      <td>
                        <div className="table-primary">
                          <strong>{node.certificate_mode || "disabled"}</strong>
                          <span className={`muted-text ${node.certificate_status === "warning" ? "danger-text" : ""}`}>
                            {node.certificate_message || node.certificate_status || "unknown"}
                          </span>
                        </div>
                      </td>
                      <td>
                        <div className="table-primary">
                          <strong>{node.is_online ? "online" : "offline"}</strong>
                          <span className="muted-text">{formatRelativeTime(node.last_seen_at)}</span>
                        </div>
                      </td>
                      <td>
                        <div className="table-primary">
                          <span className="muted-text">Agent: {node.agent_version || "unknown"}</span>
                          <span className="muted-text">Sing-box: {node.singbox_version || "unknown"}</span>
                        </div>
                      </td>
                      <td>
                        <div className="table-actions">
                          <button className="secondary" onClick={() => void openNodeDialog(node)}>Edit</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        {activeTab === "config" ? (
          <div className="table-panel">
            <div className="table-toolbar">
              <div>
                <h3>Global Node Config</h3>
                <p className="section-copy">Shared routing, outbounds, plus the global VLESS and Shadowsocks templates. Keep node-local Trojan, Hysteria2, TUIC and ACME details in each node override.</p>
              </div>
              <button onClick={onSaveConfig} disabled={busy}>Save Global Config</button>
            </div>
            <div className="form">
              <textarea className="config-editor" value={configText} onChange={(event) => setConfigText(event.target.value)} />
            </div>
          </div>
        ) : null}
      </section>

      {userDialog && userForm ? (
        <div className="overlay" onClick={closeUserDialog}>
          <section className="dialog" onClick={(event) => event.stopPropagation()}>
            <div className="dialog-head">
              <div>
                <h2>Edit User</h2>
                <p className="section-copy">Update identity, limits, tags and node access rules.</p>
              </div>
              <button className="secondary" onClick={closeUserDialog}>Close</button>
            </div>
            <div className="dialog-body">
              <div className="split">
                <label className="field">
                  <span>Name</span>
                  <input value={userForm.name} onChange={(event) => setUserForm({ ...userForm, name: event.target.value })} />
                </label>
                <label className="field">
                  <span>External ID</span>
                  <input value={userForm.externalID} onChange={(event) => setUserForm({ ...userForm, externalID: event.target.value })} />
                </label>
              </div>
              <div className="split">
                <label className="field">
                  <span>Status</span>
                  <select value={userForm.status} onChange={(event) => setUserForm({ ...userForm, status: event.target.value })}>
                    <option value="active">active</option>
                    <option value="disabled">disabled</option>
                    <option value="expired">expired</option>
                  </select>
                </label>
                <label className="field">
                  <span>Traffic Limit Bytes</span>
                  <input value={userForm.trafficLimitBytes} onChange={(event) => setUserForm({ ...userForm, trafficLimitBytes: event.target.value })} inputMode="numeric" />
                </label>
              </div>
              <div className="split">
                <label className="field">
                  <span>Node Access Mode</span>
                  <select value={userForm.nodeAccessMode} onChange={(event) => setUserForm({ ...userForm, nodeAccessMode: event.target.value })}>
                    <option value="tags">tags</option>
                    <option value="explicit">explicit</option>
                  </select>
                </label>
                <label className="field">
                  <span>Tags</span>
                  <input
                    value={userForm.tagsText}
                    onChange={(event) => setUserForm({ ...userForm, tagsText: event.target.value })}
                    placeholder="default, beta"
                  />
                </label>
              </div>

              {userForm.nodeAccessMode === "explicit" ? (
                <div className="field">
                  <span>Allowed Nodes</span>
                  <div className="checkbox-list">
                    {nodes.map((node) => {
                      const checked = userForm.allowedNodeIDs.includes(node.id);
                      return (
                        <label className="check-row" key={node.id}>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(event) => {
                              const next = event.target.checked
                                ? [...userForm.allowedNodeIDs, node.id]
                                : userForm.allowedNodeIDs.filter((value) => value !== node.id);
                              setUserForm({ ...userForm, allowedNodeIDs: next });
                            }}
                          />
                          <span className="wrap-anywhere">{node.name} ({node.domain})</span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ) : null}

              <div className="field">
                <span>Live Status</span>
                <div className="split">
                  <div className="stat-box">
                    <span className="muted-text">Presence</span>
                    <strong>{userDialog.is_online ? "online" : "offline"}</strong>
                  </div>
                  <div className="stat-box">
                    <span className="muted-text">Active sessions</span>
                    <strong>{userDialog.active_sessions ?? 0}</strong>
                  </div>
                </div>
              </div>
              <div className="field">
                <span>Current Subscription Token</span>
                <div className="token-box wrap-anywhere">
                  <code>{userDialog.subscription_token}</code>
                </div>
                <div className="stack compact-stack">
                  <a className="inline-link wrap-anywhere" href={`/sub/${userDialog.subscription_token}`} target="_blank" rel="noreferrer">
                    Open raw /sub/{userDialog.subscription_token}
                  </a>
                  <a className="inline-link wrap-anywhere" href={`/subj/${userDialog.subscription_token}`} target="_blank" rel="noreferrer">
                    Open legacy /subj/{userDialog.subscription_token}
                  </a>
                </div>
              </div>
              <div className="field">
                <span>Subscription Access</span>
                <div className="protocol-matrix">
                  {nodes.map((node) => {
                    const availableProtocols = Array.isArray(node.supported_protocols) ? node.supported_protocols : [];
                    const nodeAllowed =
                      userForm.nodeAccessMode === "explicit"
                        ? userForm.allowedNodeIDs.includes(node.id)
                        : true;
                    return (
                      <article className="protocol-card" key={node.id}>
                        <div className="meta">
                          <span className="pill subtle">{node.name}</span>
                          <span className="muted-text wrap-anywhere">{node.domain}</span>
                        </div>
                        {availableProtocols.length === 0 ? (
                          <div className="empty-state">No supported protocols in this node config.</div>
                        ) : (
                          <div className="checkbox-list">
                            {availableProtocols.map((protocol) => {
                              const entry = userProtocolAccess.find((item) => item.node_id === node.id && item.protocol === protocol);
                              const checked = entry ? entry.enabled : true;
                              return (
                                <label className="check-row" key={`${node.id}-${protocol}`}>
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    disabled={!nodeAllowed}
                                    onChange={(event) => {
                                      const next = userProtocolAccess.filter((item) => !(item.node_id === node.id && item.protocol === protocol));
                                      next.push({
                                        user_id: userDialog.id,
                                        node_id: node.id,
                                        protocol,
                                        enabled: event.target.checked,
                                      });
                                      setUserProtocolAccess(next);
                                    }}
                                  />
                                  <span>{protocolLabel(protocol)}</span>
                                </label>
                              );
                            })}
                          </div>
                        )}
                      </article>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="dialog-actions">
              <button className="danger" disabled={userDialogBusy} onClick={removeUser}>Delete User</button>
              <button className="secondary" disabled={userDialogBusy} onClick={rotateSubscription}>Rotate Subscription</button>
              <button disabled={userDialogBusy} onClick={() => void submitUserDialog()}>
                {userDialogBusy ? "Saving..." : "Save User"}
              </button>
            </div>
            {userDialogNotice ? <div className="notice">{userDialogNotice}</div> : null}
          </section>
        </div>
      ) : null}

      {nodeDialog && nodeForm ? (
        <div className="overlay" onClick={closeNodeDialog}>
          <section className="dialog" onClick={(event) => event.stopPropagation()}>
            <div className="dialog-head">
              <div>
                <h2>Edit Node</h2>
                <p className="section-copy">Update identity, access defaults and send runtime commands.</p>
              </div>
              <button className="secondary" onClick={closeNodeDialog}>Close</button>
            </div>
            <div className="dialog-body">
              <div className="split split-3">
                <label className="field">
                  <span>Name</span>
                  <input value={nodeForm.name} onChange={(event) => setNodeForm({ ...nodeForm, name: event.target.value })} />
                </label>
                <label className="field">
                  <span>Domain</span>
                  <input value={nodeForm.domain} onChange={(event) => setNodeForm({ ...nodeForm, domain: event.target.value })} />
                </label>
                <label className="field">
                  <span>Port</span>
                  <input value={nodeForm.port} onChange={(event) => setNodeForm({ ...nodeForm, port: event.target.value })} inputMode="numeric" />
                </label>
              </div>
              <div className="split">
                <label className="field">
                  <span>Status</span>
                  <select value={nodeForm.status} onChange={(event) => setNodeForm({ ...nodeForm, status: event.target.value })}>
                    <option value="pending">pending</option>
                    <option value="online">online</option>
                    <option value="offline">offline</option>
                    <option value="disabled">disabled</option>
                  </select>
                </label>
                <label className="field">
                  <span>Default Access Policy</span>
                  <select value={nodeForm.defaultAccessPolicy} onChange={(event) => setNodeForm({ ...nodeForm, defaultAccessPolicy: event.target.value })}>
                    <option value="tag">tag</option>
                    <option value="nobody">nobody</option>
                    <option value="open">open</option>
                  </select>
                </label>
              </div>
              <div className="field">
                <span>Certificates</span>
                <div className="split">
                  <label className="field">
                    <span>Certificate Mode</span>
                    <select value={nodeForm.certificateMode} onChange={(event) => setNodeForm({ ...nodeForm, certificateMode: event.target.value })}>
                      <option value="disabled">disabled</option>
                      <option value="manual">manual</option>
                      <option value="acme">acme</option>
                    </select>
                  </label>
                  <div className="stat-box">
                    <span className="muted-text">Host Type</span>
                    <strong>{isIPAddressHost(nodeForm.domain) ? "ip" : "domain"}</strong>
                  </div>
                </div>
                {isIPAddressHost(nodeForm.domain) ? (
                  <div className="notice warn-box">Bare IP detected. ACME requires a real domain pointed at this node.</div>
                ) : null}
                <p className="muted-text wrap-anywhere">
                  {nodeDialog.certificate_message || "For ACME HTTP-01, DNS must resolve to this node and ports 80/443 must be reachable from the internet."}
                </p>
              </div>
              {nodeForm.defaultAccessPolicy === "tag" ? (
                <label className="field">
                  <span>Default Access Tag</span>
                  <input value={nodeForm.defaultAccessTag} onChange={(event) => setNodeForm({ ...nodeForm, defaultAccessTag: event.target.value })} />
                </label>
              ) : null}
              <div className="split">
                <div className="stat-box">
                  <span className="muted-text">Last seen</span>
                  <strong>{formatDateTime(nodeDialog.last_seen_at)}</strong>
                </div>
                <div className="stat-box">
                  <span className="muted-text">Versions</span>
                  <strong>{nodeDialog.agent_version || "unknown"} / {nodeDialog.singbox_version || "unknown"}</strong>
                </div>
                <div className="stat-box">
                  <span className="muted-text">Active users</span>
                  <strong>{nodeDialog.active_users ?? 0}</strong>
                </div>
              </div>
              <div className="field">
                <span>Node Config</span>
                <textarea
                  className="config-editor"
                  value={nodeConfigText}
                  onChange={(event) => setNodeConfigText(event.target.value)}
                  placeholder={`{\n  "inbounds": [\n    {\n      "tag": "trojan-in",\n      "type": "trojan",\n      "listen_port": 8443,\n      "tls": {\n        "enabled": true,\n        "acme": {\n          "enabled": true\n        }\n      }\n    },\n    {\n      "tag": "hysteria2-in",\n      "type": "hysteria2",\n      "listen_port": 8444\n    }\n  ]\n}`}
                />
                <p className="muted-text wrap-anywhere">
                  Node-local config should override node-specific TLS, ACME, Reality and non-global protocols. Global config owns the shared VLESS and Shadowsocks templates.
                </p>
                <div className="meta">
                  {(nodeDialog.supported_protocols ?? []).map((protocol) => (
                    <span className="pill subtle" key={protocol}>{protocolLabel(protocol)}</span>
                  ))}
                </div>
              </div>
              <div className="field">
                <span>Recent Node Events</span>
                {!Array.isArray(nodeEvents) || nodeEvents.length === 0 ? (
                  <div className="empty-state">No node events yet.</div>
                ) : (
                  <div className="event-list">
                    {nodeEvents.map((event) => (
                      <article className="event-card" key={event.id}>
                        <div className="meta">
                          <span className={`pill ${event.level === "error" ? "warn" : event.level === "warn" ? "subtle" : ""}`}>
                            {event.type}
                          </span>
                          <span className="pill subtle">{event.source}</span>
                          <span className="muted-text wrap-anywhere">{formatDateTime(event.created_at)}</span>
                        </div>
                        <p className="muted-text wrap-anywhere">{event.message}</p>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="dialog-actions wrap-actions">
              <button className="danger" disabled={nodeDialogBusy} onClick={removeNode}>Delete Node</button>
              <button className="secondary" disabled={nodeDialogBusy} onClick={rotateEnrollToken}>Rotate Enroll Token</button>
              <button className="secondary" disabled={nodeDialogBusy} onClick={() => void runNodeCommand("ping")}>Ping</button>
              <button className="secondary" disabled={nodeDialogBusy} onClick={() => void runNodeCommand("reload")}>Reload</button>
              <button className="secondary" disabled={nodeDialogBusy} onClick={() => void runNodeCommand("restart")}>Restart</button>
              <button disabled={nodeDialogBusy} onClick={() => void submitNodeDialog()}>
                {nodeDialogBusy ? "Saving..." : "Save Node"}
              </button>
            </div>
            {nodeDialogNotice ? <div className="notice wrap-anywhere">{nodeDialogNotice}</div> : null}
          </section>
        </div>
      ) : null}
    </>
  );
}
