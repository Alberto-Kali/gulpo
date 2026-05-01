import { ProfileActions } from "../../../components/profile-actions";
import { getSubjProfiles } from "../../../lib/server-api";

export const dynamic = "force-dynamic";

export default async function SubjPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const result = await getSubjProfiles(token);

  if (!result.data) {
    return (
      <main className="page">
        <div className="shell">
          <section className="hero client-hero">
            <div className="meta">
              <span className="pill warn">Unavailable</span>
              <span className="pill subtle">/subj</span>
            </div>
            <h1>Profile list unavailable</h1>
            <p>{result.error ?? "The subscription token could not be resolved."}</p>
          </section>
        </div>
      </main>
    );
  }

  const { data } = result;
  const profiles = Array.isArray(data.profiles) ? data.profiles : [];

  function transportLabel(protocol: string, transportMode?: string, maskHost?: string) {
    if (protocol === "vless" && transportMode === "reality") {
      return `VLESS Reality via ${maskHost || "www.gosuslugi.ru"}`;
    }
    if (protocol === "hysteria2") {
      return "Hysteria2 via QUIC/TLS";
    }
    if (protocol === "shadowsocks" && transportMode === "shadowtls") {
      return `Shadowsocks via ShadowTLS${maskHost ? ` (${maskHost})` : ""}`;
    }
    if (transportMode) {
      return `${protocol} via ${transportMode}`;
    }
    return protocol;
  }

  return (
    <main className="page">
      <div className="shell">
          <section className="hero client-hero">
            <div className="meta">
              <span className="pill">Happ</span>
              <span className="pill">Multi-protocol</span>
            <span className="pill subtle">{data.user_status}</span>
            </div>
            <h1>{data.user_name || "Subscription Profiles"}</h1>
            <p>
              Use these import-ready profiles to connect your apps to any available node and protocol.
              Copy the full URI, and for protocols that need it, copy the UUID or password separately.
            </p>
          </section>

        <section className="panel panel-span-3">
          <div className="section-head">
            <div>
              <h2>Available Profiles</h2>
              <p className="section-copy">Token: <span className="wrap-anywhere token-inline">{data.subscription_token}</span></p>
            </div>
          </div>

          {data.message ? <div className="notice">{data.message}</div> : null}

          <div className="card-list subj-list">
            {profiles.map((profile) => (
              <article className="card profile-card" key={`${profile.node_id}-${profile.protocol}-${profile.port}`}>
                <div className="profile-main">
                  <div className="meta">
                    <span className="pill">{profile.status}</span>
                    <span className="pill">{profile.protocol}</span>
                    {profile.transport_mode ? <span className="pill subtle">{profile.transport_mode}</span> : null}
                    {profile.method ? <span className="pill subtle">{profile.method}</span> : null}
                    <span className="pill subtle">{profile.port}</span>
                  </div>
                  <h3>{profile.name}</h3>
                  <p className="section-copy">{transportLabel(profile.protocol, profile.transport_mode, profile.mask_host)}</p>
                  <div className="profile-grid">
                    <div className="field-readonly">
                      <span>Server</span>
                      <strong className="wrap-anywhere">{profile.server}</strong>
                    </div>
                    {profile.password_masked ? (
                      <div className="field-readonly">
                        <span>Password</span>
                        <strong className="wrap-anywhere">{profile.password_masked}</strong>
                      </div>
                    ) : null}
                    {profile.uuid ? (
                      <div className="field-readonly">
                        <span>UUID</span>
                        <strong className="wrap-anywhere">{profile.uuid}</strong>
                      </div>
                    ) : null}
                    {profile.sni ? (
                      <div className="field-readonly">
                        <span>SNI</span>
                        <strong className="wrap-anywhere">{profile.sni}</strong>
                      </div>
                    ) : null}
                    {profile.mask_host ? (
                      <div className="field-readonly">
                        <span>Mask Host</span>
                        <strong className="wrap-anywhere">{profile.mask_host}</strong>
                      </div>
                    ) : null}
                    {profile.flow ? (
                      <div className="field-readonly">
                        <span>Flow</span>
                        <strong className="wrap-anywhere">{profile.flow}</strong>
                      </div>
                    ) : null}
                    {profile.public_key ? (
                      <div className="field-readonly">
                        <span>Public Key</span>
                        <strong className="wrap-anywhere">{profile.public_key}</strong>
                      </div>
                    ) : null}
                    {profile.short_id ? (
                      <div className="field-readonly">
                        <span>Short ID</span>
                        <strong className="wrap-anywhere">{profile.short_id}</strong>
                      </div>
                    ) : null}
                    {profile.fingerprint ? (
                      <div className="field-readonly">
                        <span>Fingerprint</span>
                        <strong className="wrap-anywhere">{profile.fingerprint}</strong>
                      </div>
                    ) : null}
                    {profile.alpn?.length ? (
                      <div className="field-readonly">
                        <span>ALPN</span>
                        <strong className="wrap-anywhere">{profile.alpn.join(", ")}</strong>
                      </div>
                    ) : null}
                    {profile.obfs ? (
                      <div className="field-readonly">
                        <span>Obfuscation</span>
                        <strong className="wrap-anywhere">{profile.obfs}</strong>
                      </div>
                    ) : null}
                  </div>
                  <div className="field-readonly">
                    <span>{profile.protocol} URI</span>
                    <code className="token-box wrap-anywhere">{profile.uri}</code>
                  </div>
                </div>
                <ProfileActions
                  protocol={profile.protocol}
                  clientPassword={profile.client_password}
                  publicKey={profile.public_key}
                  shortID={profile.short_id}
                  uri={profile.uri}
                  uuid={profile.uuid}
                />
              </article>
            ))}
            {profiles.length === 0 ? (
              <article className="card profile-card">
                <div className="profile-main">
                  <h3>No profiles available</h3>
                  <p className="section-copy">
                    {data.message || "This subscription currently has no eligible profiles."}
                  </p>
                </div>
              </article>
            ) : null}
          </div>
        </section>
      </div>
    </main>
  );
}
