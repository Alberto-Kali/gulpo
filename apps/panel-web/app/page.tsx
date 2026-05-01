import { HomeDashboard } from "../components/home-dashboard";

export const dynamic = "force-dynamic";

export default function Home() {
  return (
    <main className="page">
      <div className="shell">
        <section className="hero">
          <div className="meta">
            <span className="pill">MVP</span>
            <span className="pill">sing-box</span>
            <span className="pill">pull-based nodes</span>
          </div>
          <h1>Gulpo Control Plane</h1>
          <p>
            Single-admin panel for managing users, node enrollment, configuration layering,
            subscriptions, and traffic limits for independent sing-box nodes.
          </p>
        </section>
        <HomeDashboard />
      </div>
    </main>
  );
}
