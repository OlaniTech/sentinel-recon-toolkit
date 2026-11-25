import { useRef, useState } from "react";

type Module = "subdomains" | "ports" | "services" | "headers";
type Finding = {
  id: string;
  severity: "High" | "Medium" | "Low" | "Info";
  module: string;
  target: string;
  title: string;
  evidence: string;
};

const modules: { key: Module; label: string; detail: string }[] = [
  { key: "subdomains", label: "Subdomain discovery", detail: "Passive DNS + certificate transparency" },
  { key: "ports", label: "Port scan", detail: "Top 1,000 TCP ports" },
  { key: "services", label: "Service fingerprinting", detail: "Banner and protocol detection" },
  { key: "headers", label: "Header review", detail: "Security header baseline" },
];

function buildFindings(domain: string, enabled: Module[]): Finding[] {
  const all: Finding[] = [
    { id: "F-001", severity: "High", module: "headers", target: `admin.${domain}`, title: "Missing Content-Security-Policy", evidence: "Response header 'Content-Security-Policy' not present on /login" },
    { id: "F-002", severity: "Medium", module: "services", target: `api.${domain}:443`, title: "Outdated TLS configuration", evidence: "TLSv1.0 advertised in handshake; prefer TLSv1.2+" },
    { id: "F-003", severity: "Medium", module: "headers", target: `www.${domain}`, title: "Missing HSTS header", evidence: "Strict-Transport-Security absent on HTTPS response" },
    { id: "F-004", severity: "Low", module: "ports", target: `dev.${domain}:8080`, title: "Unexpected service exposed", evidence: "HTTP service responding on non-standard port 8080" },
    { id: "F-005", severity: "Low", module: "services", target: `mail.${domain}:25`, title: "SMTP version disclosed", evidence: "Banner reveals server build identifier" },
    { id: "F-006", severity: "Info", module: "subdomains", target: `staging.${domain}`, title: "Staging host discovered", evidence: "Found via certificate transparency log" },
    { id: "F-007", severity: "Info", module: "subdomains", target: `cdn.${domain}`, title: "CDN host discovered", evidence: "Found via passive DNS record" },
  ];
  return all.filter((f) => {
    const map: Record<string, Module> = { headers: "headers", services: "services", ports: "ports", subdomains: "subdomains" };
    return enabled.includes(map[f.module] ?? "subdomains");
  });
}

export function App() {
  const [domain, setDomain] = useState("example.com");
  const [enabled, setEnabled] = useState<Module[]>(["subdomains", "ports", "services", "headers"]);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [lines, setLines] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scopeConfirmed, setScopeConfirmed] = useState(true);
  const timer = useRef<number | null>(null);

  const toggle = (key: Module) =>
    setEnabled((prev) => (prev.includes(key) ? prev.filter((m) => m !== key) : [...prev, key]));

  const run = () => {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || enabled.length === 0 || !scopeConfirmed) return;
    if (timer.current) window.clearInterval(timer.current);
    setRunning(true);
    setProgress(0);
    setLines([`[init] scope=${domain} modules=${enabled.join(",")}`]);
    setFindings([]);
    const steps = [
      "[dns] enumerating passive records…",
      `[ctx] querying certificate transparency for ${domain}…`,
      "[scan] probing top 1,000 TCP ports…",
      "[svc] fingerprinting discovered services…",
      "[http] evaluating security headers…",
      "[done] deduplicating and correlating results…",
    ];
    let step = 0;
    timer.current = window.setInterval(() => {
      setProgress((p) => {
        const next = p + 100 / steps.length;
        if (step < steps.length) {
          setLines((prev) => [...prev, steps[step] ?? ""]);
          step += 1;
        }
        if (next >= 100) {
          if (timer.current) window.clearInterval(timer.current);
          setRunning(false);
          setFindings(buildFindings(domain, enabled));
          return 100;
        }
        return next;
      });
    }, 550);
  };

  const exportReport = () => {
    const report = {
      tool: "Sentinel Recon Toolkit",
      vendor: "SYFERON",
      scope: domain,
      authorized: scopeConfirmed,
      generated_at: new Date().toISOString(),
      modules: enabled,
      finding_count: findings.length,
      findings,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-${domain}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand"><span className="brand-mark">SR</span><span>Sentinel <b>Recon Toolkit</b></span></div>
        <span className="auth-badge">Authorized assessments only</span>
      </header>
      <main className="main">
        <div className="page-head">
          <div><p className="eyebrow">Reconnaissance console</p><h1>Engagement workspace</h1></div>
          <p className="sub">Repeatable results. Auditable scope. Visible evidence.</p>
        </div>
        <div className="grid">
          <section className="panel config">
            <p className="panel-title">Scan configuration</p>
            <label className="field">Target domain
              <input value={domain} onChange={(e) => setDomain(e.target.value.toLowerCase())} spellCheck={false} />
            </label>
            <label className="check"><input type="checkbox" checked={scopeConfirmed} onChange={(e) => setScopeConfirmed(e.target.checked)} /> I confirm this domain is in scope for authorized testing.</label>
            <p className="panel-title modules-title">Modules</p>
            {modules.map((m) => (
              <label className="module" key={m.key}>
                <input type="checkbox" checked={enabled.includes(m.key)} onChange={() => toggle(m.key)} />
                <span><b>{m.label}</b><small>{m.detail}</small></span>
              </label>
            ))}
            <button className="run" onClick={run} disabled={running || !scopeConfirmed || enabled.length === 0}>
              {running ? "Scanning…" : "Run scan"}
            </button>
            {progress > 0 && (
              <div className="progress"><div style={{ width: `${progress}%` }} /></div>
            )}
            <p className="legal">This tool simulates recon output for demonstration. Only test systems you are explicitly authorized to assess.</p>
          </section>

          <section className="panel console">
            <p className="panel-title">Run log</p>
            <div className="terminal">
              {lines.length === 0 && <p className="dim">$ awaiting scan…</p>}
              {lines.map((l, i) => <p key={i} className={l.startsWith("[done]") ? "ok" : ""}>{l}</p>)}
              {running && <p className="cursor">▊</p>}
            </div>
            <div className="stat-strip">
              <div><b>{findings.length}</b><span>findings</span></div>
              <div><b>{enabled.length}</b><span>modules</span></div>
              <div><b>{progress}%</b><span>complete</span></div>
            </div>
          </section>

          <section className="panel results">
            <div className="results-head">
              <p className="panel-title">Findings</p>
              {findings.length > 0 && <button className="export" onClick={exportReport}>Export JSON</button>}
            </div>
            {findings.length === 0 ? (
              <p className="dim">Run a scan to populate findings.</p>
            ) : (
              <div className="finding-list">
                {findings.map((f) => (
                  <div className="finding" key={f.id}>
                    <div className="finding-top"><span className={`sev ${f.severity.toLowerCase()}`}>{f.severity}</span><code>{f.id}</code><span className="mod">{f.module}</span></div>
                    <b>{f.title}</b>
                    <p className="target">{f.target}</p>
                    <p className="evidence">{f.evidence}</p>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </main>
      <footer className="watermark"><span className="wm-mark">SY</span> SYFERON</footer>
    </div>
  );
}
