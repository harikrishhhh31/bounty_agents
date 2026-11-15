import { useMemo, useState, type ReactNode } from "react";

type ScopeAsset = { identifier: string; normalized_identifier: string; asset_type: string; eligible: boolean; max_severity: string | null };
type Endpoint = { method: string; url: string; host: string; path: string; source: string; scope_status: string; asset_type: string | null; observation_count: number; methods: string[]; status_codes: number[]; content_types: string[]; authentication: string | null; reason: string };
type Finding = Record<string, unknown>;
type Evidence = Record<string, unknown>;
type Program = { program_name: string; own_accounts_only: boolean | null; prohibited_testing_categories: string[]; manual_attention: string[]; reporting_requirements: string[]; disclosure_restrictions: string[]; raw_markdown_reference: string };
type Validation = { program: Program; scope: { assets: ScopeAsset[] }; burp: { requests: number; format: string; scope_configuration: boolean; include_rules: number; exclude_rules: number }; intersection: { burp_observations: number; unique_endpoints: number; in_scope: number; out_of_scope: number; policy_restricted: number; assessment_candidates: number; effective_scope: number; burp_include_rules: number; burp_exclude_rules: number } };
type ToolInfo = { name: string; available: boolean; version: string | null; enabled: boolean };
type Overview = { validation_complete: boolean; counts: Record<string, number>; severity: Record<string, number>; finding_status: Record<string, number>; classification: Record<string, number>; intersection: Record<string, number>; external_tools: { enabled: string[]; checks: { check_id: string; status: string; reason: string }[] }; reports: { kind: string; filename: string }[] };

const API = "http://127.0.0.1:8765";
const tabs = ["Import", "Scope", "Burp Traffic", "Endpoints", "Findings", "Evidence", "Tools", "Reports"];

async function api(path: string, options?: RequestInit) {
  const response = await fetch(`${API}${path}`, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.message || payload.error || "Request failed");
  return payload;
}

async function readFile(file: File) {
  return { filename: file.name, content: await file.text() };
}

export function App() {
  const [activeTab, setActiveTab] = useState("Import");
  const [assets, setAssets] = useState<ScopeAsset[]>([]);
  const [program, setProgram] = useState<Program | null>(null);
  const [traffic, setTraffic] = useState<Record<string, unknown>[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [message, setMessage] = useState("Ready for passive imports");
  const [error, setError] = useState("");
  const [target, setTarget] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [hostFilter, setHostFilter] = useState("");
  const [scopeFilter, setScopeFilter] = useState("ALL");
  const [programRules, setProgramRules] = useState("");
  const [scopeFile, setScopeFile] = useState<File | null>(null);
  const [burpFile, setBurpFile] = useState<File | null>(null);
  const [validation, setValidation] = useState<Validation | null>(null);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [enabledTools, setEnabledTools] = useState<Record<string, boolean>>({});
  const [overview, setOverview] = useState<Overview | null>(null);
  const [busy, setBusy] = useState(false);

  async function importProgram(file: File | undefined) {
    if (!file) return;
    try {
      const result = await api("/program/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(await readFile(file)) });
      setProgram(result);
      setMessage(`${result.program_name} policy imported`);
      setError("");
    } catch (cause) { setError(String(cause)); }
  }

  async function validateEngagement() {
    if (!programRules.trim() || !scopeFile || !burpFile) return;
    setBusy(true); setError(""); setMessage("Validating inputs"); setValidation(null); setFindings([]); setEvidence([]);
    const form = new FormData();
    form.append("program_rules", programRules);
    form.append("scope_file", scopeFile, scopeFile.name);
    form.append("burp_file", burpFile, burpFile.name);
    try {
      const result = await api("/engagement/validate", { method: "POST", body: form });
      setValidation(result);
      setProgram(result.program);
      setAssets(result.scope.assets);
      const [ep, tr, tl] = await Promise.all([api("/endpoints"), api("/burp/traffic"), api("/tools")]);
      setEndpoints(ep.endpoints);
      setTraffic(tr.traffic);
      setTools(Object.values(tl.tools || {}));
      setOverview(null);
      setMessage("Program policy, scope CSV, and Burp HTTP history are valid");
    } catch (cause) { setError(String(cause)); setMessage("Validation failed"); }
    finally { setBusy(false); }
  }

  const counts = useMemo(() => ({
    hosts: new Set(endpoints.map((item) => item.host)).size,
    inScope: endpoints.filter((item) => item.scope_status === "IN_SCOPE").length,
    outScope: endpoints.filter((item) => item.scope_status === "OUT_OF_SCOPE").length,
    unsupported: endpoints.filter((item) => item.scope_status === "UNSUPPORTED").length,
  }), [endpoints]);

  const filteredEndpoints = endpoints.filter((item) => (!hostFilter || item.host.includes(hostFilter.toLowerCase())) && (scopeFilter === "ALL" || item.scope_status === scopeFilter));

  async function importScope(file: File | undefined) {
    if (!file) return;
    try {
      const result = await api("/scope/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(await readFile(file)) });
      setAssets(result.assets);
      setMessage(`${result.assets.length} scope assets imported`);
      setError("");
    } catch (cause) { setError(String(cause)); }
  }

  async function importBurp(file: File | undefined) {
    if (!file) return;
    try {
      const result = await api("/burp/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(await readFile(file)) });
      const inventory = result.inventory as Endpoint[];
      setEndpoints(inventory);
      setTraffic((await api("/burp/traffic")).traffic);
      setMessage(`${result.requests} Burp observations imported; ${inventory.length} unique endpoints normalized`);
      setError("");
    } catch (cause) { setError(String(cause)); }
  }

  async function refreshResults() {
    const [newFindings, newEvidence] = await Promise.all([api("/findings"), api("/evidence")]);
    setFindings(newFindings.findings);
    setEvidence(newEvidence.evidence);
  }

  async function runAssessment() {
    if (!validation) return;
    try {
      setBusy(true); setMessage("Assessing");
      const external_tools = Object.fromEntries(Object.entries(enabledTools).filter(([, on]) => on).map(([name]) => [name, { enabled: true, options: {} }]));
      const result = await api("/assessment/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_url: target || undefined, dry_run: dryRun, external_tools }) });
      setFindings(result.findings);
      setEvidence(result.evidence);
      const [tl, ov] = await Promise.all([api("/tools"), api("/overview")]);
      setTools(Object.values(tl.tools || {}));
      setOverview(ov);
      setMessage(`Assessment complete: ${result.findings.length} findings, ${result.evidence.length} evidence items`);
      setError("");
    } catch (cause) { setError(String(cause)); }
    finally { setBusy(false); }
  }

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand"><span className="brand-mark">API</span><div><strong>API Security Assessment</strong><small>AUTHORIZED LOCAL WORKFLOW</small></div></div>
      <div className="status"><span className="status-dot" />{message}</div>
    </header>
    <div className="workspace">
      <aside className="rail">
        <p className="rail-label">WORKSPACE</p>
        {tabs.map((tab, index) => <button key={tab} className={activeTab === tab ? "nav-item active" : "nav-item"} onClick={() => setActiveTab(tab)}><span>{String(index + 1).padStart(2, "0")}</span>{tab}</button>)}
        <div className="rail-note"><span>PASSIVE FIRST</span><p>Burp observations are never replayed during import.</p></div>
      </aside>
      <main className="main-content">
        <section className="page-heading"><div><p className="eyebrow">{activeTab === "Import" ? "NEW ENGAGEMENT" : "LOCAL OPERATIONS CONSOLE"}</p><h1>{activeTab === "Import" ? "API Security Assessment" : activeTab}</h1><p className="lede">HackerOne scope is authoritative. Imported traffic becomes evidence and inventory only.</p></div><div className="scope-chip"><span>BOUNDARY</span><strong>{assets.length ? `${assets.filter((asset) => asset.eligible).length} eligible assets` : "No scope loaded"}</strong></div></section>
        {error && <div className="error-banner">{error}</div>}
        {activeTab === "Import" && <EngagementInputView programRules={programRules} setProgramRules={(value) => { setProgramRules(value); setValidation(null); }} scopeFile={scopeFile} setScopeFile={(file) => { setScopeFile(file); setValidation(null); }} burpFile={burpFile} setBurpFile={(file) => { setBurpFile(file); setValidation(null); }} validation={validation} busy={busy} onValidate={validateEngagement} onRun={runAssessment} dryRun={dryRun} setDryRun={setDryRun} findings={findings} evidence={evidence} target={target} setTarget={setTarget} tools={tools} enabledTools={enabledTools} setEnabledTools={setEnabledTools} overview={overview} />}
        {activeTab === "Scope" && <ScopeView assets={assets} />}
        {activeTab === "Burp Traffic" && <TrafficView traffic={traffic} />}
        {activeTab === "Endpoints" && <EndpointView endpoints={filteredEndpoints} hostFilter={hostFilter} setHostFilter={setHostFilter} scopeFilter={scopeFilter} setScopeFilter={setScopeFilter} />}
        {activeTab === "Findings" && <FindingView findings={findings} onRefresh={refreshResults} />}
        {activeTab === "Evidence" && <EvidenceView evidence={evidence} onRefresh={refreshResults} />}
        {activeTab === "Tools" && <ToolsView tools={tools} enabledTools={enabledTools} setEnabledTools={setEnabledTools} overview={overview} />}
        {activeTab === "Reports" && <ReportView reports={overview?.reports || []} />}
      </main>
    </div>
  </div>;
}

function EngagementInputView({ programRules, setProgramRules, scopeFile, setScopeFile, burpFile, setBurpFile, validation, busy, onValidate, onRun, dryRun, setDryRun, findings, evidence, target, setTarget, tools, enabledTools, setEnabledTools, overview }: { programRules: string; setProgramRules: (value: string) => void; scopeFile: File | null; setScopeFile: (file: File | null) => void; burpFile: File | null; setBurpFile: (file: File | null) => void; validation: Validation | null; busy: boolean; onValidate: () => void; onRun: () => void; dryRun: boolean; setDryRun: (value: boolean) => void; findings: Finding[]; evidence: Evidence[]; target: string; setTarget: (value: string) => void; tools: ToolInfo[]; enabledTools: Record<string, boolean>; setEnabledTools: (value: Record<string, boolean>) => void; overview: Overview | null }) {
  const summary = validation?.intersection;
  return <>
    <section className="input-stack">
      <label className="rules-panel"><span className="panel-kicker">01 / PROGRAM RULES &amp; REGULATIONS</span><textarea value={programRules} onChange={(event) => setProgramRules(event.target.value)} placeholder="Paste program rules, safe harbor, prohibited testing, reporting requirements, and disclosure restrictions here." aria-label="Program rules and regulations" /></label>
      <UploadPanel step="02" title="HACKERONE SCOPE" accept=".csv,text/csv" file={scopeFile} onChange={setScopeFile} />
      <UploadPanel step="03" title="BURP SCOPE / TRAFFIC JSON" accept=".json,application/json" file={burpFile} onChange={setBurpFile} />
    </section>
    <div className="action-row"><button className="primary-button" disabled={busy || !programRules.trim() || !scopeFile || !burpFile} onClick={onValidate}>{busy ? "Working..." : "Validate inputs"}</button></div>
    {validation && summary && <section className="validation-summary"><div className="section-heading"><div><p className="eyebrow">VALIDATION PASSED</p><h2>Engagement intersection</h2></div></div><div className="validation-grid"><StatusBlock title="PROGRAM POLICY" detail={validation.program.program_name} extra="Policy source loaded" /><StatusBlock title="HACKERONE SCOPE" detail={`${validation.scope.assets.length} assets`} extra="CSV parsed" /><StatusBlock title="BURP SCOPE / TRAFFIC JSON" detail={validation.burp.scope_configuration ? "Burp Scope Configuration loaded" : `${validation.burp.requests} observations`} extra={`${validation.burp.include_rules} include / ${validation.burp.exclude_rules} exclude rules`} /></div><div className="metric-strip">{[["OBSERVED", summary.burp_observations], ["UNIQUE ENDPOINTS", summary.unique_endpoints], ["EFFECTIVE SCOPE", summary.effective_scope], ["IN SCOPE", summary.in_scope], ["OUT OF SCOPE", summary.out_of_scope], ["ASSESSMENT CANDIDATES", summary.assessment_candidates]].map(([label, value]) => <div className="metric" key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>{validation.program.manual_attention.length > 0 && <p className="manual-warning">Policy warning: manual confirmation required for {validation.program.manual_attention.length} rule(s).</p>}</section>}
    {validation && <section className="run-section"><div><p className="eyebrow">EXPLICIT ACTION</p><h2>Assess eligible targets</h2><p>Only observed, eligible, in-scope endpoints that pass policy and existing safety controls can reach the assessment engine. With scope-only JSON, traffic-dependent checks remain not run.</p></div><div className="run-controls"><input aria-label="Assessment target URL" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://api.example.com" /><label className="toggle"><input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} /> Dry run</label><button className="primary-button" disabled={busy} onClick={onRun}>Start assessment</button></div>{tools.length > 0 && <div className="tool-toggles"><span className="panel-kicker">EXTERNAL TOOLS</span>{tools.map((tool) => <label key={tool.name} className="toggle"><input type="checkbox" checked={!!enabledTools[tool.name]} disabled={!tool.available} onChange={(event) => setEnabledTools({ ...enabledTools, [tool.name]: event.target.checked })} /> {tool.name}{tool.available ? "" : " (unavailable)"}</label>)}</div>}{overview && overview.classification && Object.keys(overview.classification).length > 0 && <div className="classification-summary"><span className="panel-kicker">CLASSIFICATION</span>{Object.entries(overview.classification).map(([key, value]) => <span key={key}>{key}: {value}</span>)}</div>}</section>}
    {findings.length > 0 && <FindingView findings={findings} onRefresh={() => undefined} />}
    {evidence.length > 0 && <EvidenceView evidence={evidence} onRefresh={() => undefined} />}
    {findings.length > 0 && <ReportView reports={overview?.reports || []} />}
  </>;
}

function UploadPanel({ step, title, accept, file, onChange }: { step: string; title: string; accept: string; file: File | null; onChange: (file: File | null) => void }) {
  const isScope = title === "HACKERONE SCOPE";
  return <label className="upload-row"><span className="panel-kicker">{step} / {title}</span><small>{isScope ? "CSV scope rules" : "Accepts Burp scope configuration or supported HTTP traffic."}</small><span className="file-button">Choose {isScope ? "CSV" : "JSON"}</span><strong>{file ? `${file.name} ✓` : "No file selected"}</strong><input type="file" accept={accept} onChange={(event) => onChange(event.target.files?.[0] || null)} /></label>;
}

function StatusBlock({ title, detail, extra }: { title: string; detail: string; extra: string }) { return <article className="status-block"><Status value="VALID" /><strong>{title}</strong><b>{detail}</b><small>{extra}</small></article>; }

function ProgramView({ program, onProgram }: { program: Program | null; onProgram: (file: File | undefined) => void }) {
  return <><div className="import-grid"><ImportPanel title="PROGRAM OVERVIEW" hint="Authoritative Markdown rules" accept=".md,.markdown,.txt" onChange={onProgram} /></div>{program && <DataSection title={program.program_name} count={program.prohibited_testing_categories.length}><div className="policy-summary"><p><strong>Own accounts only:</strong> {program.own_accounts_only === true ? "Yes" : "Not deterministically stated"}</p><p><strong>Prohibited:</strong> {program.prohibited_testing_categories.join(", ") || "None deterministically extracted"}</p><p><strong>Manual attention:</strong> {program.manual_attention.join(" ") || "None"}</p><p><strong>Reporting:</strong> {program.reporting_requirements.join(" ") || "Not deterministically extracted"}</p></div></DataSection>}</>;
}

function ImportView({ onScope, onBurp, counts, target, setTarget, dryRun, setDryRun, onRun, programLoaded }: { onScope: (file: File | undefined) => void; onBurp: (file: File | undefined) => void; counts: Record<string, number>; target: string; setTarget: (value: string) => void; dryRun: boolean; setDryRun: (value: boolean) => void; onRun: () => void; programLoaded: boolean }) {
  return <><div className="import-grid"><ImportPanel title="HACKERONE SCOPE" hint="CSV, TSV, JSON, or YAML" accept=".csv,.tsv,.json,.yaml,.yml" onChange={onScope} /><ImportPanel title="BURP HTTP HISTORY" hint="Traffic-bearing Burp JSON or XML" accept=".json,.xml" onChange={onBurp} /></div><div className="metric-strip">{[["SCOPE ASSETS", counts.assets], ["BURP REQUESTS", counts.requests], ["UNIQUE HOSTS", counts.hosts], ["UNIQUE ENDPOINTS", counts.endpoints], ["IN SCOPE", counts.inScope], ["OUT OF SCOPE", counts.outScope]].map(([label, value]) => <div className="metric" key={label}><span>{label}</span><strong>{value}</strong></div>)}</div><section className="run-section"><div><p className="eyebrow">EXPLICIT ACTION</p><h2>Run the existing assessment engine</h2><p>{programLoaded ? "Program policy is loaded. " : "Policy warning: import Program Overview.md for policy context. "}Only normalized, in-scope endpoints are eligible.</p></div><div className="run-controls"><input aria-label="Assessment target URL" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://api.example.com" /><label className="toggle"><input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} /> Dry run</label><button className="primary-button" onClick={onRun}>Run assessment</button></div></section></>;
}

function ImportPanel({ title, hint, accept, onChange }: { title: string; hint: string; accept: string; onChange: (file: File | undefined) => void }) { return <label className="import-panel"><span className="panel-kicker">IMPORT</span><strong>{title}</strong><small>{hint}</small><span className="file-button">Choose file</span><input type="file" accept={accept} onChange={(event) => onChange(event.target.files?.[0])} /></label>; }
function ScopeView({ assets }: { assets: ScopeAsset[] }) { return <DataSection title="Authoritative HackerOne assets" count={assets.length}><table><thead><tr><th>Asset</th><th>Type</th><th>Eligibility</th><th>Max severity</th><th>Normalized target</th></tr></thead><tbody>{assets.map((asset) => <tr key={`${asset.identifier}-${asset.asset_type}`}><td>{asset.identifier}</td><td>{asset.asset_type}</td><td><Status value={asset.eligible ? "ELIGIBLE" : "INELIGIBLE"} /></td><td>{asset.max_severity || "Not specified"}</td><td>{asset.normalized_identifier}</td></tr>)}</tbody></table></DataSection>; }
function TrafficView({ traffic }: { traffic: Record<string, unknown>[] }) { return <DataSection title="Observed Burp traffic" count={traffic.length}><table><thead><tr><th>Host</th><th>Method</th><th>Path</th><th>Status</th><th>Content type</th><th>Scope</th></tr></thead><tbody>{traffic.map((item, index) => <tr key={`${String(item.id)}-${index}`}><td>{String(item.host)}</td><td><code>{String(item.method)}</code></td><td>{String(item.path)}</td><td>{String(item.status || "-")}</td><td>{String(item.content_type || "-")}</td><td><Status value={String(item.scope_status || "PENDING")} /></td></tr>)}</tbody></table></DataSection>; }
function EndpointView({ endpoints, hostFilter, setHostFilter, scopeFilter, setScopeFilter }: { endpoints: Endpoint[]; hostFilter: string; setHostFilter: (value: string) => void; scopeFilter: string; setScopeFilter: (value: string) => void }) { return <DataSection title="Normalized endpoint inventory" count={endpoints.length}><div className="filters"><input value={hostFilter} onChange={(event) => setHostFilter(event.target.value)} placeholder="Filter host" /><select value={scopeFilter} onChange={(event) => setScopeFilter(event.target.value)}><option>ALL</option><option>IN_SCOPE</option><option>OUT_OF_SCOPE</option><option>UNSUPPORTED</option></select></div><table><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Source</th><th>Scope</th><th>Auth</th><th>Status</th><th>Observations</th></tr></thead><tbody>{endpoints.map((item) => <tr key={`${item.method}-${item.url}`}><td><code>{item.method}</code></td><td>{item.host}</td><td>{item.path}</td><td>{item.source}</td><td><Status value={item.scope_status} /></td><td>{item.authentication || "-"}</td><td>{item.status_codes.join(", ") || "-"}</td><td>{item.observation_count}</td></tr>)}</tbody></table></DataSection>; }
function FindingView({ findings, onRefresh }: { findings: Finding[]; onRefresh: () => void }) { return <DataSection title="Assessment findings" count={findings.length} action={<button className="text-button" onClick={onRefresh}>Refresh</button>}><table><thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Method</th><th>Endpoint</th><th>Identity</th><th>Status</th></tr></thead><tbody>{findings.map((item, index) => <tr key={`${String(item.finding_id)}-${index}`}><td>{String(item.title)}</td><td>{String(item.category)}</td><td><Status value={String(item.severity)} /></td><td>{String(item.confidence)}</td><td>{String(item.method || "-")}</td><td>{String(item.endpoint)}</td><td>{String(item.identity || "-")}</td><td>{String(item.status)}</td></tr>)}</tbody></table></DataSection>; }
function EvidenceView({ evidence, onRefresh }: { evidence: Evidence[]; onRefresh: () => void }) { return <DataSection title="Evidence ledger" count={evidence.length} action={<button className="text-button" onClick={onRefresh}>Refresh</button>}><div className="evidence-list">{evidence.map((item, index) => <article className="evidence-row" key={`${String(item.evidence_id)}-${index}`}><div><code>{String(item.evidence_id)}</code><strong>{String(item.check_id)}</strong></div><p>{String(item.observation)}</p><dl><div><dt>Expected</dt><dd>{String(item.expected_behavior)}</dd></div><div><dt>Observed</dt><dd>{String(item.actual_behavior)}</dd></div></dl></article>)}</div></DataSection>; }
function ReportView({ reports }: { reports: { kind: string; filename: string }[] }) {
  const kinds = ["json", "markdown", "html"];
  const available = new Set(reports.map((item) => item.kind));
  return <DataSection title="Generated reports" count={reports.length || 0}><div className="report-links">{kinds.map((kind) => <a key={kind} href={`${API}/reports/${kind}`} target="_blank">{kind.toUpperCase()} report {available.has(kind) ? "✓" : ""} <span>↗</span></a>)}</div></DataSection>;
}
function ToolsView({ tools, enabledTools, setEnabledTools, overview }: { tools: ToolInfo[]; enabledTools: Record<string, boolean>; setEnabledTools: (value: Record<string, boolean>) => void; overview: Overview | null }) {
  return <DataSection title="External tools" count={tools.length}>
    <table><thead><tr><th>Tool</th><th>Available</th><th>Version</th><th>Enabled</th></tr></thead><tbody>{tools.map((tool) => <tr key={tool.name}><td>{tool.name}</td><td><Status value={tool.available ? "AVAILABLE" : "MISSING"} /></td><td>{tool.version || "-"}</td><td><input type="checkbox" checked={!!enabledTools[tool.name]} disabled={!tool.available} onChange={(event) => setEnabledTools({ ...enabledTools, [tool.name]: event.target.checked })} /></td></tr>)}</tbody></table>
    {overview && overview.external_tools && overview.external_tools.checks && overview.external_tools.checks.length > 0 && <div className="evidence-list">{overview.external_tools.checks.map((check, index) => <article className="evidence-row" key={`${check.check_id}-${index}`}><div><code>{check.check_id}</code><strong>{check.status}</strong></div><p>{check.reason}</p></article>)}</div>}
    {overview && overview.classification && Object.keys(overview.classification).length > 0 && <div className="classification-summary"><span className="panel-kicker">CLASSIFICATION</span>{Object.entries(overview.classification).map(([key, value]) => <span key={key}>{key}: {value}</span>)}</div>}
  </DataSection>;
}
function DataSection({ title, count, action, children }: { title: string; count: number; action?: ReactNode; children: ReactNode }) { return <section className="data-section"><div className="section-heading"><div><p className="eyebrow">INVENTORY</p><h2>{title}</h2></div><div className="section-tools"><span className="count">{count}</span>{action}</div></div><div className="table-wrap">{children}</div></section>; }
function Status({ value }: { value: string }) { const tone = value.toLowerCase().includes("in_scope") || value === "ELIGIBLE" ? "good" : value.toLowerCase().includes("out") || value === "INELIGIBLE" ? "bad" : value.toLowerCase().includes("high") || value.toLowerCase().includes("critical") ? "warn" : "neutral"; return <span className={`status-pill ${tone}`}>{value.replaceAll("_", " ")}</span>; }
