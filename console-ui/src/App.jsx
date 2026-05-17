import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import AppSidebar from './components/AppSidebar';
import HeroCard from './components/HeroCard';
import RepoView from './components/RepoView';
import WatchView from './components/WatchView';
import HistoryView from './components/HistoryView';
import TestsView from './components/TestsView';
import SettingsView from './components/SettingsView';
import AnalyticsView from './components/AnalyticsView';
import ReportsView from './components/ReportsView';
import ScannerCPG from './components/ScannerCPG';
import PentestView from './components/PentestView';
import { useAuth } from './lib/AuthContext';
import { API_BASE } from './lib/api';
import { openReportWindow } from './lib/reportBuilder';
import CodeWindow from './components/CodeWindow';

function ScanView({ data, loading, error, onScan, onApplyFix, onGenerateReport, onViewGraph, llmConfig, patching, setPatching, patchResults, setPatchResults, repo, setRepo, pr, setPr }) {
  const [activeAgent, setActiveAgent] = useState('ss');
  const [includeCpg, setIncludeCpg] = useState(false);

  if (!data && !loading && !error) {
    return (
      <div className="pane-wrap">
        <h1 className="pane-h">Scan a Pull Request</h1>
        <p className="pane-sub">Enter GitHub details to start an automated security analysis.</p>
        <div className="glass form-card" style={{ gridTemplateColumns: '1fr 120px auto' }}>
          <div className="field"><label>Repository</label><input placeholder="owner/repo" value={repo} onChange={e => setRepo(e.target.value)} /></div>
          <div className="field"><label>PR #</label><input type="number" placeholder="42" value={pr} onChange={e => setPr(e.target.value)} /></div>
          <button className="btn-primary" onClick={() => onScan(repo, pr, includeCpg)}>Scan Pull Request</button>
        </div>
        <div className="option-toolbar">
          <div className="option-item">
            <span style={{ fontWeight: 600 }}>Analysis Options:</span>
          </div>
          <div className="option-item">
            <label className="switch">
              <input type="checkbox" checked={includeCpg} onChange={e => setIncludeCpg(e.target.checked)} />
              <span className="slider"></span>
            </label>
            <span>Include CPG Graph</span>
          </div>
          <div className="option-item" style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--text-3)' }}>
            Deep AST/CFG analysis using Joern & FalkorDB
          </div>
        </div>
      </div>
    );
  }

  if (loading) return <div className="state-box"><div className="spin-lg"></div><p>Analyzing PR #{pr}...</p></div>;
  if (error) return <div className="err-box">{error} <button onClick={() => onScan(repo, pr)}>Retry</button></div>;

  const agents = data.agents || [];
  const agent = agents.find(a => a.id === activeAgent) || agents[0];
  // Build patches map from findings
  const patches = {};
  (data.findings || []).forEach(f => {
    const loc = `${f.file || '?'}:${f.line || '?'}`;
    patches[loc] = { _finding: { filename: f.file, line: f.line, technique: f.tech, severity: f.severity, description: f.plain, evidence: f.before }, strategy: f.tech || 'manual_review', before: f.before || '', _evidence: f.before || '', after: f.after || '' };
  });

  const requestPatch = (loc) => {
    setPatchResults(prev => { const n = { ...prev }; delete n[loc]; return n; });
    setPatching(p => ({ ...p, [loc]: 'gen' }));
    const spec = patches[loc];
    if (!spec?._finding) { setTimeout(() => setPatching(p => ({ ...p, [loc]: 'done' })), 1500); return; }
    fetch(`${API_BASE}/api/v1/patch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_json: JSON.stringify(spec._finding), source_code: spec.before || '', filename: spec._finding.filename || 'unknown', repo: data.meta?.repo || '', ...(llmConfig || {}) }),
    }).then(r => r.json()).then(d => {
      const best = d.selected_fix || d.best_candidate || {};
      const patch = best.patch || {};
      const vr = d.verifier_report || {};
      setPatchResults(prev => ({ ...prev, [loc]: { before: d.original_source || spec.before || '', after: patch.patched_source || best.patched_source || d.patched_code || '', evidence: spec._evidence || '', confidence: best.confidence ?? null, risk: best.risk || null, breaking: best.breaking_change ?? null, shannon: d.shannon_verdict || vr.shannon_verdict || null, blocklist: vr.blocklist_verdict || null, fully_verified: vr.fully_verified ?? null, strategy: best.strategy || spec.strategy, description: best.description || '', target_line: patch.target_line || spec._finding?.line || null, filename: patch.filename || spec._finding?.filename || null } }));
      setPatching(p => ({ ...p, [loc]: 'done' }));
    }).catch(() => setPatching(p => ({ ...p, [loc]: 'error' })));
  };

  const patchLocs = Object.keys(patches);

  return (
    <div className="pane-wrap">
      <HeroCard data={data.meta} onNewScan={() => onScan(null)} onApplyFix={onApplyFix} onGenerateReport={onGenerateReport ? () => onGenerateReport(data.meta) : null} onViewGraph={onViewGraph} />

      <div className="section-h" style={{ marginBottom: 14, marginTop: 20 }}>
        <h2>Agent pipeline</h2>
        <span className="count">click any agent to see what it found</span>
      </div>
      <div className="chain">
        {agents.map((a, i) => (
          <React.Fragment key={a.id}>
            <div className={`chain-node ${activeAgent === a.id ? 'active' : ''}`} onClick={() => setActiveAgent(a.id)}>
              <div className="chain-icon">{a.icon}</div>
              <div className="chain-name">{a.name}</div>
              <div className="chain-task">{a.task}</div>
              <div className="chain-score">{a.state}</div>
            </div>
            {i < agents.length - 1 && <div className="chain-arrow">→</div>}
          </React.Fragment>
        ))}
      </div>

      <div className="agent-pane">
        <div className="agent-pane-h">
          <div className="chain-icon" style={{ margin: 0, width: 32, height: 32, fontSize: 14 }}>{agent?.icon}</div>
          <div className="name">{agent?.name}</div>
        </div>
        <div className="agent-pane-sub">{agent?.task}</div>

        {agent?.id === 'pf' ? (
          patchLocs.length === 0 ? (
            <div className="pf-empty"><div className="pf-icon">🛠</div><div>No fixable issues found.</div></div>
          ) : (
            <>
              <div className="pf-cta">
                <div className="pf-cta-title">Generate safe fixes for all issues</div>
                <button className="btn-accent" onClick={() => patchLocs.filter(l => !patching[l] && !patchResults[l]).forEach(l => requestPatch(l))} disabled={patchLocs.every(l => patching[l] || patchResults[l])}>Generate {patchLocs.length} patch{patchLocs.length !== 1 ? 'es' : ''}</button>
              </div>
              {patchLocs.map(loc => {
                const state = patching[loc]; const live = patchResults[loc];
                return (
                  <div key={loc} className="a-find" style={{ padding: '16px 18px', marginTop: 10 }}>
                    <div className="a-find-top"><span className="a-find-title">{loc}</span>
                      {live?.fully_verified && <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: 'var(--low)', background: 'rgba(107,224,168,0.12)' }}>✓ Verified</span>}
                    </div>
                    {!state && !live && <button className="btn-accent" onClick={() => requestPatch(loc)} style={{ marginTop: 8, padding: '8px 16px', fontSize: 12 }}>Generate patch</button>}
                    {state === 'gen' && <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, color: 'var(--text-2)', fontSize: 13 }}><span className="pf-spin" style={{ borderColor: 'rgba(124,131,255,0.4)', borderTopColor: 'var(--accent)' }} />Generating…</div>}
                    {state === 'error' && <div style={{ color: 'var(--crit)', fontSize: 13, marginTop: 10 }}>PatchForge failed. <button className="btn-link" onClick={() => requestPatch(loc)}>Retry</button></div>}
                    {(state === 'done' || (!state && live)) && live && (
                      <>
                        <div className="pf-dual" style={{ marginTop: 10 }}>
                          <div className="pf-pane">
                            <div className="pf-pane-h bad">Before</div>
                            <CodeWindow source={live.before || ''} focusLine={live.target_line} context={5} variant="bad" />
                          </div>
                          <div className="pf-pane">
                            <div className="pf-pane-h good">After · line {live.target_line || '?'}</div>
                            <CodeWindow source={live.after || live.before || ''} focusLine={live.target_line} context={5} variant={live.after ? "good" : "bad"} />
                          </div>
                        </div>
                        <div style={{ marginTop: 14, display: 'flex', gap: 10 }}>
                          <button className="btn-primary" style={{ padding: '8px 16px', fontSize: 12, background: 'var(--accent)', borderColor: 'transparent' }} onClick={() => {
                            if (confirm(`Are you sure you want to overwrite ${live.filename} in your local workspace?`)) {
                              fetch(`${API_BASE}/api/v1/apply-local-patch`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                  filename: live.filename,
                                  patched_source: live.after
                                })
                              }).then(r => r.json()).then(d => {
                                if (d.status === 'success') alert('Success! File patched in your local workspace.');
                                else alert('Failed to patch file: ' + (d.error || d.detail));
                              });
                            }
                          }}>Apply to Local File</button>
                          <button className="btn-ghost" style={{ padding: '8px 16px', fontSize: 12 }} onClick={() => {
                            window.dispatchEvent(new CustomEvent('sentinel:open-fix-pr', { 
                              detail: { 
                                fix: {
                                  filename: live.filename,
                                  patched_source: live.after,
                                  fix_strategy: live.strategy,
                                  fix_description: live.description,
                                  blocklist_verdict: live.blocklist,
                                  shannon_verdict: live.shannon
                                },
                                file: live.filename,
                                line: live.target_line,
                                tech: live.strategy,
                                severity: 'HIGH', // Fallback
                                plain: live.description,
                                before: live.before
                              } 
                            }));
                          }}>Open Remediation PR</button>
                          <button className="btn-accent" style={{ padding: '8px 16px', fontSize: 12, background: 'var(--low)', borderColor: 'transparent' }} onClick={() => {
                            if (!ghToken) { alert('GitHub token required'); return; }
                            fetch(`${API_BASE}/api/v1/suggest-fix`, {
                              method: 'POST',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({
                                repo: scanData.meta.repo,
                                pr_number: parseInt(scanData.meta.pr),
                                filename: live.filename,
                                line: live.target_line,
                                patched_code: live.after,
                                description: live.description,
                                github_token: ghToken
                              })
                            }).then(r => r.json()).then(d => {
                              if (d.status === 'success') alert('Suggestion posted to GitHub!');
                              else alert('Failed to post suggestion: ' + (d.error || d.detail));
                            });
                          }}>Post Suggestion to GitHub</button>
                          <button className="btn-ghost" style={{ padding: '8px 16px', fontSize: 12 }} onClick={() => setDiffFinding({ ...live, file: live.filename, line: live.target_line })}>Compare Side-by-Side</button>
                        </div>
                      </>
                    )}

                  </div>


                );
              })}
            </>
          )
        ) : (
          <div style={{ marginTop: 10 }}>
            {(data.findings || []).filter(f => agent?.id === 'ss' ? f.detected_by === 'ShadowStalker' : agent?.id === 'arch' ? f.detected_by === 'Archeologist' : true).length === 0 ? (
              <div className="pf-empty"><div className="pf-icon">✓</div><div>No issues from {agent?.name}.</div></div>
            ) : (
              (data.findings || []).filter(f => agent?.id === 'ss' ? f.detected_by === 'ShadowStalker' : agent?.id === 'arch' ? f.detected_by === 'Archeologist' : true).map((f, i) => (
                <div key={i} className="a-find">
                  <div className="a-find-top">
                    <span className={`sev-chip ${f.severity}`}>{f.severity}</span>
                    <span className="a-find-title">{f.title}</span>
                    <span className="a-find-loc">{f.file}:{f.line}</span>
                  </div>
                  <div className="a-find-desc">{f.plain}</div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}


function DiffModal({ finding, onClose }) {
  if (!finding) return null;
  return (
    <div
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: 'var(--bg-1, #15192a)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 12, maxWidth: 1100, width: '100%', maxHeight: '85vh', overflow: 'auto', padding: 24 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 14 }}>
          <h2 style={{ margin: 0, fontSize: 16 }}>Diff · {finding.file}{finding.line ? `:${finding.line}` : ''}</h2>
          <button className="btn-ghost" style={{ marginLeft: 'auto' }} onClick={onClose}>Close</button>
        </div>
        <div className="pf-dual">
          <div className="pf-pane">
            <div className="pf-pane-h bad">Before · line {finding.line || '?'}</div>
            <CodeWindow source={finding.before || ''} focusLine={finding.line} context={10} variant="bad" />
          </div>
          <div className="pf-pane">
            <div className="pf-pane-h good">After · line {finding.line || '?'}</div>
            <CodeWindow source={finding.after || finding.fix?.patched_source || ''} focusLine={finding.line} context={10} variant="good" />
          </div>
        </div>
        {finding.fix?.desc && (
          <div style={{ marginTop: 14, color: 'var(--text-2)', fontSize: 13 }}>{finding.fix.desc}</div>
        )}
      </div>
    </div>
  );
}

function App() {
  const [tab, setTab] = useState('scan');
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [diffFinding, setDiffFinding] = useState(null);
  const [preloadedGraph, setPreloadedGraph] = useState(null);
  
  // Persistence for Scan tab
  const [repo, setRepo] = useState('');
  const [pr, setPr] = useState('');
  const [patching, setPatching] = useState({});
  const [patchResults, setPatchResults] = useState({});
  const { user, ghToken, updateGhToken, provider, model, aisaKey } = useAuth();

  // View-Diff modal
  useEffect(() => {
    const h = (e) => setDiffFinding(e.detail || null);
    window.addEventListener('sentinel:view-diff', h);
    return () => window.removeEventListener('sentinel:view-diff', h);
  }, []);

  useEffect(() => {
    const handler = async (e) => {
      const f = e.detail;
      if (!scanData?.meta || !f?.fix?.patched_source) {
        alert('No patched source available for this finding.');
        return;
      }
      if (!ghToken) {
        alert('GitHub token required (Settings).');
        return;
      }
      try {
        const res = await fetch(`${API_BASE}/api/v1/create-fix-pr`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repo: scanData.meta.repo,
            pr_number: parseInt(scanData.meta.pr),
            filename: f.fix.filename || f.file,
            patched_source: f.fix.patched_source,
            fix_strategy: f.fix.fix_strategy || f.fix.label,
            fix_description: f.fix.fix_description || f.fix.desc,
            finding: { type: f.tech, technique: f.tech, filename: f.file, line: f.line,
                       severity: f.severity, description: f.plain },
            verifier_report: {
              blocklist_verdict: f.fix.blocklist_verdict,
              blocklist_details: f.fix.blocklist_details,
              shannon_verdict: f.fix.shannon_verdict,
            },
            github_token: ghToken,
          }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          throw new Error(err.detail || 'PR creation failed');
        }
        const data = await res.json();
        if (data.pr_url) window.open(data.pr_url, '_blank');
        else alert('PR created (no URL returned).');
      } catch (err) {
        alert(`Open Fix PR failed: ${err.message}`);
      }
    };
    window.addEventListener('sentinel:open-fix-pr', handler);
    return () => window.removeEventListener('sentinel:open-fix-pr', handler);
  }, [scanData, ghToken]);

  const handleScan = (repo, pr) => {
    if (!repo) {
      setScanData(null);
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo,
        pr_number: parseInt(pr),
        github_token: ghToken,
        llm_provider: provider,
        llm_model: model === 'local-default' ? null : model,
        llm_key: provider === 'aisa' ? aisaKey : null,
        include_cpg: arguments[2] || false
      })
    })
      .then(res => {
        if (!res.ok) return res.json().then(e => { throw new Error(e.detail || 'Scan failed') });
        return res.json();
      })
      .then(data => {
        // Map backend response to UI format
        const patch = data.patch_result;

        // Backend now returns findings_count; fall back to local aggregation
        const ssList = data.shadow_stalker_findings?.findings || [];
        const cveList = data.archeologist_findings?.cve_findings || [];
        const owfList = data.archeologist_findings?.one_week_flags || [];
        const fallbackCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
        const inc = (s) => { const k = (s || 'UNKNOWN').toLowerCase(); fallbackCount[k] = (fallbackCount[k] || 0) + 1; };
        ssList.forEach(f => inc(f.severity));
        cveList.forEach(c => inc(c.severity || 'MEDIUM'));
        owfList.forEach(() => inc('HIGH'));
        const fc = data.findings_count || fallbackCount;
        fc.total = fc.total ?? (fc.critical + fc.high + fc.medium + (fc.low || 0));

        const headlineForVerdict = (v) =>
          v === 'BLOCK' ? 'This pull request looks unsafe to merge.'
          : v === 'REVIEW' ? 'This pull request needs review.'
          : 'This pull request looks clean.';

        const mapped = {
          meta: {
            repo, pr, author: data.author || 'unknown',
            verdict: data.verdict,
            headline: headlineForVerdict(data.verdict),
            plain_summary: data.summary,
            confidence: data.confidence,
            risk_score: data.risk_score,
            verdict_engine: data.verdict_engine,
            reasoning: data.reasoning || [],
            findings_count: fc,
            pr_url: data.pr_url,
            graph_name: data.graph_name,
          },
          findings: data.shadow_stalker_findings?.findings?.map((f, i) => {
            let after = '';
            let fix = { label: 'Review fix', desc: 'Manual review required', verified: false };
            
            // Special case: Leaked credentials / Hardcoded secrets
            const isSecret = f.technique === 'hardcoded_secret' || f.technique === 'encoded_shell' || f.description?.toLowerCase().includes('secret') || f.description?.toLowerCase().includes('password');
            
            if (isSecret) {
              const varName = f.evidence?.split('=')[0]?.trim() || 'SECRET_KEY';
              after = `# Suggested fix: Move to .env file\nimport os\n${varName} = os.getenv("${varName}")`;
              fix = { 
                label: 'Move to environment variables', 
                desc: 'Create an .env file and populate it with the leaked credentials. Use os.getenv() to access them safely.', 
                verified: true 
              };
            }
            
            // Use PatchForge result if it applies to this finding (usually the first one)
            if (i === 0 && patch && patch.success) {
              const selected = patch.selected_fix;
              const vr = patch.verifier_report || {};
              if (selected) {
                after = selected.patch?.patched_source || selected.patched_source || after;
                fix = {
                  label: selected.strategy || 'Apply PatchForge fix',
                  desc: selected.description || fix.desc,
                  verified: vr.fully_verified === true,
                  blocklist_verdict: vr.blocklist_verdict || null,
                  shannon_verdict: vr.shannon_verdict || null,
                  blocklist_details: vr.blocklist_details || null,
                  patched_source: selected.patch?.patched_source || null,
                  filename: selected.patch?.filename || f.filename,
                  finding_id: `f${i}`,
                  fix_strategy: selected.strategy,
                  fix_description: selected.description,
                };
              }
            }

            return {
              id: `f${i}`,
              severity: f.severity,
              title: f.technique || 'Vulnerability detected',
              plain: f.description,
              file: f.filename,
              line: f.line,
              tech: f.technique,
              detected_by: 'ShadowStalker',
              before: f.evidence,
              after: after,
              fix: fix
            };
          }) || [],
          agents: [
            { id: 'arch', icon: '🗂', name: 'Archeologist', task: 'Dependencies', status: 'done', state: 'Done' },
            { id: 'ss', icon: '🔍', name: 'ShadowStalker', task: 'Static Analysis', status: 'done', state: 'Done' },
            { 
              id: 'pf', icon: '🛠', name: 'PatchForge', task: 'Patch Generation', 
              status: patch ? 'done' : 'idle', 
              state: patch ? (patch.success ? 'Success' : 'Failed') : 'Idle' 
            }
          ]
        };
        setScanData(mapped);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  };

  const handleGenerateReport = (meta) => {
    openReportWindow(meta);
    setTab('reports');
  };

  // "Apply safe fixes" — dispatch the open-fix-pr event for the first BLOCK-worthy finding with a patched source
  const handleApplyFix = () => {
    const f = (scanData?.findings || []).find(x => x.fix?.patched_source);
    if (!f) {
      alert('No verified patch is available to open. Generate a fix first.');
      return;
    }
    window.dispatchEvent(new CustomEvent('sentinel:open-fix-pr', { detail: f }));
  };

  const TokenSetup = () => {
    const [token, setToken] = useState('');
    return (
      <div className="pane-wrap" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', paddingTop: '10vh' }}>
        <div style={{ fontSize: '48px', marginBottom: '20px' }}>🔐</div>
        <h1 className="pane-h">Securely Connect GitHub</h1>
        <p className="pane-sub" style={{ maxWidth: '460px', margin: '0 auto 30px' }}>
          Sentinel-AI needs a GitHub Personal Access Token to fetch private diffs and open remediation PRs.
          Your token is encrypted with AES-256 and stored securely in our database.
        </p>
        <div className="glass form-card" style={{ width: '400px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="field">
            <label>GitHub Personal Access Token</label>
            <input type="password" placeholder="ghp_..." value={token} onChange={e => setToken(e.target.value)} />
          </div>
          <button className="btn-primary" onClick={() => updateGhToken(token)}>Save Token & Continue</button>
        </div>
        <p style={{ marginTop: '20px', fontSize: '12px', color: 'var(--text-3)' }}>
          Don't have a token? <a href="https://github.com/settings/tokens/new?scopes=repo,pull_request" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>Create one here</a>
        </p>
      </div>
    );
  };

  return (
    <div className="app-shell">
      <AppSidebar tab={tab} setTab={setTab} />
      <div className="app-main">
        <Header tab={tab} />
        <div className="app-content">
          {user && !ghToken && <TokenSetup />}
          {(!user || ghToken) && (
            <>
              {tab === 'scan' && <ScanView data={scanData} loading={loading} error={error} onScan={handleScan} onApplyFix={handleApplyFix} onGenerateReport={handleGenerateReport} onViewGraph={(g) => { setPreloadedGraph(g); setTab('cpg'); }} llmConfig={{ llm_provider: provider, llm_model: model === 'local-default' ? null : model, llm_key: provider === 'aisa' ? aisaKey : null }} patching={patching} setPatching={setPatching} patchResults={patchResults} setPatchResults={setPatchResults} repo={repo} setRepo={setRepo} pr={pr} setPr={setPr} />}
              {tab === 'repo' && <RepoView />}
              {tab === 'watch' && <WatchView />}
              {tab === 'history' && <HistoryView />}
              {tab === 'analytics' && <AnalyticsView />}
              {tab === 'tests' && <TestsView />}
              {tab === 'settings' && <SettingsView />}
              {tab === 'reports' && <ReportsView currentScan={scanData ? { ...scanData.meta, findings: scanData.findings } : null} />}
              {tab === 'cpg' && <ScannerCPG preloadedGraph={preloadedGraph} onClearPreload={() => setPreloadedGraph(null)} />}
              {tab === 'pentest' && <PentestView />}
            </>
          )}
        </div>
      </div>
      <DiffModal finding={diffFinding} onClose={() => setDiffFinding(null)} />
    </div>
  );
}

export default App;
