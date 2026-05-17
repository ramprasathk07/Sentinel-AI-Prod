import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../lib/AuthContext';
import { API_BASE } from '../lib/api';
import CodeWindow from './CodeWindow';

function buildLiveDetails(results) {
  const details = {};
  results.forEach(r => {
    const ssData = r.shadow_stalker_findings || {};
    const ssFindings = ssData.findings || [];
    const archData = r.archeologist_findings || {};
    const archRaw = archData.findings || [];

    const archFindings = archRaw.flatMap(f => {
      if (f.type === 'vulnerability') {
        const d = f.details || {};
        return [{ sev: 'MEDIUM', title: d.id || 'CVE', loc: `${d.name || '?'}@${d.version || '?'}`, desc: d.summary || '' }];
      }
      if (f.type === 'maintainer_risk') {
        const d = f.details || {};
        return [{ sev: 'HIGH', title: d.one_week_rule ? 'One-Week Rule violation' : 'Maintainer risk',
          loc: d.package || d.name || '?', desc: d.account_age_days ? `Account age: ${d.account_age_days} days` : JSON.stringify(d).slice(0, 120) }];
      }
      return [];
    });

    // Build patch specs from SS findings so PatchForge can call the API
    const fileReports = ssData.file_reports || {};
    const patches = {};
    ssFindings.forEach(f => {
      const loc = `${f.filename || '?'}:${f.line || '?'}`;
      // Use full reconstructed source if available, fall back to evidence snippet
      const fullSource = fileReports[f.filename]?.source || f.evidence || '';
      patches[loc] = {
        _finding: f,
        strategy: f.technique || 'manual_review',
        before: fullSource,
        _evidence: f.evidence || '',  // specific vulnerable snippet for context
        after: '',
        confidence: null, risk: null, breaking: null, shannon: null,
      };
    });

    details[r.pr_number] = {
      pr: r,
      agents: [
        {
          id: 'arch', icon: '🗂', name: 'Archeologist', task: 'Dependencies & maintainers',
          score: r.agent_scores?.archeologist ?? null, max: 50, status: 'done',
          trace: { type: 'arch', raw: archRaw, message: archRaw.length === 0 ? (archData.message || 'No lockfiles in this PR') : null },
          findings: archFindings,
        },
        {
          id: 'ss', icon: '🔍', name: 'ShadowStalker', task: 'Static & behavioural analysis',
          score: r.agent_scores?.shadow_stalker ?? null, max: 50, status: 'done',
          trace: { type: 'ss', files_analyzed: ssData.files_analyzed || 0, lines_analyzed: ssData.lines_analyzed || 0, summary: ssData.summary || '', file_reports: ssData.file_reports || {} },
          findings: ssFindings.map(f => ({ sev: f.severity, title: f.technique || 'Vulnerability', loc: `${f.filename || '?'}:${f.line || '?'}`, desc: f.description || '' })),
        },
        {
          id: 'lw', icon: '⚖️', name: 'Lead Warden', task: 'Combines findings into a verdict',
          score: r.risk_score ?? null, max: 50, status: 'done',
          trace: { type: 'lw', verdict_engine: r.verdict_engine || 'rule-based', attack_classification: r.attack_classification || '', agent_scores: r.agent_scores || {}, reasoning: r.reasoning || [] },
          findings: [{ sev: r.verdict === 'BLOCK' ? 'CRITICAL' : r.verdict === 'REVIEW' ? 'HIGH' : 'LOW', title: `Verdict: ${r.verdict}`, loc: r.verdict_engine || 'rule-based', desc: Array.isArray(r.reasoning) ? r.reasoning[0] || '' : (r.reasoning || '') }],
        },
        { id: 'pf', icon: '🛠', name: 'PatchForge', task: 'Generates safe fixes on demand', score: null, max: 50, status: 'idle', findings: [], trace: null },
      ],
      patches,
    };
  });
  return details;
}

/* ---------- PatchForge pane ---------- */
function PatchForgePane({ prDetails, patching, patchResults, requestPatch }) {
  const locs = Object.keys(prDetails.patches);
  if (locs.length === 0) {
    return (
      <div className="pf-empty">
        <div className="pf-icon">🛠</div>
        <div>No fixable issues found — run a live scan to populate patches.</div>
      </div>
    );
  }
  return (
    <>
      <div className="pf-cta">
        <div className="pf-cta-title">Generate safe fixes for all issues</div>
        <div className="pf-cta-sub">PatchForge generates a patched version and runs Shannon re-execution to verify the exploit no longer works.</div>
        <button
          className="btn-accent"
          onClick={() => locs.filter(l => !patching[l] && !patchResults[l]).forEach(l => requestPatch(l))}
          disabled={locs.every(l => patching[l] || patchResults[l])}
        >
          Generate {locs.length} patch{locs.length !== 1 ? 'es' : ''}
        </button>
      </div>
      <div style={{ marginTop: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {locs.map(loc => {
          const spec = prDetails.patches[loc];
          const state = patching[loc];
          const live = patchResults[loc];
          const displayData = live || (spec.after ? spec : null);

          return (
            <div key={loc} className="a-find" style={{ padding: '16px 18px' }}>
              <div className="a-find-top" style={{ flexWrap: 'wrap', gap: 6 }}>
                <span className="a-find-title">{loc}</span>
                {live && (
                  <>
                    {live.blocklist && (
                      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                        color: live.blocklist === 'PASS' ? 'var(--low)' : 'var(--crit)',
                        background: live.blocklist === 'PASS' ? 'rgba(107,224,168,0.12)' : 'var(--crit-soft)',
                        border: `1px solid ${live.blocklist === 'PASS' ? 'rgba(107,224,168,0.3)' : 'rgba(255,107,129,0.3)'}` }}>
                        Blocklist {live.blocklist}
                      </span>
                    )}
                    {live.shannon && (
                      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                        color: live.shannon === 'PASS' ? 'var(--low)' : live.shannon === 'FAIL' ? 'var(--crit)' : 'var(--med)',
                        background: live.shannon === 'PASS' ? 'rgba(107,224,168,0.12)' : live.shannon === 'FAIL' ? 'var(--crit-soft)' : 'var(--med-soft)' }}>
                        Shannon {live.shannon}
                      </span>
                    )}
                    {live.fully_verified === true && (
                      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                        color: 'var(--low)', background: 'rgba(107,224,168,0.12)',
                        border: '1px solid rgba(107,224,168,0.3)' }}>
                        ✓ Fully verified
                      </span>
                    )}
                  </>
                )}
                <span className="small muted" style={{ marginLeft: 'auto' }}>
                  strategy · <b style={{ color: 'var(--text-1)' }}>{live?.strategy || spec.strategy}</b>
                </span>
              </div>

              {live?.description && (
                <div className="small" style={{ color: 'var(--text-2)', marginTop: 4, lineHeight: 1.5 }}>
                  {live.description}
                </div>
              )}

              {!state && !live && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 10 }}>
                  <button className="btn-accent" onClick={() => requestPatch(loc)} style={{ padding: '8px 16px', fontSize: 12 }}>
                    Generate patch
                  </button>
                  <span className="small muted">Click to generate fix on demand.</span>
                </div>
              )}

              {state === 'gen' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, color: 'var(--text-2)', fontSize: 13 }}>
                  <span className="pf-spin" style={{ borderColor: 'rgba(124,131,255,0.4)', borderTopColor: 'var(--accent)' }} />
                  Generating candidates · running Shannon re-execution…
                </div>
              )}

              {state === 'error' && (
                <div style={{ color: 'var(--crit)', fontSize: 13, marginTop: 10 }}>
                  PatchForge failed — backend error. <button className="btn-link" onClick={() => requestPatch(loc)}>Retry</button>
                </div>
              )}

              {(state === 'done' || (!state && live)) && displayData && (
                <>
                  {/* Vulnerable snippet context */}
                  {(displayData.evidence || spec._evidence) && (
                    <div style={{ marginTop: 10, marginBottom: 4 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.05em', color: 'var(--crit)', marginBottom: 4 }}>
                        ⚠ VULNERABLE LINE DETECTED
                      </div>
                      <pre className="pf-evidence">{displayData.evidence || spec._evidence}</pre>
                    </div>
                  )}

                  {(() => {
                    const focus = displayData.target_line || spec._finding?.line || null;
                    const beforeSrc = displayData.before || spec.before || '';
                    const afterSrc = displayData.after || '';
                    const isEmpty = !afterSrc.trim();
                    const isUnchanged = !isEmpty && afterSrc.trim() === beforeSrc.trim();
                    return (
                      <>
                        <div className="pf-dual">
                          <div className="pf-pane">
                            <div className="pf-pane-h bad">
                              Before · line {focus || '?'}
                              <span className="small muted" style={{ marginLeft: 'auto', fontWeight: 400 }}>
                                {beforeSrc.split('\n').length} total · ±2 context
                              </span>
                            </div>
                            <CodeWindow source={beforeSrc} focusLine={focus} context={2} variant="bad" />
                          </div>
                          <div className="pf-pane">
                            <div className="pf-pane-h good">
                              After · line {focus || '?'}
                              <span className="small muted" style={{ marginLeft: 'auto', fontWeight: 400 }}>
                                {afterSrc ? `${afterSrc.split('\n').length} total · ±2 context` : 'no patch'}
                              </span>
                            </div>
                            <CodeWindow source={afterSrc} focusLine={focus} context={2} variant="good" />
                          </div>
                        </div>
                        {(isEmpty || isUnchanged) && (
                          <div style={{
                            marginTop: 10, padding: '8px 12px',
                            background: 'var(--med-soft)',
                            border: '1px solid rgba(255,214,107,0.3)',
                            borderRadius: 8,
                            color: 'var(--med)',
                            fontSize: 12,
                          }}>
                            ⚠ {isEmpty
                              ? 'LLM did not return a patched source. Try Regenerate, or switch LLM provider in Settings.'
                              : 'LLM returned an unchanged file. The model could not generate a meaningful fix. Try Regenerate.'}
                          </div>
                        )}
                      </>
                    );
                  })()}

                  <div className="pf-meta">
                    {displayData.confidence != null && <span>confidence <b>{Number(displayData.confidence).toFixed(2)}</b></span>}
                    {displayData.risk && <span>risk <b style={{ color: displayData.risk === 'LOW' ? 'var(--low)' : 'var(--high)' }}>{displayData.risk}</b></span>}
                    {displayData.breaking != null && <span>breaking <b style={{ color: displayData.breaking ? 'var(--crit)' : 'var(--low)' }}>{displayData.breaking ? 'YES' : 'NO'}</b></span>}
                    <button
                      className="btn-link"
                      style={{ marginLeft: 8, fontSize: 12 }}
                      onClick={() => requestPatch(loc)}
                    >
                      ↺ Regenerate
                    </button>
                    <button
                      className="btn-fix"
                      style={{ marginLeft: 'auto' }}
                      disabled={!displayData.after || displayData.after.trim() === (displayData.before || '').trim()}
                      onClick={(e) => {
                        e.stopPropagation();
                        const finding = spec._finding || {};
                        window.dispatchEvent(new CustomEvent('sentinel:open-fix-pr', {
                          detail: {
                            ...finding,
                            file: finding.filename || displayData.filename,
                            line: finding.line || displayData.target_line,
                            severity: finding.severity,
                            tech: finding.technique,
                            plain: finding.description,
                            fix: {
                              patched_source: displayData.after,
                              filename: displayData.filename || finding.filename,
                              fix_strategy: displayData.strategy,
                              fix_description: displayData.description,
                              blocklist_verdict: displayData.blocklist,
                              shannon_verdict: displayData.shannon,
                              label: displayData.strategy,
                              desc: displayData.description,
                            },
                          },
                        }));
                      }}
                    >
                      Apply this patch
                    </button>
                  </div>
                </>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}

/* ---------- Agent trace renderers ---------- */
function AgentTrace({ agent }) {
  const t = agent.trace;
  if (!t) return null;

  if (t.type === 'ss') {
    const fileEntries = Object.entries(t.file_reports || {});
    return (
      <div className="agent-trace-box">
        <div className="trace-meta">
          {t.files_analyzed} file{t.files_analyzed !== 1 ? 's' : ''} scanned · {t.lines_analyzed} lines analyzed
          {t.summary && <span style={{ color: 'var(--text-2)', marginLeft: 10 }}>{t.summary}</span>}
        </div>
        {fileEntries.map(([fname, report]) => (
          <div key={fname} className="trace-file">
            <div className="trace-file-hd">
              <span className="trace-fname">{fname}</span>
              <span className="small muted">{report.language || '—'} · {report.count} issue{report.count !== 1 ? 's' : ''}</span>
            </div>
            {(report.findings || []).map((f, i) => (
              <div key={i} className="trace-finding">
                <span className={`stage-pill ${f.stage || 'stage1'}`}>{f.stage || 'stage1'}</span>
                <span className="trace-tech">{f.technique || f.type}</span>
                {f.line && <span className="mono muted" style={{ fontSize: 11 }}>:{f.line}</span>}
                <span className={`sev-chip ${f.severity}`} style={{ marginLeft: 'auto' }}>{f.severity}</span>
              </div>
            ))}
          </div>
        ))}
        {fileEntries.length === 0 && <div className="trace-msg">No files with detectable patterns.</div>}
      </div>
    );
  }

  if (t.type === 'arch') {
    return (
      <div className="agent-trace-box">
        {t.message
          ? <div className="trace-msg">{t.message}</div>
          : (t.raw || []).map((f, i) => (
            <div key={i} className="trace-finding">
              <span className={`stage-pill ${f.type === 'vulnerability' ? 'vuln' : 'maint'}`}>
                {f.type === 'vulnerability' ? '🔓 CVE' : '👤 Maintainer'}
              </span>
              <span className="trace-tech">
                {f.type === 'vulnerability'
                  ? `${f.details?.name || '?'}@${f.details?.version || '?'} — ${f.details?.count ?? 1} vuln(s)`
                  : `${f.details?.package || f.details?.name || '?'} — ${f.details?.one_week_rule ? 'One-Week Rule' : 'flagged'}`}
              </span>
            </div>
          ))
        }
      </div>
    );
  }

  if (t.type === 'lw') {
    return (
      <div className="agent-trace-box">
        <div className="trace-finding" style={{ marginBottom: 6 }}>
          <span className="stage-pill">engine</span>
          <span className="trace-tech">{t.verdict_engine}</span>
          {t.attack_classification && <span className="small muted" style={{ marginLeft: 'auto' }}>{t.attack_classification}</span>}
        </div>
        {Object.entries(t.agent_scores || {}).map(([k, v]) => (
          <div key={k} className="trace-finding">
            <span className="stage-pill score">score</span>
            <span className="trace-tech">{k}</span>
            <span className="mono" style={{ marginLeft: 'auto', color: 'var(--text-1)' }}>{Number(v).toFixed(1)}</span>
          </div>
        ))}
        {(t.reasoning || []).map((r, i) => (
          <div key={i} className="trace-reasoning">• {r}</div>
        ))}
      </div>
    );
  }

  return null;
}

/* ---------- PR Detail (agent chain + agent pane) ---------- */
function PrDetail({ pr, detailsMap, llmConfig = {} }) {
  const d = detailsMap[pr.pr];
  const [activeAgent, setActiveAgent] = useState(d.agents[1].id);
  const [patching, setPatching] = useState({});
  const [patchResults, setPatchResults] = useState({});
  const agent = d.agents.find(a => a.id === activeAgent);

  const requestPatch = (loc) => {
    // Clear any prior result so UI transitions cleanly to "gen" state
    setPatchResults(prev => { const n = { ...prev }; delete n[loc]; return n; });
    setPatching(p => ({ ...p, [loc]: 'gen' }));

    const spec = d.patches[loc];
    if (!spec?._finding) {
      // Mock fallback for demo data
      setTimeout(() => setPatching(p => ({ ...p, [loc]: 'done' })), 1500);
      return;
    }

    const repoStr = d.pr?.pr_url?.replace('https://github.com/', '').split('/pull/')[0] || '';
    fetch(`${API_BASE}/api/v1/patch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_json: JSON.stringify(spec._finding),
        source_code: spec.before || '',   // FULL source — LLM needs context
        filename: spec._finding.filename || 'unknown',
        repo: repoStr,
        ...llmConfig,
      }),
    })
      .then(r => r.json())
      .then(data => {
        // Backend returns run_remediation shape: {selected_fix, all_candidates, verifier_report, ...}
        // Legacy fallback: best_candidate / patched_code.
        const best = data.selected_fix || data.best_candidate || {};
        const patch = best.patch || {};
        const vr = data.verifier_report || {};
        const patchedSource = patch.patched_source
          || best.patched_source
          || data.patched_code
          || '';
        if (!patchedSource) {
          console.warn('[patchforge] empty patched_source — data shape:', Object.keys(data || {}));
        }
        setPatchResults(prev => ({
          ...prev,
          [loc]: {
            before: spec.before || '',
            after: patchedSource,
            evidence: spec._evidence || '',
            confidence: best.confidence ?? null,
            risk: best.risk || null,
            breaking: best.breaking_change ?? null,
            shannon: data.shannon_verdict || vr.shannon_verdict || null,
            blocklist: vr.blocklist_verdict || null,
            fully_verified: vr.fully_verified ?? null,
            strategy: best.strategy || spec.strategy,
            description: best.description || '',
            target_line: patch.target_line || spec._finding?.line || null,
            filename: patch.filename || spec._finding?.filename || null,
          },
        }));
        setPatching(p => ({ ...p, [loc]: 'done' }));
      })
      .catch(err => {
        console.error('[patchforge]', err);
        setPatching(p => ({ ...p, [loc]: 'error' }));
      });
  };

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.3 }}
      className="pr-detail"
      style={{ display: 'block' }}
    >
      <div className="section-h" style={{ marginBottom: 14 }}>
        <h2>Agent pipeline</h2>
        <span className="count">click any agent to see what it found</span>
      </div>
      <div className="chain">
        {d.agents.map((a, i) => (
          <React.Fragment key={a.id}>
            <div
              className={`chain-node ${activeAgent === a.id ? 'active' : ''} ${a.findings.some(f => f.sev === 'CRITICAL') ? 'alert' : ''}`}
              onClick={() => setActiveAgent(a.id)}
            >
              <div className="chain-icon">{a.icon}</div>
              <div className="chain-name">{a.name}</div>
              <div className="chain-task">{a.task}</div>
              {a.score !== null && a.score !== undefined ? (
                <div className="chain-score"><b>{Number(a.score).toFixed(1)}</b> / {a.max} · {a.findings.length} found</div>
              ) : (
                <div className="chain-score">on demand</div>
              )}
            </div>
            {i < d.agents.length - 1 && <div className="chain-arrow">→</div>}
          </React.Fragment>
        ))}
      </div>
      <div className="agent-pane">
        <div className="agent-pane-h">
          <div className="chain-icon" style={{ margin: 0, width: 32, height: 32, fontSize: 14 }}>{agent.icon}</div>
          <div className="name">{agent.name}</div>
          {agent.score !== null && agent.score !== undefined && (
            <span className="small muted" style={{ marginLeft: 'auto' }}>weight <b style={{ color: 'var(--text-0)' }}>{Number(agent.score).toFixed(1)}</b> / {agent.max}</span>
          )}
        </div>
        <div className="agent-pane-sub">{agent.task}</div>

        {/* Trace section */}
        <AgentTrace agent={agent} />

        {/* Findings / PatchForge */}
        {agent.id === 'pf' ? (
          <PatchForgePane prDetails={d} patching={patching} patchResults={patchResults} requestPatch={requestPatch} />
        ) : agent.findings.length === 0 ? (
          <div className="pf-empty">
            <div className="pf-icon">✓</div>
            <div>No issues from {agent.name} on this pull request.</div>
          </div>
        ) : (
          agent.findings.map((f, i) => (
            <div key={i} className="a-find">
              <div className="a-find-top">
                <span className={`sev-chip ${f.sev}`}>{f.sev}</span>
                <span className="a-find-title">{f.title}</span>
                <span className="a-find-loc">{f.loc}</span>
              </div>
              <div className="a-find-desc">{f.desc}</div>
            </div>
          ))
        )}
      </div>
    </motion.div>
  );
}

/* ---------- Historic PR detail (from /history) ---------- */
function HistoricPrDetail({ pr }) {
  const fc = pr._findings_count || {};
  const total = fc.total ?? ((fc.critical || 0) + (fc.high || 0) + (fc.medium || 0) + (fc.low || 0));
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.25 }}
      className="pr-detail"
      style={{ display: 'block' }}
    >
      <div className="hero-metrics" style={{ marginBottom: 14 }}>
        <div className="hm">
          <div className="hm-lbl">Verdict</div>
          <div className="hm-val">{pr.v}</div>
          <div className="hm-sub">severity: {pr._severity || '—'}</div>
        </div>
        <div className="hm">
          <div className="hm-lbl">Confidence</div>
          <div className="hm-val">{Math.round((pr._confidence || 0) * 100)}%</div>
          <div className="hm-sub">{pr._attack || 'no class'}</div>
        </div>
        <div className="hm">
          <div className="hm-lbl">Issues</div>
          <div className="hm-val crit">{total}</div>
          <div className="hm-sub">
            {(fc.critical || 0)} crit · {(fc.high || 0)} high · {(fc.medium || 0)} med
          </div>
        </div>
        <div className="hm">
          <div className="hm-lbl">Risk score</div>
          <div className="hm-val">{(pr.risk || 0).toFixed(1)}</div>
          <div className="hm-sub">last scan</div>
        </div>
      </div>

      {Array.isArray(pr._reasoning) && pr._reasoning.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div className="summary-h" style={{ fontSize: 12, marginBottom: 6 }}>Why this verdict</div>
          {pr._reasoning.map((r, i) => (
            <div key={i} className="trace-reasoning">• {r}</div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn-ghost" onClick={() => window.open(pr.pr_url, '_blank', 'noopener')}>
          View on GitHub
        </button>
        <span className="small muted" style={{ alignSelf: 'center', marginLeft: 'auto' }}>
          Historic record from a previous scan. Click "Scan repository" to refresh.
        </span>
      </div>
    </motion.div>
  );
}

/* ---------- Repo View ---------- */
export default function RepoView() {
  const [openPr, setOpenPr] = useState(null);
  const { ghToken, user, provider, model, aisaKey } = useAuth();
  const [tokenInput, setTokenInput] = useState('');
  const [localRepo, setLocalRepo] = useState('');
  const [localMax, setLocalMax] = useState(5);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [livePRs, setLivePRs] = useState(null);
  const [liveDetails, setLiveDetails] = useState({});
  const [historyPRs, setHistoryPRs] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [recentPRs, setRecentPRs] = useState(null);
  const [recentLoading, setRecentLoading] = useState(true);
  const debounceRef = useRef(null);

  // On mount: load the 5 most recent scans from DB (persists across refreshes)
  useEffect(() => {
    const qs = user?.email ? `?limit=5&user_email=${encodeURIComponent(user.email)}` : '?limit=5';
    fetch(`${API_BASE}/api/v1/recent-scans${qs}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        const items = data?.scans || [];
        if (items.length) {
          setRecentPRs(items.map(h => ({
            pr: h.pr_number,
            title: h.pr_title || h.summary || `PR #${h.pr_number} · ${h.verdict}`,
            author: h.author || 'unknown',
            v: h.verdict,
            risk: typeof h.risk_score === 'number' ? h.risk_score : 0,
            age: h.timestamp
              ? new Date(h.timestamp + (h.timestamp.includes?.('Z') ? '' : 'Z')).toLocaleString()
              : 'previously',
            pr_url: h.pr_url,
            repo_name: h.repo_name,
            _historic: true,
            _reasoning: h.reasoning || [],
            _findings_count: h.findings_count || {},
            _attack: h.attack_classification,
            _severity: h.severity,
            _confidence: h.confidence,
          })));
        }
        setRecentLoading(false);
      })
      .catch(() => setRecentLoading(false));
  }, [user?.email]);

  // Auto-load previous scans when user types a valid owner/repo
  useEffect(() => {
    clearTimeout(debounceRef.current);
    const raw = localRepo.trim();
    const cleaned = raw.replace(/^https?:\/\/(www\.)?github\.com\//i, '').replace(/\/$/, '');
    const parts = cleaned.split('/');
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      setHistoryPRs(null);
      return;
    }
    const repoKey = `${parts[0]}/${parts[1]}`;
    debounceRef.current = setTimeout(() => {
      setHistoryLoading(true);
      fetch(`${API_BASE}/api/v1/history?repo=${encodeURIComponent(repoKey)}&limit=5`)
        .then(r => r.ok ? r.json() : null)
        .then(data => {
          const items = (data?.history || []);
          if (!items.length) { setHistoryPRs(null); setHistoryLoading(false); return; }
          const seen = new Set();
          const dedup = [];
          for (const h of items) {
            if (seen.has(h.pr_number)) continue;
            seen.add(h.pr_number);
            dedup.push(h);
            if (dedup.length >= 5) break;
          }
          setHistoryPRs(dedup.map(h => ({
            pr: h.pr_number,
            title: h.pr_title || h.summary || `Previously scanned · ${h.verdict}`,
            author: h.author || 'history',
            v: h.verdict,
            risk: typeof h.risk_score === 'number' ? h.risk_score : 0,
            age: h.timestamp
              ? new Date(h.timestamp + (h.timestamp.includes('Z') ? '' : 'Z')).toLocaleString()
              : 'previously',
            pr_url: h.pr_url,
            repo_name: h.repo_name,
            _historic: true,
            _reasoning: h.reasoning || [],
            _findings_count: h.findings_count || {},
            _attack: h.attack_classification,
            _severity: h.severity,
            _confidence: h.confidence,
          })));
          setHistoryLoading(false);
        })
        .catch(() => { setHistoryPRs(null); setHistoryLoading(false); });
    }, 350);
    return () => clearTimeout(debounceRef.current);
  }, [localRepo]);

  // Priority: live scan > repo-specific history > recent scans from DB (NO mock fallback)
  const displayPRs = livePRs ?? historyPRs ?? recentPRs ?? [];
  const displayDetails = livePRs ? liveDetails : {};
  const isHistoric = !livePRs && !!(historyPRs || recentPRs);
  const isRecent = !livePRs && !historyPRs && !!recentPRs;

  const llmConfig = {
    llm_provider: provider,
    llm_model: model === 'local-default' ? null : model,
    llm_key: provider === 'aisa' ? aisaKey : null,
  };

  const scanRepo = () => {
    if (!localRepo.trim()) { setScanError('Enter a repository (owner/repo)'); return; }
    setScanning(true);
    setScanError(null);
    const finalToken = tokenInput || ghToken;

    fetch(`${API_BASE}/api/v1/scan-repo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo: localRepo,
        github_token: finalToken,
        max_prs: parseInt(localMax) || 5,
        ...llmConfig,
      })
    })
      .then(res => {
        if (!res.ok) return res.json().then(e => { throw new Error(e.detail || 'Scan failed') });
        return res.json();
      })
      .then(data => {
        const mapped = (data.results || []).map(r => ({
          pr: r.pr_number,
          title: r.title || `PR #${r.pr_number}`,
          author: r.author || 'unknown',
          v: r.verdict || 'REVIEW',
          risk: typeof r.risk_score === 'number' ? r.risk_score : 0,
          age: 'just now',
          pr_url: r.pr_url,
        }));
        setLivePRs(mapped);
        setLiveDetails(buildLiveDetails(data.results || []));
        setOpenPr(mapped[0]?.pr ?? null);
        setScanning(false);
      })
      .catch(err => {
        console.error(err);
        setScanError(err.message);
        setScanning(false);
      });
  };

  return (
    <div className="pane-wrap">
      <h1 className="pane-h">Scan a repository</h1>
      <p className="pane-sub">Point Sentinel at any GitHub repo to scan its open pull requests.</p>

      <div className="glass form-card">
        <div className="field">
          <label>Repository</label>
          <input value={localRepo} onChange={e => setLocalRepo(e.target.value)} placeholder="owner/repo" />
        </div>
        <div className="field">
          <label>Max pull requests</label>
          <input type="number" value={localMax} onChange={e => setLocalMax(e.target.value)} />
        </div>
        <div className="field">
          <label>GitHub token {user ? '(encrypted)' : '(optional)'}</label>
          <input
            type="password"
            value={tokenInput}
            onChange={e => setTokenInput(e.target.value)}
            placeholder={ghToken ? "Using saved token" : "ghp_•••"}
          />
          {user && ghToken && !tokenInput && (
            <span className="small" style={{ color: 'var(--low)', marginTop: 2 }}>🔒 Encrypted & saved (default)</span>
          )}
          {tokenInput && (
            <span className="small" style={{ color: 'var(--accent)', marginTop: 2 }}>✨ Using custom override</span>
          )}
        </div>
        <button 
          className="btn-primary" 
          onClick={scanRepo} 
          disabled={scanning}
          style={{ display: 'flex', alignItems: 'center', gap: 8 }}
        >
          {scanning ? <><span className="spin" style={{ width: 12, height: 12 }} />Scanning...</> : 'Scan repository'}
        </button>
      </div>
      {scanError && <div style={{ color: 'var(--crit)', fontSize: 13, marginTop: 12, padding: 12, background: 'var(--crit-soft)', borderRadius: 8 }}>{scanError}</div>}

      <div className="section-h">
        <h2>
          {livePRs
            ? `${displayPRs.length} open pull request${displayPRs.length !== 1 ? 's' : ''}`
            : isRecent
              ? `Your last ${displayPRs.length} scan${displayPRs.length !== 1 ? 's' : ''}`
              : isHistoric
                ? `Last ${displayPRs.length} scan${displayPRs.length !== 1 ? 's' : ''}`
                : recentLoading
                  ? 'Loading…'
                  : 'No scans yet'}
        </h2>
        <span className="count">
          {livePRs
            ? `scanned just now · ${localRepo}`
            : isRecent
              ? 'from database · persists across refreshes'
              : isHistoric
                ? `previous scans for ${localRepo} · click any row to see details`
                : historyLoading || recentLoading
                  ? 'checking for previous scans…'
                  : 'scan a repository to populate history'}
        </span>
      </div>
      <div className="glass list-card">
        {displayPRs.length === 0 && !recentLoading && (
          <p style={{ padding: 20, color: 'var(--text-2)' }}>No scans yet. Enter a repository above and click "Scan repository" to get started.</p>
        )}
        {recentLoading && displayPRs.length === 0 && (
          <p style={{ padding: 20, color: 'var(--text-2)' }}>Loading recent scans…</p>
        )}
        {displayPRs.map((p, idx) => {
          const uniqueKey = `${p.repo_name || ''}-${p.pr}-${idx}`;
          const isOpen = openPr === uniqueKey;
          const historic = !!p._historic;
          const hasDetail = historic || !!displayDetails[p.pr];
          return (
            <React.Fragment key={uniqueKey}>
              <div
                className={`list-row pr-row ${isOpen ? 'open' : ''}`}
                style={{ gridTemplateColumns: '72px 1fr 140px 96px 92px' }}
                onClick={() => setOpenPr(isOpen ? null : uniqueKey)}
              >
                <span className="mono muted">#{p.pr}</span>
                <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>
                  {p.title}
                  <div className="small muted" style={{ marginTop: 2 }}>
                    {historic
                      ? <>{isRecent && p.repo_name ? `${p.repo_name} · ` : ''}by @{p.author || 'unknown'} · {p.age}</>
                      : <>by @{p.author} · {p.age} ago</>}
                  </div>
                </span>
                <span className={`v-pill ${p.v}`}>{p.v}</span>
                <span className="mono small" style={{ textAlign: 'right' }}>risk {typeof p.risk === 'number' ? p.risk.toFixed(1) : '—'}</span>
                <button
                  className="btn-link"
                  style={{ padding: '6px 12px' }}
                  onClick={(e) => { e.stopPropagation(); setOpenPr(isOpen ? null : uniqueKey); }}
                >
                  {isOpen ? <>Hide <span className="chev up" style={{ marginLeft: 4 }} /></> : <>View <span className="chev" style={{ marginLeft: 4 }} /></>}
                </button>
              </div>
              <AnimatePresence>
                {isOpen && hasDetail && (
                  historic
                    ? <HistoricPrDetail pr={p} />
                    : <PrDetail pr={p} detailsMap={displayDetails} llmConfig={llmConfig} />
                )}
              </AnimatePresence>
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
