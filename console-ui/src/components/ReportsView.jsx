import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, Download, Printer, ChevronDown, ChevronUp, Shield, AlertTriangle } from 'lucide-react';
import { API_BASE } from '../lib/api';
import { openReportWindow, downloadReportHTML } from '../lib/reportBuilder';
import CodeWindow from './CodeWindow';
import { Terminal, Bug } from 'lucide-react';

function pillBreakdown(fc = {}) {
  return ['critical', 'high', 'medium', 'low']
    .filter(k => (fc[k] || 0) > 0)
    .map(k => `${fc[k]} ${k}`)
    .join(' · ');
}

/* ── Main component ───────────────────────────────────────── */
export default function ReportsView({ currentScan }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [generating, setGenerating] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/history`)
      .then(r => { if (!r.ok) throw new Error('Failed'); return r.json(); })
      .then(d => { setHistory(d.history || []); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, []);

  const generateReport = (scan, key) => {
    setGenerating(key);
    openReportWindow(scan);
    setTimeout(() => setGenerating(null), 1500);
  };

  const downloadHTML = (scan) => downloadReportHTML(scan);

  return (
    <div className="pane-wrap">
      <div className="reports-header">
        <div>
          <h1 className="pane-h">Reports</h1>
          <p className="pane-sub">Generate and download security audit reports from your scan history.</p>
        </div>
      </div>

      {currentScan && (
        <div className="report-card" style={{ marginBottom: 24, borderColor: 'rgba(124,131,255,0.4)', background: 'rgba(124,131,255,0.05)' }}>
          <div style={{ padding: '12px 20px 8px', fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: 'var(--accent)', textTransform: 'uppercase' }}>
            Current Scan
          </div>
          <div className="report-card-header" onClick={() => setExpandedId(expandedId === '__current' ? null : '__current')}>
            <div className="report-card-verdict">
              <span className={`v-pill ${currentScan.verdict}`}>{currentScan.verdict}</span>
            </div>
            <div className="report-card-info">
              <div className="report-card-repo">{currentScan.repo || '—'}</div>
              <div className="report-card-meta">PR #{currentScan.pr || '?'} · just now</div>
            </div>
            <div className="report-card-stats">
              <span className="report-stat">
                <AlertTriangle size={12} />
                {(() => { const fc = currentScan.findings_count || {}; return fc.total ?? ((fc.critical||0)+(fc.high||0)+(fc.medium||0)+(fc.low||0)); })()} issues
              </span>
              <span className="report-stat">
                <Shield size={12} />
                {typeof currentScan.confidence === 'number' ? `${Math.round(currentScan.confidence * 100)}%` : '—'}
              </span>
            </div>
            <div className="report-card-chevron">
              {expandedId === '__current' ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </div>
          </div>
          <AnimatePresence>
            {expandedId === '__current' && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.25 }}
                style={{ overflow: 'hidden' }}
              >
                <div className="report-card-body">
                  {Array.isArray(currentScan.reasoning) && currentScan.reasoning.length > 0 && (
                    <div className="report-reasoning" style={{ marginBottom: 16 }}>
                      <div className="report-reasoning-label">Verdict reasoning</div>
                      {currentScan.reasoning.map((r, ri) => (
                        <div key={ri} className="report-reasoning-item">• {r}</div>
                      ))}
                    </div>
                  )}

                  <div className="report-findings-section" style={{ marginBottom: 24 }}>
                     <div className="report-reasoning-label" style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                       <Bug size={16} /> Detailed Findings
                     </div>
                     <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                       {Array.isArray(currentScan.findings) && currentScan.findings.length > 0 ? (
                         currentScan.findings.map((f, fi) => (
                           <div key={fi} className="glass" style={{ padding: 16, borderRadius: 12, border: '1px solid var(--hairline)', background: 'rgba(255,255,255,0.02)' }}>
                             <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                               <div style={{ fontWeight: 600, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                                 <span className={`sev-chip ${f.severity}`} style={{ padding: '2px 8px', fontSize: 10 }}>{f.severity}</span>
                                 {f.title || f.technique}
                               </div>
                               <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'monospace' }}>{f.file}:{f.line}</div>
                             </div>
                             <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 12, lineHeight: 1.5 }}>{f.plain || f.description}</div>
                             {f.before && (
                               <div style={{ borderRadius: 8, overflow: 'hidden', border: '1px solid var(--hairline)' }}>
                                 <div style={{ background: 'var(--bg-3)', padding: '4px 12px', fontSize: 10, color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 6, borderBottom: '1px solid var(--hairline)' }}>
                                   <Terminal size={10} /> Vulnerable Snippet
                                 </div>
                                 <CodeWindow source={f.before} focusLine={f.line} context={5} variant="bad" />
                               </div>
                             )}
                           </div>
                         ))
                       ) : (
                         <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No detailed findings found for this scan.</div>
                       )}
                     </div>
                  </div>
                  <div className="report-actions">
                    <button
                      className="btn-report-generate"
                      onClick={() => generateReport(currentScan, '__current')}
                      disabled={generating === '__current'}
                    >
                      {generating === '__current' ? (
                        <><span className="pf-spin" style={{ width: 12, height: 12, borderWidth: 1.5 }} /> Generating...</>
                      ) : (
                        <><Printer size={14} /> Print / Save as PDF</>
                      )}
                    </button>
                    <button className="btn-report-download" onClick={() => downloadHTML(currentScan)}>
                      <Download size={14} /> Download HTML
                    </button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {error && (
        <div className="err-box" style={{ marginBottom: 16 }}>{error}</div>
      )}

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 80 }}>
          <div className="spin-lg" />
        </div>
      ) : history.length === 0 && !currentScan ? (
        <div className="report-empty">
          <div className="report-empty-icon"><FileText size={48} strokeWidth={1} /></div>
          <div className="report-empty-title">No scans available</div>
          <div className="report-empty-sub">Run a security scan first, then come back to generate reports.</div>
        </div>
      ) : history.length > 0 ? (
        <div className="report-list">
          {history.map((scan, i) => {
            const key = scan.id ?? i;
            const fc = scan.findings_count || {};
            const total = fc.total ?? ((fc.critical||0)+(fc.high||0)+(fc.medium||0)+(fc.low||0));
            const isExpanded = expandedId === key;
            const isGenerating = generating === key;
            const ts = scan.timestamp
              ? new Date(scan.timestamp + (scan.timestamp.includes?.('Z') ? '' : 'Z')).toLocaleString()
              : '—';

            return (
              <div key={key} className={`report-card${isExpanded ? ' expanded' : ''}`}>
                <div
                  className="report-card-header"
                  onClick={() => setExpandedId(isExpanded ? null : key)}
                >
                  <div className="report-card-verdict">
                    <span className={`v-pill ${scan.verdict}`}>{scan.verdict}</span>
                  </div>
                  <div className="report-card-info">
                    <div className="report-card-repo">{scan.repo_name || scan.repo || '—'}</div>
                    <div className="report-card-meta">
                      PR #{scan.pr_number || scan.pr || '?'} · {ts}
                    </div>
                  </div>
                  <div className="report-card-stats">
                    <span className="report-stat">
                      <AlertTriangle size={12} />
                      {total} issue{total !== 1 ? 's' : ''}
                    </span>
                    <span className="report-stat">
                      <Shield size={12} />
                      {typeof scan.confidence === 'number' ? `${Math.round(scan.confidence * 100)}%` : '—'}
                    </span>
                  </div>
                  <div className="report-card-chevron">
                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.25 }}
                      style={{ overflow: 'hidden' }}
                    >
                      <div className="report-card-body">
                        <div className="report-preview-stats">
                          <div className="rp-stat">
                            <div className="rp-stat-label">Risk Score</div>
                            <div className="rp-stat-value" style={{
                              color: (scan.risk_score || 0) >= 15 ? 'var(--crit)' : (scan.risk_score || 0) >= 5 ? 'var(--high)' : 'var(--low)'
                            }}>
                              {typeof scan.risk_score === 'number' ? scan.risk_score.toFixed(1) : '—'}
                            </div>
                          </div>
                          <div className="rp-stat">
                            <div className="rp-stat-label">Findings</div>
                            <div className="rp-stat-value" style={{ color: total > 0 ? 'var(--crit)' : 'var(--low)' }}>
                              {total}
                            </div>
                            <div className="rp-stat-sub">{pillBreakdown(fc) || 'clean'}</div>
                          </div>
                          <div className="rp-stat">
                            <div className="rp-stat-label">Classification</div>
                            <div className="rp-stat-value" style={{ fontSize: 14 }}>
                              {scan.attack_classification || 'none'}
                            </div>
                          </div>
                        </div>

                        {Array.isArray(scan.reasoning) && scan.reasoning.length > 0 && (
                          <div className="report-reasoning">
                            <div className="report-reasoning-label">Verdict reasoning</div>
                            {scan.reasoning.map((r, ri) => (
                              <div key={ri} className="report-reasoning-item">• {r}</div>
                            ))}
                          </div>
                        )}

                        <div className="report-findings-section" style={{ marginTop: 24 }}>
                           <div className="report-reasoning-label" style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                             <Bug size={16} /> Detailed Findings
                           </div>
                           <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                             {Array.isArray(scan.findings) && scan.findings.length > 0 ? (
                               scan.findings.map((f, fi) => (
                                 <div key={fi} className="glass" style={{ padding: 16, borderRadius: 12, border: '1px solid var(--hairline)', background: 'rgba(255,255,255,0.02)' }}>
                                   <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                                     <div style={{ fontWeight: 600, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                                       <span className={`sev-chip ${f.severity}`} style={{ padding: '2px 8px', fontSize: 10 }}>{f.severity}</span>
                                       {f.title || f.technique}
                                     </div>
                                     <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'monospace' }}>{f.file}:{f.line}</div>
                                   </div>
                                   <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 12, lineHeight: 1.5 }}>{f.plain || f.description}</div>
                                   {f.before && (
                                     <div style={{ borderRadius: 8, overflow: 'hidden', border: '1px solid var(--hairline)' }}>
                                       <div style={{ background: 'var(--bg-3)', padding: '4px 12px', fontSize: 10, color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 6, borderBottom: '1px solid var(--hairline)' }}>
                                         <Terminal size={10} /> Vulnerable Snippet
                                       </div>
                                       <CodeWindow source={f.before} focusLine={f.line} context={5} variant="bad" />
                                     </div>
                                   )}
                                 </div>
                               ))
                             ) : (
                               <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No detailed findings found for this scan.</div>
                             )}
                           </div>
                        </div>

                        <div className="report-actions">
                          <button
                            className="btn-report-generate"
                            onClick={(e) => { e.stopPropagation(); generateReport(scan, key); }}
                            disabled={isGenerating}
                          >
                            {isGenerating ? (
                              <><span className="pf-spin" style={{ width: 12, height: 12, borderWidth: 1.5 }} /> Generating...</>
                            ) : (
                              <><Printer size={14} /> Print / Save as PDF</>
                            )}
                          </button>
                          <button
                            className="btn-report-download"
                            onClick={(e) => { e.stopPropagation(); downloadHTML(scan); }}
                          >
                            <Download size={14} /> Download HTML
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
