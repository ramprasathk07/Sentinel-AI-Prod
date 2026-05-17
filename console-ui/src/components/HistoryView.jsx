import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { API_BASE } from '../lib/api';

function pillBreakdown(fc = {}) {
  const order = ['critical', 'high', 'medium', 'low'];
  return order
    .filter(k => (fc[k] || 0) > 0)
    .map(k => `${fc[k]} ${k}`)
    .join(' · ');
}

function HistoryRow({ item, expanded, onToggle }) {
  const fc = item.findings_count || {};
  const total = fc.total ?? ((fc.critical || 0) + (fc.high || 0) + (fc.medium || 0) + (fc.low || 0));
  const reasoning = Array.isArray(item.reasoning) ? item.reasoning : [];
  const summary = item.summary || (reasoning[0] || '');
  const repo = item.repo_name || item.repo;
  const prNum = item.pr_number || item.pr;
  const prUrl = item.pr_url || `https://github.com/${repo}/pull/${prNum}`;

  return (
    <>
      <div
        className={`list-row pr-row ${expanded ? 'open' : ''}`}
        style={{ gridTemplateColumns: '110px 1fr 70px 70px 90px 150px 60px', cursor: 'pointer' }}
        onClick={onToggle}
      >
        <span className={`v-pill ${item.verdict}`}>{item.verdict}</span>
        <span style={{ color: 'var(--text-0)' }}>
          {repo}
          {summary && <div className="small muted" style={{ marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{summary}</div>}
        </span>
        <span className="mono muted">#{prNum}</span>
        <span className="mono small" style={{ textAlign: 'right' }}>
          {typeof item.risk_score === 'number' ? item.risk_score.toFixed(1) : '—'}
        </span>
        <span className="small" style={{ color: total > 0 ? 'var(--crit)' : 'var(--text-3)' }}>
          {total > 0 ? `${total} issue${total !== 1 ? 's' : ''}` : 'clean'}
        </span>
        <span className="small muted" style={{ textAlign: 'right' }}>
          {item.timestamp ? new Date(item.timestamp + (item.timestamp.includes('Z') ? '' : 'Z')).toLocaleString() : item.t}
        </span>
        <span className="small" style={{ textAlign: 'right', color: 'var(--accent)' }}>
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25 }}
            style={{ overflow: 'hidden', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
          >
            <div style={{ padding: '14px 18px 18px 18px' }}>
              <div className="hero-metrics" style={{ marginBottom: 14 }}>
                <div className="hm">
                  <div className="hm-lbl">Verdict</div>
                  <div className="hm-val">{item.verdict}</div>
                  <div className="hm-sub">severity: {item.severity || '—'}</div>
                </div>
                <div className="hm">
                  <div className="hm-lbl">Confidence</div>
                  <div className="hm-val">{Math.round((item.confidence || 0) * 100)}%</div>
                  <div className="hm-sub">{item.attack_classification || '—'}</div>
                </div>
                <div className="hm">
                  <div className="hm-lbl">Issues</div>
                  <div className="hm-val crit">{total}</div>
                  <div className="hm-sub">{pillBreakdown(fc) || 'no breakdown'}</div>
                </div>
              </div>

              {reasoning.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <div className="summary-h" style={{ fontSize: 12, marginBottom: 6 }}>Why this verdict</div>
                  {reasoning.map((r, i) => (
                    <div key={i} className="trace-reasoning">• {r}</div>
                  ))}
                </div>
              )}

              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-ghost" onClick={(e) => { e.stopPropagation(); window.open(prUrl, '_blank', 'noopener'); }}>
                  View on GitHub
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default function HistoryView() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openId, setOpenId] = useState(null);
  const [repoFilter, setRepoFilter] = useState('');

  const load = (repo = '') => {
    setLoading(true);
    const qs = repo ? `?repo=${encodeURIComponent(repo)}` : '';
    fetch(`${API_BASE}/api/v1/history${qs}`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch history');
        return res.json();
      })
      .then(data => {
        setHistory(data.history || []);
        setError(null);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setError(err.message);
        setHistory([]);
        setLoading(false);
      });
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="pane-wrap">
      <h1 className="pane-h">History</h1>
      <p className="pane-sub">Every scan Sentinel has run, newest first. Click any row to see the verdict reasoning.</p>

      <div className="glass form-card" style={{ gridTemplateColumns: '1fr auto auto', marginBottom: 16 }}>
        <div className="field">
          <label>Filter by repo</label>
          <input
            placeholder="owner/repo (leave empty for all)"
            value={repoFilter}
            onChange={e => setRepoFilter(e.target.value)}
          />
        </div>
        <button className="btn-primary" onClick={() => load(repoFilter)}>Apply</button>
        <button className="btn-ghost" onClick={() => { setRepoFilter(''); load(''); }}>Reset</button>
      </div>

      {error && (
        <p style={{ color: 'var(--crit)', fontSize: 12, marginBottom: 12 }}>
          {error}
        </p>
      )}

      {loading ? (
        <p style={{ color: 'var(--text-2)' }}>Loading history…</p>
      ) : history.length === 0 ? (
        <div className="glass list-card" style={{ padding: 24, textAlign: 'center', color: 'var(--text-2)' }}>
          No scans yet. Run a scan to populate history.
        </div>
      ) : (
        <div className="glass list-card">
          {history.map((h, i) => {
            const key = h.id ?? i;
            return (
              <HistoryRow
                key={key}
                item={h}
                expanded={openId === key}
                onToggle={() => setOpenId(openId === key ? null : key)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
