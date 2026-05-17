import React, { useState, useEffect } from 'react';
import { useAuth } from '../lib/AuthContext';
import { API_BASE } from '../lib/api';

export default function WatchView() {
  const { ghToken, user } = useAuth();
  const [tokenInput, setTokenInput] = useState('');
  const [repo, setRepo] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [watches, setWatches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const fetchWatches = () => {
    fetch(`${API_BASE}/api/v1/watches`)
      .then(res => res.json())
      .then(data => {
        setWatches(data.watches || []);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchWatches();
  }, []);

  const unwatch = (owner, repoName) => {
    fetch(`${API_BASE}/api/v1/watch/${owner}/${repoName}`, { method: 'DELETE' })
      .then(() => fetchWatches())
      .catch(err => setErrorMsg(`Unwatch failed: ${err.message}`));
  };

  const startWatching = () => {
    const finalToken = tokenInput || ghToken;
    if (!repo.trim()) { setErrorMsg('Enter a repository (owner/repo)'); return; }
    if (!finalToken) { setErrorMsg('GitHub token required — enter one above or save in Settings.'); return; }
    setSubmitting(true);
    setErrorMsg(null);
    fetch(`${API_BASE}/api/v1/watch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        repo: repo, 
        github_token: finalToken,
        base_url: webhookUrl || API_BASE || window.location.origin,
        user_email: user?.email || '',
      })
    })
      .then(res => {
        if (!res.ok) return res.json().then(e => { throw new Error(e.detail || 'Failed to watch') });
        return res.json();
      })
      .then(() => {
        setSubmitting(false);
        setRepo('');
        setErrorMsg(null);
        fetchWatches();
      })
      .catch(err => {
        setErrorMsg(err.message);
        setSubmitting(false);
      });
  };

  const activeWatches = watches.filter(w => w.active !== false);
  const inactiveWatches = watches.filter(w => w.active === false);

  return (
    <div className="pane-wrap">
      <h1 className="pane-h">Watching</h1>
      <p className="pane-sub">Sentinel will scan every new pull request opened in these repositories.</p>

      <div className="glass form-card" style={{ gridTemplateColumns: '2fr 1fr 1fr auto' }}>
        <div className="field">
          <label>Repository</label>
          <input placeholder="owner/repo" value={repo} onChange={e => setRepo(e.target.value)} />
        </div>
        <div className="field">
          <label>GitHub token <span style={{ color: 'var(--muted)', fontWeight: 400 }}>(needs admin:repo_hook)</span></label>
          <input
            type="password"
            value={tokenInput}
            onChange={e => setTokenInput(e.target.value)}
            placeholder={ghToken ? "Using saved token" : "ghp_•••"}
          />
          {user && ghToken && !tokenInput && (
            <span className="small" style={{ color: 'var(--low)', marginTop: 2 }}>🔒 Encrypted & saved</span>
          )}
        </div>
        <div className="field">
          <label>Webhook URL (Base)</label>
          <input placeholder="http://localhost:8005" value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)} />
        </div>
        <button className="btn-primary" onClick={startWatching} disabled={submitting}>
          {submitting ? 'Starting...' : 'Start watching'}
        </button>
      </div>

      {/* Inline error banner */}
      {errorMsg && (
        <div style={{
          marginTop: 12,
          padding: '12px 16px',
          background: 'var(--crit-soft, rgba(255,107,129,0.08))',
          border: '1px solid rgba(255,107,129,0.25)',
          borderRadius: 8,
          color: 'var(--crit)',
          fontSize: 13,
          lineHeight: 1.5,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 10,
        }}>
          <span style={{ flexShrink: 0, fontSize: 16 }}>⚠</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, marginBottom: 2 }}>Watch failed</div>
            <div>{errorMsg}</div>
            {errorMsg.includes('422') && (
              <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-2)' }}>
                Tip: Make sure your token has the <b>admin:repo_hook</b> scope and you are an admin of the repository.
              </div>
            )}
          </div>
          <button className="btn-ghost" style={{ padding: '4px 8px', fontSize: 11, flexShrink: 0 }} onClick={() => setErrorMsg(null)}>✕</button>
        </div>
      )}

      <div className="section-h">
        <h2>{activeWatches.length} active {activeWatches.length === 1 ? 'watch' : 'watches'}</h2>
        <span className="count">all scans run locally</span>
      </div>
      <div className="glass list-card">
        {loading ? (
          <p style={{ padding: 20 }}>Loading watches...</p>
        ) : activeWatches.length === 0 && inactiveWatches.length === 0 ? (
          <p style={{ padding: 20, color: 'var(--text-2)' }}>Not watching any repositories yet.</p>
        ) : (
          <>
            {activeWatches.map(w => (
              <div key={w.repo} className="list-row" style={{ gridTemplateColumns: '1fr 110px 110px 110px' }}>
                <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>
                  {w.repo}
                  <span className="small" style={{ color: 'var(--low)', marginLeft: 8 }}>● active</span>
                </span>
                <span className="small muted">{w.scan_count || 0} scans</span>
                <span className={`v-pill ${w.latest?.verdict || 'NONE'}`}>{w.latest?.verdict || 'NONE'}</span>
                <button
                  className="btn-link"
                  style={{ padding: '6px 12px', justifySelf: 'end' }}
                  onClick={() => { const [o, r] = w.repo.split('/'); unwatch(o, r); }}
                >Unwatch</button>
              </div>
            ))}
            {inactiveWatches.length > 0 && (
              <>
                <div style={{ padding: '10px 18px', fontSize: 12, color: 'var(--text-3)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  Persisted from previous session — webhook active on GitHub, re-add to reconnect
                </div>
                {inactiveWatches.map(w => (
                  <div key={w.repo} className="list-row" style={{ gridTemplateColumns: '1fr 110px 110px', opacity: 0.6 }}>
                    <span style={{ color: 'var(--text-1)', fontWeight: 500 }}>
                      {w.repo}
                      <span className="small" style={{ color: 'var(--med)', marginLeft: 8 }}>● reconnect needed</span>
                    </span>
                    <span className="small muted">from DB</span>
                    <button
                      className="btn-link"
                      style={{ padding: '6px 12px', justifySelf: 'end' }}
                      onClick={() => { const [o, r] = w.repo.split('/'); unwatch(o, r); }}
                    >Remove</button>
                  </div>
                ))}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
