import React, { useState, useEffect } from 'react';
import { useAuth } from '../lib/AuthContext';
import { API_BASE } from '../lib/api';
import { Shield, CheckCircle, AlertTriangle, ExternalLink, RefreshCw, GitBranch, Key, Settings } from 'lucide-react';

export default function GitHubConnect() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  const fetchAuthStatus = async () => {
    if (!user?.email) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/api/v1/github/status?email=${encodeURIComponent(user.email)}`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      } else {
        setError('Failed to fetch connection status');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuthStatus();
  }, [user]);

  const handleConnect = () => {
    if (!user?.email) {
      alert('Please log in with Google first.');
      return;
    }
    // Redirect to the backend OAuth initialization endpoint
    window.location.href = `${API_BASE || 'http://localhost:8005'}/api/v1/github/auth?email=${encodeURIComponent(user.email)}`;
  };

  const handleDisconnect = async () => {
    if (!user?.email || !window.confirm('Are you sure you want to disconnect your GitHub account?')) return;
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/api/v1/github/disconnect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email }),
      });
      if (res.ok) {
        setStatus(prev => ({ ...prev, connected: false, user: null }));
        alert('GitHub disconnected successfully.');
      } else {
        alert('Failed to disconnect account.');
      }
    } catch (err) {
      alert('Error disconnecting: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!user) {
    return (
      <div className="state-box">
        <Shield size={48} className="text-accent" style={{ marginBottom: 16, opacity: 0.5 }} />
        <h3>Authentication Required</h3>
        <p className="pane-sub">Please log in with your Google account on the sidebar to configure GitHub.</p>
      </div>
    );
  }

  return (
    <div className="pane-wrap">
      <div className="pane-header-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 className="pane-h">GitHub Integration</h1>
          <p className="pane-sub">Connect your personal account and manage repositories for continuous scan automation.</p>
        </div>
        <button className="btn-secondary" onClick={fetchAuthStatus} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="err-box" style={{ marginBottom: 24, display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {loading && !status ? (
        <div className="state-box">
          <div className="spin-lg"></div>
          <p>Loading status...</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24 }}>
          {/* Connection status card */}
          <div className="glass panel-card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Key size={18} className="text-accent" />
              <span>Developer Account Connection</span>
            </h3>

            {status?.connected ? (
              <div className="glass-inner" style={{ padding: 20, borderRadius: 8, border: '1px solid rgba(16,185,129,0.2)', backgroundColor: 'rgba(16,185,129,0.02)', display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{ width: 44, height: 44, borderRadius: '50%', backgroundColor: 'var(--bg-3)', border: '1px solid var(--border-3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20 }}>
                    🐙
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-1)' }}>@{status.user?.login}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-3)' }}>Authorized via User OAuth Flow</div>
                  </div>
                  <span className="badge badge-success" style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <CheckCircle size={10} /> Active
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13, borderTop: '1px solid var(--border-3)', paddingTop: 16 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-3)' }}>Connected Email:</span>
                    <span style={{ fontWeight: 500 }}>{user.email}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-3)' }}>Scopes:</span>
                    <span className="code" style={{ fontSize: 11 }}>repo, read:org</span>
                  </div>
                </div>

                <button className="btn-danger" onClick={handleDisconnect} style={{ marginTop: 8 }}>
                  Disconnect Account
                </button>
              </div>
            ) : (
              <div className="glass-inner" style={{ padding: 24, borderRadius: 8, border: '1px solid var(--border-3)', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                <div style={{ fontSize: 32 }}>🔑</div>
                <div>
                  <h4 style={{ margin: '0 0 6px 0', color: 'var(--text-1)' }}>Not Connected</h4>
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--text-3)', lineHeight: 1.4 }}>
                    Connect your GitHub account to access private repositories, see organization pull requests, and enable check run annotations.
                  </p>
                </div>
                <button className="btn-primary" onClick={handleConnect} style={{ width: '100%' }}>
                  Connect GitHub Account
                </button>
              </div>
            )}

            {/* GitHub App Installation status */}
            <div className="glass-inner" style={{ padding: 20, borderRadius: 8, border: '1px solid var(--border-3)', display: 'flex', flexDirection: 'column', gap: 16 }}>
              <h4 style={{ margin: 0, fontSize: 14, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Settings size={16} />
                <span>GitHub Application Integration</span>
              </h4>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-3)', lineHeight: 1.4 }}>
                For automatic annotations, check runs, and inline review comments directly in your Pull Requests, install the Sentinel-AI GitHub App on your user account or target organization.
              </p>
              <a
                href="https://github.com/apps/sentinel-ai-scanner/installations/new"
                target="_blank"
                rel="noreferrer"
                className="btn-secondary"
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, textDecoration: 'none' }}
              >
                <span>Install Sentinel-AI App</span>
                <ExternalLink size={14} />
              </a>
            </div>
          </div>

          {/* Repositories and Installations list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <div className="glass panel-card" style={{ padding: 24, flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <GitBranch size={18} className="text-accent" />
                <span>Active Installations</span>
              </h3>

              {status?.installations && status.installations.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {status.installations.map((inst) => (
                    <div key={inst.id} className="glass-inner" style={{ padding: 12, borderRadius: 6, display: 'flex', alignItems: 'center', gap: 12 }}>
                      <img
                        src={inst.account?.avatar_url}
                        alt={inst.account?.login}
                        style={{ width: 32, height: 32, borderRadius: '50%' }}
                      />
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-1)' }}>
                          {inst.account?.login}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
                          Type: {inst.account?.type} • ID: {inst.id}
                        </div>
                      </div>
                      <span className="badge badge-success" style={{ marginLeft: 'auto', fontSize: 10 }}>Installed</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="state-box" style={{ padding: '24px 0', border: 'none', background: 'none' }}>
                  <p style={{ margin: 0, fontSize: 12, color: 'var(--text-3)' }}>
                    No active Sentinel-AI GitHub App installations detected.
                  </p>
                </div>
              )}
            </div>

            <div className="glass panel-card" style={{ padding: 24, flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <GitBranch size={18} className="text-accent" />
                <span>Watched Repositories</span>
              </h3>
              
              <div style={{ fontSize: 12, color: 'var(--text-3)', lineHeight: 1.4 }}>
                Repositories registered under your account will trigger continuous scans automatically whenever a pull request is created or synchronized.
              </div>

              <div className="glass-inner" style={{ padding: 12, borderRadius: 6, textAlign: 'center', fontSize: 12, color: 'var(--text-3)' }}>
                Configure watches in the <span className="text-accent" style={{ fontWeight: 500 }}>Watching</span> tab to synchronize webhooks dynamically.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
