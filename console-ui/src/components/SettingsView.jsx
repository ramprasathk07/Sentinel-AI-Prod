import React from 'react';
import { useAuth } from '../lib/AuthContext';
import { motion } from 'framer-motion';

export default function SettingsView() {
  const { user, ghToken, aisaKey, updateGhToken, updateAisaKey } = useAuth();

  return (
    <div className="pane-wrap">
      <h1 className="pane-h">Settings</h1>
      <p className="pane-sub">Manage your security credentials and API keys.</p>

      <div className="stack-y" style={{ maxWidth: 800 }}>
        {/* Google Account Section */}
        <div className="glass-strong" style={{ padding: 24, marginBottom: 20 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Google Account</h2>
          {user ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <img src={user.picture} alt={user.name} style={{ width: 48, height: 48, borderRadius: '50%' }} referrerPolicy="no-referrer" />
              <div>
                <div style={{ fontSize: 15, fontWeight: 500 }}>{user.name}</div>
                <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{user.email}</div>
              </div>
              <div style={{ marginLeft: 'auto', padding: '6px 12px', borderRadius: 8, background: 'var(--low-soft)', color: 'var(--low)', fontSize: 12, fontWeight: 600 }}>
                ✓ Authenticated
              </div>
            </div>
          ) : (
            <div style={{ padding: 16, borderRadius: 12, background: 'rgba(255,107,129,0.05)', border: '1px solid var(--crit-soft)', color: 'var(--crit)', fontSize: 13 }}>
              You are not signed in. Sign in via the sidebar to enable encrypted key storage.
            </div>
          )}
        </div>

        {/* Credentials Section */}
        <div className="glass" style={{ padding: 24 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>API Credentials</h2>
          <p style={{ fontSize: 13, color: 'var(--text-3)', marginBottom: 20 }}>All keys are AES-256 encrypted and stored locally relative to your Google ID.</p>
          
          <div className="stack-y" style={{ gap: 24 }}>
            {/* GitHub Token */}
            <div className="field">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <label>GitHub Personal Access Token</label>
                {ghToken && <span style={{ fontSize: 11, color: 'var(--low)' }}>🔒 Encrypted & Saved</span>}
              </div>
              <input 
                type="password" 
                value={ghToken} 
                onChange={(e) => updateGhToken(e.target.value)} 
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" 
              />
              <p className="small muted" style={{ marginTop: 6 }}>Required for scanning private repositories and posting PR comments.</p>
            </div>

            {/* AISA Key */}
            <div className="field">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <label>AISA.one API Key</label>
                {aisaKey && <span style={{ fontSize: 11, color: 'var(--low)' }}>🔒 Encrypted & Saved</span>}
              </div>
              <input 
                type="password" 
                value={aisaKey} 
                onChange={(e) => updateAisaKey(e.target.value)} 
                placeholder="aisa_xxxxxxxxxxxxxxxxxxxx" 
              />
              {import.meta.env.VITE_AISA_KEY === aisaKey && !localStorage.getItem('sentinel_aisa_key') && (
                <p className="small" style={{ color: 'var(--accent)', marginTop: 6 }}>✨ Using demo fallback key from .env</p>
              )}
              <p className="small muted" style={{ marginTop: 6 }}>Used for accessing the universal model gateway for agent reasoning.</p>
            </div>
          </div>
        </div>

        {/* Security Info */}
        <div style={{ marginTop: 32, padding: 20, borderRadius: 16, background: 'rgba(124,131,255,0.03)', border: '1px solid var(--hairline)' }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 8 }}>How we secure your keys</h3>
          <p style={{ fontSize: 12, color: 'var(--text-3)', lineHeight: 1.6 }}>
            When you enter a key, we derive a unique 256-bit encryption key using your Google ID (sub). 
            Your API tokens are then encrypted with AES-CBC before being saved to your browser's persistent storage. 
            This means even if someone exports your local storage, they cannot read your keys without your unique Google identifier.
          </p>
        </div>
      </div>
    </div>
  );
}
