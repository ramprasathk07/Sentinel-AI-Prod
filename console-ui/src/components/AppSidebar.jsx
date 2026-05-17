import React from 'react';
import { GoogleLogin } from '@react-oauth/google';
import { useAuth } from '../lib/AuthContext';
import {
  Search, FolderGit2, Eye, Clock, BarChart3,
  FlaskConical, FileText, Settings, LogOut, Network, ShieldAlert
} from 'lucide-react';

const NAV = [
  { section: null, items: [
    { id: 'scan',      label: 'Scan',       icon: Search },
    { id: 'cpg',       label: 'CPG Scanner', icon: Network },
    { id: 'pentest',   label: 'Pentest',     icon: ShieldAlert },
    { id: 'repo',      label: 'Repository', icon: FolderGit2 },
    { id: 'watch',     label: 'Watching',   icon: Eye },
  ]},
  { section: 'INSIGHTS', items: [
    { id: 'history',   label: 'History',    icon: Clock },
    { id: 'analytics', label: 'Analytics',  icon: BarChart3 },
    { id: 'tests',     label: 'Tests',      icon: FlaskConical },
    { id: 'reports',   label: 'Reports',    icon: FileText },
  ]},
  { section: 'SYSTEM', items: [
    { id: 'settings',  label: 'Settings',   icon: Settings },
  ]},
];

export default function AppSidebar({ tab, setTab }) {
  const { user, login, logout } = useAuth();

  return (
    <aside className="sidebar" id="app-sidebar">
      {/* ── Brand ── */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-mark" />
        <div className="sidebar-brand-name">
          Sentinel<span> · AI</span>
        </div>
      </div>

      {/* ── Navigation ── */}
      <nav className="sidebar-nav">
        {NAV.map((group, gi) => (
          <div key={gi} className="sidebar-group">
            {group.section && (
              <div className="sidebar-section-label">{group.section}</div>
            )}
            {group.items.map(item => {
              const Icon = item.icon;
              const active = tab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-${item.id}`}
                  className={`sidebar-item${active ? ' active' : ''}`}
                  onClick={() => setTab(item.id)}
                >
                  <Icon size={16} strokeWidth={active ? 2.2 : 1.8} />
                  <span className="sidebar-item-label">{item.label}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* ── User profile ── */}
      <div className="sidebar-footer">
        {user ? (
          <div className="sidebar-user">
            <div className="sidebar-user-main">
              <img
                src={user.picture}
                alt={user.name}
                className="sidebar-avatar"
                referrerPolicy="no-referrer"
              />
              <div className="sidebar-user-info">
                <div className="sidebar-user-name">{user.name.split(' ')[0]}</div>
                <div className="sidebar-user-role">Local workspace</div>
              </div>
            </div>
            <button
              className="sidebar-signout"
              onClick={logout}
              title="Sign out"
            >
              <LogOut size={14} />
              <span>Sign out</span>
            </button>
          </div>
        ) : (
          <div className="sidebar-login">
            <GoogleLogin
              onSuccess={login}
              onError={() => console.error('Google Login Failed')}
              size="small"
              theme="filled_black"
              shape="pill"
              text="signin"
            />
          </div>
        )}
      </div>
    </aside>
  );
}
