import React from 'react';
import ModelSelector from './ModelSelector';

const TAB_LABELS = {
  scan: 'Scan',
  cpg: 'CPG Scanner',
  pentest: 'Pentest',
  repo: 'Repository',
  watch: 'Watching',
  history: 'History',
  analytics: 'Analytics',
  tests: 'Tests',
  reports: 'Reports',
  settings: 'Settings',
};

export default function Header({ tab }) {
  return (
    <div className="topbar" id="topbar">
      <div className="topbar-breadcrumb">
        <span className="topbar-crumb-root">Workspace</span>
        <span className="topbar-crumb-sep">/</span>
        <span className="topbar-crumb-current">{TAB_LABELS[tab] || 'Scan'}</span>
      </div>
      <div className="topbar-right">
        <ModelSelector />
        <div className="topbar-divider" />
        <span className="live-dot" />
        <span className="topbar-status">All systems operational</span>
      </div>
    </div>
  );
}
