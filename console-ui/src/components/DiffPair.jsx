import React, { useState } from 'react';
import UnifiedDiff from './UnifiedDiff';
import { Columns, Eye, ChevronDown } from 'lucide-react';

export default function DiffPair({
  original = '',
  patched = '',
  filename = 'Source Code',
  originalTitle = 'Original Vulnerable Source',
  patchedTitle = 'Remediated Patched Source',
  contextLines = 3,
}) {
  const [viewMode, setViewMode] = useState('unified'); // 'unified' | 'split'

  return (
    <div className="glass diff-pair-container" style={{ borderRadius: 10, overflow: 'hidden', border: '1px solid var(--border-3)' }}>
      {/* Diff Toolbar */}
      <div className="diff-toolbar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', backgroundColor: 'var(--bg-2)', borderBottom: '1px solid var(--border-3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{filename}</span>
          <span className="badge badge-accent" style={{ fontSize: 10 }}>{viewMode === 'unified' ? 'Unified Diff' : 'Side-by-Side'}</span>
        </div>
        
        <div className="segmented-control" style={{ display: 'flex', gap: 4, padding: 2, borderRadius: 6, backgroundColor: 'var(--bg-3)' }}>
          <button
            className={`btn-icon ${viewMode === 'unified' ? 'active' : ''}`}
            onClick={() => setViewMode('unified')}
            style={{ fontSize: 11, padding: '4px 8px', borderRadius: 4, border: 'none', background: viewMode === 'unified' ? 'var(--bg-1)' : 'transparent', color: viewMode === 'unified' ? 'var(--text-1)' : 'var(--text-3)', cursor: 'pointer' }}
          >
            Unified
          </button>
          <button
            className={`btn-icon ${viewMode === 'split' ? 'active' : ''}`}
            onClick={() => setViewMode('split')}
            style={{ fontSize: 11, padding: '4px 8px', borderRadius: 4, border: 'none', background: viewMode === 'split' ? 'var(--bg-1)' : 'transparent', color: viewMode === 'split' ? 'var(--text-1)' : 'var(--text-3)', cursor: 'pointer' }}
          >
            Split View
          </button>
        </div>
      </div>

      {/* View Mode Rendering */}
      {viewMode === 'unified' ? (
        <div style={{ overflowX: 'auto', backgroundColor: '#090d16', padding: 8 }}>
          <UnifiedDiff before={original} after={patched} contextLines={contextLines} />
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, backgroundColor: 'var(--border-3)', overflowX: 'auto' }}>
          {/* Original Pane */}
          <div style={{ backgroundColor: '#090d16', padding: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }}>
              {originalTitle}
            </div>
            <pre style={{ margin: 0, fontSize: 12, fontFamily: 'monospace', color: '#e2e8f0', overflowX: 'auto', lineHeight: 1.5 }}>
              {original || '(empty)'}
            </pre>
          </div>
          {/* Patched Pane */}
          <div style={{ backgroundColor: '#090d16', padding: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }}>
              {patchedTitle}
            </div>
            <pre style={{ margin: 0, fontSize: 12, fontFamily: 'monospace', color: '#e2e8f0', overflowX: 'auto', lineHeight: 1.5 }}>
              {patched || '(empty)'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
