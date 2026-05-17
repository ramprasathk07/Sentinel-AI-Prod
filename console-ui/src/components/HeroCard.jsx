import React from 'react';
import { motion } from 'framer-motion';

export default function HeroCard({ data, onApplyFix, onGenerateReport, onNewScan }) {
  if (!data) return null;
  const v = data.verdict.toLowerCase();
  const fc = data.findings_count || {};
  const critical = fc.critical || 0;
  const high = fc.high || 0;
  const medium = fc.medium || 0;
  const total = fc.total ?? (critical + high + medium + (fc.low || 0));
  const prUrl = data.pr_url || `https://github.com/${data.repo}/pull/${data.pr}`;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
      className={`glass-strong hero ${v}`}
    >
      <div className="hero-row">
        <div className={`verdict-badge ${v === 'block' ? '' : v}`}>
          <div className="verdict-icon">
            {v === 'block' && '⛔'}
            {v === 'review' && '⚠️'}
            {v === 'approve' && '✓'}
          </div>
          <div className="verdict-label">{data.verdict}</div>
        </div>
        <div className="hero-body">
          <div className="hero-eyebrow">
            <span className="repo">{data.repo}</span>
            <span className="dot" />
            <span className="pr">PR #{data.pr}</span>
            <span className="dot" />
            <span>by @{data.author}</span>
          </div>
          <div className="hero-headline">{data.headline}</div>
          <div className="hero-plain">{data.plain_summary}</div>
          <div className="hero-metrics">
            <div className="hm">
              <div className="hm-lbl">Issues found</div>
              <div className="hm-val crit">{total}</div>
              <div className="hm-sub">{critical} critical · {high} high · {medium} medium</div>
            </div>
            <div className="hm">
              <div className="hm-lbl">Confidence</div>
              <div className="hm-val">{Math.round(data.confidence * 100)}%</div>
              <div className="hm-sub">very high</div>
            </div>
            <div className="hm">
              <div className="hm-lbl">Scan time</div>
              <div className="hm-val">8.7s</div>
              <div className="hm-sub">4 agents · local</div>
            </div>
          </div>
        </div>
        <div className="hero-cta">
          <button className="btn-primary" onClick={onApplyFix} disabled={!onApplyFix}>Apply safe fixes</button>
          <button className="btn-ghost" onClick={() => window.open(prUrl, '_blank', 'noopener')}>View on GitHub</button>
          {data.graph_name && (
            <button 
              className="btn-ghost" 
              style={{ borderColor: 'rgba(107,224,168,0.4)', color: 'var(--low)' }} 
              onClick={() => arguments[0].onViewGraph(data.graph_name)}
            >
              View CPG Graph
            </button>
          )}
          {onGenerateReport && (
            <button className="btn-ghost" style={{ borderColor: 'rgba(124,131,255,0.4)', color: 'var(--accent)' }} onClick={onGenerateReport}>
              Generate Report
            </button>
          )}
          {onNewScan && (
            <button className="btn-ghost" style={{ fontSize: 12, padding: '8px 16px' }} onClick={onNewScan}>
              New Scan
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}
