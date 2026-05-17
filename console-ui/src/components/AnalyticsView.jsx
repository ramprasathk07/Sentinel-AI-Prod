import React, { useState, useEffect } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { API_BASE } from '../lib/api';

// ── palette matches index.css vars ──────────────────────────────
const C = {
  accent: '#7c83ff',
  crit:   '#ff6b81',
  high:   '#ffaa6b',
  med:    '#ffd66b',
  low:    '#6be0a8',
  teal:   '#6be0d8',
  purple: '#b06bff',
  glass:  'rgba(255,255,255,0.04)',
  hair:   'rgba(255,255,255,0.07)',
  text0:  'rgba(255,255,255,0.95)',
  text2:  'rgba(255,255,255,0.55)',
};

const VERDICT_COLORS = { BLOCK: C.crit, REVIEW: C.high, APPROVE: C.low };
const SEV_COLORS = { critical: C.crit, high: C.high, medium: C.med, low: C.low, info: C.accent };

const TOOLTIP_STYLE = {
  background: '#0e0e20',
  border: `1px solid ${C.hair}`,
  borderRadius: 8,
  color: C.text0,
  fontSize: 12,
  padding: '8px 12px',
};

// ── tiny helpers ─────────────────────────────────────────────────
function StatCard({ label, value, sub, color }) {
  return (
    <div style={{
      background: C.glass,
      border: `1px solid ${C.hair}`,
      borderRadius: 12,
      padding: '20px 24px',
      flex: 1,
      minWidth: 160,
    }}>
      <div style={{ fontSize: 11, color: C.text2, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || C.text0, letterSpacing: '-0.03em' }}>
        {value ?? '—'}
      </div>
      {sub && <div style={{ fontSize: 12, color: C.text2, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <h2 style={{ fontSize: 13, fontWeight: 600, color: C.text2, textTransform: 'uppercase',
                 letterSpacing: '0.08em', margin: '32px 0 16px' }}>
      {children}
    </h2>
  );
}

function Card({ children, style }) {
  return (
    <div style={{
      background: C.glass,
      border: `1px solid ${C.hair}`,
      borderRadius: 12,
      padding: 20,
      ...style,
    }}>
      {children}
    </div>
  );
}

function EmptyState() {
  return (
    <div style={{ textAlign: 'center', padding: '64px 0', color: C.text2 }}>
      <div style={{ fontSize: 40, marginBottom: 12 }}>📊</div>
      <div style={{ fontSize: 15, fontWeight: 500, color: C.text0, marginBottom: 6 }}>No scan data yet</div>
      <div style={{ fontSize: 13 }}>Run your first scan to populate analytics.</div>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={TOOLTIP_STYLE}>
      {label && <div style={{ fontWeight: 600, marginBottom: 6 }}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || C.text0 }}>
          {p.name}: <strong>{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</strong>
        </div>
      ))}
    </div>
  );
};

// ── main component ───────────────────────────────────────────────
export default function AnalyticsView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = () => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/api/v1/analytics`)
      .then(r => { if (!r.ok) throw new Error(`API ${r.status}`); return r.json(); })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  };

  useEffect(() => { load(); }, []);

  if (loading) return (
    <div className="pane-wrap">
      <h1 className="pane-h">Analytics</h1>
      <div style={{ display: 'flex', justifyContent: 'center', padding: 80 }}>
        <div className="spin-lg" />
      </div>
    </div>
  );

  if (error) return (
    <div className="pane-wrap">
      <h1 className="pane-h">Analytics</h1>
      <div className="err-box">{error}</div>
    </div>
  );

  if (!data || data.total_scans === 0) return (
    <div className="pane-wrap">
      <h1 className="pane-h">Analytics</h1>
      <EmptyState />
    </div>
  );

  const {
    total_scans, avg_confidence, avg_risk_score,
    verdict_distribution, severity_totals, attack_classifications,
    scans_over_time, top_repos, engine_split, patch_acceptance, risk_distribution,
  } = data;

  // Verdict pie data
  const verdictPie = Object.entries(verdict_distribution || {}).map(([name, value]) => ({ name, value }));

  // Severity bar data
  const sevBar = Object.entries(severity_totals || {})
    .filter(([k]) => k !== 'unknown')
    .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value, fill: SEV_COLORS[name] || C.accent }));

  // Engine split donut
  const enginePie = [
    { name: 'Rule-based', value: engine_split?.rule_based || 0, fill: C.accent },
    { name: 'LLM-assisted', value: engine_split?.llm_assisted || 0, fill: C.teal },
  ].filter(e => e.value > 0);

  const blockCount = verdict_distribution?.BLOCK || 0;
  const blockRate = total_scans ? Math.round(blockCount / total_scans * 100) : 0;
  const acceptRate = patch_acceptance?.acceptance_rate;

  return (
    <div className="pane-wrap">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 className="pane-h" style={{ marginBottom: 4 }}>Analytics</h1>
          <p className="pane-sub" style={{ margin: 0 }}>Aggregate intelligence across all scanned pull requests.</p>
        </div>
        <button
          className="btn-link"
          style={{ fontSize: 12, color: C.text2 }}
          onClick={load}
        >
          ↻ Refresh
        </button>
      </div>

      {/* ── KPI row ── */}
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Total Scans" value={total_scans.toLocaleString()} />
        <StatCard label="Block Rate" value={`${blockRate}%`} sub={`${blockCount} blocked`} color={blockCount > 0 ? C.crit : C.low} />
        <StatCard label="Avg Risk Score" value={avg_risk_score} sub="rule-engine scale" color={avg_risk_score >= 15 ? C.crit : avg_risk_score >= 5 ? C.high : C.low} />
        <StatCard label="Avg Confidence" value={`${avg_confidence}%`} />
        {acceptRate !== null && (
          <StatCard label="Patch Acceptance" value={`${acceptRate}%`} sub={`${patch_acceptance.accepted} accepted · ${patch_acceptance.rejected} rejected`} color={acceptRate >= 70 ? C.low : C.high} />
        )}
      </div>

      {/* ── Scans over time ── */}
      {scans_over_time?.length > 0 && (
        <>
          <SectionTitle>Scan Volume — Last 30 Days</SectionTitle>
          <Card>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={scans_over_time} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={C.accent} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={C.crit} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={C.crit} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={C.hair} vertical={false} />
                <XAxis dataKey="date" tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false}
                  tickFormatter={d => d?.slice(5)} />
                <YAxis tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: 12, color: C.text2, paddingTop: 8 }} />
                <Area type="monotone" dataKey="total" name="Total" stroke={C.accent} strokeWidth={2} fill="url(#gTotal)" />
                <Area type="monotone" dataKey="blocks" name="Blocked" stroke={C.crit} strokeWidth={2} fill="url(#gBlock)" />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </>
      )}

      {/* ── 3-col row: verdict pie + severity bar + engine donut ── */}
      <SectionTitle>Verdict & Severity Breakdown</SectionTitle>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 1fr', gap: 12 }}>

        {/* verdict donut */}
        <Card style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 12, color: C.text2, marginBottom: 8, alignSelf: 'flex-start' }}>Verdict Split</div>
          {verdictPie.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={verdictPie} cx="50%" cy="50%" innerRadius={48} outerRadius={72}
                    dataKey="value" paddingAngle={3}>
                    {verdictPie.map((entry, i) => (
                      <Cell key={i} fill={VERDICT_COLORS[entry.name] || C.accent} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center', marginTop: 4 }}>
                {verdictPie.map(v => (
                  <div key={v.name} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: C.text2 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: VERDICT_COLORS[v.name] || C.accent }} />
                    {v.name} <strong style={{ color: C.text0 }}>{v.value}</strong>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={{ fontSize: 12, color: C.text2, padding: '40px 0' }}>No verdict data</div>
          )}
        </Card>

        {/* severity bar */}
        <Card>
          <div style={{ fontSize: 12, color: C.text2, marginBottom: 8 }}>Finding Severity Totals</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={sevBar} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.hair} vertical={false} />
              <XAxis dataKey="name" tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" name="Findings" radius={[4, 4, 0, 0]}>
                {sevBar.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* engine donut */}
        <Card style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 12, color: C.text2, marginBottom: 8, alignSelf: 'flex-start' }}>Verdict Engine</div>
          {enginePie.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={enginePie} cx="50%" cy="50%" innerRadius={48} outerRadius={72}
                    dataKey="value" paddingAngle={3}>
                    {enginePie.map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4, width: '100%', padding: '0 8px' }}>
                {enginePie.map(e => (
                  <div key={e.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: C.text2 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: e.fill, flexShrink: 0 }} />
                    <span style={{ flex: 1 }}>{e.name}</span>
                    <strong style={{ color: C.text0 }}>{e.value}</strong>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={{ fontSize: 12, color: C.text2, padding: '40px 0' }}>No engine data</div>
          )}
        </Card>
      </div>

      {/* ── Risk distribution ── */}
      {risk_distribution && (
        <>
          <SectionTitle>Risk Score Distribution</SectionTitle>
          <Card>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={risk_distribution} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 80 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.hair} horizontal={false} />
                <XAxis type="number" tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="bucket" tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false} width={80} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Scans" radius={[0, 4, 4, 0]}>
                  {risk_distribution.map((r, i) => (
                    <Cell key={i} fill={i === 0 ? C.crit : i === 1 ? C.high : C.low} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </>
      )}

      {/* ── Attack classifications ── */}
      {attack_classifications?.length > 0 && (
        <>
          <SectionTitle>Attack Classifications</SectionTitle>
          <Card>
            <ResponsiveContainer width="100%" height={Math.max(160, attack_classifications.length * 32)}>
              <BarChart data={attack_classifications} layout="vertical"
                margin={{ top: 0, right: 16, bottom: 0, left: 140 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.hair} horizontal={false} />
                <XAxis type="number" tick={{ fill: C.text2, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: C.text2, fontSize: 11 }} tickLine={false}
                  axisLine={false} width={140}
                  tickFormatter={v => v?.length > 18 ? v.slice(0, 18) + '…' : v} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Occurrences" fill={C.purple} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </>
      )}

      {/* ── Top repos ── */}
      {top_repos?.length > 0 && (
        <>
          <SectionTitle>Top Repositories</SectionTitle>
          <Card style={{ padding: 0, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.hair}` }}>
                  {['Repository', 'Scans', 'Blocked', 'Block Rate', 'Avg Risk'].map(h => (
                    <th key={h} style={{ padding: '10px 16px', textAlign: 'left', color: C.text2,
                                        fontWeight: 500, fontSize: 11, textTransform: 'uppercase',
                                        letterSpacing: '0.06em' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {top_repos.map((r, i) => {
                  const rate = r.scans ? Math.round(r.blocks / r.scans * 100) : 0;
                  return (
                    <tr key={r.repo} style={{ borderBottom: `1px solid ${C.hair}`, background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                      <td style={{ padding: '10px 16px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                        <a href={`https://github.com/${r.repo}`} target="_blank" rel="noreferrer"
                          style={{ color: C.accent, textDecoration: 'none' }}>
                          {r.repo}
                        </a>
                      </td>
                      <td style={{ padding: '10px 16px', color: C.text0 }}>{r.scans}</td>
                      <td style={{ padding: '10px 16px', color: r.blocks > 0 ? C.crit : C.text2 }}>{r.blocks}</td>
                      <td style={{ padding: '10px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ flex: 1, height: 4, background: C.hair, borderRadius: 99, maxWidth: 80 }}>
                            <div style={{ width: `${rate}%`, height: '100%', borderRadius: 99,
                                          background: rate > 50 ? C.crit : rate > 20 ? C.high : C.low }} />
                          </div>
                          <span style={{ color: C.text2, fontSize: 11, minWidth: 28 }}>{rate}%</span>
                        </div>
                      </td>
                      <td style={{ padding: '10px 16px', color: r.avg_risk >= 15 ? C.crit : r.avg_risk >= 5 ? C.high : C.low }}>
                        {r.avg_risk}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {/* ── Patch feedback ── */}
      {(patch_acceptance.accepted + patch_acceptance.rejected) > 0 && (
        <>
          <SectionTitle>Developer Feedback on Findings</SectionTitle>
          <div style={{ display: 'flex', gap: 12 }}>
            <StatCard label="👍 Accepted" value={patch_acceptance.accepted} color={C.low} />
            <StatCard label="👎 Rejected" value={patch_acceptance.rejected} color={C.crit} />
            <StatCard label="Acceptance Rate" value={`${patch_acceptance.acceptance_rate ?? 0}%`}
              sub="based on PR comment reactions" color={C.accent} />
          </div>
        </>
      )}

      <div style={{ height: 40 }} />
    </div>
  );
}
