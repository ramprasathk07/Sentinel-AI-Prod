import React from 'react';
import { SCAN } from '../data';

export default function Donut({ findingsCount = SCAN.findings_count }) {
  const data = [
    { v: findingsCount.critical, c: 'var(--crit)', l: 'Critical' },
    { v: findingsCount.high, c: 'var(--high)', l: 'High' },
    { v: findingsCount.medium, c: 'var(--med)', l: 'Medium' },
  ];
  const total = data.reduce((a, d) => a + d.v, 0);
  const r = 36;
  const circ = 2 * Math.PI * r;
  let off = 0;

  return (
    <div className="donut">
      <svg className="donut-svg" width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        {data.map((d, i) => {
          const len = (d.v / total) * circ;
          const dasharray = `${len} ${circ - len}`;
          const dashoffset = -off;
          off += len;
          return (
            <circle
              key={i}
              cx="50" cy="50" r={r}
              fill="none" stroke={d.c} strokeWidth="10"
              strokeDasharray={dasharray}
              strokeDashoffset={dashoffset}
              strokeLinecap="butt"
              transform="rotate(-90 50 50)"
            />
          );
        })}
        <text x="50" y="48" textAnchor="middle" fill="var(--text-0)" fontSize="20" fontWeight="600" letterSpacing="-0.02em">{total}</text>
        <text x="50" y="62" textAnchor="middle" fill="var(--text-3)" fontSize="9" letterSpacing="0.1em">ISSUES</text>
      </svg>
      <div className="donut-legend">
        {data.map((d, i) => (
          <div key={i} className="lg">
            <span className="lg-dot" style={{ background: d.c }} />
            <span>{d.l}</span>
            <span className="lg-c">{d.v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
