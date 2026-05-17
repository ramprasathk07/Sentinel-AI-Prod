import React, { useState, useEffect } from 'react';
import { API_BASE } from '../lib/api';
import { TESTS as MOCK_TESTS } from '../data';

export default function TestsView() {
  const [tests, setTests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  const fetchResults = () => {
    fetch(`${API_BASE}/api/v1/test-results`)
      .then(res => res.json())
      .then(data => {
        if (data.results) setTests(data.results);
        else setTests(MOCK_TESTS);
        setLoading(false);
      })
      .catch(() => {
        setTests(MOCK_TESTS);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchResults();
  }, []);

  const runTests = () => {
    setRunning(true);
    fetch(`${API_BASE}/api/v1/run-tests`, { method: 'POST' })
      .then(() => {
        // Poll for results after a delay
        setTimeout(fetchResults, 2000);
        setTimeout(() => setRunning(false), 3000);
      });
  };

  const passed = tests.filter(t => t.status === 'pass').length;
  const failed = tests.length - passed;
  const lat = tests.reduce((a, t) => a + (t.t_ms || 0), 0);

  return (
    <div className="pane-wrap">
      <h1 className="pane-h">Tests</h1>
      <p className="pane-sub">Self-checks that confirm Sentinel itself is working correctly.</p>

      <div className="stat-grid">
        <div className="glass stat-c"><div className="stat-lbl">Passing</div><div className="stat-v good">{passed}</div></div>
        <div className="glass stat-c"><div className="stat-lbl">Failing</div><div className="stat-v bad">{failed}</div></div>
        <div className="glass stat-c"><div className="stat-lbl">Total tests</div><div className="stat-v">{tests.length}</div></div>
        <div className="glass stat-c"><div className="stat-lbl">Total time</div><div className="stat-v">{(lat / 1000).toFixed(1)}s</div></div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button className="btn-primary" onClick={runTests} disabled={running}>
          {running ? 'Running...' : 'Run all tests'}
        </button>
        <button className="btn-ghost" onClick={fetchResults}>Refresh</button>
      </div>

      <div className="glass list-card">
        {loading ? <p style={{ padding: 20 }}>Loading tests...</p> : tests.map((t, i) => (
          <div key={i} className="list-row" style={{ gridTemplateColumns: '1fr 100px 100px' }}>
            <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{t.name}</span>
            <span style={{ color: t.status === 'pass' ? 'var(--low)' : 'var(--crit)', fontSize: 12, fontWeight: 600, letterSpacing: '0.06em' }}>
              {t.status === 'pass' ? '✓ Passed' : '✕ Failed'}
            </span>
            <span className="mono small muted" style={{ textAlign: 'right' }}>{t.t_ms} ms</span>
          </div>
        ))}
      </div>
    </div>
  );
}
