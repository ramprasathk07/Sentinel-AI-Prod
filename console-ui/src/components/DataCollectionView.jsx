import React, { useState, useEffect } from 'react';
import { useAuth } from '../lib/AuthContext';
import { API_BASE } from '../lib/api';
import DiffPair from './DiffPair';
import { 
  Database, Clock, Download, ThumbsUp, ThumbsDown, 
  ChevronRight, ChevronDown, CheckCircle, XCircle, 
  Edit3, Save, Copy, Check, RefreshCw, AlertCircle
} from 'lucide-react';

export default function DataCollectionView() {
  const { user } = useAuth();
  const [subTab, setSubTab] = useState('pending'); // 'pending' | 'history'
  const [pendingPairs, setPendingPairs] = useState([]);
  const [historyPairs, setHistoryPairs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Pagination for history
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotal, setHistoryTotal] = useState(0);
  const historyLimit = 10;

  // Track review notes per pending pair
  const [reviewNotes, setReviewNotes] = useState({});
  // Track trace generation loading states
  const [traceLoading, setTraceLoading] = useState({});
  // Track expanded history item IDs
  const [expandedHistory, setExpandedHistory] = useState({});
  // Editing traces
  const [editingTrace, setEditingTrace] = useState({});
  const [editedTraceContent, setEditedTraceContent] = useState({});
  // Copied states
  const [copiedId, setCopiedId] = useState(null);

  const fetchPending = async () => {
    try {
      setRefreshing(true);
      const res = await fetch(`${API_BASE}/api/v1/rl/pending`);
      if (res.ok) {
        const data = await res.json();
        setPendingPairs(data);
      } else {
        setError('Failed to load pending dataset pairs');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  };

  const fetchHistory = async () => {
    try {
      setRefreshing(true);
      const res = await fetch(`${API_BASE}/api/v1/rl/pairs?page=${historyPage}&limit=${historyLimit}`);
      if (res.ok) {
        const data = await res.json();
        setHistoryPairs(data.items || []);
        setHistoryTotal(data.total || 0);
      } else {
        setError('Failed to load labeled history');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  };

  useEffect(() => {
    if (subTab === 'pending') {
      fetchPending();
    } else {
      fetchHistory();
    }
  }, [subTab, historyPage]);

  const handleLabelSubmit = async (pairId, decision) => {
    const notes = reviewNotes[pairId] || '';
    setTraceLoading(prev => ({ ...prev, [pairId]: true }));
    try {
      const res = await fetch(`${API_BASE}/api/v1/rl/label`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pair_id: pairId,
          decision: decision, // 'ACCEPT' | 'REJECT'
          notes: notes,
          user_email: user?.email || 'anonymous@sentinel.ai'
        })
      });

      if (res.ok) {
        const result = await res.json();
        // Remove from list or update inline status
        setPendingPairs(prev => prev.filter(p => p.pair_id !== pairId));
        alert(decision === 'ACCEPT' ? 'Fix accepted! Reasoning trace generation triggered in background.' : 'Fix rejected.');
      } else {
        const errData = await res.json();
        alert(`Failed to submit label: ${errData.detail || 'Unknown error'}`);
      }
    } catch (err) {
      alert(`Error submitting label: ${err.message}`);
    } finally {
      setTraceLoading(prev => {
        const copy = { ...prev };
        delete copy[pairId];
        return copy;
      });
    }
  };

  const handleUpdateTrace = async (pairId) => {
    const updatedContent = editedTraceContent[pairId];
    if (!updatedContent) return;
    try {
      const res = await fetch(`${API_BASE}/api/v1/rl/trace/edit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pair_id: pairId,
          reasoning_trace: updatedContent
        })
      });

      if (res.ok) {
        // Update local state
        setHistoryPairs(prev => prev.map(p => {
          if (p.pair_id === pairId) {
            return { ...p, reasoning_trace: updatedContent };
          }
          return p;
        }));
        setEditingTrace(prev => ({ ...prev, [pairId]: false }));
        alert('Reasoning trace updated successfully.');
      } else {
        alert('Failed to update trace.');
      }
    } catch (err) {
      alert('Error updating trace: ' + err.message);
    }
  };

  const handleCopyJson = (pair) => {
    navigator.clipboard.writeText(JSON.stringify(pair, null, 2));
    setCopiedId(pair.pair_id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleExpandHistory = (id) => {
    setExpandedHistory(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const startEditTrace = (pair) => {
    setEditingTrace(prev => ({ ...prev, [pair.pair_id]: true }));
    setEditedTraceContent(prev => ({ ...prev, [pair.pair_id]: pair.reasoning_trace || '' }));
  };

  const triggerExport = () => {
    window.open(`${API_BASE || 'http://localhost:8005'}/api/v1/rl/export`, '_blank');
  };

  return (
    <div className="pane-wrap">
      {/* Header */}
      <div className="pane-header-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 className="pane-h">RL Data Collection</h1>
          <p className="pane-sub">Review remediation candidates and manage Stage 3 M-GRPO RL fine-tuning alignments.</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button className="btn-secondary" onClick={triggerExport} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Download size={14} />
            <span>Export Dataset (.JSONL)</span>
          </button>
          <button className="btn-secondary" onClick={subTab === 'pending' ? fetchPending : fetchHistory} disabled={refreshing} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RefreshCw size={14} className={refreshing ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Tabs Menu */}
      <div className="tabs-header" style={{ display: 'flex', gap: 16, borderBottom: '1px solid var(--border-3)', marginBottom: 24 }}>
        <button 
          className={`tab-btn${subTab === 'pending' ? ' active' : ''}`}
          onClick={() => setSubTab('pending')}
          style={{ padding: '12px 16px', background: 'none', border: 'none', borderBottom: subTab === 'pending' ? '2px solid var(--accent)' : 'none', color: subTab === 'pending' ? 'var(--text-1)' : 'var(--text-3)', fontWeight: 600, cursor: 'pointer' }}
        >
          Pending Review ({pendingPairs.length})
        </button>
        <button 
          className={`tab-btn${subTab === 'history' ? ' active' : ''}`}
          onClick={() => setSubTab('history')}
          style={{ padding: '12px 16px', background: 'none', border: 'none', borderBottom: subTab === 'history' ? '2px solid var(--accent)' : 'none', color: subTab === 'history' ? 'var(--text-1)' : 'var(--text-3)', fontWeight: 600, cursor: 'pointer' }}
        >
          Labeled History ({historyTotal})
        </button>
      </div>

      {error && (
        <div className="err-box" style={{ marginBottom: 24 }}>
          <AlertCircle size={16} style={{ marginRight: 8 }} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="state-box">
          <div className="spin-lg"></div>
          <p>Loading dataset pairs...</p>
        </div>
      ) : subTab === 'pending' ? (
        /* PENDING REVIEW TABS */
        pendingPairs.length === 0 ? (
          <div className="state-box" style={{ padding: 48 }}>
            <Database size={48} className="text-accent" style={{ marginBottom: 16, opacity: 0.5 }} />
            <h4>No Pending Remediation Pairs</h4>
            <p className="pane-sub" style={{ maxWidth: 400, margin: '8px auto 0' }}>
              When PatchForge generates patches during a BLOCK PR scan, they will be staged here for developer alignment labeling.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
            {pendingPairs.map((pair) => (
              <div key={pair.pair_id} className="glass panel-card" style={{ padding: 24, border: '1px solid var(--border-3)' }}>
                {/* Meta details */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>{pair.repo}</h3>
                    <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>
                      Scan ID: <span className="code">{pair.scan_id}</span> • Pair ID: <span className="code">{pair.pair_id}</span>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span className="badge badge-accent">{pair.finding_type || 'Vulnerability'}</span>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>
                      Line {pair.finding?.line} in <span className="code">{pair.file_path}</span>
                    </div>
                  </div>
                </div>

                {/* Diff Viewer */}
                <div style={{ marginBottom: 20 }}>
                  <DiffPair 
                    original={pair.original} 
                    patched={pair.patched} 
                    filename={pair.file_path} 
                    originalTitle="Original Vulnerable Code"
                    patchedTitle="PatchForge Remediated Code"
                    contextLines={5}
                  />
                </div>

                {/* Human Label controls */}
                <div className="glass-inner" style={{ padding: 20, borderRadius: 8, display: 'grid', gridTemplateColumns: '1fr 300px', gap: 20, alignItems: 'flex-end' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>
                      Developer Review Notes
                    </label>
                    <textarea
                      placeholder="Add design notes, correctness observations, or why this patch was chosen..."
                      value={reviewNotes[pair.pair_id] || ''}
                      onChange={(e) => setReviewNotes(prev => ({ ...prev, [pair.pair_id]: e.target.value }))}
                      style={{ width: '100%', minHeight: 70, padding: 10, borderRadius: 6, backgroundColor: 'var(--bg-3)', border: '1px solid var(--border-3)', color: 'var(--text-1)', resize: 'vertical', fontSize: 13 }}
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', textAlign: 'center', marginBottom: 4 }}>
                      Submit human alignment reward rating
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                      <button 
                        className="btn-danger" 
                        onClick={() => handleLabelSubmit(pair.pair_id, 'REJECT')}
                        disabled={traceLoading[pair.pair_id]}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                      >
                        <ThumbsDown size={14} />
                        <span>Reject Fix</span>
                      </button>
                      <button 
                        className="btn-success" 
                        onClick={() => handleLabelSubmit(pair.pair_id, 'ACCEPT')}
                        disabled={traceLoading[pair.pair_id]}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                      >
                        <ThumbsUp size={14} />
                        <span>Accept Fix</span>
                      </button>
                    </div>
                    {traceLoading[pair.pair_id] && (
                      <div style={{ fontSize: 11, color: 'var(--accent)', textAlign: 'center', marginTop: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
                        <RefreshCw size={12} className="spin" />
                        Generating reasoning trace...
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        /* HISTORY LABELED PAIRS */
        historyPairs.length === 0 ? (
          <div className="state-box" style={{ padding: 48 }}>
            <Clock size={48} className="text-accent" style={{ marginBottom: 16, opacity: 0.5 }} />
            <h4>No Labeled History Available</h4>
            <p className="pane-sub" style={{ maxWidth: 400, margin: '8px auto 0' }}>
              Once you accept or reject patches, your labeled alignment records with reasoning traces will appear here.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {historyPairs.map((pair) => {
              const isExpanded = expandedHistory[pair.pair_id];
              const totalReward = (
                (pair.human_reward || 0) * 0.6 +
                (pair.shannon_reward || 0) * 0.2 +
                (pair.verifier_reward || 0) * 0.2
              ).toFixed(2);

              return (
                <div key={pair.pair_id} className="glass panel-card" style={{ padding: '16px 20px', border: '1px solid var(--border-3)' }}>
                  {/* Collapsed Header Summary */}
                  <div 
                    onClick={() => toggleExpandHistory(pair.pair_id)}
                    style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 14 }}>{pair.repo}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
                          <span>Pair ID: <span className="code">{pair.pair_id}</span></span>
                          <span>•</span>
                          <span>File: <span className="code">{pair.file_path}</span></span>
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                      {/* Reward Badge */}
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Composite Reward</div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent)' }}>{totalReward}</div>
                      </div>

                      {/* Decision Badge */}
                      {pair.human_reward > 0 ? (
                        <span className="badge badge-success" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <CheckCircle size={10} /> ACCEPTED
                        </span>
                      ) : (
                        <span className="badge badge-danger" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <XCircle size={10} /> REJECTED
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Expanded detail section */}
                  {isExpanded && (
                    <div style={{ borderTop: '1px solid var(--border-3)', marginTop: 16, paddingTop: 16, display: 'flex', flexDirection: 'column', gap: 20 }}>
                      
                      {/* Reward Breakdown table */}
                      <div>
                        <h4 style={{ margin: '0 0 10px 0', fontSize: 13, color: 'var(--text-2)' }}>Reward Function Breakdown</h4>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                          <div className="glass-inner" style={{ padding: 10, borderRadius: 6, textAlign: 'center' }}>
                            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Human Label (60%)</div>
                            <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>{pair.human_reward ?? 0}</div>
                          </div>
                          <div className="glass-inner" style={{ padding: 10, borderRadius: 6, textAlign: 'center' }}>
                            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Shannon PoC (20%)</div>
                            <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>{pair.shannon_reward ?? 0}</div>
                          </div>
                          <div className="glass-inner" style={{ padding: 10, borderRadius: 6, textAlign: 'center' }}>
                            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>MiniVerifier (20%)</div>
                            <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>{pair.verifier_reward ?? 0}</div>
                          </div>
                          <div className="glass-inner" style={{ padding: 10, borderRadius: 6, textAlign: 'center', backgroundColor: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.2)' }}>
                            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Calculated Total</div>
                            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--accent)', marginTop: 4 }}>{totalReward}</div>
                          </div>
                        </div>
                      </div>

                      {/* Diffpair container */}
                      <div>
                        <h4 style={{ margin: '0 0 10px 0', fontSize: 13, color: 'var(--text-2)' }}>Patch Code Comparison</h4>
                        <DiffPair 
                          original={pair.original} 
                          patched={pair.patched} 
                          filename={pair.file_path} 
                          originalTitle="Original Vulnerable Code"
                          patchedTitle="Applied Remediated Patch"
                          contextLines={3}
                        />
                      </div>

                      {/* Reasoning Trace edit form */}
                      <div className="glass-inner" style={{ padding: 16, borderRadius: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                          <h4 style={{ margin: 0, fontSize: 13, color: 'var(--text-2)' }}>Reasoning trace (M-GRPO training trace)</h4>
                          {!editingTrace[pair.pair_id] ? (
                            <button className="btn-secondary" onClick={() => startEditTrace(pair)} style={{ padding: '4px 8px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
                              <Edit3 size={12} />
                              <span>Edit Trace</span>
                            </button>
                          ) : (
                            <div style={{ display: 'flex', gap: 8 }}>
                              <button className="btn-secondary" onClick={() => setEditingTrace(prev => ({ ...prev, [pair.pair_id]: false }))} style={{ padding: '4px 8px', fontSize: 11 }}>
                                Cancel
                              </button>
                              <button className="btn-success" onClick={() => handleUpdateTrace(pair.pair_id)} style={{ padding: '4px 8px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
                                <Save size={12} />
                                <span>Save</span>
                              </button>
                            </div>
                          )}
                        </div>

                        {editingTrace[pair.pair_id] ? (
                          <textarea
                            value={editedTraceContent[pair.pair_id]}
                            onChange={(e) => setEditedTraceContent(prev => ({ ...prev, [pair.pair_id]: e.target.value }))}
                            style={{ width: '100%', minHeight: 120, padding: 10, borderRadius: 6, backgroundColor: 'var(--bg-3)', border: '1px solid var(--border-3)', color: '#a7f3d0', fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }}
                          />
                        ) : (
                          <pre style={{ margin: 0, padding: 10, borderRadius: 6, backgroundColor: '#022c22', color: '#34d399', fontSize: 12, fontFamily: 'monospace', overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid #064e3b' }}>
                            {pair.reasoning_trace || '(no trace generated)'}
                          </pre>
                        )}
                      </div>

                      {/* Action utilities */}
                      <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
                        <button className="btn-secondary" onClick={() => handleCopyJson(pair)} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                          {copiedId === pair.pair_id ? <Check size={14} className="text-success" /> : <Copy size={14} />}
                          <span>{copiedId === pair.pair_id ? 'Copied JSON!' : 'Copy raw JSON'}</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )
      )}

      {/* History Pagination Footer */}
      {subTab === 'history' && historyTotal > historyLimit && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 24 }}>
          <button 
            className="btn-secondary" 
            disabled={historyPage === 1}
            onClick={() => setHistoryPage(prev => Math.max(1, prev - 1))}
          >
            Previous
          </button>
          <span style={{ display: 'flex', alignItems: 'center', padding: '0 12px', fontSize: 13, color: 'var(--text-2)' }}>
            Page {historyPage} of {Math.ceil(historyTotal / historyLimit)}
          </span>
          <button 
            className="btn-secondary" 
            disabled={historyPage >= Math.ceil(historyTotal / historyLimit)}
            onClick={() => setHistoryPage(prev => prev + 1)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
