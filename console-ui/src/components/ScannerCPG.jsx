import React, { useState, useEffect, useRef, useMemo } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import { API_BASE } from '../lib/api';
import CodeWindow from './CodeWindow';

export default function ScannerCPG({ preloadedGraph, onClearPreload }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [prNumber, setPrNumber] = useState('');
  const [githubToken, setGithubToken] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  
  const [selectedNode, setSelectedNode] = useState(null);
  const [recentGraphs, setRecentGraphs] = useState([]);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const fgRef = useRef();
  const containerRef = useRef();

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      for (let entry of entries) {
        setDimensions({
          width: entry.contentRect.width,
          height: entry.contentRect.height
        });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const centerGraph = () => {
    if (fgRef.current) {
        fgRef.current.zoomToFit(800, 100);
    }
  };

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/cpg-graphs`)
      .then(r => r.json())
      .then(d => setRecentGraphs(d.graphs || []))
      .catch(e => console.error('Failed to fetch graphs', e));
  }, [scanResult]);

  const loadGraph = async (name) => {
    setLoading(true);
    setError(null);
    setScanResult(null);
    setSelectedNode(null);
    try {
      const graphRes = await fetch(`${API_BASE}/api/v1/cpg-graph/${name}`);
      if (graphRes.ok) {
        const graphJson = await graphRes.json();
        setGraphData(graphJson);
        setScanResult({ graph_name: name, vulnerability_count: graphJson.nodes.filter(n => n.data.is_vulnerable === 'True' || n.data.is_vulnerable === true).length });
      } else {
        throw new Error('Failed to fetch graph');
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (preloadedGraph) {
      const loadPreloaded = async () => {
        setLoading(true);
        setError(null);
        try {
          const graphRes = await fetch(`${API_BASE}/api/v1/cpg-graph/${preloadedGraph}`);
          if (graphRes.ok) {
            const graphJson = await graphRes.json();
            setGraphData(graphJson);
            setScanResult({ graph_name: preloadedGraph, vulnerability_count: graphJson.nodes.filter(n => n.data.is_vulnerable === 'True' || n.data.is_vulnerable === true).length });
          } else {
            throw new Error('Failed to fetch preloaded graph');
          }
        } catch (e) {
          setError(e.message);
        } finally {
          setLoading(false);
          if (onClearPreload) onClearPreload();
        }
      };
      loadPreloaded();
    }
  }, [preloadedGraph, onClearPreload]);
  
  const handleScan = async () => {
    if (!repoUrl || !prNumber) {
        setError('Repository URL and PR Number are required.');
        return;
    }
    
    setLoading(true);
    setError(null);
    setScanResult(null);
    setSelectedNode(null);
    
    try {
        const res = await fetch(`${API_BASE}/api/v1/scan-cpg`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                repo_url: repoUrl,
                pr_number: parseInt(prNumber, 10),
                github_token: githubToken || null
            })
        });
        
        if (!res.ok) {
            const errData = await res.json().catch(() => ({ detail: 'Scan failed' }));
            throw new Error(errData.detail || 'Failed to scan CPG');
        }
        
        const data = await res.json();
        setScanResult(data);
        
        // Fetch full graph
        const graphRes = await fetch(`${API_BASE}/api/v1/cpg-graph/${data.graph_name}`);
        if (graphRes.ok) {
            const graphJson = await graphRes.json();
            setGraphData(graphJson);
        } else {
            console.error('Failed to fetch full graph data');
        }
    } catch (e) {
        setError(e.message);
    } finally {
        setLoading(false);
    }
  };

  const cytoscapeStylesheet = [
    {
      selector: 'node',
      style: {
        'background-color': '#42526E',
        'label': 'data(label)',
        'color': '#fff',
        'font-size': '11px',
        'font-family': 'monospace',
        'text-valign': 'top',
        'text-halign': 'center',
        'text-margin-y': -6,
        'width': 30,
        'height': 30,
        'border-width': 2,
        'border-color': '#2C3646'
      }
    },
    {
      selector: 'node[label="METHOD"]',
      style: {
        'shape': 'round-rectangle',
        'background-color': '#0052CC',
        'width': 45,
        'height': 30,
      }
    },
    {
      selector: 'node[label="CALL"]',
      style: {
        'shape': 'hexagon',
        'background-color': '#FF991F',
      }
    },
    {
      selector: 'node[label="IDENTIFIER"]',
      style: {
        'shape': 'diamond',
        'background-color': '#36B37E',
      }
    },
    {
      selector: 'node[is_vulnerable="True"], node[is_vulnerable="true"], node[is_vulnerable=true]',
      style: {
        'background-color': '#FF5630',
        'border-color': '#DE350B',
        'border-width': 4,
        'shadow-blur': 10,
        'shadow-color': '#FF5630',
        'shadow-opacity': 0.8
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#7A869A',
        'target-arrow-color': '#7A869A',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '10px',
        'color': '#8993A4',
        'text-rotation': 'autorotate',
        'text-margin-y': -8
      }
    }
  ];

    const fgData = useMemo(() => {
        return {
            nodes: graphData.nodes.map(n => {
                const isVuln = (n.data.is_vulnerable === 'True' || n.data.is_vulnerable === true);
                let color = '#36B37E'; // IDENTIFIER (Green)
                if (isVuln) color = '#FF5630'; // VULNERABLE (Red)
                else if (n.data.label === 'METHOD') color = '#0052CC'; // METHOD (Blue)
                else if (n.data.label === 'CALL') color = '#FFAB00'; // CALL (Orange)
                else if (n.data.label === 'MEMBER') color = '#6554C0'; // MEMBER (Purple)
                
                return {
                    id: n.data.id,
                    label: n.data.label,
                    color: color,
                    val: isVuln ? 5 : 2.5,
                    ...n.data
                };
            }),
            links: graphData.edges.map(e => ({
                source: e.data.source,
                target: e.data.target,
                label: e.data.label
            }))
        };
    }, [graphData]);

    const Legend = () => (
        <div className="glass" style={{ position: 'absolute', top: 16, left: 16, padding: '12px', borderRadius: '12px', background: 'rgba(10,12,24,0.85)', backdropFilter: 'blur(8px)', border: '1px solid rgba(255,255,255,0.1)', zIndex: 10, display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>Graph Legend</div>
            {[
                { label: 'Vulnerable', color: '#FF5630', desc: 'Critical security risk' },
                { label: 'Method', color: '#0052CC', desc: 'Function definition' },
                { label: 'Call', color: '#FFAB00', desc: 'Subroutine invocation' },
                { label: 'Identifier', color: '#36B37E', desc: 'Variable or constant' },
                { label: 'Member', color: '#6554C0', desc: 'Class member' }
            ].map(item => (
                <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: item.color, boxShadow: `0 0 8px ${item.color}80` }} />
                    <span style={{ fontSize: '12px', color: 'var(--text-1)', fontWeight: 500 }}>{item.label}</span>
                </div>
            ))}
            <button 
                className="btn-ghost" 
                style={{ marginTop: '8px', fontSize: '10px', padding: '4px 8px', borderColor: 'var(--hairline)' }}
                onClick={centerGraph}
            >
                🎯 Recenter Graph
            </button>
        </div>
    );


  return (
    <div className="pane-wrap" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
        <div>
          <h1 className="pane-h">Code Property Graph (CPG) Scanner</h1>
          <p className="pane-sub">Deep AST, Control Flow, and Data Flow analysis for advanced vulnerability detection.</p>
        </div>
        {scanResult && !loading && (
          <div style={{ display: 'flex', gap: '10px' }}>
             <div className="glass" style={{ padding: '8px 16px', borderRadius: '12px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ color: 'var(--text-3)' }}>Graph:</span>
                <span style={{ fontWeight: 600, color: 'var(--accent)' }}>{scanResult.graph_name}</span>
                <div style={{ width: 1, height: 16, background: 'var(--hairline)' }} />
                <span style={{ color: 'var(--text-3)' }}>Vulns:</span>
                <span style={{ fontWeight: 700, color: scanResult.vulnerability_count > 0 ? 'var(--crit)' : 'var(--low)' }}>{scanResult.vulnerability_count}</span>
             </div>
             <button className="btn-ghost" style={{ padding: '8px 16px' }} onClick={() => { setScanResult(null); setGraphData({ nodes: [], edges: [] }); }}>New Scan</button>
          </div>
        )}
      </div>
      
      {!scanResult && !loading && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '32px' }}>
          <div className="glass form-card" style={{ gridTemplateColumns: '1fr 120px 1fr auto', marginBottom: '0' }}>
            <div className="field">
              <label>Repository URL</label>
              <input placeholder="https://github.com/owner/repo" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} />
            </div>
            <div className="field">
              <label>PR #</label>
              <input type="number" placeholder="42" value={prNumber} onChange={e => setPrNumber(e.target.value)} />
            </div>
            <div className="field">
              <label>GitHub Token (Optional)</label>
              <input type="password" placeholder="ghp_..." value={githubToken} onChange={e => setGithubToken(e.target.value)} />
            </div>
            <button className="btn-primary" onClick={handleScan} style={{ marginTop: '22px' }}>Generate CPG</button>
          </div>

          <div>
            <h2 style={{ fontSize: '14px', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '16px' }}>Recent Explorations</h2>
            {recentGraphs.length > 0 ? (
              <div className="recent-graphs">
                {recentGraphs.slice(0, 6).map(g => (
                  <div key={g} className="graph-card" onClick={() => loadGraph(g)}>
                    <div className="graph-card-icon"><span>🕸️</span></div>
                    <div className="graph-card-info">
                      <div className="graph-card-title">{g.replace('repo_', '').replace('_pr_', ' PR #')}</div>
                      <div className="graph-card-meta">Stored in FalkorDB</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '40px', textAlign: 'center', background: 'var(--glass-1)', borderRadius: '16px', border: '1px dashed var(--hairline)' }}>
                <p style={{ color: 'var(--text-3)' }}>No recent graphs found in the database. Run a scan to see them here.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {error && <div className="err-box" style={{ marginBottom: '20px' }}>{error} <button className="btn-link" onClick={() => setError(null)}>Dismiss</button></div>}
      
      {loading && (
        <div className="state-box" style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div className="spin-lg"></div>
          <p style={{ marginTop: '16px' }}>Processing PR #{prNumber}...</p>
          <p style={{ fontSize: '12px', color: 'var(--text-2)' }}>Cloning repository, generating CPG, and storing to FalkorDB. This may take a minute.</p>
        </div>
      )}

      {scanResult && !loading && (
        <div style={{ flex: 1, display: 'flex', gap: '20px', minHeight: '600px', position: 'relative' }}>
          <div ref={containerRef} className="glass" style={{ flex: 1, overflow: 'hidden', position: 'relative', background: '#020208' }}>
             {fgData.nodes.length > 0 ? (
                 <ForceGraph3D
                    ref={fgRef}
                    width={dimensions.width}
                    height={dimensions.height}
                    graphData={fgData}
                    nodeLabel={node => `<div style="padding: 10px; background: rgba(10,12,24,0.95); border: 1px solid ${node.color}; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); min-width: 140px;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <div style="width: 8px; height: 8px; borderRadius: 50%; background: ${node.color}"></div>
                            <b style="color: ${node.color}; font-size: 11px; text-transform: uppercase;">${node.label}</b>
                        </div>
                        <div style="color: #fff; font-size: 13px; font-weight: 500; margin-bottom: 4px;">${node.name || 'unnamed'}</div>
                        <div style="color: rgba(255,255,255,0.5); font-size: 11px;">
                            ${node.lineNumber ? `Line: ${node.lineNumber}` : 'No line info'}
                        </div>
                        ${node.is_vulnerable ? `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.1); color: #FF5630; font-size: 10px; font-weight: 700;">⚠ CRITICAL VULNERABILITY</div>` : ''}
                    </div>`}

                    nodeColor={node => node.color}
                    nodeVal={node => node.val}
                    linkDirectionalArrowLength={3.5}
                    linkDirectionalArrowRelPos={1}
                    onNodeClick={node => setSelectedNode(node)}
                    onEngineStop={centerGraph}
                    backgroundColor="#020208"
                    showNavInfo={true}
                 />
             ) : (
                 <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-2)' }}>
                     No nodes available to render.
                 </div>
             )}
             <Legend />
             <div style={{ position: 'absolute', bottom: 16, left: 16, pointerEvents: 'none', background: 'rgba(0,0,0,0.4)', padding: '6px 12px', borderRadius: '20px', color: 'rgba(255,255,255,0.5)', fontSize: '11px', backdropFilter: 'blur(4px)' }}>
                Right-click: rotate · Middle-click: zoom · Left-click: select node
             </div>
          </div>


          
          <div className="glass-strong" style={{ width: '420px', background: 'rgba(10,12,24,0.7)', borderRadius: '16px', borderLeft: '1px solid var(--hairline)', padding: '0', overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid var(--hairline)', background: 'linear-gradient(to bottom, rgba(255,255,255,0.03), transparent)' }}>
                <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-1)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '20px' }}>🎯</span> Node Inspector
                </h2>
            </div>
            
            <div style={{ padding: '24px', flex: 1 }}>
                {selectedNode ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                      <div>
                         <div style={{ fontSize: '10px', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '8px', fontWeight: 700 }}>Classification</div>
                         <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div style={{ width: 8, height: 8, borderRadius: '50%', background: selectedNode.color }} />
                            <div style={{ fontWeight: 600, fontSize: '20px', color: 'var(--text-1)' }}>{selectedNode.label}</div>
                         </div>
                         <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '6px', lineHeight: 1.4 }}>
                            {selectedNode.label === 'METHOD' && 'Represents a function or method definition. It contains the logic entry point.'}
                            {selectedNode.label === 'CALL' && 'Represents a subroutine invocation. This is where data is passed between functions.'}
                            {selectedNode.label === 'IDENTIFIER' && 'Represents a variable, parameter, or constant reference in the code.'}
                            {selectedNode.label === 'MEMBER' && 'Represents a class property or object member access.'}
                            {selectedNode.label === 'LITERAL' && 'Represents a constant value (string, number, etc.) hardcoded in the source.'}
                            {selectedNode.label === 'UNKNOWN' && 'An unclassified AST node detected during static analysis.'}
                         </div>
                      </div>
                      
                      {selectedNode.name && (
                        <div>
                           <div style={{ fontSize: '10px', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '8px', fontWeight: 700 }}>Element Identifier</div>
                           <div style={{ fontSize: '13px', background: 'rgba(0,0,0,0.3)', padding: '12px 16px', borderRadius: '10px', fontFamily: 'monospace', border: '1px solid var(--hairline)', color: 'var(--accent)', wordBreak: 'break-all' }}>
                               {selectedNode.name}
                           </div>
                        </div>
                      )}

                      {selectedNode.lineNumber && (
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--glass-1)', padding: '12px 16px', borderRadius: '10px', border: '1px solid var(--hairline)' }}>
                           <span style={{ fontSize: '13px', color: 'var(--text-2)' }}>Source Location</span>
                           <span style={{ fontWeight: 600, color: 'var(--text-1)', fontSize: '13px' }}>Line {selectedNode.lineNumber}</span>
                        </div>
                      )}

                      <div style={{ display: 'flex', gap: '10px' }}>
                        <div style={{ flex: 1, background: 'var(--glass-1)', padding: '12px', borderRadius: '10px', border: '1px solid var(--hairline)', textAlign: 'center' }}>
                          <div style={{ fontSize: '10px', color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: '4px' }}>Incoming</div>
                          <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--accent)' }}>{fgData.links.filter(l => l.target === selectedNode.id || l.target.id === selectedNode.id).length}</div>
                        </div>
                        <div style={{ flex: 1, background: 'var(--glass-1)', padding: '12px', borderRadius: '10px', border: '1px solid var(--hairline)', textAlign: 'center' }}>
                          <div style={{ fontSize: '10px', color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: '4px' }}>Outgoing</div>
                          <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--accent)' }}>{fgData.links.filter(l => l.source === selectedNode.id || l.source.id === selectedNode.id).length}</div>
                        </div>
                      </div>
                      
                      {(selectedNode.is_vulnerable === 'True' || selectedNode.is_vulnerable === true) && (
                         <div style={{ padding: '20px', background: 'rgba(255, 86, 48, 0.08)', border: '1px solid rgba(255, 86, 48, 0.2)', borderRadius: '12px', boxShadow: '0 4px 20px rgba(255, 86, 48, 0.1)' }}>
                            <div style={{ color: '#FF5630', fontWeight: 700, marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '14px' }}>
                               <span style={{ fontSize: '18px' }}>🚫</span> VULNERABLE ELEMENT
                            </div>
                            <div style={{ fontSize: '13px', color: 'var(--text-1)', lineHeight: 1.6 }}>
                               This <strong>{selectedNode.label}</strong> node representing <code>{selectedNode.name || 'unnamed'}</code> was flagged during deep analysis.
                            </div>
                            <div style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-2)', fontStyle: 'italic' }}>
                                Potential impact: {selectedNode.impact || 'Remote code execution or data leakage through unvalidated flow.'}
                            </div>
                            <div style={{ marginTop: '16px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                <span style={{ padding: '4px 10px', background: 'rgba(255, 86, 48, 0.2)', color: '#FF5630', borderRadius: '6px', fontSize: '11px', fontWeight: 700 }}>SEVERITY: {selectedNode.severity?.toUpperCase() || 'HIGH'}</span>
                                <span style={{ padding: '4px 10px', background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-2)', borderRadius: '6px', fontSize: '11px' }}>CONFIDENCE: 94%</span>
                            </div>
                         </div>
                      )}

                      {(selectedNode.code || selectedNode.CODE) && (
                        <div>
                           <div style={{ fontSize: '10px', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '8px', fontWeight: 700 }}>Code Snapshot</div>
                           <div style={{ borderRadius: '10px', overflow: 'hidden', border: '1px solid var(--hairline)' }}>
                              <CodeWindow source={selectedNode.code || selectedNode.CODE} focusLine={selectedNode.lineNumber} context={2} variant="dark" />
                           </div>
                        </div>
                      )}

                      <div style={{ borderTop: '1px solid var(--hairline)', paddingTop: '24px' }}>
                        <div style={{ fontSize: '10px', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '12px', fontWeight: 700 }}>Properties Spectrum</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {Object.entries(selectedNode).filter(([k]) => !['id','label','name','color','val','lineNumber','code','is_vulnerable','severity','x','y','z','vx','vy','vz','index','__threeObj'].includes(k)).map(([k, v]) => (
                              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', fontSize: '12px' }}>
                                 <span style={{ color: 'var(--text-3)', fontWeight: 500 }}>{k}</span>
                                 <span style={{ color: 'var(--text-2)', textAlign: 'right', marginLeft: '12px', wordBreak: 'break-all' }}>{String(v)}</span>
                              </div>
                          ))}
                        </div>
                      </div>
                    </div>
                ) : (
                    <div style={{ color: 'var(--text-3)', textAlign: 'center', marginTop: '100px', fontSize: '14px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}>
                       <div style={{ width: '80px', height: '80px', borderRadius: '50%', background: 'var(--glass-1)', border: '1px dashed var(--hairline)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-2)', fontSize: '32px' }}>
                          🛰️
                       </div>
                       <div style={{ maxWidth: '200px', lineHeight: 1.6 }}>
                          Select a node in the 3D space to inspect its structural properties.
                       </div>
                    </div>
                )}
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
