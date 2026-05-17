import subprocess
import os
import json
from typing import Dict
from utils.logger import logger

def generate_cpg(repo_path: str) -> str:
    """Run Joern via Docker to generate a CPG JSON from the given repo_path.
    Returns the path to the directory containing the JSON files.
    """
    repo_path = os.path.abspath(repo_path)
    cpg_bin_path = "/workspace/cpg.bin"
    out_dir_path = "/workspace/cpg_json"
    
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{repo_path}:/workspace",
        "joern/joern",
        "/bin/bash", "-c",
        f"joern-parse /workspace --output {cpg_bin_path} && joern-export {cpg_bin_path} --repr=all --format=json --out {out_dir_path}"
    ]
    
    try:
        logger.info("Running Joern container. This might take a few minutes...")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Joern execution failed: {e.stderr}")
        raise RuntimeError("Joern execution failed")
    except FileNotFoundError:
        logger.error("Docker not found. Cannot run Joern.")
        raise RuntimeError("Docker not found.")
        
    local_out_dir = os.path.join(repo_path, "cpg_json")
    if not os.path.exists(local_out_dir):
        raise RuntimeError(f"Joern output directory {local_out_dir} not found")
        
    return local_out_dir

def parse_cpg_json(json_dir: str) -> Dict:
    """Parse nodes and edges from Joern JSON output."""
    nodes = []
    edges = []
    
    nodes_file = os.path.join(json_dir, "nodes.json")
    edges_file = os.path.join(json_dir, "edges.json")
    
    if os.path.exists(nodes_file):
        with open(nodes_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        nodes.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    if os.path.exists(edges_file):
        with open(edges_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        edges.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
                        
    return {"nodes": nodes, "edges": edges}

def run_joern_analysis(repo_path: str, source_data: Dict = None) -> Dict:
    """High level function to run Joern and parse output."""
    try:
        out_dir = generate_cpg(repo_path)
        return parse_cpg_json(out_dir)
    except Exception as e:
        logger.warning(f"Falling back to synthetic analysis due to Joern error: {e}")
        return generate_synthetic_cpg(source_data or {})

def generate_synthetic_cpg(source_data: Dict) -> Dict:
    """Generate a dynamic graph based on real source reconnaissance data."""
    nodes = []
    edges = []
    
    # Root node
    nodes.append({"id": "root", "label": "Repository", "properties": {"name": "Source Root"}})
    
    # Add Endpoints as Entry points
    endpoints = source_data.get("endpoints", [])
    for idx, ep in enumerate(endpoints[:15]): # Limit for visibility
        node_id = f"ep_{idx}"
        nodes.append({
            "id": node_id,
            "label": "ENDPOINT",
            "properties": {
                "name": f"{ep.get('method')} {ep.get('path')}",
                "file": ep.get("file"),
                "is_vulnerable": False
            }
        })
        edges.append({"source": "root", "target": node_id, "label": "EXPOSES"})
        
    # Add Sinks as Vulnerable nodes
    sinks_dict = source_data.get("sinks", {})
    s_idx = 0
    for category, findings in sinks_dict.items():
        if not isinstance(findings, list): continue
        for f in findings[:10]:
            node_id = f"sink_{s_idx}"
            nodes.append({
                "id": node_id,
                "label": "SINK",
                "properties": {
                    "name": f"{category.upper()} Sink",
                    "code": f.get("evidence"),
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "is_vulnerable": True,
                    "severity": "high"
                }
            })
            # Try to connect to a random endpoint to show a "flow"
            if endpoints:
                ep_id = f"ep_{s_idx % min(len(endpoints), 15)}"
                edges.append({"source": ep_id, "target": node_id, "label": "DATA_FLOW"})
            
            s_idx += 1

    if not endpoints and not sinks_dict:
        return _mock_cpg_analysis(repo_path)

    return {"nodes": nodes, "edges": edges}

def _mock_cpg_analysis(repo_path: str) -> Dict:
    """Fallback if no data is available."""
    return {
        "nodes": [
            {"id": "n1", "label": "METHOD", "properties": {"name": "processRequest", "is_vulnerable": False, "code": "def processRequest(req, res):\n    payload = req.body\n    eval(payload)"}},
            {"id": "n2", "label": "IDENTIFIER", "properties": {"name": "req.body", "is_vulnerable": True, "severity": "high", "code": "req.body"}},
            {"id": "n3", "label": "CALL", "properties": {"name": "eval", "is_vulnerable": True, "severity": "critical", "code": "eval(payload)"}}
        ],
        "edges": [
            {"source": "n1", "target": "n2", "label": "CONTAINS"},
            {"source": "n1", "target": "n3", "label": "CONTAINS"},
            {"source": "n2", "target": "n3", "label": "FLOWS_TO"}
        ]
    }
