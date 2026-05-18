import uuid
import subprocess
import tempfile
from typing import Optional, List, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.graph_db import create_graph, add_node, add_edge, query_entire_graph, query_nodes_by_vulnerability, list_graphs
from core.joern_runner import run_joern_analysis
from utils.logger import logger

router = APIRouter()

class CPGScanRequest(BaseModel):
    repo_url: str
    pr_number: int
    github_token: Optional[str] = None

class CPGScanResponse(BaseModel):
    scan_id: str
    vulnerability_count: int
    graph_name: str
    vulnerabilities: List[Dict]

def _clone_repo(repo_url: str, token: Optional[str], dest_dir: str):
    """Clone a GitHub repository into dest_dir."""
    if token and "github.com" in repo_url:
        auth_url = repo_url.replace("https://", f"https://{token}@")
    else:
        auth_url = repo_url
        
    cmd = ["git", "clone", "--depth", "1", auth_url, dest_dir]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Git clone failed: {e.stderr}")
        raise RuntimeError("Failed to clone repository")

@router.post("/scan-cpg", response_model=CPGScanResponse)
async def scan_cpg(req: CPGScanRequest):
    repo_url = req.repo_url.strip()
    
    # Auto-sanitize PR URL formats (e.g. trailing /pull, /pull/3, /pulls/3)
    import re
    pr_match = re.match(r"^(https?://github\.com/[^/]+/[^/]+)/pull(?:s)?(?:/\d+)?/?$", repo_url, re.IGNORECASE)
    if pr_match:
        repo_url = pr_match.group(1)
        
    repo_url = repo_url.rstrip("/")
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]
        
    if not repo_url.startswith("http"):
        repo_url = f"https://github.com/{repo_url}"
        
    scan_id = str(uuid.uuid4())
    
    # Extract owner/repo for graph name
    parts = repo_url.rstrip('/').split('/')
    if len(parts) >= 2:
        owner, repo = parts[-2], parts[-1]
    else:
        owner, repo = "unknown", "repo"
        
    graph_name = f"repo_{owner}_{repo}_pr_{req.pr_number}"
    
    # Create temp directory
    tmp_dir = tempfile.mkdtemp(prefix=f"cpg_scan_{scan_id}_")
    
    try:
        logger.info(f"Cloning {repo_url} to {tmp_dir}")
        _clone_repo(repo_url, req.github_token, tmp_dir)

        logger.info(f"Running Joern analysis on {tmp_dir}")
        cpg_data = run_joern_analysis(tmp_dir)
        
        logger.info(f"Creating FalkorDB graph: {graph_name}")
        create_graph(graph_name)
        
        nodes = cpg_data.get("nodes", [])
        edges = cpg_data.get("edges", [])
        
        # Populate DB
        for node in nodes:
            node_id = str(node.get("id"))
            label = node.get("label", "Node")
            props = node.get("properties", {})
            add_node(graph_name, node_id, label, props)
            
        for edge in edges:
            source = str(edge.get("source") or edge.get("outNode"))
            target = str(edge.get("target") or edge.get("inNode"))
            label = edge.get("label", "RELATED")
            add_edge(graph_name, source, target, label)
            
        vulns = query_nodes_by_vulnerability(graph_name)
        
        return CPGScanResponse(
            scan_id=scan_id,
            vulnerability_count=len(vulns),
            graph_name=graph_name,
            vulnerabilities=vulns
        )
        
    except Exception as e:
        logger.error(f"CPG Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cpg-graph/{graph_name}")
async def get_cpg_graph(graph_name: str):
    """Retrieve the graph for rendering in Cytoscape.js"""
    try:
        data = query_entire_graph(graph_name)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cpg-graphs")
async def get_cpg_graphs():
    """List all available CPG graphs"""
    try:
        graphs = list_graphs()
        # Filter for our naming convention repo_
        filtered = [g for g in graphs if g.startswith("repo_")]
        return {"graphs": filtered}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

