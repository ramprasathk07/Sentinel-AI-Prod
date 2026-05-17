import os
from typing import Dict, Any, List
from falkordb import FalkorDB
from utils.logger import logger

FALKORDB_URI = os.getenv("FALKORDB_URI", "redis://localhost:6379")

try:
    _client = FalkorDB.from_url(FALKORDB_URI)
except Exception as e:
    _client = None
    logger.warning(f"Failed to connect to FalkorDB at {FALKORDB_URI}: {e}")

def create_graph(graph_name: str):
    if not _client:
        raise ConnectionError("FalkorDB client not initialized.")
    graph = _client.select_graph(graph_name)
    try:
        graph.query("CREATE INDEX ON :Node(id)")
    except Exception:
        pass
    return graph

def add_node(graph_name: str, node_id: str, label: str, properties: Dict[str, Any]):
    if not _client:
        return
    graph = _client.select_graph(graph_name)
    
    params = {"id": node_id}
    props_str_list = ["id: $id"]
    for k, v in properties.items():
        if v is None:
            continue
        params[k] = v
        props_str_list.append(f"{k}: ${k}")
        
    props_str = ", ".join(props_str_list)
    
    query = f"MERGE (n:{label} {{{props_str}}})"
    try:
        graph.query(query, params)
    except Exception as e:
        logger.warning(f"FalkorDB add_node error: {e}")

def add_edge(graph_name: str, from_id: str, to_id: str, edge_type: str):
    if not _client:
        return
    graph = _client.select_graph(graph_name)
    query = f"""
    MATCH (a {{id: $from_id}}), (b {{id: $to_id}})
    MERGE (a)-[r:`{edge_type}`]->(b)
    """
    try:
        graph.query(query, {"from_id": from_id, "to_id": to_id})
    except Exception as e:
        logger.warning(f"FalkorDB add_edge error: {e}")

def query_nodes_by_vulnerability(graph_name: str) -> List[Dict]:
    if not _client:
        return []
    graph = _client.select_graph(graph_name)
    try:
        result = graph.query("MATCH (n {is_vulnerable: true}) RETURN n")
        nodes = []
        for record in result.result_set:
            n = record[0]
            nodes.append(n.properties)
        return nodes
    except Exception:
        return []

def query_entire_graph(graph_name: str) -> Dict:
    if not _client:
        return {"nodes": [], "edges": []}
    graph = _client.select_graph(graph_name)
    try:
        nodes_res = graph.query("MATCH (n) RETURN n")
        nodes = []
        for record in nodes_res.result_set:
            n = record[0]
            node_data = {"id": n.properties.get("id"), "label": n.labels[0] if n.labels else "Node"}
            node_data.update(n.properties)
            nodes.append({"data": node_data})
            
        edges_res = graph.query("MATCH (a)-[r]->(b) RETURN a.id, r, b.id")
        edges = []
        for record in edges_res.result_set:
            source = record[0]
            r = record[1]
            target = record[2]
            edges.append({
                "data": {
                    "source": source,
                    "target": target,
                    "label": r.relation
                }
            })
            
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        logger.warning(f"FalkorDB query_entire_graph error: {e}")
        return {"nodes": [], "edges": []}

def get_graph_summary(graph_name: str) -> Dict:
    if not _client:
        return {}
    graph = _client.select_graph(graph_name)
    try:
        res = graph.query("MATCH (n) RETURN count(n)")
        node_count = res.result_set[0][0] if res.result_set else 0
        
        res_edges = graph.query("MATCH ()-[r]->() RETURN count(r)")
        edge_count = res_edges.result_set[0][0] if res_edges.result_set else 0
        
        return {"node_count": node_count, "edge_count": edge_count}
    except Exception:
        return {"node_count": 0, "edge_count": 0}

def list_graphs() -> List[str]:
    if not _client:
        return []
    try:
        # Try native list_graphs first
        graphs = _client.list_graphs()
        if graphs:
            return graphs
    except Exception:
        pass
    
    # Fallback: scan all keys for the graph prefix
    try:
        # FalkorDB stores graphs as keys. We can try to list keys.
        # This is a bit hacky but works as a fallback.
        keys = _client.connection.keys('*')
        graphs = set()
        for k in keys:
            ks = k.decode('utf-8')
            if ks.startswith('repo_'):
                graphs.add(ks)
        return list(graphs)
    except Exception as e:
        logger.warning(f"Fallback list_graphs error: {e}")
        return []

def persist_cpg_graph(graph_name: str, cpg_data: Dict):
    """Store CPG nodes and edges in FalkorDB."""
    if not _client:
        logger.warning("FalkorDB not connected. Cannot persist CPG.")
        return
        
    create_graph(graph_name)
    nodes = cpg_data.get("nodes", [])
    edges = cpg_data.get("edges", [])
    
    logger.info(f"Persisting {len(nodes)} nodes and {len(edges)} edges to {graph_name}")
    
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
    
    return graph_name
