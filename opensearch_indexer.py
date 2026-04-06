import json
import os
from typing import Dict, Any, List, Optional

from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import boto3


def get_opensearch_client() -> OpenSearch:
    host = os.environ["OPENSEARCH_HOST"]  # e.g. search-my-domain.us-east-1.es.amazonaws.com
    region = os.environ.get("AWS_REGION", "us-east-1")
    service = os.environ.get("OPENSEARCH_SERVICE", "es")  # 'es' for managed OpenSearch, 'aoss' for serverless

    session = boto3.Session()
    credentials = session.get_credentials()
    frozen = credentials.get_frozen_credentials()
    awsauth = AWS4Auth(
        frozen.access_key,
        frozen.secret_key,
        region,
        service,
        session_token=frozen.token,
    )

    return OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        timeout=30,
    )


def ensure_index(client: OpenSearch, index_name: str, mapping: Dict[str, Any]) -> None:
    if client.indices.exists(index=index_name):
        return
    client.indices.create(index=index_name, body=mapping)


NODES_MAPPING = {
    "settings": {
        "index": {"number_of_shards": 1, "number_of_replicas": 1}
    },
    "mappings": {
        "properties": {
            "entity_id": {"type": "keyword"},
            "entity": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "type": {"type": "keyword"},
            "threat_score": {"type": "float"},
            "source_refs": {"type": "keyword"},
            "connections": {"type": "keyword"},
            "locations": {"type": "keyword"},
            "organizations": {"type": "keyword"},
            "confidence": {"type": "keyword"}
        }
    }
}

EDGES_MAPPING = {
    "settings": {
        "index": {"number_of_shards": 1, "number_of_replicas": 1}
    },
    "mappings": {
        "properties": {
            "edge_id": {"type": "keyword"},
            "source": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "target": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "relationship": {"type": "keyword"},
            "weight": {"type": "float"},
            "source_refs": {"type": "keyword"}
        }
    }
}


def make_entity_id(node: Dict[str, Any]) -> str:
    return f'{node["type"]}#{node["entity"]}'


def make_edge_id(edge: Dict[str, Any]) -> str:
    return f'{edge["source"]}|{edge["relationship"]}|{edge["target"]}'


def normalize_node(node: Dict[str, Any]) -> Dict[str, Any]:
    doc = {
        "entity_id": make_entity_id(node),
        "entity": node["entity"],
        "type": node["type"],
        "threat_score": float(node.get("threat_score", 0.0)),
        "source_refs": node.get("source_refs", []),
        "connections": node.get("connections", []),
        "locations": node.get("locations", []),
        "organizations": node.get("organizations", []),
        "confidence": node.get("confidence", "")
    }
    return doc


def normalize_edge(edge: Dict[str, Any]) -> Dict[str, Any]:
    doc = {
        "edge_id": make_edge_id(edge),
        "source": edge["source"],
        "target": edge["target"],
        "relationship": edge["relationship"],
        "weight": float(edge.get("weight", 0.0)),
        "source_refs": edge.get("source_refs", [])
    }
    return doc


def bulk_index(client: OpenSearch, index_name: str, docs: List[Dict[str, Any]], id_field: str) -> Dict[str, int]:
    if not docs:
        return {"indexed": 0}

    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index_name, "_id": doc[id_field]}}))
        lines.append(json.dumps(doc))

    body = "\n".join(lines) + "\n"
    response = client.bulk(body=body, refresh=True)

    indexed = 0
    if response.get("errors"):
        failures = []
        for item in response.get("items", []):
            result = item.get("index", {})
            status = result.get("status", 0)
            if 200 <= status < 300:
                indexed += 1
            else:
                failures.append(result)
        raise RuntimeError(f"Bulk index completed with failures: {failures[:3]}")
    else:
        indexed = len(docs)

    return {"indexed": indexed}


def index_graph(graph: Dict[str, Any],
                client: Optional[OpenSearch] = None,
                nodes_index: str = "hybrid-intel-nodes",
                edges_index: str = "hybrid-intel-edges") -> Dict[str, Any]:
    client = client or get_opensearch_client()

    ensure_index(client, nodes_index, NODES_MAPPING)
    ensure_index(client, edges_index, EDGES_MAPPING)

    node_docs = [normalize_node(n) for n in graph.get("nodes", [])]
    edge_docs = [normalize_edge(e) for e in graph.get("edges", [])]

    node_result = bulk_index(client, nodes_index, node_docs, "entity_id")
    edge_result = bulk_index(client, edges_index, edge_docs, "edge_id")

    return {
        "nodes_index": nodes_index,
        "edges_index": edges_index,
        "nodes_indexed": node_result["indexed"],
        "edges_indexed": edge_result["indexed"]
    }


def load_graph(path: str = "unified_graph.json") -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    graph_path = os.environ.get("GRAPH_PATH", "unified_graph.json")
    graph = load_graph(graph_path)
    result = index_graph(graph)
    print(json.dumps(result, indent=2))
