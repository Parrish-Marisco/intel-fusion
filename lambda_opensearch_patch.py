# Add this to your existing Lambda after the graph is built.
# It indexes nodes and edges into OpenSearch.

from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import boto3
import json
import os

def get_opensearch_client():
    host = os.environ["OPENSEARCH_HOST"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    service = os.environ.get("OPENSEARCH_SERVICE", "es")

    session = boto3.Session()
    credentials = session.get_credentials().get_frozen_credentials()
    awsauth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        region,
        service,
        session_token=credentials.token,
    )

    return OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        timeout=30,
    )

def ensure_index(client, index_name, mapping):
    if not client.indices.exists(index=index_name):
        client.indices.create(index=index_name, body=mapping)

NODES_MAPPING = {
    "mappings": {
        "properties": {
            "entity_id": {"type": "keyword"},
            "entity": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
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
    "mappings": {
        "properties": {
            "edge_id": {"type": "keyword"},
            "source": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "target": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "relationship": {"type": "keyword"},
            "weight": {"type": "float"},
            "source_refs": {"type": "keyword"}
        }
    }
}

def bulk_index(client, index_name, docs, id_field):
    if not docs:
        return 0

    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index_name, "_id": doc[id_field]}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    response = client.bulk(body=body, refresh=True)
    if response.get("errors"):
        raise RuntimeError("OpenSearch bulk indexing failed")
    return len(docs)

def index_graph_to_opensearch(graph):
    client = get_opensearch_client()
    nodes_index = os.environ.get("OPENSEARCH_NODES_INDEX", "hybrid-intel-nodes")
    edges_index = os.environ.get("OPENSEARCH_EDGES_INDEX", "hybrid-intel-edges")

    ensure_index(client, nodes_index, NODES_MAPPING)
    ensure_index(client, edges_index, EDGES_MAPPING)

    node_docs = []
    for n in graph["nodes"]:
        node_docs.append({
            "entity_id": f'{n["type"]}#{n["entity"]}',
            "entity": n["entity"],
            "type": n["type"],
            "threat_score": float(n.get("threat_score", 0.0)),
            "source_refs": n.get("source_refs", []),
            "connections": n.get("connections", []),
            "locations": n.get("locations", []),
            "organizations": n.get("organizations", []),
            "confidence": n.get("confidence", "")
        })

    edge_docs = []
    for e in graph["edges"]:
        edge_docs.append({
            "edge_id": f'{e["source"]}|{e["relationship"]}|{e["target"]}',
            "source": e["source"],
            "target": e["target"],
            "relationship": e["relationship"],
            "weight": float(e.get("weight", 0.0)),
            "source_refs": e.get("source_refs", [])
        })

    return {
        "nodes_indexed": bulk_index(client, nodes_index, node_docs, "entity_id"),
        "edges_indexed": bulk_index(client, edges_index, edge_docs, "edge_id")
    }

# Then inside lambda_handler, after graph is built:
# os_result = index_graph_to_opensearch(graph)
# include os_result in your response
