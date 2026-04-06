
import json
import csv
import io
import os
from typing import Dict, List, Any, Set
import boto3

s3 = boto3.client("s3")

def read_csv_from_s3(bucket: str, key: str) -> List[Dict[str, Any]]:
    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj["Body"].read().decode("utf-8")
    return list(csv.DictReader(io.StringIO(body)))

def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default

def build_nodes(entities_rows: List[Dict[str, Any]], reports_rows: List[Dict[str, Any]], edges_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nodes: Dict[str, Dict[str, Any]] = {}

    for row in entities_rows:
        node_id = row.get("name")
        if not node_id:
            continue
        nodes[node_id] = {
            "id": node_id,
            "type": row.get("type", "Unknown"),
            "threat_score": safe_float(row.get("threat_score")),
            "confidence": row.get("confidence"),
            "mentions": safe_int(row.get("mentions")),
            "last_seen": row.get("last_seen"),
            "primary_location": row.get("primary_location"),
            "status": row.get("status"),
        }

    referenced_nodes: Set[str] = set()
    for row in edges_rows:
        if row.get("source"):
            referenced_nodes.add(row["source"])
        if row.get("target"):
            referenced_nodes.add(row["target"])

    for row in reports_rows:
        for item in row.get("entities", "").split("|"):
            item = item.strip()
            if item:
                referenced_nodes.add(item)
        if row.get("location"):
            referenced_nodes.add(row["location"])

    known_locations = {r.get("primary_location") for r in entities_rows if r.get("primary_location")}
    known_locations |= {r.get("location") for r in reports_rows if r.get("location")}

    for node_id in referenced_nodes:
        if node_id in nodes:
            continue
        inferred_type = "Location" if node_id in known_locations else "Unknown"
        nodes[node_id] = {
            "id": node_id,
            "type": inferred_type,
            "threat_score": 0.0,
            "confidence": None,
            "mentions": 0,
            "last_seen": None,
            "primary_location": node_id if inferred_type == "Location" else None,
            "status": None,
        }

    return list(nodes.values())

def build_edges(edges_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    for row in edges_rows:
        source = row.get("source")
        target = row.get("target")
        if not source or not target:
            continue
        output.append({
            "source": source,
            "target": target,
            "relationship": row.get("relationship", "related_to"),
            "weight": safe_float(row.get("weight"), 1.0),
        })
    return output

def build_report_index(reports_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    for row in reports_rows:
        output.append({
            "report_id": row.get("report_id"),
            "date": row.get("date"),
            "source_type": row.get("source_type"),
            "confidence": row.get("confidence"),
            "location": row.get("location"),
            "excerpt": row.get("excerpt"),
            "entities": [x.strip() for x in row.get("entities", "").split("|") if x.strip()],
            "relevance": row.get("relevance"),
        })
    return output

def build_unified_graph(entities_rows: List[Dict[str, Any]], reports_rows: List[Dict[str, Any]], edges_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "metadata": {
            "generated_by": "aws_lambda",
            "node_count": 0,
            "edge_count": 0,
            "report_count": len(reports_rows),
        },
        "nodes": build_nodes(entities_rows, reports_rows, edges_rows),
        "edges": build_edges(edges_rows),
        "reports": build_report_index(reports_rows),
    }

def lambda_handler(event, context):
    bucket = event.get("bucket") or os.environ.get("BUCKET")
    entities_key = event.get("entities_key") or os.environ.get("ENTITIES_KEY", "input/entities.csv")
    reports_key = event.get("reports_key") or os.environ.get("REPORTS_KEY", "input/reports.csv")
    edges_key = event.get("edges_key") or os.environ.get("EDGES_KEY", "input/edges.csv")
    output_key = event.get("output_key") or os.environ.get("OUTPUT_KEY", "output/unified_graph.json")

    if not bucket:
        raise ValueError("Missing required bucket name in event or BUCKET environment variable.")

    entities_rows = read_csv_from_s3(bucket, entities_key)
    reports_rows = read_csv_from_s3(bucket, reports_key)
    edges_rows = read_csv_from_s3(bucket, edges_key)

    graph = build_unified_graph(entities_rows, reports_rows, edges_rows)
    graph["metadata"]["node_count"] = len(graph["nodes"])
    graph["metadata"]["edge_count"] = len(graph["edges"])

    s3.put_object(
        Bucket=bucket,
        Key=output_key,
        Body=json.dumps(graph, indent=2).encode("utf-8"),
        ContentType="application/json",
    )

    return {
        "statusCode": 200,
        "message": "unified_graph.json generated successfully",
        "bucket": bucket,
        "output_key": output_key,
        "node_count": graph["metadata"]["node_count"],
        "edge_count": graph["metadata"]["edge_count"],
        "report_count": graph["metadata"]["report_count"],
    }
