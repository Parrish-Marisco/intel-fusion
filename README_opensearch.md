# OpenSearch Integration for Hybrid Intelligence Analysis Platform

## Files
- `opensearch_indexer.py` — standalone indexer for `unified_graph.json`
- `lambda_opensearch_patch.py` — patch snippets to add OpenSearch indexing to your Lambda

## Install
```bash
pip install opensearch-py boto3 requests-aws4auth
```

## Environment variables
```bash
export OPENSEARCH_HOST=search-your-domain.us-east-1.es.amazonaws.com
export AWS_REGION=us-east-1
export OPENSEARCH_SERVICE=es
export GRAPH_PATH=unified_graph.json
```

Optional:
```bash
export OPENSEARCH_NODES_INDEX=hybrid-intel-nodes
export OPENSEARCH_EDGES_INDEX=hybrid-intel-edges
```

## Run
```bash
python opensearch_indexer.py
```

## Suggested OpenSearch indexes
- `hybrid-intel-nodes`
- `hybrid-intel-edges`

## Useful sample queries

### Top threat entities
```json
{
  "size": 10,
  "sort": [{"threat_score": "desc"}],
  "query": {
    "bool": {
      "filter": [
        {"term": {"type": "Person"}}
      ]
    }
  }
}
```

### Find all nodes tied to JNIM
```json
{
  "query": {
    "term": {
      "connections": "Jama'at Nusrat al-Islam wal-Muslimin (JNIM)"
    }
  }
}
```

### Find all edges for Ibrahim Traore
```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"source.keyword": "Ibrahim Traore"}},
        {"term": {"target.keyword": "Ibrahim Traore"}}
      ],
      "minimum_should_match": 1
    }
  }
}
```
