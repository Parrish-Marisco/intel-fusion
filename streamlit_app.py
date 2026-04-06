import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import networkx as nx


st.set_page_config(page_title="Hybrid Intelligence Analysis Platform", layout="wide")


@st.cache_data
def load_graph_from_file(uploaded_file=None, fallback_path: str = "unified_graph.json") -> Dict[str, Any]:
    if uploaded_file is not None:
        return json.load(uploaded_file)

    path = Path(fallback_path)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))

    return {"nodes": [], "edges": [], "metadata": {}}


def nodes_to_df(nodes: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for n in nodes:
        rows.append({
            "entity": n.get("entity"),
            "type": n.get("type"),
            "threat_score": n.get("threat_score", 0.0),
            "source_refs": ", ".join(n.get("source_refs", [])),
            "connections_count": len(n.get("connections", [])),
            "confidence": n.get("confidence", ""),
            "locations": ", ".join(n.get("locations", [])) if "locations" in n else "",
            "organizations": ", ".join(n.get("organizations", [])) if "organizations" in n else "",
        })
    return pd.DataFrame(rows)


def edges_to_df(edges: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for e in edges:
        rows.append({
            "source": e.get("source"),
            "target": e.get("target"),
            "relationship": e.get("relationship"),
            "weight": e.get("weight", 0.0),
            "source_refs": ", ".join(e.get("source_refs", [])),
        })
    return pd.DataFrame(rows)


def build_graph(edges: List[Dict[str, Any]]) -> nx.Graph:
    g = nx.Graph()
    for e in edges:
        g.add_edge(
            e.get("source"),
            e.get("target"),
            relationship=e.get("relationship"),
            weight=e.get("weight", 0.0),
        )
    return g


def get_node_lookup(nodes: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {n["entity"]: n for n in nodes if "entity" in n}


def subgraph_for_entity(graph: nx.Graph, center: str, depth: int = 1) -> nx.Graph:
    if center not in graph:
        return nx.Graph()

    selected = {center}
    frontier = {center}

    for _ in range(depth):
        next_frontier = set()
        for node in frontier:
            next_frontier.update(graph.neighbors(node))
        selected.update(next_frontier)
        frontier = next_frontier

    return graph.subgraph(selected).copy()


def plot_network(graph: nx.Graph, node_lookup: Dict[str, Dict[str, Any]], title: str):
    fig, ax = plt.subplots(figsize=(10, 7))

    if graph.number_of_nodes() == 0:
        ax.text(0.5, 0.5, "No graph data available for this selection.", ha="center", va="center")
        ax.axis("off")
        st.pyplot(fig)
        return

    pos = nx.spring_layout(graph, seed=42)

    node_sizes = []
    labels = {}
    for node in graph.nodes():
        score = node_lookup.get(node, {}).get("threat_score", 0.2)
        node_sizes.append(800 + (score * 2200))
        labels[node] = node

    nx.draw_networkx_nodes(graph, pos, node_size=node_sizes, ax=ax)
    nx.draw_networkx_edges(graph, pos, width=1.5, ax=ax)
    nx.draw_networkx_labels(graph, pos, labels=labels, font_size=8, ax=ax)

    ax.set_title(title)
    ax.axis("off")
    st.pyplot(fig)


def plot_top_entities(df: pd.DataFrame, title: str, n: int = 10):
    fig, ax = plt.subplots(figsize=(10, 5))
    top_df = df.sort_values("threat_score", ascending=False).head(n)
    ax.bar(top_df["entity"], top_df["threat_score"])
    ax.set_title(title)
    ax.set_xlabel("Entity")
    ax.set_ylabel("Threat Score")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)


def build_hotspot_df(nodes_df: pd.DataFrame) -> pd.DataFrame:
    if nodes_df.empty:
        return pd.DataFrame(columns=["entity", "threat_score", "connections_count"])
    return (
        nodes_df[nodes_df["type"] == "Location"][["entity", "threat_score", "connections_count"]]
        .sort_values("threat_score", ascending=False)
        .reset_index(drop=True)
    )


def related_edges_df(edges_df: pd.DataFrame, entity: str) -> pd.DataFrame:
    if edges_df.empty or not entity:
        return pd.DataFrame(columns=edges_df.columns)
    return edges_df[(edges_df["source"] == entity) | (edges_df["target"] == entity)].reset_index(drop=True)


def main():
    st.title("Hybrid Intelligence Analysis Platform")
    st.caption("HUMINT + OSINT fusion, threat scoring, and graph-based entity analysis")

    uploaded_file = st.sidebar.file_uploader("Upload unified_graph.json", type=["json"])
    graph_data = load_graph_from_file(uploaded_file)

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    metadata = graph_data.get("metadata", {})

    nodes_df = nodes_to_df(nodes)
    edges_df = edges_to_df(edges)
    node_lookup = get_node_lookup(nodes)
    graph = build_graph(edges)

    st.sidebar.header("Filters")

    entity_types = sorted(nodes_df["type"].dropna().unique().tolist()) if not nodes_df.empty else []
    selected_types = st.sidebar.multiselect("Entity types", entity_types, default=entity_types)

    min_score = float(nodes_df["threat_score"].min()) if not nodes_df.empty else 0.0
    max_score = float(nodes_df["threat_score"].max()) if not nodes_df.empty else 1.0
    score_range = st.sidebar.slider("Threat score range", min_value=0.0, max_value=1.0, value=(min_score, max_score), step=0.01)

    filtered_nodes_df = nodes_df.copy()
    if not filtered_nodes_df.empty:
        filtered_nodes_df = filtered_nodes_df[
            filtered_nodes_df["type"].isin(selected_types) &
            filtered_nodes_df["threat_score"].between(score_range[0], score_range[1])
        ].reset_index(drop=True)

    st.subheader("Overview")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Nodes", metadata.get("node_count", len(nodes)))
    c2.metric("Edges", metadata.get("edge_count", len(edges)))
    c3.metric("Entity Types", len(metadata.get("entity_types", entity_types)))
    c4.metric("Filtered Nodes", len(filtered_nodes_df))

    tab1, tab2, tab3, tab4 = st.tabs(["Threat Overview", "Entity Explorer", "Hotspots", "Raw Data"])

    with tab1:
        left, right = st.columns(2)

        with left:
            if not filtered_nodes_df.empty:
                plot_top_entities(filtered_nodes_df, "Top Entities by Threat Score", n=min(10, len(filtered_nodes_df)))
            else:
                st.info("No entities match the current filters.")

        with right:
            type_counts = (
                filtered_nodes_df["type"].value_counts().reset_index()
                if not filtered_nodes_df.empty else pd.DataFrame(columns=["type", "count"])
            )
            if not type_counts.empty:
                type_counts.columns = ["type", "count"]
                fig, ax = plt.subplots(figsize=(8, 5))
                ax.bar(type_counts["type"], type_counts["count"])
                ax.set_title("Entity Counts by Type")
                ax.set_xlabel("Type")
                ax.set_ylabel("Count")
                st.pyplot(fig)
            else:
                st.info("No type distribution available.")

    with tab2:
        entity_options = filtered_nodes_df["entity"].tolist() if not filtered_nodes_df.empty else []
        selected_entity = st.selectbox("Select entity", options=entity_options)

        depth = st.slider("Graph depth", min_value=1, max_value=2, value=1, step=1)

        if selected_entity:
            node = node_lookup.get(selected_entity, {})
            st.markdown(f"### {selected_entity}")
            detail_cols = st.columns(4)
            detail_cols[0].metric("Type", node.get("type", ""))
            detail_cols[1].metric("Threat Score", node.get("threat_score", 0.0))
            detail_cols[2].metric("Connections", len(node.get("connections", [])))
            detail_cols[3].metric("Sources", len(node.get("source_refs", [])))

            st.write("**Source References:**", ", ".join(node.get("source_refs", [])))
            if node.get("locations"):
                st.write("**Locations:**", ", ".join(node.get("locations", [])))
            if node.get("organizations"):
                st.write("**Organizations:**", ", ".join(node.get("organizations", [])))
            if node.get("confidence"):
                st.write("**Confidence:**", node.get("confidence"))

            st.write("**Connections:**", ", ".join(node.get("connections", [])))

            entity_subgraph = subgraph_for_entity(graph, selected_entity, depth=depth)
            plot_network(entity_subgraph, node_lookup, f"Relationship Map: {selected_entity}")

            st.write("#### Related Edges")
            st.dataframe(related_edges_df(edges_df, selected_entity), use_container_width=True)

    with tab3:
        hotspot_df = build_hotspot_df(filtered_nodes_df)
        if not hotspot_df.empty:
            st.dataframe(hotspot_df, use_container_width=True)

            fig, ax = plt.subplots(figsize=(10, 5))
            ax.bar(hotspot_df["entity"], hotspot_df["threat_score"])
            ax.set_title("Location Hotspots")
            ax.set_xlabel("Location")
            ax.set_ylabel("Threat Score")
            ax.tick_params(axis="x", rotation=45)
            st.pyplot(fig)
        else:
            st.info("No location data available for the current filters.")

    with tab4:
        st.write("### Nodes")
        st.dataframe(filtered_nodes_df, use_container_width=True)

        st.write("### Edges")
        if not filtered_nodes_df.empty:
            visible_entities = set(filtered_nodes_df["entity"].tolist())
            filtered_edges_df = edges_df[
                edges_df["source"].isin(visible_entities) | edges_df["target"].isin(visible_entities)
            ].reset_index(drop=True)
        else:
            filtered_edges_df = edges_df

        st.dataframe(filtered_edges_df, use_container_width=True)

        st.download_button(
            label="Download visible nodes as CSV",
            data=filtered_nodes_df.to_csv(index=False).encode("utf-8"),
            file_name="filtered_nodes.csv",
            mime="text/csv"
        )

        st.download_button(
            label="Download visible edges as CSV",
            data=filtered_edges_df.to_csv(index=False).encode("utf-8"),
            file_name="filtered_edges.csv",
            mime="text/csv"
        )


if __name__ == "__main__":
    main()
