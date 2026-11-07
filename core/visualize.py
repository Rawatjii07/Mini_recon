"""Network graph visualization for scan results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import networkx as nx


def build_graph(scan_data: dict[str, Any], target: str, output_path: str | Path = "output/scan_graph.png", show: bool = True) -> Path:
    """Build and save a graph showing domain -> subdomains -> directories -> vulnerabilities."""

    graph = nx.DiGraph()
    colors: list[str] = []

    graph.add_node(target, kind="domain")

    for subdomain in scan_data.get("subdomains", []):
        host = subdomain.get("host", "")
        graph.add_node(host, kind="subdomain_live" if subdomain.get("live") else "subdomain_dead")
        graph.add_edge(target, host)

    for directory in scan_data.get("directories", []):
        path = directory.get("path", "")
        graph.add_node(path, kind="directory")
        graph.add_edge(target, path)

    for fuzz in scan_data.get("fuzzing", []):
        if fuzz.get("possible_vulnerability"):
            label = f"{fuzz.get('param')}:{fuzz.get('attack_type')}:{fuzz.get('payload')[:18]}"
            graph.add_node(label, kind="vulnerability")
            graph.add_edge(target, label)

    color_map = {
        "domain": "blue",
        "subdomain_live": "green",
        "subdomain_dead": "gray",
        "directory": "orange",
        "vulnerability": "red",
    }
    for node in graph.nodes:
        colors.append(color_map.get(graph.nodes[node].get("kind"), "gray"))

    plt.figure(figsize=(12, 8))
    positions = nx.spring_layout(graph, seed=42)
    nx.draw(
        graph,
        positions,
        with_labels=True,
        node_color=colors,
        node_size=1300,
        font_size=8,
        arrows=True,
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path)
    if show:
        plt.show()
    plt.close()
    return path
