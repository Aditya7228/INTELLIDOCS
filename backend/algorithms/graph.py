from enum import Enum
from typing import Dict, List, Set, Tuple, Optional

class RelationType(str, Enum):
    EXACT_DUPLICATE = "exact_duplicate"
    POSSIBLE_NEAR_DUPLICATE = "possible_near_duplicate"
    VERSION = "version"
    RELATED = "related"

class Edge:
    def __init__(self, target_id: int, relation_type: str, score: float):
        self.target_id = target_id
        self.relation_type = relation_type
        self.score = score

class DocumentGraph:
    """
    Adjacency List Document Graph data structure for document relationships & BFS traversal.
    """
    def __init__(self):
        self._adj: Dict[int, List[Edge]] = {}

    def add_node(self, doc_id: int):
        if doc_id not in self._adj:
            self._adj[doc_id] = []

    def add_edge(self, doc_a: int, doc_b: int, relation_type: str, score: float):
        self.add_node(doc_a)
        self.add_node(doc_b)

        # Undirected graph edge insertion (check existing to avoid duplicates)
        if not any(e.target_id == doc_b for e in self._adj[doc_a]):
            self._adj[doc_a].append(Edge(doc_b, relation_type, score))
        if not any(e.target_id == doc_a for e in self._adj[doc_b]):
            self._adj[doc_b].append(Edge(doc_a, relation_type, score))

    def get_neighbors(self, doc_id: int) -> List[Edge]:
        return self._adj.get(doc_id, [])

    def bfs_related(self, start_doc_id: int, max_depth: int = 2) -> List[Tuple[int, str, float, int]]:
        """
        BFS traversal up to max_depth. Returns list of (target_doc_id, relation_type, score, depth).
        """
        if start_doc_id not in self._adj:
            return []

        visited: Set[int] = {start_doc_id}
        queue: List[Tuple[int, int]] = [(start_doc_id, 0)]  # (doc_id, depth)
        results: List[Tuple[int, str, float, int]] = []

        while queue:
            curr_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            for edge in self._adj.get(curr_id, []):
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    results.append((edge.target_id, edge.relation_type, edge.score, depth + 1))
                    queue.append((edge.target_id, depth + 1))

        return results

    def remove_node(self, doc_id: int):
        if doc_id in self._adj:
            del self._adj[doc_id]
        for node, edges in list(self._adj.items()):
            self._adj[node] = [e for e in edges if e.target_id != doc_id]

