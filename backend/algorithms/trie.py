from typing import Dict, Set, List, Optional

class TrieNode:
    def __init__(self):
        self.children: Dict[str, "TrieNode"] = {}
        self.is_end: bool = False
        # Documents containing any token below this prefix.
        self.doc_ids: Set[int] = set()
        # Documents containing this exact token (only meaningful when is_end=True).
        self.terminal_doc_ids: Set[int] = set()

class Trie:
    """
    Trie (Prefix Tree) data structure for sub-50ms search autocomplete and prefix lookup.
    """
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word: str, doc_id: int):
        word = word.lower().strip()
        if not word:
            return

        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
            node.doc_ids.add(doc_id)

        node.is_end = True
        node.terminal_doc_ids.add(doc_id)

    def search_prefix(
        self,
        prefix: str,
        limit: int = 10,
        accessible_doc_ids: Optional[Set[int]] = None,
    ) -> List[str]:
        prefix = prefix.lower().strip()
        if not prefix:
            return []

        node = self.root
        for char in prefix:
            if char not in node.children:
                return []
            node = node.children[char]

        # Subtree traversal to collect matching words
        results = []
        self._dfs_collect(node, prefix, results, limit, accessible_doc_ids)
        return results

    def _dfs_collect(
        self,
        node: TrieNode,
        current_prefix: str,
        results: List[str],
        limit: int,
        accessible_doc_ids: Optional[Set[int]] = None,
    ):
        if len(results) >= limit:
            return

        if node.is_end and (
            accessible_doc_ids is None
            or node.terminal_doc_ids.intersection(accessible_doc_ids)
        ):
            results.append(current_prefix)

        for char, child_node in sorted(node.children.items()):
            if len(results) >= limit:
                break
            if accessible_doc_ids is not None and not child_node.doc_ids.intersection(accessible_doc_ids):
                continue
            self._dfs_collect(
                child_node, current_prefix + char, results, limit, accessible_doc_ids
            )

    def remove_doc(self, word: str, doc_id: int):
        word = word.lower().strip()
        node = self.root
        nodes_visited = [node]
        for char in word:
            if char not in node.children:
                return
            node = node.children[char]
            nodes_visited.append(node)

        for n in nodes_visited:
            n.doc_ids.discard(doc_id)
        node.terminal_doc_ids.discard(doc_id)
