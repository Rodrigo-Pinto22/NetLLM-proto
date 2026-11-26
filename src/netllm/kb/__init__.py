"""Knowledge base: Chroma collections per scope, retrieval with provenance, prompt formatting.

  store.py     - KnowledgeStore: kb_admin vs. kb_session_<id> collections, add/query/drop_session
  context.py   - format_context: retrieved chunks -> quoted <passage> block + citation list
  tools.py     - kb_search, the MCP tool the model calls (session filled in by the agent loop)
Planned:
  manifest.py  - which source files (and hashes) went into a KB build, so eval runs can cite a KB version
"""

from .context import Citation, Context, format_context
from .store import Embedder, Hit, KnowledgeStore, SentenceTransformerEmbedder, open_store
