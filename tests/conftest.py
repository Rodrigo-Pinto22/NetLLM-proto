import hashlib
import math
import re
import sys
import types

import pytest


class FakeTokenizer:
    """One token per whitespace-separated word: deterministic and needs no model download."""

    def encode(self, text: str, add_special_tokens: bool = True) -> list[int]:
        return list(range(len(text.split())))


@pytest.fixture
def fake_transformers(monkeypatch):
    """Replace `transformers` so Chunker() builds a FakeTokenizer instead of downloading bge."""
    requested: list[str] = []

    def from_pretrained(name: str) -> FakeTokenizer:
        requested.append(name)
        return FakeTokenizer()

    module = types.ModuleType("transformers")
    module.AutoTokenizer = types.SimpleNamespace(from_pretrained=from_pretrained)
    monkeypatch.setitem(sys.modules, "transformers", module)
    return requested


@pytest.fixture
def make_chunker(fake_transformers):
    from netllm.ingest.chunker import Chunker

    def make(**kwargs) -> Chunker:
        return Chunker(**kwargs)

    return make


def words(n: int, word: str = "w") -> str:
    return " ".join(f"{word}{i}" for i in range(n))


class BagOfWordsEmbedder:
    """Deterministic stand-in for the embedding model: hashed word counts, L2-normalised."""

    dim = 64

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        for w in re.findall(r"\w+", text.lower()):
            v[int(hashlib.md5(w.encode()).hexdigest(), 16) % self.dim] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def embed_documents(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


@pytest.fixture
def store():
    """KnowledgeStore on an in-memory Chroma, emptied for every test."""
    import chromadb
    from chromadb.config import Settings

    from netllm.kb.store import KnowledgeStore

    client = chromadb.EphemeralClient(settings=Settings(allow_reset=True, anonymized_telemetry=False))
    client.reset()  # in-memory clients share state within a process
    return KnowledgeStore(client, BagOfWordsEmbedder())
