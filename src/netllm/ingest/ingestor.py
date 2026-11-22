"""
Used offline to build the knowledge base AND at runtime for files users upload.

Every chunk is stamped with a scope:
  admin   - curated KB built offline (textbooks, RFCs); shared by all sessions
  session - uploaded/pasted during a session; visible to that session only
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from .chunker import Chunker
from .cleaner import Cleaner
from .models import Chunk, Document, Page
from .parsers import Parser, PdfParser, TextParser
from .splitter import SectionSplitter

# ----------------------------------------------------------------------- ingestor
Scope = Literal["admin", "session"]

DEFAULT_PARSERS: dict[str, Parser] = {".pdf": PdfParser(), ".md": TextParser(), ".txt": TextParser()}

class Ingestor:
    """load -> clean -> split -> chunk. Each stage is swappable."""

    def __init__(self, parsers: dict[str, Parser] | None = None, cleaner: Cleaner | None = None,
                 splitter: SectionSplitter | None = None, chunker: Chunker | None = None):
        self.parsers = parsers or DEFAULT_PARSERS
        self.cleaner = cleaner or Cleaner()
        self.splitter = splitter or SectionSplitter()
        self.chunker = chunker or Chunker()

    def load(self, path: str | Path) -> Document:
        path = Path(path)
        parser = self.parsers.get(path.suffix.lower())
        if parser is None:
            raise ValueError(f"No parser for '{path.suffix}'. Supported: {sorted(self.parsers)}")
        return parser.parse(path)

    def ingest(self, path: str | Path, scope: Scope = "admin") -> list[Chunk]:
        """A file on disk: a textbook offline, or a user upload at runtime."""
        path = Path(path)
        doc = self.load(path)
        doc.metadata["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        return self._process(doc, scope)

    def ingest_text(self, text: str, source: str = "user_input", scope: Scope = "session") -> list[Chunk]:
        """Raw text pasted into the chat at runtime."""
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return self._process(Document(source, [Page(text, 1)], {"sha256": sha}), scope)

    def ingest_dir(self, folder: str | Path, scope: Scope = "admin") -> list[Chunk]:
        chunks: list[Chunk] = []
        for path in sorted(Path(folder).rglob("*")):
            if path.suffix.lower() in self.parsers:
                chunks.extend(self.ingest(path, scope))
        return chunks

    def _process(self, doc: Document, scope: Scope) -> list[Chunk]:
        doc = self.cleaner.clean(doc)
        chunks = self.chunker.chunk(doc, self.splitter.split(doc))
        # Provenance: with source/section/page/part from the chunker, enough to cite a chunk and to
        # tell which exact file version it came from (sha256 of the raw bytes or pasted text).
        for c in chunks:
            c.metadata["scope"] = scope
            if "sha256" in doc.metadata:
                c.metadata["source_sha256"] = doc.metadata["sha256"]
        return chunks


def write_jsonl(chunks: list[Chunk], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(asdict(c), ensure_ascii=False) + "\n" for c in chunks)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="file or folder")
    ap.add_argument("--out", default="data/chunks.jsonl")
    ap.add_argument("--scope", choices=["admin", "session"], default="admin")
    args = ap.parse_args()

    ing = Ingestor()
    src = Path(args.input)
    chunks = ing.ingest_dir(src, args.scope) if src.is_dir() else ing.ingest(src, args.scope)
    write_jsonl(chunks, args.out)

    sizes = sorted(ing.chunker.n_tokens(c.text) for c in chunks)
    if sizes:
        print(f"{len(chunks)} chunks -> {args.out}")
        print(f"tokens  min {sizes[0]}  median {sizes[len(sizes) // 2]}  max {sizes[-1]}")