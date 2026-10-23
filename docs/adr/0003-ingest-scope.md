# 0003 — Ingested chunks carry a scope (admin | session)

**Status:** accepted · 2026-10-21

The curated knowledge base (textbooks, RFCs, built offline) and material a learner uploads during a
session go through the same ingestor, but must not mix: uploads are private to a session and must
not change answers for others or for eval runs. Every chunk is therefore stamped with
`metadata["scope"]`, and the KB stores each scope in its own Chroma collection.
