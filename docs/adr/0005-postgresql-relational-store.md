# 0005 — PostgreSQL as the relational store

**Status:** accepted · 2026-11-18

Sessions, messages, upload records, the fact store and the run index need a relational store next
to Chroma (see [storage.md](../storage.md)), and deleting a session must reliably delete everything
derived from it. We use a local PostgreSQL server, configured with `NETLLM_DATABASE_URL` in `.env`
and changed only through versioned migrations (Alembic). Foreign keys with `ON DELETE CASCADE` make
`purge_session` a single delete, `timestamptz` columns carry `expires_at`, and concurrent access is
ready for when several sessions or a UI run at once. Tables are split into a `core` schema (durable,
backed up) and a `session` schema (personal and ephemeral, excluded with
`pg_dump --exclude-schema=session`), so backups never keep data that retention says to delete. The
cost is one more service to run locally (a container in development) and a migration step in setup.
Chroma stays the vector store; moving vectors into `pgvector` is left open.
