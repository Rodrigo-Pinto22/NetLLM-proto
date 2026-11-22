# 0010 — Flyway for database migrations

**Status:** accepted · 2026-11-19 · supersedes the migration tool (Alembic) in [0005](0005-postgresql-relational-store.md)

ADR 0005 named Alembic for PostgreSQL schema changes. We use Flyway instead. Migrations are plain
SQL files in `migrations/` (`V<n>__<description>.sql`), so the schema is readable without knowing
an ORM, and SQL features like schemas, `jsonb` and identity columns are written as is. Migrations
run from the official Flyway image as a one-shot `flyway` compose service. `app` starts only after
it succeeds, which keeps migrations out of the app image and means the host needs no Java. Flyway
creates the `core` and `session` schemas and keeps its history table in `core`, and `clean` is
disabled. Applied migrations are never edited; every change is a new version. The cost is that
migrations aren't generated from Python models, every schema change is written by hand in SQL, and
rolling back means writing a new migration, since Flyway Community has no undo.
