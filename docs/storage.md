# Storage design

**Status:** draft · 2026-11-17

What NetLLM stores, where, for how long, and how it is deleted. Values marked *(proposed)* are
defaults to confirm, not decisions yet.

## 1. Inventory

| Store | Contents | Truth or derived | Scope | Lifetime | Personal data | Deleted by |
| --- | --- | --- | --- | --- | --- | --- |
| `data/kb_docs/` | Curated sources (textbooks, RFCs) | **Source of truth** | admin | Durable | No | Manual |
| KB manifest | Source hashes, ingest params, embed model → `kb_version` | **Source of truth** | admin | Durable | No | Never (versions are kept) |
| Chroma `kb_admin_<kb_version>` | Vectors + chunk metadata for one KB build | Derived (manifest + docs) | admin | Durable, last N builds kept | No | Rebuild / prune old versions |
| Chroma `kb_session_<session_id>` | Vectors of a learner's uploads | Derived (upload) | session | Ephemeral | **Yes** | `purge_session` drops the collection |
| Uploads (`data/sessions/<session_id>/`) | Raw files a learner uploads (pcaps, notes) | **Source of truth** | session | Ephemeral | **Yes, high risk** | `purge_session` |
| PostgreSQL | Sessions, messages, upload records, fact store, run index | **Source of truth** | session / learner | Mixed (see §5) | **Yes** | `purge_session` / expiry job |
| Fact store (table in relational DB) | Facts inferred about the learner, with provenance | Derived (messages) | session (later: learner) | Ephemeral now | **Yes** | Cascades from the source session |
| `data/traces/` | LLM / tool-call traces | Derived (session) | session | Ephemeral | **Yes** (full conversations) | Expiry job |
| `runs/<run_id>/` | Eval metadata and results | **Source of truth** | admin | Durable, immutable | No | Manual only |

Rules that apply to every store:

- **One owner per fact.** Chroma stores vectors and the metadata needed to filter them. Anything
  relational (who uploaded what, when it expires) lives in the relational DB, which refers to Chroma
  by collection name or chunk id.
- **Scopes never mix** ([ADR 0003](adr/0003-ingest-scope.md)): admin and session data are in
  separate collections, and nothing in session scope affects other sessions or eval runs.

## 2. Durable vs ephemeral

The test is **"can it be rebuilt from something else?"**

- **Durable source of truth:** `kb_docs/`, KB manifests, `runs/`. Back these up.
- **Durable but derived:** admin Chroma collections. They are a cache of manifest + docs: rebuild
  them, don't back them up.
- **Ephemeral by design:** everything in session scope (uploads, session collections, messages,
  facts, traces). It cannot be rebuilt and is deleted on purpose. **Never back it up**, or backups
  would undo deletions.

## 3. Relational store: PostgreSQL

The relational store is **PostgreSQL**, running locally (for example in a container) and configured
through a `NETLLM_DATABASE_URL` DSN in `.env`. It provides real foreign keys with
`ON DELETE CASCADE` (which `purge_session` relies on), `JSONB` for flexible metadata, `timestamptz`
for expiry, and concurrent access when several sessions or a web UI run at once. Schema changes are
versioned migrations (Alembic). See [ADR 0005](adr/0005-postgresql-relational-store.md).

Tables are split into two schemas so that backups follow §2:

- `core`: durable data (`runs`). Backed up.
- `session`: ephemeral, personal data (`sessions`, `messages`, `uploads`, `facts`). Excluded from
  backups (`pg_dump --exclude-schema=session`).

Planned tables (sketch):

| Table | Key columns |
| --- | --- |
| `session.sessions` | `id` (random, pseudonymous), `profile`, `created_at`, `expires_at` |
| `session.messages` | `id`, `session_id` → sessions, `role`, `content`, `created_at` |
| `session.uploads` | `id`, `session_id` → sessions, `filename`, `sha256`, `size`, `created_at`, `expires_at` |
| `session.facts` | `id`, `session_id` → sessions, `source_message_id` → messages, `subject`, `value`, `confidence`, `created_at`, `expires_at` |
| `core.runs` | `run_id`, `started_at`, `kb_version`, `question_set`, `chat_model`, `git_sha` (index only, files stay in `runs/`) |

### Fact store

Facts are what the tutor infers about the learner ("knows the TCP handshake", "confuses SYN and
ACK"). Every fact carries **provenance** (`session_id`, `source_message_id`), so deleting a session
removes everything learned from it. Facts are session-scoped for now. Per-learner long-term facts
(`memory/long_term/`) amount to a profile of a person and need their own decision before they are
built: consent, how the learner sees and deletes them, and a retention limit.

## 4. KB versioning

- A **manifest** is written for each admin KB build (`data/manifests/<kb_version>.json`):
  - every source file: path, `sha256`, size
  - ingestor version and chunking parameters
  - embed model name and revision
- **`kb_version` = a short hash of the canonicalised manifest.** Identical inputs give the same
  version, and any change gives a new one.
- **Changing the embedding model always means a new version**, because vectors from different models
  can't be compared.
- **Chunk ids are deterministic:** `hash(source_sha256, chunk_index)`, so rebuilds are stable and
  two builds can be diffed.
- **Builds are immutable.** A new build creates `kb_admin_<kb_version>`, then a pointer
  (`data/manifests/current`) is switched. The last *3 (proposed)* builds are kept for comparison.
- Every eval run records the `kb_version` it used.

## 5. Runs

- `runs/<run_id>/` is **written once**: `meta.json` + `results.jsonl` (+ plots). Re-running creates a
  new `run_id`, and existing runs are never edited.
- `meta.json` records what is needed to reproduce the run: `git_sha`, `chat_model`, `embed_model`,
  `kb_version`, question-set file and version, profile, seed, and the start/end time.
- Runs read **admin scope only**. Pcaps used by evals are curated fixtures, never session uploads.
  Record a fixture by path + `sha256` instead of copying it into the run folder.

## 6. Privacy and retention

**Why uploads are the main risk:** a learner's own capture can contain real IP/MAC addresses, DNS
queries (browsing history), cookies and sometimes cleartext credentials. Notes and chat messages can
contain anything the learner types.

**Principles**

- **Local only.** All models run through Ollama on the same machine, so no learner data is sent to
  a third party. This is a property the design must keep: adding any remote service needs an ADR.
- **Collect as little as possible.** Session ids are random. No names or emails are stored. Profiles
  describe a level and a teaching mode, not a person.
- **Log references, not contents.** Traces and app logs record ids, hashes and tool names, not raw
  upload bytes or packet payloads.
- **Deletion covers derived copies too.** Deleting an upload also deletes its chunks, vectors and the
  facts inferred from it.

**Retention** *(proposed defaults)*

| Data | Retention |
| --- | --- |
| Raw uploads | Deleted after processing, at session end at the latest |
| Session Chroma collection, messages, facts | Session end, or 24 h after last activity |
| Traces | 7 days |
| Per-learner long-term facts | Not built yet (see §3) |
| Admin KB, manifests, runs | Kept indefinitely (no personal data) |

**Enforcement**

- Each ephemeral row has an `expires_at`. A cleanup command (`netllm-gc`, run at startup and on a
  schedule) purges expired sessions and traces.
- **One deletion path:** `purge_session(session_id)` removes the upload folder, drops
  `kb_session_<session_id>`, deletes the session's rows (messages, uploads and facts cascade) and its
  traces. It is the only code that deletes session data, and it is idempotent.
- **A test** creates a session with an upload, messages and facts, calls `purge_session`, and checks
  that nothing referencing that `session_id` remains in any store.
- **Learners are told** what is stored and for how long, and can end a session to delete its data
  immediately (the right to erasure, if GDPR applies to a deployment).

## 7. Open decisions

- Whether `pgvector` should later replace Chroma, giving one store instead of two. Not now: Chroma
  is already in place.
- KB versioning scheme (manifest hash + immutable collections) → ADR once implemented.
- Retention defaults in §6 → confirm, then record them in an ADR.
- Long-term learner facts: whether to build them at all, consent, and how learners see and delete them.
