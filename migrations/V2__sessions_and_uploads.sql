-- session.sessions and session.uploads (docs/storage.md §3), SCRUM-27.
-- Both are personal + ephemeral: they live in the `session` schema (excluded from backups) and
-- carry expires_at. Deleting a session cascades to its uploads and trace events.

-- Random, pseudonymous id: no name or email is ever stored for a learner.
CREATE TABLE session.sessions (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    profile     text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL DEFAULT now() + interval '24 hours'
);

CREATE INDEX sessions_expires_idx ON session.sessions (expires_at);

-- One row per uploaded file. The raw file is deleted after ingestion; its chunks live in the
-- Chroma collection kb_session_<session_id> and carry upload_id, so one upload can be removed.
CREATE TABLE session.uploads (
    id          uuid        PRIMARY KEY,
    session_id  uuid        NOT NULL REFERENCES session.sessions (id) ON DELETE CASCADE,
    filename    text        NOT NULL,
    sha256      text        NOT NULL,
    size_bytes  bigint      NOT NULL,
    n_chunks    integer     NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL DEFAULT now() + interval '24 hours'
);

CREATE INDEX uploads_session_idx ON session.uploads (session_id);

-- Promised in V1: trace events now cascade with their session. NULL session_id stays allowed
-- (e.g. /smoke writes events that belong to no session).
ALTER TABLE session.trace_events
    ADD CONSTRAINT trace_events_session_fk
    FOREIGN KEY (session_id) REFERENCES session.sessions (id) ON DELETE CASCADE;
