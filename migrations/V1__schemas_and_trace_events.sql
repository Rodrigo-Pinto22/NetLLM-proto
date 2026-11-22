-- Schemas core/session (docs/storage.md, ADR 0005) and session.trace_events.
-- Flyway creates both schemas (FLYWAY_SCHEMAS=core,session) and keeps its history in core.
-- core: durable, backed up. session: personal + ephemeral, excluded from backups.
-- Never edit a migration that has been applied; add V2__..., V3__... instead.

-- session_id gets a FK to session.sessions (ON DELETE CASCADE) once that table exists (SCRUM-27).
CREATE TABLE session.trace_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id  uuid,
    kind        text        NOT NULL,
    payload     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL DEFAULT now() + interval '7 days'
);

CREATE INDEX trace_events_session_idx ON session.trace_events (session_id);
CREATE INDEX trace_events_expires_idx ON session.trace_events (expires_at);
