-- Iteration 1 (offline, local experiments): the minimum to record, replay and compare sessions.
--   core:    labs, lab_steps (loaded from YAML at start-up), eval_runs (index of runs/<run_id>/).
--   session: turns (new); sessions, trace_events, uploads (extended).
-- Identity/consent/pseudonyms, mastery, KB metadata and insights are deferred (see the data model
-- doc). Adding them later is additive: e.g. a nullable pseudo_id column on sessions and uploads.

-- ---------------------------------------------------------------- core: course domain
-- Source of truth is a YAML file; the app upserts these rows at start-up. Slugs as keys so the
-- YAML and the database use the same ids (e.g. 'lab3-tcp', 'lab3-tcp.s2').
CREATE TABLE core.labs (
    id      text PRIMARY KEY,
    title   text NOT NULL
);

CREATE TABLE core.lab_steps (
    id                text    PRIMARY KEY,
    lab_id            text    NOT NULL REFERENCES core.labs (id) ON DELETE CASCADE,
    ordinal           integer NOT NULL CHECK (ordinal >= 1),
    goal              text    NOT NULL,
    expected_outcome  text,             -- for the policy/post-check only; never shown to students
    -- Checked at commit, not per row, so the loader can reorder steps (swap 1 and 2) in one go.
    UNIQUE (lab_id, ordinal) DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (lab_id, id)                 -- target of the composite FKs below
);

-- ---------------------------------------------------------------- core: evaluation runs
-- One row per run. Raw outputs stay in runs/<run_id>/ (written once, never edited).
CREATE TABLE core.eval_runs (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    profile       text        NOT NULL,   -- configs/profiles/<profile>.yaml
    chat_model    text        NOT NULL,
    embed_model   text        NOT NULL,
    kb_version    text        NOT NULL,   -- manifest hash (docs/storage.md §4); no table yet
    question_set  text        NOT NULL,   -- e.g. 'questions/v0.2.yaml'
    seed          integer,
    git_sha       text        NOT NULL,
    started_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz CHECK (finished_at IS NULL OR finished_at >= started_at),
    results_path  text        NOT NULL UNIQUE
);

CREATE INDEX eval_runs_profile_idx ON core.eval_runs (profile, started_at);

-- ---------------------------------------------------------------- session.sessions
-- Lab/step chosen at the start (US-02). The composite FK makes sure the step belongs to that lab;
-- it is only checked when step_id is set (a session may pick a lab but no step yet).
ALTER TABLE session.sessions
    ADD COLUMN lab_id   text REFERENCES core.labs (id),
    ADD COLUMN step_id  text,
    ADD COLUMN ended_at timestamptz,
    ADD CONSTRAINT sessions_step_fk
        FOREIGN KEY (lab_id, step_id) REFERENCES core.lab_steps (lab_id, id),
    ADD CONSTRAINT sessions_ended_after_created CHECK (ended_at IS NULL OR ended_at >= created_at);

CREATE INDEX sessions_profile_idx ON session.sessions (profile, created_at);

-- Offline experiments must outlive a day: 24 h would delete the data before it is analysed.
-- NOT NULL is kept so the expiry job and session_exists() work unchanged.
ALTER TABLE session.sessions     ALTER COLUMN expires_at SET DEFAULT now() + interval '90 days';
ALTER TABLE session.uploads      ALTER COLUMN expires_at SET DEFAULT now() + interval '90 days';
ALTER TABLE session.trace_events ALTER COLUMN expires_at SET DEFAULT now() + interval '90 days';

-- ---------------------------------------------------------------- session.turns
-- One student message and the tutor's reply. answer is NULL while the turn is in progress (or if
-- it failed); how it was produced is in trace_events.
CREATE TABLE session.turns (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id    uuid        NOT NULL REFERENCES session.sessions (id) ON DELETE CASCADE,
    idx           integer     NOT NULL CHECK (idx >= 0),   -- position in the session, from 0
    step_id       text        REFERENCES core.lab_steps (id),  -- the student may change step
    user_message  text        NOT NULL,
    answer        text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    answered_at   timestamptz,
    UNIQUE (session_id, idx)
);

-- ---------------------------------------------------------------- session.trace_events
-- Events now hang off a turn, in order. turn_id stays NULL for events outside a conversation
-- (e.g. /smoke); seq is required exactly when turn_id is set.
ALTER TABLE session.trace_events
    ADD COLUMN turn_id bigint  REFERENCES session.turns (id) ON DELETE CASCADE,
    ADD COLUMN seq     integer CHECK (seq >= 0),
    ADD COLUMN actor   text,                     -- 'tutor', 'analyst', 'policy', 'mcp:<tool>', ...
    ADD CONSTRAINT trace_events_turn_seq_uq UNIQUE (turn_id, seq),
    ADD CONSTRAINT trace_events_seq_iff_turn CHECK ((turn_id IS NULL) = (seq IS NULL)),
    ADD CONSTRAINT trace_events_kind_chk CHECK (kind IN (
        'retrieval', 'tool_call', 'tool_result', 'policy_decision',
        'llm_call', 'subagent_step', 'answer', 'refusal', 'error'));

CREATE INDEX trace_events_turn_idx ON session.trace_events (turn_id);
CREATE INDEX trace_events_kind_ts_idx ON session.trace_events (kind, created_at);

-- ---------------------------------------------------------------- session.uploads
-- What the file is, so a capture (US-10) and a document (US-15) can be told apart. Existing rows
-- and the current upload endpoint only handle documents, hence the default.
ALTER TABLE session.uploads
    ADD COLUMN kind text NOT NULL DEFAULT 'document'
        CHECK (kind IN ('pcap', 'config', 'gns3', 'document'));

CREATE INDEX uploads_sha256_idx ON session.uploads (sha256);
