"""Sessions/uploads/retrieve endpoints, with Postgres replaced by an in-memory repo, Chroma by an
in-memory client and the embedding model by a bag-of-words fake. No Docker, no model download."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import words
from fastapi.testclient import TestClient

from netllm.api.services.sessions import SessionRow, SessionService, safe_filename
from netllm.ingest.models import Chunk


class FakeRepo:
    def __init__(self):
        self.sessions: dict[uuid.UUID, SessionRow] = {}
        self.uploads = {}
        self.fail_add_upload = False

    def create_session(self, profile):
        now = datetime.now(UTC)
        row = SessionRow(uuid.uuid4(), profile, now, now + timedelta(hours=24))
        self.sessions[row.id] = row
        return row

    def session_exists(self, session_id):
        return session_id in self.sessions

    def add_upload(self, row):
        if self.fail_add_upload:
            raise RuntimeError("db down")
        self.uploads[row.id] = row

    def delete_session(self, session_id):
        self.sessions.pop(session_id, None)
        self.uploads = {k: u for k, u in self.uploads.items() if u.session_id != session_id}


@pytest.fixture
def env(store, fake_transformers, tmp_path, monkeypatch):
    monkeypatch.setenv("NETLLM_PROFILE", "beginner_socratic")  # independent of your .env
    from netllm.api.app import create_app
    from netllm.api.deps import get_session_service
    from netllm.ingest import Chunker, Ingestor

    repo = FakeRepo()
    service = SessionService(repo, store, Ingestor(chunker=Chunker(min_tokens=1)),
                             sessions_dir=tmp_path / "sessions", max_upload_bytes=1000,
                             profile_exists=lambda name: name in {"beginner_socratic", "advanced_direct"})
    app = create_app()
    app.dependency_overrides[get_session_service] = lambda: service
    return TestClient(app), repo, store, tmp_path / "sessions"


def new_session(client) -> str:
    r = client.post("/sessions", json={"profile": "advanced_direct"})
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


def upload(client, sid, name="notes.md", text=f"# Notes\nsyn retransmission {words(5)}"):
    return client.post(f"/sessions/{sid}/uploads", files={"file": (name, text.encode(), "text/markdown")})


def test_create_session_default_and_unknown_profile(env):
    client, repo, *_ = env
    r = client.post("/sessions")
    assert r.status_code == 201
    assert r.json()["profile"] == "beginner_socratic"  # NETLLM_PROFILE default
    assert client.post("/sessions", json={"profile": "nope"}).status_code == 422
    assert client.post("/sessions", json={"profile": "../etc"}).status_code == 422


def test_upload_ingests_into_session_scope_and_deletes_raw_file(env):
    client, repo, store, sessions_dir = env
    sid = new_session(client)
    r = upload(client, sid)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["filename"] == "notes.md" and body["n_chunks"] == 1
    assert uuid.UUID(body["upload_id"]) in repo.uploads
    assert store.client.get_collection(f"kb_session_{sid}", embedding_function=None).count() == 1
    assert not any(sessions_dir.rglob("*.md"))  # raw upload gone


def test_retrieve_returns_both_scopes_with_provenance(env):
    client, repo, store, _ = env
    store.add([Chunk("a1", "TCP > Handshake\n\nsyn synack ack",
                     {"source": "rfc793.txt", "section": "TCP > Handshake", "page": 30, "part": 0,
                      "scope": "admin", "source_sha256": "ab" * 32})])
    sid = new_session(client)
    up = upload(client, sid).json()

    r = client.post(f"/sessions/{sid}/retrieve", json={"query": "syn", "k": 5})
    assert r.status_code == 200, r.text
    passages = {p["scope"]: p for p in r.json()["passages"]}
    assert passages["admin"]["source"] == "rfc793.txt" and passages["admin"]["upload_id"] is None
    assert passages["session"]["source"] == "notes.md"
    assert passages["session"]["upload_id"] == up["upload_id"]
    assert passages["session"]["source_sha256"] == up["sha256"]
    assert r.json()["context"].count("<passage ") == 2


def test_other_session_cannot_see_upload(env):
    client, *_ = env
    sid, other = new_session(client), new_session(client)
    upload(client, sid)
    passages = client.post(f"/sessions/{other}/retrieve", json={"query": "syn"}).json()["passages"]
    assert passages == []


@pytest.mark.parametrize("name,text,code", [
    ("capture.docx", "x", 415),
    ("big.md", "x" * 1001, 413),
    ("empty.md", "  \n", 400),
    ("only_heading.md", "# Title", 422),  # no body text -> no chunks
])
def test_upload_rejections(env, name, text, code):
    client, repo, *_ = env
    sid = new_session(client)
    assert upload(client, sid, name, text).status_code == code
    assert repo.uploads == {}


def test_unknown_session_is_404_and_bad_id_is_422(env):
    client, *_ = env
    assert upload(client, str(uuid.uuid4())).status_code == 404
    assert client.post(f"/sessions/{uuid.uuid4()}/retrieve", json={"query": "x"}).status_code == 404
    assert upload(client, "not-a-uuid").status_code == 422


def test_failed_db_write_undoes_vectors(env):
    client, repo, store, _ = env
    sid = new_session(client)
    repo.fail_add_upload = True
    with pytest.raises(RuntimeError):
        upload(client, sid)
    assert store.client.get_collection(f"kb_session_{sid}", embedding_function=None).count() == 0


def test_delete_session_purges_everything_and_is_idempotent(env):
    client, repo, store, sessions_dir = env
    sid = new_session(client)
    upload(client, sid)
    assert client.delete(f"/sessions/{sid}").status_code == 204
    assert client.delete(f"/sessions/{sid}").status_code == 204
    assert repo.sessions == {} and repo.uploads == {}
    assert f"kb_session_{sid}" not in {c.name for c in store.client.list_collections()}
    assert not (sessions_dir / sid).exists()


@pytest.mark.parametrize("raw,expected", [
    ("notes.md", "notes.md"),
    ("../../etc/passwd.md", "passwd.md"),
    ("C:\\Users\\me\\my notes.md", "my_notes.md"),
    ("", "upload"),
    ("..", "upload"),
])
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected
