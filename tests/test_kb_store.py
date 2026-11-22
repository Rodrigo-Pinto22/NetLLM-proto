import hashlib

import pytest
from conftest import BagOfWordsEmbedder, words

from netllm.ingest.models import Chunk
from netllm.kb.store import KnowledgeStore, session_collection_name

SID = "3f1c2a9e-0b7d-4c55-9a1e-6d2f8b4c7e10"


def chunk(cid: str, text: str, scope: str, **meta) -> Chunk:
    return Chunk(cid, text, {"source": f"{cid}.md", "section": "S", "page": 1, "part": 0,
                             "scope": scope, **meta})


def collections(store) -> set[str]:
    return {c.name for c in store.client.list_collections()}


def test_scopes_go_to_separate_collections(store):
    store.add([chunk("a1", "tcp handshake syn ack", "admin"),
               chunk("s1", "my notes on tcp", "session")], session_id=SID)
    assert collections(store) == {"kb_admin", f"kb_session_{SID}"}
    assert store.client.get_collection("kb_admin", embedding_function=None).count() == 1
    assert store.client.get_collection(f"kb_session_{SID}", embedding_function=None).count() == 1


def test_session_chunk_requires_session_id(store):
    with pytest.raises(ValueError, match="session_id"):
        store.add([chunk("s1", "notes", "session")])


def test_unknown_scope_rejected(store):
    with pytest.raises(ValueError, match="Unknown scope"):
        store.add([chunk("x", "text", "public")])


@pytest.mark.parametrize("bad", ["", "../kb_admin", "a b", "x" * 64, "-leading"])
def test_session_id_is_validated(bad):
    with pytest.raises(ValueError):
        session_collection_name(bad)


def test_query_without_session_sees_admin_only(store):
    store.add([chunk("a1", "tcp handshake", "admin"),
               chunk("s1", "tcp handshake in my capture", "session")], session_id=SID)
    hits = store.query("tcp handshake", k=5)
    assert [h.id for h in hits] == ["a1"]
    assert {h.scope for h in hits} == {"admin"}


def test_query_with_session_merges_and_ranks_by_distance(store):
    store.add([chunk("a1", "dns resolver caching", "admin"),
               chunk("a2", "tcp three way handshake", "admin"),
               chunk("s1", "tcp handshake syn", "session")], session_id=SID)
    hits = store.query("tcp handshake syn", session_id=SID, k=2)
    assert [h.id for h in hits] == ["s1", "a2"]
    assert hits[0].distance <= hits[1].distance


def test_sessions_do_not_see_each_other(store):
    other = "other-session"
    store.add([chunk("s1", "secret upload of session one", "session")], session_id=SID)
    assert store.query("secret upload", session_id=other) == []
    assert collections(store) == {f"kb_session_{SID}"}  # querying never creates collections


def test_hits_carry_provenance(store):
    store.add([chunk("s1", "arp request who has", "session", page=7, source_sha256="ab" * 32)],
              session_id=SID)
    [hit] = store.query("arp request", session_id=SID)
    assert hit.text == "arp request who has"
    assert hit.metadata == {"source": "s1.md", "section": "S", "page": 7, "part": 0,
                            "scope": "session", "source_sha256": "ab" * 32, "session_id": SID}
    assert hit.citation == "s1.md, S, p. 7"


def test_reingest_upserts(store):
    c = chunk("a1", "tcp", "admin")
    store.add([c])
    store.add([c])
    assert store.client.get_collection("kb_admin", embedding_function=None).count() == 1


def test_drop_session_is_idempotent_and_leaves_admin(store):
    store.add([chunk("a1", "tcp", "admin"), chunk("s1", "tcp", "session")], session_id=SID)
    store.drop_session(SID)
    store.drop_session(SID)
    assert collections(store) == {"kb_admin"}


def test_delete_upload_removes_only_that_upload(store):
    store.add([chunk("s1", "tcp", "session", upload_id="u1"),
               chunk("s2", "tcp", "session", upload_id="u2")], session_id=SID)
    store.delete_upload(SID, "u1")
    store.delete_upload(SID, "u1")
    store.delete_upload("no-such-session", "u1")
    assert [h.id for h in store.query("tcp", session_id=SID)] == ["s2"]


def test_admin_collection_cannot_shadow_sessions(store):
    with pytest.raises(ValueError):
        KnowledgeStore(store.client, BagOfWordsEmbedder(), admin_collection="kb_session_x")


def test_ingest_then_retrieve_in_both_scopes(store, fake_transformers, tmp_path):
    """The 'done when': a document ingested in either scope comes back with correct provenance."""
    from netllm.ingest import Chunker, Ingestor

    ing = Ingestor(chunker=Chunker(min_tokens=1))
    kb = tmp_path / "rfc793.md"
    kb.write_text(f"# TCP\n## Handshake\nsyn synack ack {words(5)}", encoding="utf-8")
    up = tmp_path / "my_notes.md"
    up.write_text(f"# Notes\nmy capture shows syn retransmissions {words(5)}", encoding="utf-8")

    store.add(ing.ingest(kb, scope="admin"))
    store.add(ing.ingest(up, scope="session"), session_id=SID)

    by_source = {h.metadata["source"]: h for h in store.query("syn", session_id=SID, k=5)}
    admin, session = by_source["rfc793.md"], by_source["my_notes.md"]
    assert admin.scope == "admin" and admin.metadata["section"] == "TCP > Handshake"
    assert admin.metadata["source_sha256"] == hashlib.sha256(kb.read_bytes()).hexdigest()
    assert "session_id" not in admin.metadata
    assert session.scope == "session" and session.metadata["session_id"] == SID
    assert session.metadata["source_sha256"] == hashlib.sha256(up.read_bytes()).hexdigest()
