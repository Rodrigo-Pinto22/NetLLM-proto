"""Capture catalog: ids resolve to files inside one folder, and nothing else (ADR 0013)."""

import hashlib

import pytest
from pydantic import ValidationError

from netllm.config import Settings
from netllm.pcap import tools
from netllm.pcap.captures import CaptureCatalog, CaptureError, CatalogFile


def capture(**kw):
    return {"id": "lab-a", "file": "a.pcapng", "description": "test capture", **kw}


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "traces"
    d.mkdir()
    (d / "a.pcapng").write_bytes(b"packets")
    return d


def catalog(folder, *captures):
    return CaptureCatalog(CatalogFile.model_validate({"captures": list(captures)}).captures, folder)


def test_shipped_catalog_loads():
    s = Settings(_env_file=None)
    cat = CaptureCatalog.load(s.captures_file, s.captures_dir)
    assert "tcp-trace1" in {c.id for c in cat.list()}


def test_resolve(folder):
    assert catalog(folder, capture()).resolve("lab-a") == (folder / "a.pcapng").resolve()


def test_unknown_id_lists_the_known_ones(folder):
    with pytest.raises(CaptureError, match=r"Unknown capture 'nope'\. Available: lab-a"):
        catalog(folder, capture()).resolve("nope")


def test_missing_file(folder):
    with pytest.raises(CaptureError, match="missing"):
        catalog(folder, capture(file="gone.pcapng")).resolve("lab-a")


def test_sha256_pins_the_file(folder):
    good = hashlib.sha256(b"packets").hexdigest()
    assert catalog(folder, capture(sha256=good)).resolve("lab-a")
    with pytest.raises(CaptureError, match="not the expected file"):
        catalog(folder, capture(sha256="0" * 64)).resolve("lab-a")


@pytest.mark.parametrize("bad", ["../secret.pcap", "/etc/passwd", "sub/../../x", ""])
def test_file_must_stay_inside_folder(bad):
    with pytest.raises(ValidationError, match="relative path inside"):
        CatalogFile.model_validate({"captures": [capture(file=bad)]})


def test_symlink_out_of_folder_is_refused(folder, tmp_path):
    (tmp_path / "outside.pcapng").write_bytes(b"x")
    (folder / "link.pcapng").symlink_to(tmp_path / "outside.pcapng")
    with pytest.raises(CaptureError, match="outside"):
        catalog(folder, capture(file="link.pcapng")).resolve("lab-a")


def test_duplicate_ids_rejected():
    with pytest.raises(ValidationError, match="duplicate capture ids: lab-a"):
        CatalogFile.model_validate({"captures": [capture(), capture()]})


def test_list_captures_tool(monkeypatch, folder):
    monkeypatch.setattr(tools, "_catalog", lambda: catalog(folder, capture()))
    assert tools.list_captures() == {"captures": [{"id": "lab-a", "description": "test capture"}]}
