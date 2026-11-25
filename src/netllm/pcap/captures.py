"""Capture catalog: which packet captures the tools may open, by id (ADR 0013).

The model names a capture by a short id ('tcp-trace1'), never by a path. Ids are resolved here,
against configs/captures.yaml, to files inside one folder (data/traces/). So:
  - a small model cannot get a long path wrong;
  - the model cannot open any other file on the machine;
  - an optional sha256 pins the exact file, so an experiment cannot silently run on a different one.
Session uploads (a student's own capture) will add a second source of ids later.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SLUG = r"^[a-z0-9][a-z0-9.-]*$"


class CaptureError(ValueError):
    """Unknown id, missing file or wrong file. The message is meant for the model to read."""


class Capture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=SLUG)
    file: str = Field(description="Path relative to the captures folder")
    description: str = Field(min_length=1)
    sha256: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("file")
    @classmethod
    def _stays_inside_folder(cls, v: str) -> str:
        p = PurePosixPath(v)
        if p.is_absolute() or ".." in p.parts or not v:
            raise ValueError(f"file must be a relative path inside the captures folder, got {v!r}")
        return v


class CatalogFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    captures: list[Capture]

    @model_validator(mode="after")
    def _ids_unique(self) -> CatalogFile:
        ids = [c.id for c in self.captures]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate capture ids: {', '.join(dupes)}")
        return self


class CaptureCatalog:
    def __init__(self, captures: list[Capture], folder: Path):
        self.folder = folder.resolve()
        self._by_id = {c.id: c for c in captures}
        self._verified: set[str] = set()

    @classmethod
    def load(cls, file: Path, folder: Path) -> CaptureCatalog:
        data = CatalogFile.model_validate(yaml.safe_load(file.read_text(encoding="utf-8")))
        return cls(data.captures, folder)

    def list(self) -> list[Capture]:
        return list(self._by_id.values())

    def resolve(self, capture_id: str) -> Path:
        c = self._by_id.get(capture_id)
        if c is None:
            known = ", ".join(sorted(self._by_id)) or "none"
            raise CaptureError(f"Unknown capture {capture_id!r}. Available: {known} (see list_captures)")
        path = (self.folder / c.file).resolve()
        if not path.is_relative_to(self.folder):  # e.g. a symlink pointing elsewhere
            raise CaptureError(f"Capture {capture_id!r} points outside {self.folder}")
        if not path.is_file():
            raise CaptureError(f"Capture {capture_id!r}: file {c.file} is missing from {self.folder}")
        if c.sha256 and capture_id not in self._verified:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != c.sha256:
                raise CaptureError(f"Capture {capture_id!r}: {c.file} is not the expected file "
                                   f"(sha256 {digest[:12]}…, expected {c.sha256[:12]}…)")
            self._verified.add(capture_id)
        return path
