"""Course domain (labs and steps): read configs/domain.yaml and copy it into core.labs / core.lab_steps.

The YAML file is the source of truth; the tables are a copy, so sessions and turns can point at a
real lab or step with a foreign key. Syncing is a full mirror in one transaction:
  - labs/steps in the file are inserted or updated,
  - labs/steps no longer in the file are deleted,
  - if a deleted lab/step is still used by a session or turn, the database refuses and nothing
    changes (keep it in the file instead).

Run: uv run netllm-domain [path/to/domain.yaml]
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

SLUG = r"^[a-z0-9][a-z0-9.-]*$"


# ------------------------------------------------------------------------- the file
class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a typo like `expected_outcom` is an error

    id: str = Field(pattern=SLUG)
    goal: str = Field(min_length=1)
    expected_outcome: str | None = None


class Lab(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=SLUG)
    title: str = Field(min_length=1)
    steps: list[Step] = Field(min_length=1)

    @model_validator(mode="after")
    def _step_ids_belong_to_lab(self) -> Lab:
        for s in self.steps:
            if not s.id.startswith(f"{self.id}."):
                raise ValueError(f"step {s.id!r} must start with '{self.id}.'")
        return self


class Domain(BaseModel):
    model_config = ConfigDict(extra="forbid")

    labs: list[Lab] = Field(min_length=1)  # an empty file would otherwise delete every lab

    @model_validator(mode="after")
    def _ids_unique(self) -> Domain:
        for kind, ids in (("lab", [lab.id for lab in self.labs]),
                          ("step", [s.id for lab in self.labs for s in lab.steps])):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            if dupes:
                raise ValueError(f"duplicate {kind} ids: {', '.join(dupes)}")
        return self


def load_domain(path: Path) -> Domain:
    return Domain.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


# ----------------------------------------------------------------------- the tables
class DomainSyncError(Exception):
    """The database refused the sync (e.g. a removed step is still used by a session)."""


@dataclass
class SyncReport:
    labs: int
    steps: int
    labs_removed: int
    steps_removed: int


def sync_domain(conn: psycopg.Connection, domain: Domain) -> SyncReport:
    """Mirror `domain` into core.labs / core.lab_steps in one transaction (all or nothing)."""
    lab_rows = [(lab.id, lab.title) for lab in domain.labs]
    step_rows = [(s.id, lab.id, i, s.goal, s.expected_outcome)
                 for lab in domain.labs for i, s in enumerate(lab.steps, start=1)]
    lab_ids = [r[0] for r in lab_rows]
    step_ids = [r[0] for r in step_rows]

    try:
        with conn.transaction(), conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO core.labs (id, title) VALUES (%s, %s) "
                "ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title", lab_rows)
            # Removed steps first, so their ordinals are free for the steps that stay.
            cur.execute("DELETE FROM core.lab_steps WHERE id <> ALL(%s)", (step_ids,))
            steps_removed = cur.rowcount
            cur.executemany(
                "INSERT INTO core.lab_steps (id, lab_id, ordinal, goal, expected_outcome) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET lab_id = EXCLUDED.lab_id, ordinal = EXCLUDED.ordinal, "
                "goal = EXCLUDED.goal, expected_outcome = EXCLUDED.expected_outcome", step_rows)
            cur.execute("DELETE FROM core.labs WHERE id <> ALL(%s)", (lab_ids,))
            labs_removed = cur.rowcount
    except psycopg.errors.ForeignKeyViolation as e:
        raise DomainSyncError(
            "A lab or step removed from the YAML is still used by a session or turn; "
            f"keep it in the file. Database said: {e.diag.message_detail or e}") from e
    except psycopg.errors.UniqueViolation as e:
        raise DomainSyncError(f"Conflicting ids or step order: {e.diag.message_detail or e}") from e

    return SyncReport(len(lab_rows), len(step_rows), labs_removed, steps_removed)


# --------------------------------------------------------------------------- command
def main(argv: list[str] | None = None) -> int:
    from netllm.config import get_settings

    s = get_settings()
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else s.domain_file

    domain = load_domain(path)  # a validation error stops here, before touching the database
    try:
        with psycopg.connect(s.database_url) as conn:
            r = sync_domain(conn, domain)
    except DomainSyncError as e:
        print(f"Domain sync failed, nothing changed: {e}", file=sys.stderr)
        return 1
    print(f"Synced {path.name}: {r.labs} labs, {r.steps} steps "
          f"(removed {r.labs_removed} labs, {r.steps_removed} steps).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
