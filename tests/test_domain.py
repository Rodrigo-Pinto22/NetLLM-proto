"""configs/domain.yaml validation. The database sync itself needs Postgres and is checked by hand
(uv run netllm-domain)."""

import pytest
from pydantic import ValidationError

from netllm.config import Settings
from netllm.domain import Domain, load_domain


def lab(lab_id="lab1", steps=None, **extra):
    return {"id": lab_id, "title": "Lab", "steps": steps or [{"id": f"{lab_id}.s1", "goal": "g"}],
            **extra}


def test_shipped_domain_loads():
    d = load_domain(Settings(_env_file=None).domain_file)
    assert d.labs and all(lab.steps for lab in d.labs)


def test_valid_domain():
    d = Domain.model_validate({"labs": [lab(steps=[{"id": "lab1.s1", "goal": "a"},
                                                   {"id": "lab1.s2", "goal": "b",
                                                    "expected_outcome": "x"}])]})
    assert [s.id for s in d.labs[0].steps] == ["lab1.s1", "lab1.s2"]


@pytest.mark.parametrize("data, message", [
    ({"labs": []}, "at least 1"),
    ({"labs": [lab(), lab()]}, "duplicate lab ids: lab1"),
    ({"labs": [lab(steps=[{"id": "lab1.s1", "goal": "a"}, {"id": "lab1.s1", "goal": "b"}])]},
     "duplicate step ids: lab1.s1"),
    ({"labs": [lab(steps=[{"id": "other.s1", "goal": "a"}])]}, "must start with 'lab1.'"),
    ({"labs": [lab(lab_id="Lab 1")]}, "pattern"),
    ({"labs": [lab(steps=[{"id": "lab1.s1", "goal": "a", "expected_outcom": "typo"}])]},
     "Extra inputs"),
])
def test_invalid_domain(data, message):
    with pytest.raises(ValidationError, match=message):
        Domain.model_validate(data)
