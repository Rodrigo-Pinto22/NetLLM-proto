"""Settings from .env (machine-specific) + a static learner profile (configs/profiles/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Profile(BaseModel):
    name: str
    level: Literal["beginner", "intermediate", "advanced"]
    language: str = "en"
    mode: Literal["socratic", "direct"] = "direct"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_prefix="NETLLM_", extra="ignore")

    # Ollama reads OLLAMA_HOST itself; mirrored here so the rest of the code has one source.
    ollama_host: str = "http://localhost:11434"
    chat_model: str = "gemma4:e2b"
    embed_model: str = "BAAI/bge-small-en-v1.5"

    data_dir: Path = ROOT / "data"
    runs_dir: Path = ROOT / "runs"
    profiles_dir: Path = ROOT / "configs" / "profiles"
    questions_dir: Path = ROOT / "questions"
    profile: str = "beginner_socratic"

    @property
    def kb_docs_dir(self) -> Path:
        return self.data_dir / "kb_docs"

    @property
    def chroma_dir(self) -> Path:
        return self.data_dir / "chroma"

    @property
    def traces_dir(self) -> Path:
        return self.data_dir / "traces"

    def load_profile(self, name: str | None = None) -> Profile:
        path = self.profiles_dir / f"{name or self.profile}.yaml"
        return Profile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def get_settings() -> Settings:
    return Settings()
