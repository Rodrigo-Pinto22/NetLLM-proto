from netllm.config import ROOT, Settings


def test_defaults_point_inside_repo(monkeypatch):
    s = Settings(_env_file=None)
    assert s.chroma_dir == ROOT / "data" / "chroma"
    assert s.traces_dir == ROOT / "data" / "traces"


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("NETLLM_CHAT_MODEL", "some-model")
    assert Settings(_env_file=None).chat_model == "some-model"


def test_shipped_profiles_load():
    s = Settings(_env_file=None)
    for path in s.profiles_dir.glob("*.yaml"):
        assert s.load_profile(path.stem).name == path.stem
