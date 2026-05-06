from pathlib import Path
from typing import Any, Dict


def load_registry(path: str = "registry.yml") -> Dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "PyYAML eksik. Kurulum: py -m pip install -r requirements.txt"
        ) from exc

    registry_path = Path(path)
    if not registry_path.exists():
        raise FileNotFoundError(f"registry.yml bulunamadı: {registry_path.resolve()}")

    with registry_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    data.setdefault("global", {})
    data.setdefault("sources", [])
    return data


def enabled_sources(registry: Dict[str, Any]):
    for source in registry.get("sources", []):
        if source.get("enabled", False):
            yield source
