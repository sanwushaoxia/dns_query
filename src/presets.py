from __future__ import annotations

from pathlib import Path

PRESET_DIR = Path(__file__).resolve().parent.parent / "presets"


def list_presets() -> list[str]:
    if not PRESET_DIR.exists():
        return []
    return sorted(path.stem for path in PRESET_DIR.glob("*.txt"))


def load_preset(name: str) -> list[str]:
    path = PRESET_DIR / f"{name}.txt"
    if not path.exists():
        available = ", ".join(list_presets()) or "(none)"
        raise FileNotFoundError(f"unknown preset {name!r}; available: {available}")
    return load_domain_file(path)


def load_domain_file(path: Path) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = line.split()[0].lower().rstrip(".")
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains
