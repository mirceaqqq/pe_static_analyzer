import yaml
from pathlib import Path
from typing import Dict, Any

DEFAULT_CONFIG_PATH = Path("config/config.yaml")

DEFAULTS = {
    "weights": {},
}


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load YAML config; fallback to defaults if missing or invalid.
    """
    cfg: Dict[str, Any] = DEFAULTS.copy()
    try:
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                cfg.update(data)
    except Exception:
        # swallow errors; caller can rely on defaults
        pass
    return cfg
