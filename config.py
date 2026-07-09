"""
Central config loader. Every module pulls its settings from here
instead of reading config.yaml directly, so there's one place to
change if the config format evolves.
"""

import os
import yaml

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")


class ConfigError(Exception):
    pass


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    if not os.path.exists(path):
        raise ConfigError(
            f"Config file not found at {path}. "
            f"Copy config.yaml.example to config.yaml and fill in your values."
        )

    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    _validate(cfg)
    return cfg


def _validate(cfg: dict) -> None:
    required_top_level = ["bloodhound", "domain"]
    for key in required_top_level:
        if key not in cfg:
            raise ConfigError(f"Missing required config section: '{key}'")

    bh = cfg["bloodhound"]
    using_ce = "api_id" in bh and "api_key" in bh
    using_legacy = "neo4j_uri" in bh

    if not using_ce and not using_legacy:
        raise ConfigError(
            "bloodhound config must specify either CE credentials "
            "(api_id/api_key/base_url) or legacy credentials (neo4j_uri/neo4j_user/neo4j_password)."
        )


if __name__ == "__main__":
    # Quick sanity check: `python config.py`
    cfg = load_config()
    print("Config loaded OK. Sections found:", list(cfg.keys()))
