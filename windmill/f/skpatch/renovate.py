#requirements:
#skpatch
"""Windmill wrapper: run one Renovate pass against the configured git host.

Wraps skpatch.renovate.run_renovate, which shells out to the official
renovate/renovate container on the worker. The worker needs Docker access
and outbound HTTPS to the configured endpoint; no credential lives in this
script, it is read from config_path's renovate.token_file.
"""
from dataclasses import asdict

from skpatch.config import load_config
from skpatch.renovate import run_renovate


def main(config_path: str) -> dict:
    cfg = load_config(config_path)
    if cfg.renovate is None:
        raise ValueError("no renovate block in config_path")
    result = run_renovate(cfg.renovate)
    return asdict(result)
