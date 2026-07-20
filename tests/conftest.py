from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    spec = spec_from_file_location(name, ROOT / relative_path)
    module = module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def demo_app_module():
    return load_module("ztlab_demo_app", "app/app.py")


@pytest.fixture
def authz_bridge_module():
    return load_module("ztlab_authz_bridge", "gateway/authz-bridge/app.py")

