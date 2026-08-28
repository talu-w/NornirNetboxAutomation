"""Shared fixtures for the bunnyauto core tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

ENV_YAML = textwrap.dedent(
    """
    environments:
      test:
        nb_url: https://netbox-lab.example.com
        default_tag: nornirtest
        token_env: BUNNYAUTO_TEST_NB_TOKEN
      prod:
        nb_url: https://netbox.example.com/
        default_tag: networking-active
        token_env: BUNNYAUTO_PROD_NB_TOKEN
        protected: true
    """
).strip()


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / "bunnyauto.yaml"
    path.write_text(ENV_YAML, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with the bunnyauto-relevant variables unset."""
    for name in (
        "NORNIR_USERNAME",
        "NORNIR_PASSWORD",
        "BUNNYAUTO_TEST_NB_TOKEN",
        "BUNNYAUTO_PROD_NB_TOKEN",
        "BUNNYAUTO_ENV_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
