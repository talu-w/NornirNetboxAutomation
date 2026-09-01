"""Unit coverage for the bunnyauto core modules (no Nornir / NetBox calls)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bunnyauto.common import (
    LEGACY_NETMIKO_EXTRAS,
    build_netmiko_extras,
    env_flag,
    normalize_tags,
    ssl_verify_setting,
)
from bunnyauto.context import Credentials, Settings, build_context
from bunnyauto.environments import load_environments, resolve_environment
from bunnyauto.errors import (
    BunnyautoError,
    ConfigError,
    EnvVarError,
    TagMismatchError,
    UnknownEnvironmentError,
)
from bunnyauto.preflight import preflight, preflight_device_credentials
from bunnyauto.reporting import Reporter, make_reporter
from bunnyauto.result import EXIT_CODES, Status, ToolResult

# ---------------------------------------------------------------------------
# normalize_tags
# ---------------------------------------------------------------------------


class _Tag:
    def __init__(self, slug: str) -> None:
        self.slug = slug
        self.name = slug.title()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, []),
        ([], []),
        (["NornirTest", "Core"], ["core", "nornirtest"]),
        ([{"slug": "nornirtest", "name": "NornirTest"}], ["nornirtest"]),
        ([{"name": "Only Name"}], ["only name"]),
        ([_Tag("ssh-legacy")], ["ssh-legacy"]),
        (["dup", "DUP", {"slug": "dup"}], ["dup"]),
    ],
)
def test_normalize_tags(raw, expected):
    assert normalize_tags(raw) == expected


# ---------------------------------------------------------------------------
# netmiko extras
# ---------------------------------------------------------------------------


def _settings(**over) -> Settings:
    base = dict(
        environment="test",
        nb_url="https://nb.example.com",
        config_file=Path("config.yaml"),
        target_tag="nornirtest",
    )
    base.update(over)
    return Settings(**base)


def test_build_netmiko_extras_default_vs_legacy():
    default = build_netmiko_extras(_settings(), legacy=False)
    legacy = build_netmiko_extras(_settings(), legacy=True)

    assert default["fast_cli"] is False
    assert "disable_sha2_fix" not in default
    assert legacy["disable_sha2_fix"] is True
    assert legacy["disabled_algorithms"] == LEGACY_NETMIKO_EXTRAS["disabled_algorithms"]
    # timeouts still come from settings in the legacy profile
    assert legacy["conn_timeout"] == default["conn_timeout"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("false", False),
        ("No", False),
        ("1", True),
        ("/etc/ssl/ca.pem", "/etc/ssl/ca.pem"),
    ],
)
def test_ssl_verify_setting(value, expected):
    assert ssl_verify_setting(value) == expected


def test_env_flag(monkeypatch):
    assert env_flag("BUNNYAUTO_X") is False
    monkeypatch.setenv("BUNNYAUTO_X", "yes")
    assert env_flag("BUNNYAUTO_X") is True
    monkeypatch.setenv("BUNNYAUTO_X", "0")
    assert env_flag("BUNNYAUTO_X") is False


# ---------------------------------------------------------------------------
# environments
# ---------------------------------------------------------------------------


def test_load_environments(env_file):
    envs = load_environments(env_file)
    assert set(envs) == {"test", "prod"}
    assert envs["prod"].protected is True
    assert envs["test"].protected is False
    # trailing slash on nb_url is stripped
    assert envs["prod"].nb_url == "https://netbox.example.com"


def test_environment_token_reads_its_own_var(env_file, monkeypatch):
    env = resolve_environment("test", env_file)
    assert env.token is None
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_TOKEN", "  abc123  ")
    assert env.token == "abc123"


def test_firewall_config_is_optional_and_parsed(tmp_path):
    path = tmp_path / "bunnyauto.yaml"
    path.write_text(
        "environments:\n"
        "  test:\n"
        "    nb_url: https://nb\n"
        "    default_tag: t\n"
        "    token_env: X\n"
        "  prod:\n"
        "    nb_url: https://nb2\n"
        "    default_tag: p\n"
        "    token_env: Y\n"
        "    fw_url: https://fw.example.com/\n"
        "    fw_token_env: FW_TOK\n",
        encoding="utf-8",
    )
    envs = load_environments(path)
    assert envs["test"].fw_url is None
    assert envs["prod"].fw_url == "https://fw.example.com"  # trailing slash stripped
    assert envs["prod"].fw_token_env == "FW_TOK"


def test_firewall_url_without_token_env_is_rejected(tmp_path):
    path = tmp_path / "bunnyauto.yaml"
    path.write_text(
        "environments:\n  test:\n    nb_url: https://nb\n    default_tag: t\n"
        "    token_env: X\n    fw_url: https://fw\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="fw_token_env"):
        load_environments(path)


def test_resolve_unknown_environment(env_file):
    with pytest.raises(UnknownEnvironmentError) as exc:
        resolve_environment("staging", env_file)
    assert "staging" in str(exc.value)
    assert "test" in str(exc.value) and "prod" in str(exc.value)


def test_missing_environment_file(tmp_path):
    with pytest.raises(ConfigError):
        load_environments(tmp_path / "nope.yaml")


def test_bad_nb_url(tmp_path):
    bad = tmp_path / "bunnyauto.yaml"
    bad.write_text(
        "environments:\n  test:\n    nb_url: nb.example.com\n"
        "    default_tag: t\n    token_env: X\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_environments(bad)


def test_unknown_key_rejected(tmp_path):
    bad = tmp_path / "bunnyauto.yaml"
    bad.write_text(
        "environments:\n  test:\n    nb_url: https://x\n    default_tag: t\n"
        "    token_env: X\n    protcted: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_environments(bad)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


def test_friendly_message_has_prefix_and_fix():
    err = BunnyautoError("something broke", fix="do the thing")
    lines = err.friendly().splitlines()
    assert lines[0] == "bunnyauto: something broke"
    assert lines[1].strip() == "Fix:  do the thing"


def test_friendly_message_without_fix():
    assert BunnyautoError("nope").friendly() == "bunnyauto: nope"


def test_tag_mismatch_is_bunnyauto_error():
    err = TagMismatchError("networking-active", "test", "nornirtest")
    assert isinstance(err, BunnyautoError)
    assert "force-tag" in err.friendly()


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------


def test_preflight_credentials_missing():
    with pytest.raises(EnvVarError):
        preflight_device_credentials()


def test_preflight_credentials_partial(monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    with pytest.raises(EnvVarError, match="both"):
        preflight_device_credentials()


def test_preflight_credentials_ok(monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    monkeypatch.setenv("NORNIR_PASSWORD", "secret")
    assert preflight_device_credentials() == ("alice", "secret")


def test_preflight_missing_token(env_file, monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    monkeypatch.setenv("NORNIR_PASSWORD", "secret")
    env = resolve_environment("prod", env_file)
    with pytest.raises(EnvVarError, match="BUNNYAUTO_PROD_NB_TOKEN"):
        preflight(env)


def test_preflight_full_ok(env_file, monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    monkeypatch.setenv("NORNIR_PASSWORD", "secret")
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_TOKEN", "tok")
    creds = preflight(resolve_environment("test", env_file))
    assert creds == Credentials(username="alice", password="secret", nb_token="tok")


def test_preflight_can_skip_devices_and_netbox(env_file):
    """A firewall-only tool runs with neither NORNIR_* nor a NetBox token set."""
    creds = preflight(resolve_environment("test", env_file), need_devices=False, need_netbox=False)
    assert creds == Credentials(username="", password="", nb_token="")


def test_preflight_carries_token_through_when_not_required(env_file, monkeypatch):
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_TOKEN", "tok")
    creds = preflight(resolve_environment("test", env_file), need_devices=False, need_netbox=False)
    assert creds.nb_token == "tok"


# ---------------------------------------------------------------------------
# result
# ---------------------------------------------------------------------------


def test_exit_codes_cover_every_status():
    assert set(EXIT_CODES) == set(Status)
    assert EXIT_CODES[Status.DRIFT] == 10
    assert EXIT_CODES[Status.CHANGED] == 20


def test_tool_result_as_dict():
    result = ToolResult(
        status=Status.DRIFT,
        summary="3 interfaces would change",
        changes=["Gi1/0/1: vlan 10 -> 20"],
        artifacts=[Path("/tmp/report.xlsx")],
        data={"changed": 3},
    )
    payload = result.as_dict()
    assert payload["status"] == "drift"
    assert payload["exit_code"] == 10
    assert payload["artifacts"] == ["/tmp/report.xlsx"]
    assert payload["data"] == {"changed": 3}
    assert result.exit_code == 10


# ---------------------------------------------------------------------------
# build_context (no Nornir init — lazy)
# ---------------------------------------------------------------------------


@pytest.fixture
def _creds_env(monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    monkeypatch.setenv("NORNIR_PASSWORD", "secret")
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_TOKEN", "tok-test")
    monkeypatch.setenv("BUNNYAUTO_PROD_NB_TOKEN", "tok-prod")


@pytest.fixture
def nornir_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        "inventory:\n"
        "  plugin: NetBoxInventory2\n"
        "  options:\n"
        "    nb_url: https://placeholder.example.com\n"
        "    ssl_verify: false\n"
        "runner:\n"
        "  plugin: threaded\n"
        "  options:\n"
        "    num_workers: 10\n",
        encoding="utf-8",
    )
    return path


def test_build_context_defaults_tag_from_environment(env_file, nornir_config, _creds_env):
    ctx = build_context(
        env="test",
        reporter=make_reporter(),
        config_file=nornir_config,
        env_file=env_file,
    )
    assert ctx.settings.target_tag == "nornirtest"
    assert ctx.settings.nb_url == "https://netbox-lab.example.com"
    assert ctx.settings.ssl_verify is False
    assert ctx.creds.nb_token == "tok-test"
    assert ctx.environment.protected is False
    assert ctx._nr is None and ctx._nb is None  # nothing built yet


def test_build_context_cross_tag_guard(env_file, nornir_config, _creds_env):
    with pytest.raises(TagMismatchError):
        build_context(
            env="test",
            reporter=make_reporter(),
            config_file=nornir_config,
            env_file=env_file,
            tag="networking-active",
        )


def test_build_context_force_tag_allows_mismatch(env_file, nornir_config, _creds_env):
    ctx = build_context(
        env="prod",
        reporter=make_reporter(),
        config_file=nornir_config,
        env_file=env_file,
        tag="nornirtest",
        force_tag=True,
    )
    assert ctx.settings.target_tag == "nornirtest"
    assert ctx.settings.protected is True


def test_build_context_applies_timeout_overrides(env_file, nornir_config, _creds_env):
    ctx = build_context(
        env="test",
        reporter=make_reporter(),
        config_file=nornir_config,
        env_file=env_file,
        timeouts={"read_timeout": 300.0, "bogus": 1.0},
    )
    assert ctx.settings.read_timeout == 300.0
    assert not hasattr(ctx.settings, "bogus")


def test_reporter_json_render(capsys):
    reporter = Reporter(json_mode=True)
    reporter.render(ToolResult(status=Status.OK, summary="all good"))
    out = capsys.readouterr().out
    assert '"status": "ok"' in out
    assert '"exit_code": 0' in out
