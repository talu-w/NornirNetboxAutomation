"""The per-device backup task: collect, (optionally) sanitize, write to disk.

Adapted from ``save_device_outputs`` in ``perform_backup.py`` /
``perform_backup_safe.py``. The rich progress callback is gone (Nornir threads
the run; the tool reports around it); the sanitize step is a parameter instead
of a separate script. When ``sanitize`` is true and a secret survives, the host
fails and no config file is written — the fail-closed behaviour is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command

from bunnyauto.backup.interfaces import INTERFACE_COMMANDS, build_interface_rows
from bunnyauto.backup.sanitize import SanitizationError, sanitize_running_config
from bunnyauto.backup.workbook import create_interface_workbook

_RUNNING_CONFIG = "show running-config"
_ENVIRONMENT = "show env all"


@dataclass(slots=True)
class HostBackup:
    """What one device's backup produced. Carried as the Nornir Result value."""

    host: str
    sanitized: bool = True
    directory: Path | None = None
    config_path: Path | None = None
    environment_path: Path | None = None
    workbook_path: Path | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


def collect_device_backup(
    task: Task,
    *,
    output_dir: Path,
    sanitize: bool,
    read_timeout: float,
) -> Result:
    host = task.host.name
    record = HostBackup(host=host, sanitized=sanitize)

    def fail(message: str, exc: Exception | None = None) -> Result:
        record.error = message
        return Result(host=task.host, failed=True, exception=exc, result=record)

    # --- running configuration ------------------------------------------------
    try:
        running = task.run(
            name=_RUNNING_CONFIG,
            task=netmiko_send_command,
            command_string=_RUNNING_CONFIG,
            read_timeout=read_timeout,
        )[-1]
    except Exception as exc:
        return fail(f"could not collect running-config: {exc}", exc)
    if running.failed:
        return fail(f"running-config command failed: {running.exception or running.result}")

    running_config = str(running.result)
    # Keep the raw config out of print_result / any run log.
    running.result = "running-config collected (contents omitted from logs)"
    if not running_config.strip():
        return fail("device returned an empty running configuration")

    if sanitize:
        try:
            config_text = sanitize_running_config(running_config)
        except SanitizationError as exc:
            return fail(f"sanitization failed — config not written: {exc}", exc)
    else:
        config_text = running_config.rstrip() + "\n"

    # --- environment --------------------------------------------------------
    try:
        environment = task.run(
            name=_ENVIRONMENT,
            task=netmiko_send_command,
            command_string=_ENVIRONMENT,
            read_timeout=read_timeout,
        )[-1]
    except Exception as exc:
        return fail(f"could not collect environment: {exc}", exc)
    if environment.failed:
        return fail(f"environment command failed: {environment.exception or environment.result}")
    environment_output = str(environment.result)
    if not environment_output.strip():
        return fail("device returned empty environment information")

    # --- interface show-commands ------------------------------------------
    interface_outputs: dict[str, str] = {}
    command_errors: dict[str, str] = {}
    for key, command in INTERFACE_COMMANDS.items():
        try:
            collected = task.run(
                name=command,
                task=netmiko_send_command,
                command_string=command,
                read_timeout=read_timeout,
            )[-1]
        except Exception as exc:
            return fail(f"could not run {command!r}: {exc}", exc)
        if collected.failed:
            return fail(f"{command!r} failed: {collected.exception or collected.result}")
        text = str(collected.result)
        if text.strip():
            interface_outputs[key] = text
        else:
            command_errors[command] = "Device returned no output."
            record.warnings.append(f"{command}: no output")

    rows = build_interface_rows(interface_outputs)

    # --- write ------------------------------------------------------------
    host_dir = output_dir / host
    config_path = host_dir / f"{host}.cfg"
    environment_path = host_dir / f"{host}_environment.txt"
    workbook_path = host_dir / f"{host}_interfaces.xlsx"
    try:
        host_dir.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_text, encoding="utf-8")
        config_path.chmod(0o600)
        environment_path.write_text(environment_output.rstrip() + "\n", encoding="utf-8")
        create_interface_workbook(
            hostname=host,
            rows=rows,
            command_errors=command_errors,
            output_path=workbook_path,
        )
    except OSError as exc:
        return fail(f"could not write backup files: {exc}", exc)

    record.directory = host_dir
    record.config_path = config_path
    record.environment_path = environment_path
    record.workbook_path = workbook_path
    return Result(host=task.host, changed=False, result=record)
