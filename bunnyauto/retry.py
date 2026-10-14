"""Retry the devices whose SSH connection failed, once the rest have been done.

An SSH login to a device sometimes fails for no lasting reason — a busy VTY line,
a banner that arrived late, a connection reset under the load of a parallel run —
and works when the tool is simply started again. :func:`run_with_retries` does
that start-again for the operator: it runs a task over the whole inventory,
then runs it again over only the devices that *failed to connect*, up to
``settings.connect_retries`` more times, and returns one result per device.
Only the last attempt's outcome is reported, so a device that connects on a
retry never shows an error, and one that never connects shows its final one.

What counts as "failed to connect" is deliberately narrow (:func:`is_connect_failure`):
the task failed, the device has no open Netmiko session (so the failure came while
connecting, before any command went out), and the exception is a transient SSH or
socket error. That keeps three things out of the retry:

* a command that failed on an open session — it may have partly run (``send-command
  --config-mode``), and its failure isn't a connection problem anyway;
* an authentication failure — the credentials are shared across the fleet, so
  repeating a wrong password risks locking the account for every device;
* anything that isn't a network error (a bug, a bad inventory entry).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

from netmiko.exceptions import NetmikoBaseException
from nornir.core.exceptions import NornirSubTaskError
from nornir_netmiko.connections import CONNECTION_NAME
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException

if TYPE_CHECKING:
    from nornir.core import Nornir
    from nornir.core.task import AggregatedResult

    from bunnyauto.context import Context

#: Extra passes over the devices that failed to connect (``--connect-retries``).
DEFAULT_CONNECT_RETRIES = 3
#: Seconds to wait before each of those passes (``--retry-delay``), so a busy
#: device has a moment to free its VTY lines.
DEFAULT_RETRY_DELAY = 5.0

# Netmiko/Paramiko errors that mean "no session, try again later" (a timeout, a
# dropped banner read, an unreachable port) ...
_TRANSIENT = (SSHException, NetmikoBaseException, OSError, EOFError)
# ... except the ones a second try can't fix. NetmikoAuthenticationException is a
# paramiko AuthenticationException, so this covers it.
_PERMANENT = (AuthenticationException, BadHostKeyException)


def _exceptions(results: Any) -> Iterator[BaseException]:
    """Every real exception in a Nornir ``MultiResult``, subtasks included.

    A task that catches its subtask's error and returns normally (the health
    collector) still leaves the failed subtask in the list, so this finds it. The
    ``NornirSubTaskError`` wrapper a failed ``task.run`` raises is skipped: the
    exception inside it is also in the list as its own result.
    """
    for item in results:
        if isinstance(item, list):  # a nested MultiResult
            yield from _exceptions(item)
            continue
        exception = getattr(item, "exception", None)
        if exception is not None and not isinstance(exception, NornirSubTaskError):
            yield exception


def is_connect_failure(host: Any, results: Any) -> bool:
    """Did this device's task fail because the SSH session never came up?"""
    if not results.failed:
        return False
    exceptions = list(_exceptions(results))
    if not exceptions or any(isinstance(exc, _PERMANENT) for exc in exceptions):
        return False
    if not any(isinstance(exc, _TRANSIENT) for exc in exceptions):
        return False
    # Nornir stores a session only once it is fully open, so an open one means the
    # failure came later — a command, not the connection.
    return CONNECTION_NAME not in getattr(host, "connections", {})


def run_with_retries(
    ctx: Context,
    targets: Nornir,
    *,
    task: Callable[..., Any],
    name: str,
    description: str,
    **task_args: Any,
) -> AggregatedResult:
    """Run ``task`` on ``targets``; re-run it on the devices that failed to connect.

    The first pass is the ordinary tracked ``targets.run`` every tool used to make.
    After it, each retry pass covers only the devices that still fail to connect,
    after ``settings.retry_delay`` seconds, until they connect or
    ``settings.connect_retries`` passes are spent. The returned results hold, per
    device, the outcome of its last attempt — so the caller's usual per-device
    error handling sees a failure only if the device never connected.
    """
    retries = max(0, ctx.settings.connect_retries)
    results = _run_pass(ctx, targets, task, name, description, task_args, will_retry=retries > 0)

    for attempt in range(1, retries + 1):
        pending = _unreachable(targets, results)
        if not pending:
            return results

        delay = max(0.0, ctx.settings.retry_delay)
        ctx.reporter.step(
            f"{len(pending)} device(s) failed to connect — retry {attempt}/{retries}"
            f"{f' in {delay:g}s' if delay else ''}: {', '.join(sorted(pending))}"
        )
        if delay:
            time.sleep(delay)

        subset = _only(targets, pending)
        again = _run_pass(
            ctx,
            subset,
            task,
            name,
            f"{description} (retry {attempt}/{retries})",
            task_args,
            will_retry=attempt < retries,
            # Nornir skips hosts it has marked failed unless told otherwise.
            on_failed=True,
        )
        for host, outcome in again.items():
            results[host] = outcome
            if not outcome.failed:
                targets.data.recover_host(host)
                ctx.reporter.info(f"{host}: connected on retry {attempt}/{retries}")

    unreachable = _unreachable(targets, results) if retries else set()
    if unreachable:
        ctx.reporter.warn(
            f"{len(unreachable)} device(s) still failed to connect after {retries} "
            f"retr{'y' if retries == 1 else 'ies'}: {', '.join(sorted(unreachable))}"
        )
    return results


def _run_pass(
    ctx: Context,
    nr: Nornir,
    task: Callable[..., Any],
    name: str,
    description: str,
    task_args: dict[str, Any],
    *,
    will_retry: bool,
    **run_options: Any,
) -> AggregatedResult:
    # While retries remain, a connect failure isn't reported as a failure — the
    # progress line says it will be tried again.
    retry_check = is_connect_failure if will_retry else None
    with ctx.reporter.track(nr, description=description, retry_check=retry_check) as tracked:
        return tracked.run(task=task, name=name, **run_options, **task_args)


def _only(targets: Nornir, names: set[str]) -> Nornir:
    return targets.filter(filter_func=lambda host: host.name in names)


def _unreachable(targets: Nornir, results: AggregatedResult) -> set[str]:
    hosts = targets.inventory.hosts
    return {
        name for name, outcome in results.items() if is_connect_failure(hosts.get(name), outcome)
    }
