"""The interactive front door — no command-line knowledge required.

``python -m bunnyauto.hub``, ``bunnyauto`` with no arguments, or the
``nornir_hub.py`` shim all land here. The hub does exactly what
:mod:`bunnyauto.cli` does — pick an environment, gather a tool's arguments,
build one Context, run the tool, render the result — except it asks instead of
reading ``argv``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping

from bunnyauto.context import build_context
from bunnyauto.environments import Environment, load_environments
from bunnyauto.errors import BunnyautoError
from bunnyauto.preflight import preflight_device_credentials
from bunnyauto.reporting import Reporter, make_reporter
from bunnyauto.tools import REGISTRY
from bunnyauto.tools.base import COMMON_ARG_DESTS, Tool, timeouts_from_args

InputFn = Callable[[str], str]

_QUIT = {"q", "quit", "exit"}
_BACK = {"b", "back", ""}


def main(argv: list[str] | None = None, *, input_fn: InputFn = input) -> int:
    parser = argparse.ArgumentParser(prog="bunnyauto-hub", add_help=True)
    parser.add_argument("--env-file", default=None, help="path to bunnyauto.yaml")
    args = parser.parse_args(argv)

    reporter = make_reporter()
    reporter.say("bunnyauto — interactive hub")

    try:
        username, _ = preflight_device_credentials()
        environments = load_environments(args.env_file)
    except BunnyautoError as exc:
        reporter.say(exc.friendly())
        return 1

    reporter.say(f"  device login: {username}")
    for env in environments.values():
        state = "set" if env.token else "NOT set — reads/writes to this network will fail"
        reporter.say(f"  {env.token_env}: {state}")

    while True:
        try:
            environment = _choose_environment(environments, reporter, input_fn)
        except EOFError:
            environment = None
        if environment is None:
            reporter.say("bye.")
            return 0
        if _tool_loop(environment, args.env_file, reporter, input_fn) == "quit":
            reporter.say("bye.")
            return 0


# ---------------------------------------------------------------------------
# menus
# ---------------------------------------------------------------------------


def _choose_environment(
    environments: Mapping[str, Environment],
    reporter: Reporter,
    input_fn: InputFn,
) -> Environment | None:
    names = list(environments)
    reporter.say("\nWhich network?")
    for index, name in enumerate(names, start=1):
        env = environments[name]
        marker = "   (PRODUCTION)" if env.protected else ""
        reporter.say(f"  {index}. {name} — {env.nb_url} — tag {env.default_tag}{marker}")
    reporter.say("  q. quit")

    while True:
        choice = input_fn("Choose a network: ").strip().casefold()
        if choice in _QUIT:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return environments[names[int(choice) - 1]]
        reporter.say("  (enter a number from the list, or 'q')")


def _tool_loop(
    environment: Environment,
    env_file: str | None,
    reporter: Reporter,
    input_fn: InputFn,
) -> str:
    """Run tools for one environment. Returns ``"quit"`` or ``"back"``."""
    tools = list(REGISTRY.values())
    while True:
        reporter.say(f"\n[{environment.name}] what would you like to do?")
        for index, tool in enumerate(tools, start=1):
            reporter.say(f"  {index}. {tool.name} — {tool.summary}")
        reporter.say("  b. back to network choice    q. quit")

        try:
            choice = input_fn("Choose a tool: ").strip().casefold()
        except EOFError:
            return "quit"
        if choice in _QUIT:
            return "quit"
        if choice in _BACK:
            return "back"
        if not (choice.isdigit() and 1 <= int(choice) <= len(tools)):
            reporter.say("  (enter a number from the list, 'b', or 'q')")
            continue

        tool = tools[int(choice) - 1]
        try:
            _run_tool(tool, environment, env_file, reporter, input_fn)
        except BunnyautoError as exc:
            reporter.say(exc.friendly())
        except KeyboardInterrupt:
            reporter.say("\ncancelled")


# ---------------------------------------------------------------------------
# argument prompting
# ---------------------------------------------------------------------------


def prompt_for_args(tool: Tool, *, input_fn: InputFn = input) -> argparse.Namespace:
    """Ask only for what the tool needs and has no safe default for.

    Positionals are always asked. Boolean flags the tool defines itself (plus
    ``--apply`` for write tools) are asked as yes/no. Everything from
    :func:`add_common_arguments` keeps its default.
    """
    parser = argparse.ArgumentParser(add_help=False)
    tool.add_arguments(parser)
    if tool.writes:
        parser.add_argument("--apply", action="store_true")
        parser.add_argument("--yes", action="store_true")

    namespace = argparse.Namespace()
    for action in parser._actions:
        if action.dest != "help":
            setattr(namespace, action.dest, action.default)

    for action in parser._actions:
        dest = action.dest
        if dest in ("help", "yes"):
            continue
        if not action.option_strings:  # positional
            setattr(namespace, dest, _ask(action.help or dest, input_fn=input_fn))
        elif dest in COMMON_ARG_DESTS:
            continue
        elif action.nargs == 0:  # store_true / store_false flag
            question = (action.help or dest).rstrip(".?") + "?"
            setattr(
                namespace,
                dest,
                _ask_bool(question, default=bool(action.default), input_fn=input_fn),
            )
    return namespace


def _run_tool(
    tool: Tool,
    environment: Environment,
    env_file: str | None,
    reporter: Reporter,
    input_fn: InputFn,
) -> None:
    args = prompt_for_args(tool, input_fn=input_fn)

    ctx = build_context(
        env=environment.name,
        reporter=reporter,
        env_file=env_file,
        tag=getattr(args, "tag", None),
        force_tag=getattr(args, "force_tag", False),
        legacy_ssh=getattr(args, "legacy_ssh", False),
        apply=getattr(args, "apply", False),
        assume_yes=True,  # the hub does its own confirming, below
        timeouts=timeouts_from_args(args),
    )
    try:
        reporter.banner(ctx.environment, ctx.settings.target_tag)
        if ctx.settings.apply and not _confirm_apply(ctx.environment, reporter, input_fn):
            reporter.say("not applying — nothing was changed")
            return
        result = tool.run(ctx, args)
        reporter.render(result)
    finally:
        ctx.close()


def _confirm_apply(environment: Environment, reporter: Reporter, input_fn: InputFn) -> bool:
    if environment.protected:
        reporter.say(f"This will APPLY changes to PRODUCTION ({environment.nb_url}).")
        typed = input_fn(f"Type the environment name ({environment.name}) to proceed: ").strip()
        return typed == environment.name
    return _ask_bool("Apply these changes now", default=False, input_fn=input_fn)


# ---------------------------------------------------------------------------
# small prompt helpers
# ---------------------------------------------------------------------------


def _ask(prompt: str, *, default: str | None = None, input_fn: InputFn = input) -> str:
    suffix = f" [{default}]" if default else ""
    raw = input_fn(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def _ask_bool(prompt: str, *, default: bool = False, input_fn: InputFn = input) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input_fn(f"{prompt} [{hint}]: ").strip().casefold()
    if not raw:
        return default
    return raw in {"y", "yes"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
