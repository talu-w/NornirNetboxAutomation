"""``python -m bunnyauto`` / the ``bunnyauto`` console script — the CI entry point.

Assembles the argument parser from the tool registry, builds one ``Context``,
runs the chosen tool, and returns its exit code. The interactive hub
(:mod:`bunnyauto.hub`) does the same work with prompts instead of ``argv``.

Commands are ``bunnyauto --env <env> <category> <tool> [options]``, e.g.
``bunnyauto --env prod wired backup`` or ``bunnyauto --env test wireless sync``;
see :mod:`bunnyauto.categories`.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys

from bunnyauto import __version__
from bunnyauto.categories import CATEGORIES, DEFAULT_ROLES
from bunnyauto.common import env_flag
from bunnyauto.context import build_context
from bunnyauto.errors import BunnyautoError
from bunnyauto.prompts import terminal_input
from bunnyauto.reporting import make_reporter
from bunnyauto.tools import REGISTRY
from bunnyauto.tools.base import timeouts_from_args

#: Pre-category (flat) names that also changed their own name, mapped to where
#: they live now. Everything else keeps its name inside its category.
_RENAMED: dict[str, tuple[str, str]] = {
    "wireless-sync": ("wireless", "sync"),
    "wireless-enrich": ("wireless", "sync"),
    "fw-subnet-check": ("security", "subnet-check"),
}
#: Tools folded into another tool of the same category: (category, old) -> new.
_MERGED: dict[tuple[str, str], str] = {
    ("wireless", "enrich"): "sync",  # 2026-09-24
}
#: Global options that take a value, so the value isn't mistaken for a category.
_VALUE_OPTIONS = frozenset({"--env", "--env-file"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bunnyauto",
        description="NetBox-driven, Nornir-executed network automation.",
    )
    parser.add_argument("--version", action="version", version=f"bunnyauto {__version__}")
    parser.add_argument(
        "--env",
        required=True,
        metavar="NAME",
        help="target environment from bunnyauto.yaml (e.g. test, prod) — always required",
    )
    parser.add_argument(
        "--env-file",
        default=None,
        help="path to the environment overlay (default: ./bunnyauto.yaml)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the result as one JSON object on stdout; suppress prose",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=env_flag("BUNNYAUTO_DEBUG"),
        help="show full tracebacks instead of one-line errors",
    )

    categories = parser.add_subparsers(dest="category", required=True, metavar="<category>")
    for key, tools in REGISTRY.items():
        category = CATEGORIES[key]
        category_parser = categories.add_parser(
            key,
            help=category.summary,
            description=_category_description(key),
        )
        subparsers = category_parser.add_subparsers(dest="tool", required=True, metavar="<tool>")
        for tool in tools.values():
            tool_parser = subparsers.add_parser(
                tool.name, help=tool.summary, description=tool.summary
            )
            if tool.writes:
                tool_parser.add_argument(
                    "--apply",
                    action="store_true",
                    help=getattr(tool, "apply_help", None)
                    or "apply the change (default: plan only, nothing written)",
                )
                tool_parser.add_argument(
                    "--yes",
                    action="store_true",
                    help="skip confirmation prompts — for non-interactive/CI use",
                )
            tool.add_arguments(tool_parser)
    return parser


def _category_description(key: str) -> str:
    category = CATEGORIES[key]
    text = f"{category.title}: {category.summary}."
    if category.branch is not None:
        text += (
            " Its tools only touch devices that carry the environment's tag and whose "
            f"NetBox role is {DEFAULT_ROLES[category.branch]!r} or any role beneath it "
            f"(set roles.{category.branch} in bunnyauto.yaml if your slug differs; "
            "'netbox scope' shows what that reaches)."
        )
    return text


def _category_hint(argv: list[str]) -> str | None:
    """The corrected command when a tool name is typed where a category belongs.

    ``bunnyauto --env test backup --raw`` -> ``bunnyauto --env test wired backup --raw``;
    a renamed tool (``wireless-sync``) is pointed at its new name too, and a tool
    merged into another (``wireless enrich``) at the one that does its job now.
    """
    index = _first_positional(argv)
    if index is None:
        return None
    word = argv[index]
    if word in REGISTRY:
        old = argv[index + 1] if index + 1 < len(argv) else None
        new = _MERGED.get((word, old)) if old else None
        if new is None:
            return None
        fixed = [*argv[: index + 1], new, *argv[index + 2 :]]
        return f"'{word} {old}' is now part of '{word} {new}' — run: " + shlex.join(
            ["bunnyauto", *fixed]
        )
    if word in _RENAMED:
        category, tool = _RENAMED[word]
        lead = f"{word!r} is now '{category} {tool}'"
    else:
        homes = [category for category, tools in REGISTRY.items() if word in tools]
        if len(homes) != 1:
            return None
        category, tool = homes[0], word
        lead = f"{word!r} is a {category} tool"
    fixed = [*argv[:index], category, tool, *argv[index + 1 :]]
    return f"{lead} — run: {shlex.join(['bunnyauto', *fixed])}"


def _first_positional(argv: list[str]) -> int | None:
    """Index of the first token that isn't a global option or an option's value."""
    skip_next = False
    for index, token in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if token in _VALUE_OPTIONS:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        return index
    return None


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        # `bunnyauto` with no arguments opens the interactive hub.
        from bunnyauto.hub import main as hub_main

        return hub_main([])

    hint = _category_hint(raw)
    if hint is not None:
        message = f"bunnyauto: {hint}"
        if "--json" in raw:
            json.dump(
                {"status": "error", "summary": message, "exit_code": 2, "changes": []},
                sys.stdout,
            )
            sys.stdout.write("\n")
        else:
            sys.stderr.write(f"{message}\n")
        return 2

    parser = build_parser()
    args = parser.parse_args(raw)
    reporter = make_reporter(json_mode=args.json)
    tool = REGISTRY[args.category][args.tool]

    def _fail(message: str, code: int = 1) -> int:
        if args.json:
            json.dump(
                {"status": "error", "summary": message, "exit_code": code, "changes": []},
                sys.stdout,
            )
            sys.stdout.write("\n")
        else:
            reporter.error(message)
        return code

    ctx = None
    try:
        ctx = build_context(
            env=args.env,
            reporter=reporter,
            env_file=args.env_file,
            config_file=getattr(args, "config", "config.yaml"),
            tag=getattr(args, "tag", None),
            force_tag=getattr(args, "force_tag", False),
            region=getattr(args, "region", None),
            site=getattr(args, "site", None),
            legacy_ssh=getattr(args, "legacy_ssh", False),
            apply=getattr(args, "apply", False),
            assume_yes=getattr(args, "yes", False),
            timeouts=timeouts_from_args(args),
            need_devices=getattr(tool, "needs_devices", True),
            need_netbox=getattr(tool, "needs_netbox", True),
            category=CATEGORIES[args.category],
            role=getattr(args, "role", None),
            # A tool's mid-run question needs someone at a terminal; never in --json.
            ask_fn=None if args.json else terminal_input(),
        )
        ctx.banner()
        result = tool.run(ctx, args)
    except BunnyautoError as exc:
        if args.debug:
            raise
        return _fail(exc.friendly())
    except KeyboardInterrupt:  # pragma: no cover
        return _fail("interrupted", 130)
    except Exception as exc:  # unexpected — NetBox down, a device library blew up, ...
        if args.debug:
            raise
        return _fail(f"bunnyauto: unexpected error: {exc} (run with --debug for the traceback)")
    finally:
        if ctx is not None:
            ctx.close()

    reporter.render(result)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
