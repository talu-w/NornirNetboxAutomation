"""``python -m bunnyauto`` / the ``bunnyauto`` console script — the CI entry point.

Assembles the argument parser from the tool registry, builds one ``Context``,
runs the chosen tool, and returns its exit code. The interactive hub
(:mod:`bunnyauto.hub`, migration step 3) does the same work with prompts instead
of ``argv``.
"""

from __future__ import annotations

import argparse
import sys

from bunnyauto import __version__
from bunnyauto.common import env_flag
from bunnyauto.context import build_context
from bunnyauto.errors import BunnyautoError
from bunnyauto.reporting import make_reporter
from bunnyauto.tools import REGISTRY
from bunnyauto.tools.base import timeouts_from_args

_GLOBAL_VALUE_FLAGS = {"--env", "--env-file"}
_GLOBAL_BOOL_FLAGS = {"--json", "--debug"}


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

    subparsers = parser.add_subparsers(dest="tool", required=True, metavar="<tool>")
    for tool in REGISTRY.values():
        tool_parser = subparsers.add_parser(tool.name, help=tool.summary, description=tool.summary)
        if tool.writes:
            tool_parser.add_argument(
                "--apply",
                action="store_true",
                help="apply the change (default: plan only, nothing written)",
            )
            tool_parser.add_argument(
                "--yes",
                action="store_true",
                help="skip confirmation prompts — for non-interactive/CI use",
            )
        tool.add_arguments(tool_parser)
    return parser


def forward_argv(tool_name: str, argv: list[str]) -> list[str]:
    """Rewrite a shim's ``argv`` into canonical form: globals, then the tool name.

    Lets ``python send_command.py --env test 'show version'`` reach
    ``bunnyauto --env test send-command 'show version'``.
    """
    lead: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in _GLOBAL_VALUE_FLAGS:
            lead.extend(argv[index : index + 2])
            index += 2
            continue
        if token in _GLOBAL_BOOL_FLAGS or any(
            token.startswith(f"{flag}=") for flag in _GLOBAL_VALUE_FLAGS
        ):
            lead.append(token)
            index += 1
            continue
        break
    return [*lead, tool_name, *argv[index:]]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    reporter = make_reporter(json_mode=args.json)
    tool = REGISTRY[args.tool]

    ctx = None
    try:
        ctx = build_context(
            env=args.env,
            reporter=reporter,
            env_file=args.env_file,
            config_file=getattr(args, "config", "config.yaml"),
            tag=getattr(args, "tag", None),
            force_tag=getattr(args, "force_tag", False),
            legacy_ssh=getattr(args, "legacy_ssh", False),
            apply=getattr(args, "apply", False),
            assume_yes=getattr(args, "yes", False),
            timeouts=timeouts_from_args(args),
        )
        reporter.banner(ctx.environment, ctx.settings.target_tag)
        result = tool.run(ctx, args)
    except BunnyautoError as exc:
        if args.debug:
            raise
        reporter.error(exc.friendly())
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        reporter.error("interrupted")
        return 130
    finally:
        if ctx is not None:
            ctx.close()

    reporter.render(result)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
