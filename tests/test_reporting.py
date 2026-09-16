"""Regression tests: the Reporter must not let Rich swallow literal ``[...]`` text.

Rich's ``Console.print`` treats ``[...]`` as markup by default and silently drops
anything that isn't a recognised style name — so a policy field annotation like
``[dstaddr]`` (fw-subnet-check) or a menu label like ``[test]`` (the hub) used to
vanish outright instead of printing. Every Reporter method that hands dynamic
content to the console must escape it first.
"""

from __future__ import annotations

import io

from bunnyauto.environments import Environment
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status, ToolResult


def _rich_reporter() -> tuple[Reporter, io.StringIO]:
    stream = io.StringIO()
    reporter = Reporter(json_mode=False, use_rich=True, stream=stream)
    return reporter, stream


def test_rich_is_available_in_this_environment():
    """Sanity check: if this fails, the tests below are silently no-ops."""
    reporter, _ = _rich_reporter()
    assert reporter._console is not None


def test_info_preserves_literal_brackets():
    reporter, stream = _rich_reporter()
    reporter.info("12/allow_outbound [dstaddr] (security-policy), 15/allow_lan [srcaddr]")
    out = stream.getvalue()
    assert "[dstaddr]" in out
    assert "[srcaddr]" in out


def test_warn_and_step_preserve_literal_brackets():
    reporter, stream = _rich_reporter()
    reporter.step("checking interface port10 [ip 10.1.2.1/24]")
    reporter.warn("subnet overlaps [dstaddr] on policy 12")
    out = stream.getvalue()
    assert "[ip 10.1.2.1/24]" in out
    assert "[dstaddr]" in out


def test_say_preserves_literal_brackets():
    """The hub's menu prompts embed labels like '[test]' — not markup."""
    reporter, stream = _rich_reporter()
    reporter.say("[test] what would you like to do?")
    assert "[test]" in stream.getvalue()


def test_render_summary_and_changes_preserve_literal_brackets():
    reporter, stream = _rich_reporter()
    result = ToolResult(
        status=Status.DRIFT,
        summary="10.1.2.0/24 is IN USE — referenced [dstaddr]",
        changes=["10.1.2.0/24  (vlan2)  exact  —  policies: 12/allow-out [dstaddr]"],
    )
    reporter.render(result)
    out = stream.getvalue()
    assert "[dstaddr]" in out
    assert "DRIFT" in out


def test_banner_preserves_literal_brackets_in_the_line():
    reporter, stream = _rich_reporter()
    env = Environment(
        name="test",
        nb_url="https://nb.example.com [staging]",
        default_tag="nornirtest",
        token_env="TOK",
    )
    reporter.banner(env, "nornirtest")
    assert "[staging]" in stream.getvalue()
