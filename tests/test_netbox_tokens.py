"""Tests for the pure vendor-model -> NetBox device-type matcher (no NetBox, no HTTP)."""

from __future__ import annotations

from types import SimpleNamespace

from bunnyauto.netbox.tokens import match_record, tokens


def _dt(model="", slug=""):
    return SimpleNamespace(model=model, slug=slug)


AP_655 = _dt(model="Aruba AP-655", slug="hpe-aruba-ap-655")
AP_635 = _dt(model="Aruba AP-635", slug="hpe-aruba-ap-635")
A7210 = _dt(model="A7210", slug="a7210")


def test_tokens():
    assert tokens("hpe-aruba-ap-655") == ["hpe", "aruba", "ap", "655"]
    assert tokens("Aruba AP-655") == ["aruba", "ap", "655"]
    assert tokens("655") == ["655"]


# --- the real-world case this fix is for --------------------------------


def test_bare_model_number_matches_ndx_style_slug():
    """Aruba reports '655'; NetBox has model 'Aruba AP-655' / slug 'hpe-aruba-ap-655'."""
    assert match_record(["655"], [AP_655, AP_635, A7210]) is AP_655


def test_ap_prefixed_candidate_matches_too():
    assert match_record(["AP-655"], [AP_655, AP_635, A7210]) is AP_655


def test_exact_model_string_still_matches():
    assert match_record(["A7210"], [AP_655, AP_635, A7210]) is A7210


# --- token boundaries prevent false positives ---------------------------


def test_does_not_spuriously_match_substring_inside_a_longer_token():
    weird = _dt(model="8655X", slug="vendor-8655x")
    assert match_record(["655"], [weird]) is None


def test_no_match_returns_none():
    assert match_record(["999"], [AP_655, AP_635]) is None


# --- disambiguation across candidates ------------------------------------


def test_true_ambiguity_returns_none_even_with_a_more_specific_candidate():
    """Two device types that both contain 'AP-655' as a token run: unresolvable."""
    clash = _dt(model="Other AP-655-EU", slug="other-ap-655-eu")
    assert match_record(["655", "AP-655"], [AP_655, clash]) is None


def test_bare_number_alone_unambiguous_despite_a_similar_looking_model():
    """A coincidental '1655' model doesn't clash with '655' — different token."""
    coincidence = _dt(model="Widget-1655", slug="widget-1655")
    assert match_record(["655"], [AP_655, coincidence]) is AP_655


def test_empty_candidates_and_types_are_handled():
    assert match_record([], [AP_655]) is None
    assert match_record(["655"], []) is None
    assert match_record([""], [AP_655]) is None
