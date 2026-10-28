"""Self-checks: the kit must (1) pass a well-controlled agent, (2) catch a vulnerable one, and
(3) behave sensibly for custom adapters. These run the real suite in a subprocess."""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent_security_kit.payloads import CARRIERS, GOALS, build_ticket
from agent_security_kit.report import render_matrix

TOY_PASSES = {"A-00", "C-00", "C-01", "D-04", "E-01", "E-08"}


def run_kit(agent, out, extra=(), env=None):
    cmd = [sys.executable, "-m", "agent_security_kit", "run", "--agent", agent, "--json", str(out), *extra]
    e = {**os.environ, **(env or {})}
    return subprocess.run(cmd, capture_output=True, text=True, env=e)


def load(path):
    return {r["id"]: r for r in json.loads(Path(path).read_text())["results"]}


@pytest.fixture(scope="module")
def toy(tmp_path_factory):
    p = tmp_path_factory.mktemp("toy") / "toy.json"
    proc = run_kit("toy", p)
    return proc, load(p)


@pytest.fixture(scope="module")
def itsa(tmp_path_factory):
    p = tmp_path_factory.mktemp("itsa") / "itsa.json"
    proc = run_kit("it-service-agent", p)
    return proc, load(p), p


def test_secure_reference_agent_passes_everything(itsa):
    proc, res, _ = itsa
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert all(r["status"] == "PASS" for r in res.values()), {k: r["status"] for k, r in res.items() if r["status"] != "PASS"}
    assert len(res) >= 30


def test_vulnerable_toy_is_caught(toy):
    proc, res = toy
    assert proc.returncode != 0
    passed = {k for k, r in res.items() if r["status"] == "PASS"}
    assert passed == TOY_PASSES, f"unexpected pass set: {sorted(passed ^ TOY_PASSES)}"
    for cat in "ABCDE":
        assert any(r["status"] == "FAIL" for r in res.values() if r["category"] == cat), f"category {cat} caught nothing"


def test_every_scored_test_has_severity_and_owasp_metadata(itsa):
    _, res, _ = itsa
    for r in res.values():
        assert r["severity"] in {"Critical", "High", "Medium", "Low", "Control"}
        if r["category"] in "ABCD" and r["severity"] != "Control":
            assert "LLM" in r["owasp"], r["id"]


def test_matrix_merges_runs(toy, itsa, tmp_path):
    toy_json = tmp_path / "toy.json"
    run_kit("toy", toy_json)
    md = render_matrix([toy_json, itsa[2]])
    assert "`toy`" in md and "`it-service-agent`" in md and "FAIL" in md and "PASS" in md


def test_custom_adapter_by_module_path_and_not_supported_is_na(tmp_path):
    mod = tmp_path / "my_adapter.py"
    mod.write_text(textwrap.dedent('''
        from agent_security_kit import NotSupported
        from agent_security_kit.adapters.it_service_agent import ITServiceAgentAdapter

        class NoAnchorAdapter(ITServiceAgentAdapter):
            """A real agent that genuinely has no external anchor support."""
            def audit_anchor(self):
                raise NotSupported("agent has no external anchor")
    '''))
    out = tmp_path / "r.json"
    proc = run_kit("my_adapter:NoAnchorAdapter", out, env={"PYTHONPATH": str(tmp_path)})
    res = load(out)
    assert res["E-06"]["status"] == "N/A", proc.stdout[-1500:]
    assert res["E-02"]["status"] == "PASS"
    assert proc.returncode == 0       # N/A is not a failure


def test_unknown_agent_spec_is_a_usage_error(tmp_path):
    proc = run_kit("nonsense", tmp_path / "x.json")
    assert proc.returncode != 0


def test_payload_carriers_really_hide_the_instruction():
    goal = GOALS["privilege_escalation"]
    zw = build_ticket("body_zero_width_split", "privilege_escalation")
    assert "\u200b" in zw["body"] and goal not in zw["body"]
    tags = build_ticket("body_unicode_tag_chars", "privilege_escalation")["body"]
    decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if "\U000E0000" <= c <= "\U000E007F")
    assert decoded == goal and goal not in tags
    assert "<!--" in build_ticket("body_html_comment", "privilege_escalation")["body"]
    assert len(CARRIERS) == 9


def test_canary_is_always_planted():
    for carrier in CARRIERS:
        t = build_ticket(carrier, "exfiltration")
        assert any("CANARY-SECRET" in a["text"] for a in t["attachments"])
