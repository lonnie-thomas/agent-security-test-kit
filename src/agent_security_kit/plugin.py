"""pytest plugin: --agent selection, per-test metadata markers, N/A handling, and report output."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from .adapter import AgentAdapter, NotSupported
from .report import aggregate, render_markdown, render_terminal

BUILTIN_AGENTS = {
    "toy": "agent_security_kit.adapters.toy_vulnerable:VulnerableToyAdapter",
    "it-service-agent": "agent_security_kit.adapters.it_service_agent:ITServiceAgentAdapter",
}
_RECORDS: dict[str, dict[str, Any]] = {}


def resolve_adapter_class(spec: str) -> type[AgentAdapter]:
    target = BUILTIN_AGENTS.get(spec, spec)
    if ":" not in target:
        raise pytest.UsageError(f"--agent must be one of {sorted(BUILTIN_AGENTS)} or 'package.module:ClassName'")
    mod, cls = target.split(":", 1)
    return getattr(importlib.import_module(mod), cls)


def pytest_addoption(parser):
    g = parser.getgroup("agent-security-kit")
    g.addoption("--agent", default="toy", help="toy | it-service-agent | package.module:AdapterClass")
    g.addoption("--kit-json", default=None, help="write machine-readable results to this path")
    g.addoption("--kit-md", default=None, help="write a markdown report to this path")


def pytest_configure(config):
    config.addinivalue_line("markers", "kit(id, title, category, severity, owasp): test metadata for the report")
    _RECORDS.clear()
    try:    # fail fast with a clear message instead of 83 identical fixture errors
        resolve_adapter_class(config.getoption("--agent"))
    except (ImportError, AttributeError) as exc:
        raise pytest.UsageError(f"cannot load adapter {config.getoption('--agent')!r}: {exc}") from exc


@pytest.fixture
def adapter(request, tmp_path):
    cls = resolve_adapter_class(request.config.getoption("--agent"))
    a = cls(tmp_path / "agent")
    yield a
    a.close()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    marker = item.get_closest_marker("kit")
    if marker is None:
        return
    if call.excinfo is not None and call.excinfo.errisinstance(NotSupported):
        rep.outcome = "skipped"
        rep.longrepr = (str(item.fspath), 0, f"N/A: {call.excinfo.value}")
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        kw = marker.kwargs
        rec = _RECORDS.setdefault(kw["id"], {"id": kw["id"], "title": kw["title"], "category": kw["category"],
                                             "severity": kw["severity"], "owasp": kw.get("owasp", ""),
                                             "cases": []})
        callspec = getattr(item, "callspec", None)
        msg = ""
        if rep.outcome == "failed" and call.excinfo is not None:
            msg = str(call.excinfo.value).strip().splitlines()[0][:220] if str(call.excinfo.value).strip() else call.excinfo.typename
        elif rep.outcome == "skipped":
            msg = "not supported by adapter"
        rec["cases"].append({"param": callspec.id if callspec else "", "outcome": rep.outcome, "message": msg})


def pytest_sessionfinish(session):
    cfg = session.config
    agent = cfg.getoption("--agent")
    results = aggregate(_RECORDS)
    payload = {"agent": agent, "results": results}
    if cfg.getoption("--kit-json"):
        Path(cfg.getoption("--kit-json")).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if cfg.getoption("--kit-md"):
        Path(cfg.getoption("--kit-md")).write_text(render_markdown(agent, results), encoding="utf-8")


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    results = aggregate(_RECORDS)
    if results:
        terminalreporter.section(f"agent-security-test-kit results: {config.getoption('--agent')}")
        for line in render_terminal(results):
            terminalreporter.write_line(line)
