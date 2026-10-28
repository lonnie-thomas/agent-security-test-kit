"""Result aggregation and rendering (terminal, markdown, cross-agent matrix)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Control": 4}
CATEGORY_NAMES = {
    "A": "Hidden / indirect instructions",
    "B": "Unauthorized actions and scope",
    "C": "Forged / replayed approvals",
    "D": "False 'done' claims",
    "E": "Audit log integrity",
}

OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure", "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning", "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses", "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def aggregate(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for rec in records.values():
        cases = rec["cases"]
        failed = [c for c in cases if c["outcome"] == "failed"]
        passed = [c for c in cases if c["outcome"] == "passed"]
        skipped = [c for c in cases if c["outcome"] == "skipped"]
        if failed:
            status = "FAIL"
        elif passed:
            status = "PASS"
        elif skipped:
            status = "N/A"
        else:
            status = "ERROR"
        out.append({**{k: rec[k] for k in ("id", "title", "category", "severity", "owasp")},
                    "status": status, "passed": len(passed), "failed": len(failed), "skipped": len(skipped),
                    "total": len(cases), "failures": [f"[{c['param']}] {c['message']}" if c["param"] else c["message"]
                                                       for c in failed[:3]]})
    return sorted(out, key=lambda r: r["id"])


def _cell(r: dict[str, Any]) -> str:
    if r["status"] == "FAIL":
        return f"❌ FAIL ({r['failed']}/{r['total']})"
    if r["status"] == "PASS":
        return f"✅ PASS ({r['passed']}/{r['total']})" if r["total"] > 1 else "✅ PASS"
    return r["status"]


def summary_counts(results: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in results if r["severity"] != "Control"]
    fails = [r for r in scored if r["status"] == "FAIL"]
    by_sev = {s: sum(1 for r in fails if r["severity"] == s) for s in ("Critical", "High", "Medium", "Low")}
    return {"tests": len(scored), "passed": sum(1 for r in scored if r["status"] == "PASS"),
            "failed": len(fails), "na": sum(1 for r in scored if r["status"] == "N/A"),
            "failed_by_severity": by_sev, "control_failures": sum(
                1 for r in results if r["severity"] == "Control" and r["status"] != "PASS"),
            "case_total": sum(r["total"] for r in results), "case_failed": sum(r["failed"] for r in results)}


def render_terminal(results: list[dict[str, Any]]) -> list[str]:
    lines = [f"{'ID':<5} {'Sev':<8} {'Result':<16} Test"]
    for r in results:
        lines.append(f"{r['id']:<5} {r['severity']:<8} {_cell(r):<16} {r['title']}")
    fails = [r for r in results if r["status"] == "FAIL"]
    if fails:
        lines.append("\nFirst failure example per failed test:")
        for r in sorted(fails, key=lambda r: (SEVERITY_ORDER[r["severity"]], r["id"])):
            lines.append(f"  {r['id']} ({r['severity']}) {r['failures'][0][:150]}")
    c = summary_counts(results)
    lines.append(f"\nscored tests: {c['tests']}  passed: {c['passed']}  failed: {c['failed']}  n/a: {c['na']}  "
                 f"failed by severity: {c['failed_by_severity']}  (cases: {c['case_total'] - c['case_failed']}/{c['case_total']} passed)")
    return lines


def render_markdown(agent: str, results: list[dict[str, Any]]) -> str:
    c = summary_counts(results)
    md = [f"# Agent security test report: `{agent}`", "",
          f"**Scored tests:** {c['tests']} &nbsp; **Passed:** {c['passed']} &nbsp; **Failed:** {c['failed']} "
          f"&nbsp; **N/A:** {c['na']}  ",
          f"**Failed by severity:** Critical {c['failed_by_severity']['Critical']}, High {c['failed_by_severity']['High']}, "
          f"Medium {c['failed_by_severity']['Medium']}, Low {c['failed_by_severity']['Low']}  ",
          f"**Cases:** {c['case_total'] - c['case_failed']}/{c['case_total']} passed (parametrised payload/carrier combinations)", "",
          "| ID | Category | Test | Severity | OWASP LLM Top 10 (2025) | Result |", "|---|---|---|---|---|---|"]
    for r in results:
        md.append(f"| {r['id']} | {CATEGORY_NAMES[r['category']]} | {r['title']} | {r['severity']} | "
                  f"{r['owasp'] or '-'} | {_cell(r)} |")
    fails = [r for r in results if r["status"] == "FAIL"]
    if fails:
        md += ["", "## Failure details (first examples)", ""]
        for r in sorted(fails, key=lambda r: (SEVERITY_ORDER[r["severity"]], r["id"])):
            md.append(f"* **{r['id']} ({r['severity']})**: {r['title']}")
            md += [f"    * `{f}`" for f in r["failures"]]
    return "\n".join(md) + "\n"


def render_matrix(files: list[str | Path]) -> str:
    runs = [json.loads(Path(f).read_text(encoding="utf-8")) for f in files]
    agents = [r["agent"] for r in runs]
    by_id: dict[str, dict[str, Any]] = {}
    for run in runs:
        for r in run["results"]:
            by_id.setdefault(r["id"], {"meta": r, "cells": {}})["cells"][run["agent"]] = _cell(r)
    md = ["| ID | Category | Test | Severity | OWASP (2025) | " + " | ".join(f"`{a}`" for a in agents) + " |",
          "|---|---|---|---|---|" + "---|" * len(agents)]
    for tid in sorted(by_id):
        m = by_id[tid]["meta"]
        md.append(f"| {tid} | {CATEGORY_NAMES[m['category']]} | {m['title']} | {m['severity']} | {m['owasp'] or '-'} | "
                  + " | ".join(by_id[tid]["cells"].get(a, "-") for a in agents) + " |")
    tot = ["", "| Agent | Scored tests | Passed | Failed | Failed Critical | Failed High | Failed Medium |", "|---|---|---|---|---|---|---|"]
    for run in runs:
        c = summary_counts(run["results"])
        f = c["failed_by_severity"]
        tot.append(f"| `{run['agent']}` | {c['tests']} | {c['passed']} | {c['failed']} | {f['Critical']} | {f['High']} | {f['Medium']} |")
    return "\n".join(md + tot) + "\n"
