"""Adapter for Project 1: it-service-agent-demo (package `it_service_agent`).

Install that project first (`pip install -e ../it-service-agent-demo`) or point ITSA_HOME at its checkout.
"""
from __future__ import annotations

import copy
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from ..adapter import (AUTHORIZED, LOW_PRIVILEGE, TAMPER_APPROVER, TAMPER_PLAN, TAMPER_SIGNATURE, UNKNOWN,
                       ActionSpec, AgentAdapter, AuditVerdict, ExecutionReport, NotSupported, ReportedAction,
                       TriageResult)

_PRINCIPALS = {AUTHORIZED: "riley.chen@example.test", LOW_PRIVILEGE: "jamie.park@example.test"}


def _import_itsa():
    home = os.environ.get("ITSA_HOME")
    if home:
        sys.path.insert(0, str(Path(home) / "src"))
    try:
        import it_service_agent  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError("it_service_agent is not importable. Run `pip install -e <path to it-service-agent-demo>` "
                          "or set ITSA_HOME to its checkout.") from exc
    return it_service_agent


class ITServiceAgentAdapter(AgentAdapter):
    name = "it-service-agent"

    def __init__(self, workdir: Path):
        super().__init__(workdir)
        itsa = _import_itsa()
        from it_service_agent import cli, policy
        from it_service_agent.util import Clock
        self.itsa, self.policy = itsa, policy
        root = Path(os.environ["ITSA_HOME"]) if os.environ.get("ITSA_HOME") else cli.ROOT
        self.clock = Clock()
        self.registry = itsa.ApproverRegistry.from_file(root / "examples/config/approvers.demo.json")
        self.audit = itsa.AuditLog(self.workdir / "audit.jsonl", self.clock)
        self.executor = itsa.MockExecutor(clock=self.clock)
        self.authority = itsa.ApprovalAuthority(self.registry, self.clock)
        self.agent = itsa.ITServiceAgent(itsa.RunbookStore(root / "runbooks"), self.executor, self.audit,
                                         self.authority, clock=self.clock)

    # -- helpers -----------------------------------------------------------------------------
    def _plan(self, triage: TriageResult):
        """Return the agent's Plan, rebuilt if the kit modified the action list (plan-swap scenario)."""
        from it_service_agent.models import Action, Plan
        plan = triage.raw
        if [(a.name, a.params) for a in plan.actions] == [(a.name, a.params) for a in triage.actions]:
            return plan
        d = plan.to_dict()
        cite = plan.actions[0].citation if plan.actions else None
        d["actions"] = [Action(a.name, dict(a.params), cite).to_dict() for a in triage.actions]
        return Plan.from_dict(d)

    def _report(self, rep) -> ExecutionReport:
        status_map = {"succeeded": "success"}
        return ExecutionReport([ReportedAction(o.name, o.params, status_map.get(o.status, o.status))
                                for o in rep.outcomes], rep.all_succeeded, rep.summary())

    # -- interface ---------------------------------------------------------------------------
    def triage(self, ticket):
        from it_service_agent.models import Ticket
        plan = self.agent.triage(Ticket.from_dict(ticket))
        return TriageResult(plan.digest()[:16], [ActionSpec(a.name, dict(a.params)) for a in plan.actions],
                            plan.summary, plan)

    def issue_approval(self, triage, principal=AUTHORIZED, ttl_seconds=900):
        plan = triage.raw
        if principal == UNKNOWN:
            from it_service_agent.approvals import SIGNED_FIELDS, _sign
            a = self.authority.issue(plan, _PRINCIPALS[AUTHORIZED], ttl_seconds)
            a["approver"] = "mallory@example.test"
            a["signature"] = _sign(secrets.token_bytes(32), {k: a[k] for k in SIGNED_FIELDS})
            return a
        return self.authority.issue(plan, _PRINCIPALS[principal], ttl_seconds)

    def tamper_approval(self, approval, kind):
        a = copy.deepcopy(approval)
        if kind == TAMPER_SIGNATURE:
            a["signature"] = a["signature"][:-1] + ("0" if a["signature"][-1] != "0" else "1")
        elif kind == TAMPER_APPROVER:
            a["approver"] = "pat.ortiz@example.test" if a["approver"] != "pat.ortiz@example.test" else "riley.chen@example.test"
        elif kind == TAMPER_PLAN:
            a["plan_digest"] = "0" * 64
        return a

    def advance_clock(self, seconds):
        self.clock.advance(seconds)

    def execute(self, triage, approval):
        return self._report(self.agent.execute(self._plan(triage), approval))

    def attempt_action(self, name, params, principal=AUTHORIZED):
        from it_service_agent.models import Action, Citation, Plan
        cite = Citation("adhoc.md", "RB-ADHOC-000", "Remediation", 1, 2, "0" * 64)
        user = params.get("user", "jordan.lee@example.test")
        plan = Plan("KIT-ADHOC", "0" * 64, "jordan.lee@example.test", user if "@" in user else "jordan.lee@example.test",
                    [Action(name, dict(params), cite)], [cite], "ad hoc", "kit", self.clock.iso())
        approval = self.authority.issue(plan, _PRINCIPALS[principal])
        return self._report(self.agent.execute(plan, approval))

    def executed_ledger(self):
        return [{"action": e["action"], "params": e["params"], "status": e["status"],
                 "state_changing": self.policy.is_state_changing(e["action"])} for e in self.executor.ledger]

    def executor_state(self):
        return self.executor.snapshot()

    def inject_executor_fault(self, mode, actions):
        (self.executor.fail_actions if mode == "fail" else self.executor.noop_actions).update(actions)

    def audit_path(self):
        return self.audit.path

    def audit_entries(self):
        return self.audit.entries()

    def verify_audit(self, anchor=None):
        r = self.audit.verify(anchor)
        return AuditVerdict(r.ok, "; ".join(r.errors) or f"{r.entries} entries verified")

    def audit_anchor(self):
        return self.audit.anchor()

    def audit_action_results(self):
        out = []
        for e in self.audit.entries():
            if e.get("event") == "action.result":
                s = e["data"]["status"]
                out.append({"action": e["data"]["action"], "status": "success" if s == "succeeded" else s})
        return out
