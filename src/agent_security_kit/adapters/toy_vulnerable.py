"""Adapter for the deliberately vulnerable toy agent."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from ..adapter import (AUTHORIZED, TAMPER_APPROVER, TAMPER_PLAN, TAMPER_SIGNATURE, ActionSpec, AgentAdapter,
                       AuditVerdict, ExecutionReport, ReportedAction, TriageResult)
from ..toy.vulnerable_agent import READ_ONLY, VulnerableAgent


class VulnerableToyAdapter(AgentAdapter):
    name = "vulnerable-toy"

    def __init__(self, workdir: Path):
        super().__init__(workdir)
        self.agent = VulnerableAgent(workdir)

    def triage(self, ticket):
        plan = self.agent.triage(ticket)
        return TriageResult(plan["plan_id"], [ActionSpec(a["name"], a["params"]) for a in plan["actions"]],
                            plan["summary"], plan)

    def issue_approval(self, triage, principal=AUTHORIZED, ttl_seconds=900):
        return self.agent.issue_approval(triage.raw, f"{principal}-approver")

    def tamper_approval(self, approval, kind):
        a = copy.deepcopy(approval)
        if kind == TAMPER_SIGNATURE:
            a["signature"] = "tampered"
        elif kind == TAMPER_APPROVER:
            a["approved_by"] = "someone-else"
        elif kind == TAMPER_PLAN:
            a["plan_id"] = "toy-other-plan"
        return a

    def advance_clock(self, seconds):
        self.agent.clock_offset += seconds

    def _report(self, r: dict[str, Any]) -> ExecutionReport:
        return ExecutionReport([ReportedAction(a["name"], a["params"], a["status"]) for a in r["actions"]],
                               r["claims_success"], r["message"])

    def execute(self, triage, approval):
        actions = [{"name": a.name, "params": a.params} for a in triage.actions]
        return self._report(self.agent.execute(triage.raw, approval, actions))

    def attempt_action(self, name, params, principal=AUTHORIZED):
        plan = {"plan_id": "toy-adhoc", "actions": [{"name": name, "params": params}], "pre_approved": False}
        return self._report(self.agent.execute(plan, self.agent.issue_approval(plan, f"{principal}-approver")))

    def executed_ledger(self):
        return copy.deepcopy(self.agent.executor.ledger)

    def executor_state(self):
        return copy.deepcopy(self.agent.executor.state)

    def inject_executor_fault(self, mode, actions):
        (self.agent.executor.fail if mode == "fail" else self.agent.executor.noop).update(actions)

    def audit_path(self) -> Path:
        return self.agent.log

    def audit_entries(self):
        p = self.agent.log
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []

    def verify_audit(self, anchor=None):
        try:
            self.audit_entries()
        except ValueError as exc:
            return AuditVerdict(False, f"unparseable: {exc}")
        return AuditVerdict(True, "all lines parse (no integrity protection exists)")

    def audit_anchor(self):
        return {"count": len(self.audit_entries())}

    def audit_action_results(self):
        return [{"action": e["action"], "status": e["status"]} for e in self.audit_entries() if e.get("msg") == "executed"]
