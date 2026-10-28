"""The adapter interface: the only thing you implement to point the kit at your agent.

The kit drives your agent through a small, deliberately boring surface:

    triage(ticket)            -> what the agent *proposes* (no side effects allowed)
    issue_approval(...)       -> obtain an approval the way your system's approvers would
    execute(triage, approval) -> run the plan through the agent's gate and executor
    attempt_action(...)       -> simulate a (compromised / hallucinating) planner asking for ONE action
    executed_ledger()         -> GROUND TRUTH from the executor, independent of what the agent says
    executor_state()          -> ground-truth system state
    audit_*                   -> the agent's audit log (a JSONL file) and its integrity verifier

Ground truth (`executed_ledger`, `executor_state`) must come from the executor / system of record,
NOT from the agent's own report; otherwise the "false done" checks cannot work.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Principals the kit asks the adapter to approve as.
AUTHORIZED = "authorized"          # a registered approver cleared for the plan's risk
LOW_PRIVILEGE = "low_privilege"    # a registered approver whose clearance is below high-risk plans
UNKNOWN = "unknown"                # someone who is not a registered approver (signs with their own key)

# Tamper kinds for tamper_approval().
TAMPER_SIGNATURE = "signature"
TAMPER_APPROVER = "approver"
TAMPER_PLAN = "plan"


class NotSupported(Exception):
    """Raise from an adapter method for a capability the agent genuinely lacks by design
    (the test is then reported N/A rather than pass/fail). Do NOT use this to hide a gap:
    a missing control should be a FAIL, not N/A."""


@dataclass
class ActionSpec:
    name: str
    params: dict[str, str]


@dataclass
class TriageResult:
    plan_id: str
    actions: list[ActionSpec]
    summary: str = ""
    raw: Any = None                      # opaque adapter payload (the agent's own plan object)


@dataclass
class ReportedAction:
    name: str
    params: dict[str, str]
    status: str                          # success | failed | skipped | denied


@dataclass
class ExecutionReport:
    actions: list[ReportedAction] = field(default_factory=list)
    claims_success: bool = False         # does the agent tell the user "it's done / resolved"?
    message: str = ""


@dataclass
class AuditVerdict:
    ok: bool
    detail: str = ""


class AgentAdapter(ABC):
    name: str = "unnamed-agent"

    def __init__(self, workdir: Path):
        self.workdir = Path(workdir)

    # -- agent behaviour ---------------------------------------------------------------------
    @abstractmethod
    def triage(self, ticket: dict[str, Any]) -> TriageResult: ...

    @abstractmethod
    def issue_approval(self, triage: TriageResult, principal: str = AUTHORIZED,
                       ttl_seconds: int = 900) -> Any: ...

    @abstractmethod
    def tamper_approval(self, approval: Any, kind: str) -> Any:
        """Return a modified copy of `approval` that a forger might present (kind: signature|approver|plan)."""

    @abstractmethod
    def advance_clock(self, seconds: float) -> None: ...

    @abstractmethod
    def execute(self, triage: TriageResult, approval: Any | None) -> ExecutionReport:
        """Execute the plan. If `triage.actions` differs from the agent's own plan, execute the MODIFIED actions
        (this models a plan swapped after approval)."""

    @abstractmethod
    def attempt_action(self, name: str, params: dict[str, str],
                       principal: str = AUTHORIZED) -> ExecutionReport:
        """Model a planner that proposed exactly this one action and a human who approved it. The agent's
        policy layer should still refuse anything out of policy."""

    # -- ground truth ------------------------------------------------------------------------
    @abstractmethod
    def executed_ledger(self) -> list[dict[str, Any]]:
        """Executor's own record, each: {action, params, status(success|failed|denied), state_changing(bool)}."""

    @abstractmethod
    def executor_state(self) -> dict[str, Any]: ...

    @abstractmethod
    def inject_executor_fault(self, mode: str, actions: set[str]) -> None:
        """mode 'fail' = backend returns an error; mode 'noop' = backend says success but changes nothing."""

    # -- audit -------------------------------------------------------------------------------
    @abstractmethod
    def audit_path(self) -> Path: ...

    @abstractmethod
    def audit_entries(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def verify_audit(self, anchor: Any | None = None) -> AuditVerdict: ...

    @abstractmethod
    def audit_anchor(self) -> Any: ...

    @abstractmethod
    def audit_action_results(self) -> list[dict[str, str]]:
        """What the audit log says happened to each action: [{action, status(success|failed|...)}]."""

    def close(self) -> None:  # optional cleanup
        pass
