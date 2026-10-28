"""Pytest-based security test kit for human-gated IT automation agents (synthetic data only)."""
from .adapter import (AUTHORIZED, LOW_PRIVILEGE, UNKNOWN, ActionSpec, AgentAdapter, AuditVerdict, ExecutionReport,
                      NotSupported, ReportedAction, TriageResult)

__version__ = "0.1.0"
__all__ = ["AgentAdapter", "TriageResult", "ActionSpec", "ExecutionReport", "ReportedAction", "AuditVerdict",
           "NotSupported", "AUTHORIZED", "LOW_PRIVILEGE", "UNKNOWN"]
