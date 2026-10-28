import pytest


def kit(id: str, title: str, category: str, severity: str, owasp: str = ""):
    """Attach report metadata. severity: Critical | High | Medium | Low | Control."""
    return pytest.mark.kit(id=id, title=title, category=category, severity=severity, owasp=owasp)
