"""
scopeguard.finding
~~~~~~~~~~~~~~~~~~
Finding records produced by the validation engine.
Severity levels mirror the spec exactly:
  BLOCK    — engagement cannot proceed
  CLARIFY  — requires explicit client response in writing
  MISSING  — required field absent
  NOTE     — implicit assumption that should be made explicit
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    BLOCK = "BLOCK"
    CLARIFY = "CLARIFY"
    MISSING = "MISSING"
    NOTE = "NOTE"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.BLOCK, Severity.CLARIFY, Severity.MISSING, Severity.NOTE]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    description: str
    resolution: str
    field_path: Optional[str] = None       # dot-notation path to the offending field
    related_fields: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        loc = f" [{self.field_path}]" if self.field_path else ""
        return f"[{self.severity.value}] {self.rule_id}{loc}: {self.description}"

    def is_blocker(self) -> bool:
        return self.severity == Severity.BLOCK


class FindingList:
    """Accumulates findings and provides summary queries."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def all(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: f.severity)

    def blockers(self) -> list[Finding]:
        return [f for f in self._findings if f.severity == Severity.BLOCK]

    def missing(self) -> list[Finding]:
        return [f for f in self._findings if f.severity == Severity.MISSING]

    def blocks_generation(self) -> bool:
        """Return True when BLOCK or MISSING findings exist.

        MISSING findings mean required data is absent — documents generated
        without that data would be incomplete and must not be issued.
        """
        return any(f.severity in (Severity.BLOCK, Severity.MISSING)
                   for f in self._findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def has_blockers(self) -> bool:
        return any(f.is_blocker() for f in self._findings)

    def count(self) -> dict[str, int]:
        return {s.value: sum(1 for f in self._findings if f.severity == s)
                for s in Severity}

    def __len__(self) -> int:
        return len(self._findings)

    def __iter__(self):
        return iter(self.all())
