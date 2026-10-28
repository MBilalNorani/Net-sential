"""Rule Conflict Detector: duplicate, redundant, shadowed, contradictory, overly broad."""
from __future__ import annotations
from dataclasses import dataclass
from .models import Rule


@dataclass
class Finding:
    kind: str       # duplicate | redundant | shadowed | contradiction | overly_broad
    severity: str   # info | warning | critical
    rules: tuple
    message: str


def _net_covers(a, b) -> bool:
    if a is None: return True
    if b is None: return False
    return a.version == b.version and b.subnet_of(a)


def _net_overlaps(a, b) -> bool:
    if a is None or b is None: return True
    return a.version == b.version and a.overlaps(b)


def covers(a: Rule, b: Rule) -> bool:
    """True if every packet matched by b is also matched by a."""
    if a.proto != "any" and a.proto != b.proto: return False
    if not _net_covers(a.net("src"), b.net("src")): return False
    if not _net_covers(a.net("dst"), b.net("dst")): return False
    (alo, ahi), (blo, bhi) = a.ports(), b.ports()
    if not (alo <= blo and bhi <= ahi): return False
    if a.mac != "any" and a.mac != b.mac: return False
    return True


def overlaps(a: Rule, b: Rule) -> bool:
    if a.proto != "any" and b.proto != "any" and a.proto != b.proto: return False
    if not _net_overlaps(a.net("src"), b.net("src")): return False
    if not _net_overlaps(a.net("dst"), b.net("dst")): return False
    (alo, ahi), (blo, bhi) = a.ports(), b.ports()
    if ahi < blo or bhi < alo: return False
    if a.mac != "any" and b.mac != "any" and a.mac != b.mac: return False
    return True


def _label(r: Rule) -> str:
    return f"#{r.id} [{r.describe()}]" if r.id is not None else f"[{r.describe()}]"


def analyze(rules: list[Rule]) -> list[Finding]:
    """Rules are evaluated top to bottom, first match wins."""
    active = [r for r in rules if r.enabled]
    out: list[Finding] = []
    for r in active:
        if r.key() == Rule().key():
            what = "blocks ALL traffic" if r.action == "drop" else "allows ALL traffic"
            out.append(Finding("overly_broad", "critical" if r.action == "drop" else "warning",
                               (r,), f"{_label(r)} {what} (matches everything)"))
    for i, a in enumerate(active):
        for b in active[i + 1:]:
            if a.key() == b.key() and a.action == b.action:
                out.append(Finding("duplicate", "info", (a, b), f"{_label(b)} duplicates {_label(a)}"))
            elif covers(a, b):
                if a.action == b.action:
                    out.append(Finding("redundant", "info", (a, b),
                                       f"{_label(b)} is redundant: {_label(a)} already does the same"))
                else:
                    out.append(Finding("shadowed", "critical", (a, b),
                                       f"{_label(b)} will NEVER take effect: {_label(a)} matches first with the opposite action"))
            elif overlaps(a, b) and a.action != b.action and not covers(b, a):
                out.append(Finding("contradiction", "warning", (a, b),
                                   f"{_label(a)} and {_label(b)} overlap with opposite actions; result depends on order"))
    return out
