"""Rule Impact Simulator: which flows change verdict if a rule is added?"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from .models import Rule


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    proto: str = "tcp"
    dport: int | None = None
    src_mac: str = ""
    name: str = ""

    def label(self) -> str:
        port = f":{self.dport}" if self.dport is not None else ""
        return self.name or f"{self.src_ip} -> {self.dst_ip}{port}/{self.proto}"


@dataclass
class Change:
    flow: Flow
    before: str
    after: str
    by_rule: Rule | None


def matches(rule: Rule, flow: Flow) -> bool:
    if rule.proto != "any" and rule.proto != flow.proto: return False
    s, d = rule.net("src"), rule.net("dst")
    if s is not None and ipaddress.ip_address(flow.src_ip) not in s: return False
    if d is not None and ipaddress.ip_address(flow.dst_ip) not in d: return False
    if rule.dport != "any":
        if flow.dport is None: return False
        lo, hi = rule.ports()
        if not (lo <= flow.dport <= hi): return False
    if rule.mac != "any" and flow.src_mac.lower() != rule.mac: return False
    return True


def verdict(rules: list[Rule], flow: Flow, default: str = "accept"):
    for r in rules:
        if r.enabled and matches(r, flow):
            return r.action, r
    return default, None


def impact(rules: list[Rule], proposed: Rule, flows: list[Flow], position: int | None = None) -> list[Change]:
    new_rules = list(rules)
    new_rules.insert(len(new_rules) if position is None else position, proposed)
    changes = []
    for f in flows:
        before, _ = verdict(rules, f)
        after, by = verdict(new_rules, f)
        if before != after:
            changes.append(Change(f, before, after, by))
    return changes
