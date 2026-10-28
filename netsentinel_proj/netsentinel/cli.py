from __future__ import annotations
import argparse
import json
import os
import sys
from . import __version__, nft
from .conflicts import analyze
from .models import Rule
from .simulator import Flow, impact
from .store import Store

ICON = {"info": "i", "warning": "!", "critical": "X"}


def _rule_args(p):
    p.add_argument("--action", choices=["accept", "drop"], default="drop")
    p.add_argument("--proto", default="any", help="any|tcp|udp|icmp")
    p.add_argument("--src", default="any")
    p.add_argument("--dst", default="any")
    p.add_argument("--dport", default="any", help="22 or 1000-2000")
    p.add_argument("--mac", default="any")
    p.add_argument("--comment", default="")


def _rule(a) -> Rule:
    return Rule(a.action, a.proto, a.src, a.dst, a.dport, a.mac, a.comment)


def build_parser():
    p = argparse.ArgumentParser(prog="netsentinel", description="NetSentinel TwinGuard CLI")
    p.add_argument("--db", default=os.environ.get("NETSENTINEL_DB", os.path.expanduser("~/.netsentinel.db")))
    p.add_argument("--version", action="version", version=__version__)
    s = p.add_subparsers(dest="cmd", required=True)

    a = s.add_parser("add", help="add a rule"); _rule_args(a); a.add_argument("--pos", type=int)
    s.add_parser("list", help="list rules in evaluation order")
    r = s.add_parser("rm", help="remove a rule"); r.add_argument("id", type=int)
    s.add_parser("check", help="detect conflicting / redundant rules")
    s.add_parser("render", help="print the nftables ruleset")
    m = s.add_parser("simulate", help="show which flows a NEW rule would change (nothing is saved)")
    _rule_args(m); m.add_argument("--flows", required=True, help="JSON file with flows"); m.add_argument("--pos", type=int)
    ap = s.add_parser("apply", help="validate, snapshot and apply the ruleset")
    ap.add_argument("--yes", action="store_true", help="really apply (default is dry-run)")
    ap.add_argument("--force", action="store_true", help="apply even with critical findings")
    rb = s.add_parser("rollback", help="restore the previous snapshot")
    rb.add_argument("--yes", action="store_true")
    s.add_parser("snapshots", help="list snapshots")
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    st = Store(a.db)
    rules = st.rules()

    if a.cmd == "add":
        new = _rule(a)
        rid = st.add(new, a.pos)
        print(f"added rule #{rid}: {new.describe()}")
        findings = analyze(st.rules())
        for f in (x for x in findings if any(r.id == rid for r in x.rules)):
            print(f"  [{ICON[f.severity]}] {f.message}")
    elif a.cmd == "list":
        if not rules: print("no rules")
        for i, r in enumerate(rules, 1):
            print(f"{i:>2}. #{r.id:<3} {'on ' if r.enabled else 'off'} {r.describe()}  {('# ' + r.comment) if r.comment else ''}")
    elif a.cmd == "rm":
        print("removed" if st.remove(a.id) else "no such rule")
    elif a.cmd == "check":
        findings = analyze(rules)
        for f in findings: print(f"[{ICON[f.severity]}] {f.kind}: {f.message}")
        print(f"{len(findings)} finding(s)" if findings else "no conflicts found")
        return 1 if any(f.severity == "critical" for f in findings) else 0
    elif a.cmd == "render":
        print(nft.render(rules), end="")
    elif a.cmd == "simulate":
        flows = [Flow(**d) for d in json.load(open(a.flows))]
        new = _rule(a)
        print(f"proposed: {new.describe()}")
        changes = impact(rules, new, flows, a.pos)
        if not changes: print("no flow changes verdict")
        for c in changes: print(f"  {c.flow.label():<42} {c.before} -> {c.after}")
        print(f"{len(changes)} of {len(flows)} flows affected")
        future = list(rules); future.insert(len(future) if a.pos is None else a.pos, new)
        for f in analyze(future):
            if new in f.rules: print(f"  [{ICON[f.severity]}] {f.message}")
    elif a.cmd == "apply":
        crit = [f for f in analyze(rules) if f.severity == "critical"]
        if crit and not a.force:
            for f in crit: print(f"[X] {f.message}")
            print("refusing to apply (use --force to override)")
            return 2
        text = nft.render(rules)
        ok, msg = nft.check(text)
        if not ok:
            print("nft syntax check failed:\n" + msg); return 2
        ok, msg = nft.apply(text, dry_run=not a.yes)
        print(msg)
        if ok and a.yes:
            print(f"applied; snapshot #{st.snapshot('apply', text, rules)} saved")
        return 0 if ok else 2
    elif a.cmd == "rollback":
        snaps = st.snapshots()
        if len(snaps) < 2:
            print("need at least 2 snapshots to roll back"); return 2
        target = snaps[-2]
        text, old_rules = st.get_snapshot(target["id"])
        ok, msg = nft.apply(text, dry_run=not a.yes)
        print(msg)
        if ok and a.yes:
            st.replace_all(old_rules)
            tid = target["id"]
            print(f"rolled back to snapshot #{tid}; new snapshot #{st.snapshot(f'rollback to #{tid}', text, old_rules)}")
        return 0 if ok else 2
    elif a.cmd == "snapshots":
        for s in st.snapshots(): print(f"#{s['id']}  {s['label']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
