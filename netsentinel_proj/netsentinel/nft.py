"""Render rules to an nftables ruleset and apply it atomically (one `nft -f` transaction)."""
from __future__ import annotations
import shutil
import subprocess
from .models import Rule

TABLE = "netsentinel"


def rule_to_nft(r: Rule) -> str:
    p = []
    if r.mac != "any": p.append(f"ether saddr {r.mac}")
    for key, word in (("src", "saddr"), ("dst", "daddr")):
        net = r.net(key)
        if net is not None:
            p.append(f"{'ip6' if net.version == 6 else 'ip'} {word} {net}")
    if r.proto in ("tcp", "udp"):
        p.append(f"{r.proto} dport {r.dport}" if r.dport != "any" else f"meta l4proto {r.proto}")
    elif r.proto == "icmp":
        p.append("meta l4proto { icmp, ipv6-icmp }")
    p += ["counter", r.action]
    if r.comment:
        p.append('comment "%s"' % r.comment.replace('"', "").replace("\\", "")[:100])
    return " ".join(p)


def render(rules: list[Rule]) -> str:
    body = "\n".join(f"        {rule_to_nft(r)}" for r in rules if r.enabled)
    return (
        f"table inet {TABLE}\n"          # create if missing, so the delete below never fails
        f"delete table inet {TABLE}\n"   # then replace everything in ONE atomic transaction
        f"table inet {TABLE} {{\n"
        f"    chain forward {{\n"
        f"        type filter hook forward priority 0; policy accept;\n"
        f"{body}\n"
        f"    }}\n"
        f"}}\n"
    )


def have_nft() -> bool:
    return shutil.which("nft") is not None


def check(text: str) -> tuple[bool, str]:
    """Syntax-check with `nft -c` (needs nft installed; root may be required)."""
    if not have_nft():
        return True, "nft not installed here; syntax check skipped"
    r = subprocess.run(["nft", "-c", "-f", "-"], input=text, capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def apply(text: str, dry_run: bool = True) -> tuple[bool, str]:
    if dry_run:
        return True, "dry-run: nothing applied"
    if not have_nft():
        return False, "nft not found. Run this on the Linux gateway as root."
    r = subprocess.run(["nft", "-f", "-"], input=text, capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()
