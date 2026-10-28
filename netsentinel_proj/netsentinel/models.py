from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, asdict

ACTIONS = ("accept", "drop")
PROTOS = ("any", "tcp", "udp", "icmp")
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass
class Rule:
    action: str = "drop"
    proto: str = "any"
    src: str = "any"      # "any" or CIDR / IP
    dst: str = "any"
    dport: str = "any"    # "any", "23" or "1000-2000"
    mac: str = "any"      # source MAC
    comment: str = ""
    enabled: bool = True
    id: int | None = None

    def __post_init__(self):
        self.action = self.action.lower()
        self.proto = self.proto.lower()
        self.mac = self.mac.lower()
        self.dport = str(self.dport)
        self.validate()

    def validate(self):
        if self.action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        if self.proto not in PROTOS:
            raise ValueError(f"proto must be one of {PROTOS}")
        for v in (self.src, self.dst):
            if v != "any":
                ipaddress.ip_network(v, strict=False)
        if self.mac != "any" and not _MAC.match(self.mac):
            raise ValueError("mac must look like aa:bb:cc:dd:ee:ff")
        if self.dport != "any":
            if self.proto not in ("tcp", "udp"):
                raise ValueError("dport needs proto tcp or udp")
            lo, hi = self.ports()
            if not (0 <= lo <= hi <= 65535):
                raise ValueError("invalid port range")

    def ports(self) -> tuple[int, int]:
        if self.dport == "any":
            return (0, 65535)
        if "-" in self.dport:
            a, b = self.dport.split("-", 1)
            return (int(a), int(b))
        return (int(self.dport), int(self.dport))

    def net(self, which: str):
        v = getattr(self, which)
        return None if v == "any" else ipaddress.ip_network(v, strict=False)

    def key(self) -> tuple:
        return (self.proto, str(self.net("src")), str(self.net("dst")), self.ports(), self.mac)

    def describe(self) -> str:
        parts = [self.action.upper(), self.proto]
        if self.src != "any": parts.append(f"src {self.src}")
        if self.dst != "any": parts.append(f"dst {self.dst}")
        if self.dport != "any": parts.append(f"dport {self.dport}")
        if self.mac != "any": parts.append(f"mac {self.mac}")
        return " ".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)
