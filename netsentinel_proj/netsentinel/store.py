"""SQLite persistence: ordered rules + snapshots (used for rollback)."""
from __future__ import annotations
import json
import sqlite3
import time
from .models import Rule

_FIELDS = ("action", "proto", "src", "dst", "dport", "mac", "comment", "enabled")


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY AUTOINCREMENT, pos INTEGER NOT NULL,
              action TEXT, proto TEXT, src TEXT, dst TEXT, dport TEXT, mac TEXT, comment TEXT, enabled INTEGER);
            CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, label TEXT,
              ruleset TEXT, rules_json TEXT);
        """)

    def rules(self) -> list[Rule]:
        rows = self.db.execute("SELECT * FROM rules ORDER BY pos, id").fetchall()
        return [Rule(**{k: (bool(r[k]) if k == "enabled" else r[k]) for k in _FIELDS}, id=r["id"]) for r in rows]

    def add(self, rule: Rule, position: int | None = None) -> int:
        n = self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        pos = n if position is None else max(0, min(position, n))
        self.db.execute("UPDATE rules SET pos = pos + 1 WHERE pos >= ?", (pos,))
        cur = self.db.execute(
            "INSERT INTO rules(pos,action,proto,src,dst,dport,mac,comment,enabled) VALUES(?,?,?,?,?,?,?,?,?)",
            (pos, rule.action, rule.proto, rule.src, rule.dst, rule.dport, rule.mac, rule.comment, int(rule.enabled)))
        self.db.commit()
        return cur.lastrowid

    def remove(self, rule_id: int) -> bool:
        cur = self.db.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        self.db.commit()
        return cur.rowcount > 0

    def replace_all(self, rules: list[Rule]):
        self.db.execute("DELETE FROM rules")
        for i, r in enumerate(rules):
            self.db.execute(
                "INSERT INTO rules(pos,action,proto,src,dst,dport,mac,comment,enabled) VALUES(?,?,?,?,?,?,?,?,?)",
                (i, r.action, r.proto, r.src, r.dst, r.dport, r.mac, r.comment, int(r.enabled)))
        self.db.commit()

    def snapshot(self, label: str, ruleset: str, rules: list[Rule]) -> int:
        cur = self.db.execute("INSERT INTO snapshots(ts,label,ruleset,rules_json) VALUES(?,?,?,?)",
                              (time.time(), label, ruleset, json.dumps([r.to_dict() for r in rules])))
        self.db.commit()
        return cur.lastrowid

    def snapshots(self):
        return self.db.execute("SELECT id, ts, label FROM snapshots ORDER BY id").fetchall()

    def get_snapshot(self, snap_id: int):
        row = self.db.execute("SELECT * FROM snapshots WHERE id=?", (snap_id,)).fetchone()
        if row is None:
            return None
        rules = [Rule(**{k: d[k] for k in _FIELDS}) for d in json.loads(row["rules_json"])]
        return row["ruleset"], rules
