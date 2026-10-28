import json
from netsentinel import nft
from netsentinel.cli import main
from netsentinel.conflicts import analyze
from netsentinel.models import Rule
from netsentinel.simulator import Flow, impact, verdict
from netsentinel.store import Store

def kinds(rules): return sorted(f.kind for f in analyze(rules))

def test_validation():
    for bad in [dict(action="allow"), dict(proto="tcp", dport="70000"), dict(src="999.1.1.1"), dict(dport="23"), dict(mac="zz")]:
        try: Rule(**bad)
        except ValueError: continue
        raise AssertionError(f"accepted {bad}")

def test_duplicate_and_redundant():
    a = Rule("drop", "tcp", dport="23")
    assert kinds([a, Rule("drop", "tcp", dport="23")]) == ["duplicate"]
    assert kinds([Rule("drop", "tcp"), Rule("drop", "tcp", dport="23")]) == ["redundant"]

def test_shadowed_is_critical():
    f = analyze([Rule("drop", "tcp", src="10.0.0.0/8"), Rule("accept", "tcp", src="10.1.0.0/16", dport="22")])
    assert [x.kind for x in f] == ["shadowed"] and f[0].severity == "critical"

def test_exception_is_not_a_conflict():
    # narrow accept BEFORE broad drop is the normal "exception" pattern
    assert kinds([Rule("accept", "tcp", src="10.0.1.0/24", dport="22"), Rule("drop", "tcp", dport="22")]) == []

def test_contradiction_and_overly_broad():
    assert kinds([Rule("drop", "tcp", src="10.0.0.0/8"), Rule("accept", "tcp", dport="22")]) == ["contradiction"]
    assert kinds([Rule("drop")]) == ["overly_broad"]

def test_impact_simulation():
    flows = [Flow("1.1.1.1", "2.2.2.2", "tcp", 23), Flow("1.1.1.1", "2.2.2.2", "tcp", 22)]
    ch = impact([], Rule("drop", "tcp", dport="23"), flows)
    assert len(ch) == 1 and ch[0].flow.dport == 23 and (ch[0].before, ch[0].after) == ("accept", "drop")
    # a rule already shadowed by an earlier one changes nothing
    assert impact([Rule("drop", "tcp")], Rule("drop", "tcp", dport="23"), flows) == []
    assert verdict([Rule("drop", mac="aa:bb:cc:dd:ee:ff")], Flow("1.1.1.1", "2.2.2.2", src_mac="AA:BB:CC:DD:EE:FF"))[0] == "drop"

def test_nft_render():
    txt = nft.render([Rule("drop", "tcp", src="10.0.0.0/8", dport="23", comment='bad "quote"'),
                      Rule("accept", mac="aa:bb:cc:dd:ee:ff"), Rule("drop", "icmp", enabled=False)])
    assert "ip saddr 10.0.0.0/8 tcp dport 23 counter drop comment \"bad quote\"" in txt
    assert "ether saddr aa:bb:cc:dd:ee:ff counter accept" in txt
    assert "icmp" not in txt                                  # disabled rule skipped
    assert txt.startswith("table inet netsentinel\ndelete table inet netsentinel\n")

def test_store_order_and_snapshot():
    s = Store()
    s.add(Rule("drop", "tcp", dport="1")); s.add(Rule("drop", "tcp", dport="2")); s.add(Rule("drop", "tcp", dport="3"), position=0)
    assert [r.dport for r in s.rules()] == ["3", "1", "2"]
    sid = s.snapshot("t", "txt", s.rules())
    assert [r.dport for r in s.get_snapshot(sid)[1]] == ["3", "1", "2"]

def test_cli_flow(tmp_path, capsys):
    db = str(tmp_path / "t.db"); base = ["--db", db]
    assert main(base + ["add", "--proto", "tcp", "--dport", "23", "--comment", "no telnet"]) == 0
    assert main(base + ["check"]) == 0
    main(base + ["simulate", "--flows", "examples/flows.json", "--proto", "tcp", "--dport", "23"] ) 
    out = capsys.readouterr().out
    assert "0 of 5" in out or "no flow changes" in out         # already blocked by rule #1
    assert main(base + ["apply"]) == 0                          # dry-run
    assert main(base + ["add", "--action", "drop"]) == 0        # drop-everything rule
    assert main(base + ["apply"]) == 2                          # refused: critical finding
