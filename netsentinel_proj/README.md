# NetSentinel TwinGuard

Test every firewall rule in a safe copy of the LAN *before* it reaches the real network.

## Quick start (Python 3.10+, no dependencies)
    python3 -m netsentinel add --action accept --proto tcp --src 10.0.1.0/24 --dport 22
    python3 -m netsentinel add --proto tcp --dport 23 --comment "no telnet"
    python3 -m netsentinel check                                   # conflicts
    python3 -m netsentinel simulate --flows examples/flows.json --mac f4:f2:6d:90:12:ac
    python3 -m netsentinel render                                  # nftables ruleset
    python3 -m netsentinel apply            # dry-run;  add --yes on the Linux gateway (root)
    python3 -m netsentinel rollback --yes   # restore the previous snapshot
Tests: `python3 run_tests.py` (or `pytest -q`).

## Layout
- `models.py`     Rule + validation
- `conflicts.py`  duplicate / redundant / shadowed / contradictory / overly broad
- `simulator.py`  Rule Impact Simulator (first-match, default accept)
- `nft.py`        render + atomic apply (`table / delete table / table {...}` in one `nft -f`)
- `store.py`      SQLite rules + snapshots (rollback)
- `cli.py`        command line

## Roadmap
1. DONE  core rule engine, conflicts, impact simulator, nft render, snapshots, CLI
2. Discovery (Scapy ARP sweep + SYN scan) -> device inventory -> Flow list for the simulator
3. Digital Twin: build a Mininet topology from the inventory, replay attacks before/after a rule
4. Health check after apply + automatic rollback
5. Flask/FastAPI dashboard + live monitoring + anomaly detection
