#!/usr/bin/env python3
"""Run the exact validate+difference body used by research(action=contract_diff)."""

import json
from pathlib import Path

from mmat.argument import goal_contract
from mmat.graph.store import Store
from mmat.research import contracts, domain_profiles


ROOT = Path("/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01")
GOAL_ID = "997c4414743d45af"
PAYLOAD_PATH = Path(__file__).resolve().parent / "contract-v2-payload.json"
OUTPUT_PATH = Path(__file__).resolve().parent / "contract-v2-diff.json"

payload = json.loads(PAYLOAD_PATH.read_text(encoding="utf-8"))
store = Store(ROOT / "graph.db")
try:
    contracts.validate(payload, goal_contract(store, GOAL_ID))
    difference = domain_profiles.difference(contracts.get(store, GOAL_ID), payload)
finally:
    store.close()

OUTPUT_PATH.write_text(
    json.dumps(difference, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(difference, ensure_ascii=False, sort_keys=True, indent=2))
