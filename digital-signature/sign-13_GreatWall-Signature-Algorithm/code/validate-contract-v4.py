#!/usr/bin/env python3
"""Replay the contract_diff validation body against the live root graph."""

import json
from pathlib import Path

from mmat.argument import goal_contract
from mmat.graph.store import Store
from mmat.research import contracts, decision_rules, domain_profiles
from mmat.research.provenance import canonical


ROOT = Path("/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01")
GOAL_ID = "997c4414743d45af"
PAYLOAD_PATH = Path(__file__).resolve().parent / "contract-v5-payload.json"
OUTPUT_PATH = Path(__file__).resolve().parent / "contract-v5-diff.json"

payload = json.loads(PAYLOAD_PATH.read_text(encoding="utf-8"))
store = Store(ROOT / "graph.db")
try:
    goal = goal_contract(store, GOAL_ID)
    old = contracts.get(store, GOAL_ID)
    contracts.validate(payload, goal)
    decision_rules.preserve(old["payload"], payload)

    obligations = {item["key"]: item for item in payload["obligations"]}
    for item in old["payload"]["obligations"]:
        if not item["required"]:
            continue
        proposed = obligations.get(item["key"])
        if proposed is None or canonical(
            {key: value for key, value in proposed.items() if key != "execution"}
        ) != canonical(
            {key: value for key, value in item.items() if key != "execution"}
        ):
            raise RuntimeError("required obligation changed: " + item["key"])
        if "execution" in item and canonical(proposed.get("execution")) != canonical(
            item["execution"]
        ):
            raise RuntimeError("execution obligation changed: " + item["key"])

    for name in contracts.GROUPS:
        if old["payload"][name]["status"] == "explicit" and canonical(
            old["payload"][name]
        ) != canonical(payload[name]):
            raise RuntimeError("explicit contract group changed: " + name)

    difference = domain_profiles.difference(old, payload)
finally:
    store.close()

OUTPUT_PATH.write_text(
    json.dumps(difference, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(difference, ensure_ascii=False, sort_keys=True, indent=2))
