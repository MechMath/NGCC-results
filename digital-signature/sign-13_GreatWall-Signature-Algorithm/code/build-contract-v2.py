#!/usr/bin/env python3
"""Build the contract v2 candidate from the stored v1 payload without mutating it."""

import copy
import json
import sqlite3
from pathlib import Path


ROOT = Path("/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01")
DB_PATH = ROOT / "graph.db"
OUT_PATH = Path(__file__).resolve().parent / "contract-v2-payload.json"
GOAL_ID = "997c4414743d45af"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as db:
    row = db.execute(
        "SELECT payload_blob FROM research_contracts "
        "WHERE goal_id=? ORDER BY version DESC LIMIT 1",
        (GOAL_ID,),
    ).fetchone()
    if row is None:
        raise SystemExit("active research contract not found")
    blob_path = ROOT / "blobs" / row[0]
    if not blob_path.is_file():
        raise SystemExit(f"blob payload not found: {blob_path}")
    payload = json.loads(blob_path.read_text(encoding="utf-8"))

original_required = {
    item["key"]: copy.deepcopy(item)
    for item in payload["obligations"]
    if item["required"]
}

impact_evidence = [
    "reviewed_proof",
    "exact_computation",
    "certified_numerics",
    "measurement",
]

payload["obligations"].extend(
    [
        {
            "key": "existential_supported_impact",
            "required": True,
            "requires_formalization": False,
            "allowed_evidence": impact_evidence,
            "scope": {
                "object": "Original GreatWall scheme or an original supported implementation",
                "model": (
                    "The proposal-declared security model, supported parameters and "
                    "declared invocation conditions"
                ),
                "variants": (
                    "At least one original supported parameter variant/profile; every "
                    "original parameter set or both implementation profiles is not required"
                ),
                "impact": (
                    "Security/unforgeability, soundness/proof-system integrity, "
                    "robustness, availability or interoperability"
                ),
                "success": (
                    "One supported witness with a causal finite impact at least "
                    "NGCC Low-equivalent"
                ),
            },
            "statement": (
                "For governing goal completion, read the user's acceptance clause and "
                "the retained v1 required_conclusion together without dropping the "
                "term 'attack or security defect': there must exist at least one "
                "evidence-supported causal finite impact of at least NGCC Low on the "
                "original submission or an original supported implementation. The "
                "qualifying impact may be a security/unforgeability impact; a "
                "soundness/proof-system-integrity defect; a robustness defect; an "
                "availability defect; or an interoperability defect. One supported "
                "witness in at least one original supported parameter variant/profile "
                "suffices, but it must respect the original scheme's declared security "
                "model, supported parameters, invocation conditions and the prohibition "
                "on attacking any online system. The retained v1 wording "
                "'attack or security/soundness defect' is preserved verbatim and is not "
                "replaced; it is a required family of qualifying examples and is not an "
                "exhaustive restriction that excludes the other expressly admissible "
                "impacts. A bare proof gap, compilation failure, timeout, toy-only "
                "parameter or unspecified adversary guess is insufficient."
            ),
        },
        {
            "key": "source_compliance_and_contamination",
            "required": True,
            "requires_formalization": False,
            "allowed_evidence": [
                "literature",
                "exact_computation",
                "certified_numerics",
                "measurement",
            ],
            "scope": {
                "object": "All source acquisition and evidence used by the investigation",
                "sources": (
                    "The exact authorized goal sources, the original ZIP and pinned PDF, "
                    "original implementations/test vectors inside the ZIP, and general "
                    "foundational literature only"
                ),
                "prohibitions": (
                    "All constraints/value forbidden_sources entries; no attack or "
                    "security evaluation of this scheme, prohibited harness/ngcc.dev "
                    "material, listed papers/messages, mirrors, reports, fixes, PRs, "
                    "issues, commits or online-system attack"
                ),
            },
            "statement": (
                "Use only the source exceptions, original objects and general "
                "foundational literature expressly authorized by the immutable user "
                "request; obey every constraints/value forbidden_sources restriction "
                "and its online_attack_prohibition. If a prohibited source is "
                "encountered accidentally, stop the affected read, record its source, "
                "exact observed-content range and time in contamination.json, disclose "
                "it in the final report, and never use the contaminated material as "
                "independent evidence. Do not search for the prohibited attack or "
                "security-evaluation material and do not conceal any accidental "
                "exposure. The final deliverable must report contamination status and "
                "system obstacles accurately."
            ),
        },
        {
            "key": "evidence_honesty_and_reproducibility",
            "required": True,
            "requires_formalization": False,
            "allowed_evidence": [
                "reviewed_proof",
                "exact_computation",
                "certified_numerics",
                "measurement",
                "literature",
            ],
            "scope": {
                "object": "Every reported finding, proof, computation and experiment",
                "quantified_result": (
                    "Theory must state time, memory, query access and applicable "
                    "parameters; experiments retain exact code, commands, actual output, "
                    "environment and positive and negative controls"
                ),
                "evidence_boundary": (
                    "Source verification, mathematical applicability and demonstrated "
                    "impact are distinct claims"
                ),
            },
            "statement": (
                "For every reported result, use outputs/value/result_core and retain "
                "its exact evidence status and unresolved scope. Never report unexecuted "
                "work as executed or an unproved claim as proved. A theoretical result "
                "must quantify time, memory, query access and applicable parameters; a "
                "local experiment must preserve code, exact commands, actual output, "
                "environment, and positive and negative controls. Distinguish source "
                "verification from mathematical applicability and from the demonstrated "
                "causal impact. A missing proof, failed search, compilation failure, "
                "timeout or failed stronger sufficient bound refutes nothing."
            ),
        },
    ]
)

if payload["obligations"][: len(original_required)] and any(
    payload["obligations"][index] != original_required[item["key"]]
    for index, item in enumerate(
        [item for item in payload["obligations"] if item["required"]][
            : len(original_required)
        ]
    )
):
    raise SystemExit("internal error: original required obligation changed")

payload["decision_rules"]["rules"].extend(
    [
        {
            "id": "existential_supported_impact_governing_leaves",
            "obligation_key": "existential_supported_impact",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
            "requirement_paths": [
                "/inputs/value/object",
                "/inputs/value/implementation_profiles/0",
                "/inputs/value/implementation_profiles/1",
                "/inputs/value/supported_pylon_parameters/0",
                "/inputs/value/supported_pylon_parameters/1",
                "/inputs/value/supported_pylon_parameters/2",
                "/inputs/value/supported_pylon_parameters/3",
                "/outputs/value/accepted_answer_form",
                "/outputs/value/admissible_impacts/0",
                "/outputs/value/admissible_impacts/1",
                "/outputs/value/admissible_impacts/2",
                "/outputs/value/admissible_impacts/3",
                "/outputs/value/admissible_impacts/4",
                "/outputs/value/required_conclusion",
                "/outputs/value/result_core/0",
                "/outputs/value/result_core/1",
                "/outputs/value/result_core/2",
                "/outputs/value/result_core/3",
                "/security/value/attacker",
                "/security/value/claimed_security_model",
                "/security/value/conditions/0",
                "/security/value/conditions/1",
                "/security/value/conditions/2",
                "/security/value/conditions/3",
                "/security/value/impact_threshold",
                "/inputs/value/claimed_calling_conditions/0",
                "/inputs/value/claimed_calling_conditions/1",
                "/inputs/value/claimed_calling_conditions/2",
            ],
        },
        {
            "id": "quantified_adversary_and_evidence_governing_leaves",
            "obligation_key": "evidence_honesty_and_reproducibility",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
            "requirement_paths": [
                "/outputs/value/accepted_answer_form",
                "/outputs/value/result_core/0",
                "/outputs/value/result_core/1",
                "/outputs/value/result_core/2",
                "/outputs/value/result_core/3",
                "/security/value/attacker",
                "/security/value/claimed_security_model",
                "/security/value/conditions/0",
                "/security/value/conditions/3",
                "/security/value/impact_threshold",
                "/constraints/value/evidence_honesty",
                "/constraints/value/reproducibility",
                "/inputs/value/claimed_calling_conditions/0",
                "/inputs/value/claimed_calling_conditions/1",
                "/inputs/value/claimed_calling_conditions/2",
            ],
        },
        {
            "id": "source_and_contamination_governing_leaves",
            "obligation_key": "source_compliance_and_contamination",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
            "requirement_paths": [
                "/constraints/value/contamination_rule",
                "/constraints/value/forbidden_sources/0",
                "/constraints/value/forbidden_sources/1",
                "/constraints/value/forbidden_sources/2",
                "/constraints/value/forbidden_sources/3",
                "/constraints/value/forbidden_sources/4",
                "/constraints/value/forbidden_sources/5",
                "/constraints/value/forbidden_sources/6",
                "/constraints/value/forbidden_sources/7",
                "/constraints/value/forbidden_sources/8",
                "/constraints/value/online_attack_prohibition",
                "/constraints/value/source_allowance",
                "/security/value/attacker",
            ],
        },
    ]
)

OUT_PATH.write_text(
    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
print(f"wrote {OUT_PATH}")
print(f"scope_chars={len(payload['scope'])}")
print(f"required_obligations={[item['key'] for item in payload['obligations'] if item['required']]}")
print(f"decision_rule_count={len(payload['decision_rules']['rules'])}")
