import json
from pathlib import Path


SOURCE = Path(__file__).resolve().parent / "contract-v5-payload.json"
DESTINATION = Path(__file__).resolve().parent / "contract-v6-payload.json"


payload = json.loads(SOURCE.read_text(encoding="utf-8"))

# Human authorization 9ae3a8b608774809.
causal = next(
    item for item in payload["obligations"] if item["key"] == "causal_attack_or_defect"
)
causal["scope"]["variants"] = (
    "The search and applicability domain spans all four original parameter "
    "variants and both original S/f profiles without narrowing the object "
    "family. Goal success requires one independently verified valid witness in "
    "at least one original supported parameter variant and implementation "
    "profile; no toy, unsupported, or out-of-declared-invocation profile "
    "qualifies."
)

rules = {item["id"]: item for item in payload["decision_rules"]["rules"]}
rules["original_scope_and_impact"]["requirement_paths"] = [
    "/inputs/value/object",
    "/inputs/value/implementation_profiles/0",
    "/inputs/value/implementation_profiles/1",
    "/inputs/value/supported_pylon_parameters/0",
    "/inputs/value/supported_pylon_parameters/1",
    "/inputs/value/supported_pylon_parameters/2",
    "/inputs/value/supported_pylon_parameters/3",
    "/inputs/value/claimed_calling_conditions/0",
    "/inputs/value/claimed_calling_conditions/1",
    "/inputs/value/claimed_calling_conditions/2",
    "/outputs/value/accepted_answer_form",
    "/outputs/value/required_conclusion",
    "/security/value/attacker",
    "/security/value/claimed_security_model",
    "/security/value/conditions/0",
    "/security/value/conditions/1",
    "/security/value/conditions/2",
    "/security/value/conditions/3",
    "/security/value/impact_threshold",
]
rules["quantified_adversary_and_evidence"]["requirement_paths"] = [
    "/inputs/value/claimed_calling_conditions/0",
    "/inputs/value/claimed_calling_conditions/1",
    "/inputs/value/claimed_calling_conditions/2",
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
]

process = next(
    item
    for item in payload["obligations"]
    if item["key"] == "research_process_compliance_and_deliverables"
)
process["scope"]["route_discipline"] = (
    "First establish the problem contract from the original materials before "
    "choosing a research route. Route changes are permitted. Do not chase only "
    "an easily proved special proposition; report unresolved results honestly "
    "rather than substituting a narrower claim for the original task."
)
process["statement"] += (
    " Before choosing a research route, establish the problem contract from "
    "the original materials. Route changes are permitted, but do not chase only "
    "an easily proved special proposition; if the original question remains "
    "unresolved, report that honestly rather than presenting a narrower or "
    "special-case result as completion."
)

payload["security"]["value"]["primitive_target"] = (
    "Derived research direction, not a mandatory specialization: for the "
    "original (ivowf,ct), one may investigate finding pt' with "
    "Pylon(ivowf,pt')=ct. The original task also admits independently verified "
    "implementation robustness, availability, interoperability, proof-system "
    "integrity, and other security/soundness defects in the original scheme or "
    "an original supported implementation under its declared parameters, "
    "calling conditions, and impact threshold."
)

payload["decision_rules"]["coverage_note"] = (
    "The catalogue preserves the original existential impact condition and all "
    "source, evidence, budget, graph, and deliverable requirements. The search "
    "and applicability domain spans all declared variants and profiles, while "
    "goal success requires one independently verified valid witness in any one "
    "original supported variant/profile. Original-impact and quantified-evidence "
    "rules point to their governing leaves. The Pylon preimage statement is a "
    "derived research direction, not a mandatory specialization that excludes "
    "other expressly admissible defect classes."
)

DESTINATION.write_text(
    json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
print(DESTINATION)
