import json
from pathlib import Path


SOURCE = Path(
    "/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01/run/slots/"
    "80eb7e8531bb4c98/contract-v2-payload.json"
)
DESTINATION = Path(__file__).resolve().parent / "contract-v5-payload.json"


payload = json.loads(SOURCE.read_text(encoding="utf-8"))

process_key = "research_process_compliance_and_deliverables"
if not any(item["key"] == process_key for item in payload["obligations"]):
    payload["obligations"].append(
        {
            "allowed_evidence": ["measurement", "literature"],
            "key": process_key,
            "required": True,
            "requires_formalization": False,
            "scope": {
                "object": (
                    "The complete investigation, actual resource use, source "
                    "acquisition, graph record and final artifacts"
                ),
                "budget": (
                    "Cumulative limits are 8 hours, 80 metered model launches and "
                    "12 execution jobs, with a 1200-second per-dispatch limit; "
                    "the live ledger and remaining balance remain authoritative."
                ),
                "deliverables": (
                    "Keep research-report.md, results.json, sources.jsonl, "
                    "experimental files and failed attempts in this task workspace; "
                    "report reproduction steps, unresolved issues, contamination "
                    "status and system obstacles."
                ),
                "record": (
                    "Record algorithms, propositions, experiments, evidence and "
                    "relations in the research graph, and never report unexecuted "
                    "work as executed."
                ),
                "source_acquisition": (
                    "When local literature is needed, record the ID or DOI and "
                    "purpose in literature-requests.json and use the planner copy. "
                    "The backup remains subject to every prohibited-source rule. "
                    "Do not bypass Turnstile."
                ),
            },
            "statement": (
                "Obey the exact cumulative 8-hour, 80-metered-launch and "
                "12-execution-job limits, the 1200-second per-dispatch limit, the "
                "live ledger and the user's reserve for write-up; do not expand "
                "budgets, modify Agent source code or read other task directories. "
                "Preserve the required research-report.md, results.json, "
                "sources.jsonl, experimental files and failed attempts in the task "
                "workspace, with actual findings, reproduction steps, unresolved "
                "issues, contamination status and system obstacles. Record "
                "algorithms, propositions, experiments, evidence and relations in "
                "the research graph. When local literature is needed, use "
                "literature-requests.json with the literature ID or DOI and "
                "purpose, keep every prohibited-source restriction applicable to "
                "that backup, and do not bypass Turnstile. Follow the current MMAT "
                "role/provider configuration."
            ),
        }
    )

rule_id = "research_process_and_deliverables_governing_leaves"
if not any(item["id"] == rule_id for item in payload["decision_rules"]["rules"]):
    payload["decision_rules"]["rules"].append(
        {
            "counterexample_obligation_key": None,
            "id": rule_id,
            "obligation_key": process_key,
            "predicate": {"kind": "semantic"},
            "requirement_paths": [
                "/constraints/value/workspace_and_budget_rules",
                "/constraints/value/graph_record",
                "/constraints/value/evidence_honesty",
                "/constraints/value/reproducibility",
                "/constraints/value/contamination_rule",
                "/constraints/value/source_allowance",
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
                "/outputs/value/required_deliverables/0",
                "/outputs/value/required_deliverables/1",
                "/outputs/value/required_deliverables/2",
                "/outputs/value/required_deliverables/3",
                "/outputs/value/required_deliverables/4",
                "/outputs/value/required_deliverables/5",
                "/outputs/value/required_deliverables/6",
                "/outputs/value/required_deliverables/7",
                "/outputs/value/required_deliverables/8",
            ],
        }
    )

payload["decision_rules"]["coverage_note"] = (
    "The catalogue preserves every prior rule and explicit requirement. "
    "The new process rule retains the actual budget, graph-record, deliverables "
    "and source-acquisition route. The existential-supported-impact rule governs "
    "goal success: the search and applicability domain spans every original "
    "parameter variant and implementation profile, while one supported witness "
    "in one original profile suffices. The older broader scope rule remains as "
    "a search-domain and applicability statement, not a requirement to produce "
    "a witness for every profile."
)

# v2 already introduced an existential obligation, but the independent review
# found that the older broad rule could still be read as an all-profile success
# quantifier. Preserve every frozen rule and obligation, and add an exact-leaf
# governing rule that states the existential success reading explicitly.
existential_rule_id = "existential_success_quantifier_exact"
if not any(item["id"] == existential_rule_id for item in payload["decision_rules"]["rules"]):
    payload["decision_rules"]["rules"].append(
        {
            "counterexample_obligation_key": None,
            "id": existential_rule_id,
            "obligation_key": "existential_supported_impact",
            "predicate": {"kind": "semantic"},
            "requirement_paths": [
                "/outputs/value/required_conclusion",
                "/outputs/value/accepted_answer_form",
                "/outputs/value/admissible_impacts/0",
                "/outputs/value/admissible_impacts/1",
                "/outputs/value/admissible_impacts/2",
                "/outputs/value/admissible_impacts/3",
                "/outputs/value/admissible_impacts/4",
                "/outputs/value/result_core/0",
                "/outputs/value/result_core/1",
                "/outputs/value/result_core/2",
                "/outputs/value/result_core/3",
                "/security/value/impact_threshold",
                "/security/value/claimed_security_model",
                "/security/value/conditions/0",
                "/security/value/conditions/1",
                "/security/value/conditions/2",
                "/security/value/conditions/3",
                "/inputs/value/implementation_profiles/0",
                "/inputs/value/implementation_profiles/1",
                "/inputs/value/supported_pylon_parameters/0",
                "/inputs/value/supported_pylon_parameters/1",
                "/inputs/value/supported_pylon_parameters/2",
                "/inputs/value/supported_pylon_parameters/3",
                "/inputs/value/claimed_calling_conditions/0",
                "/inputs/value/claimed_calling_conditions/1",
                "/inputs/value/claimed_calling_conditions/2",
            ],
        }
    )

DESTINATION.write_text(
    json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
print(DESTINATION)
