import json
from pathlib import Path


SOURCE = Path(
    "/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01/run/slots/"
    "80eb7e8531bb4c98/contract-v2-payload.json"
)
DESTINATION = Path(
    "/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01/slots/orch-graph/orch/"
    "contract-v3-payload.json"
)


payload = json.loads(SOURCE.read_text(encoding="utf-8"))

constraints = payload["constraints"]["value"]
constraints["literature_copy_route"] = (
    "WSL has no mounted Windows disk. When local literature is needed, record the "
    "literature ID or DOI and intended use in literature-requests.json and let the "
    "planner provide the copy. The backup may contain prohibited work; the same "
    "prohibited-source rules apply, and its current completeness and freshness are "
    "not revalidated by this contract."
)
constraints["turnstile_policy"] = (
    "Do not bypass Turnstile. If a network download fails, request the local copy "
    "through the declared literature-requests.json route."
)

obligations = payload["obligations"]
causal = next(
    obligation
    for obligation in obligations
    if obligation["key"] == "causal_attack_or_defect"
)
causal["scope"]["variants"] = (
    "The search and applicability domain spans all four original parameter variants "
    "and both original S/f profiles without narrowing the object family; goal success "
    "requires one valid witness in at least one original supported parameter variant "
    "and implementation profile, not success in every variant or profile."
)

obligations.append(
    {
        "allowed_evidence": ["measurement", "literature"],
        "key": "research_process_compliance_and_deliverables",
        "required": True,
        "requires_formalization": False,
        "scope": {
            "object": (
                "The complete investigation, its actual resource use, source "
                "acquisition, graph record and final artifacts"
            ),
            "budget": (
                "The user's cumulative limits are 8 hours, 80 metered model launches "
                "and 12 execution jobs, with a 1200-second per-dispatch limit; the "
                "live ledger, runner limit and remaining balance remain authoritative."
            ),
            "deliverables": (
                "Keep research-report.md, results.json, sources.jsonl, experimental "
                "files and failed attempts in this task workspace; report reproduction "
                "steps, unresolved issues, contamination status and system obstacles."
            ),
            "record": (
                "Record algorithms, propositions, experiments, evidence and relations "
                "in the research graph, and do not report unexecuted work as executed."
            ),
            "source_acquisition": (
                "Use the declared local-literature request route when needed and never "
                "bypass Turnstile."
            ),
        },
        "statement": (
            "Obey the exact cumulative 8-hour, 80-metered-launch and 12-execution-job "
            "limits, the 1200-second per-dispatch limit, the live ledger and the user's "
            "reserve for write-up; do not expand budgets, modify Agent source code or "
            "read other task directories. Preserve the required research-report.md, "
            "results.json, sources.jsonl, experimental files and failed attempts in the "
            "task workspace, with actual findings, reproduction steps, unresolved "
            "issues, contamination status and system obstacles. Record algorithms, "
            "propositions, experiments, evidence and relations in the research graph. "
            "When local literature is needed, use literature-requests.json with the "
            "literature ID or DOI and purpose, keep every prohibited-source restriction "
            "applicable to that backup, and do not bypass Turnstile. Follow the current "
            "MMAT role/provider configuration."
        ),
    }
)

decision_rules = payload["decision_rules"]
rules = decision_rules["rules"]
scope_rule = next(
    rule for rule in rules if rule["id"] == "original_scope_and_impact"
)
scope_rule["requirement_paths"] = [
    "/inputs/value/object",
    "/inputs/value/implementation_profiles/0",
    "/inputs/value/implementation_profiles/1",
    "/inputs/value/supported_pylon_parameters/0",
    "/inputs/value/supported_pylon_parameters/1",
    "/inputs/value/supported_pylon_parameters/2",
    "/inputs/value/supported_pylon_parameters/3",
    "/outputs/value/accepted_answer_form",
    "/outputs/value/required_conclusion",
    "/security/value/attacker",
    "/security/value/claimed_security_model",
    "/security/value/conditions/0",
    "/security/value/conditions/1",
    "/security/value/conditions/2",
    "/security/value/conditions/3",
    "/inputs/value/claimed_calling_conditions/0",
    "/inputs/value/claimed_calling_conditions/1",
    "/inputs/value/claimed_calling_conditions/2",
]

source_rule = next(
    rule
    for rule in rules
    if rule["id"] == "source_and_contamination_governing_leaves"
)
source_rule["requirement_paths"].extend(
    [
        "/constraints/value/literature_copy_route",
        "/constraints/value/turnstile_policy",
    ]
)

rules.append(
    {
        "counterexample_obligation_key": None,
        "id": "research_process_and_deliverables_governing_leaves",
        "obligation_key": "research_process_compliance_and_deliverables",
        "predicate": {"kind": "semantic"},
        "requirement_paths": [
            "/constraints/value/workspace_and_budget_rules",
            "/constraints/value/graph_record",
            "/constraints/value/evidence_honesty",
            "/constraints/value/reproducibility",
            "/constraints/value/contamination_rule",
            "/constraints/value/literature_copy_route",
            "/constraints/value/turnstile_policy",
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

decision_rules["coverage_note"] = (
    "These rules encode the user's original existential-impact condition, exact "
    "variants/profiles domain, quantified adversary/evidence requirements, all source "
    "and contamination restrictions, and the budget, graph-record and deliverable "
    "requirements. They do not require every variant to yield a witness."
)

DESTINATION.write_text(
    json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
