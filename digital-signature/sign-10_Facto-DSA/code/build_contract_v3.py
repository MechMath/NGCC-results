import copy
import json
from pathlib import Path


RUN = Path("/home/mmat/mmat-preview/runs/ngcc-sign-10-ds01")
CONTRACT_V2 = RUN / "blobs/a57ba3554b2b2cb094ab15bfd614705367929ccbf3e32e9ae32eb955184080a5"
ORIGINAL_REQUEST = RUN / "blobs/5405e58a5384e93655d20a5ca18857a7bd785d8d6bf1c5e3234483c828b6afce"
OUTPUT = Path(__file__).with_name("contract_v3.json")


payload = json.loads(CONTRACT_V2.read_text())
original = json.loads(ORIGINAL_REQUEST.read_text())
payload = copy.deepcopy(payload)

payload["scope"] = original["statement"]

constraints = payload["constraints"]["value"]
constraints["allowed_access"] = (
    "Only the public submitted ZIP, the one fixed harness PDF URL named in the original request, "
    "the submitted implementation, generic foundational literature subject to the stated exclusions, "
    "and local execution are allowed. Do not browse the rest of ngcc-dev/ngcc-harness."
)
constraints["original_request_verbatim"] = original["statement"]
constraints["task_modes"] = ["attack", "prove", "implement", "estimate"]
constraints["research_deliverables"] = {
    "required_files": [
        "research-report.md",
        "results.json",
        "sources.jsonl",
        "contamination.json",
    ],
    "required_workspace_artifacts": [
        "experiment files",
        "failed attempts",
        "reproduction steps",
        "system obstacles",
        "contamination status",
    ],
    "task_workspace": "current task workspace only",
    "honest_unresolved_report": (
        "When no supported result is obtained, report the research honestly and label unresolved "
        "or failed work; this is not counted as a successful attack result."
    ),
}
constraints["research_graph_requirement"] = (
    "Record algorithms, propositions, experiments, evidence, and their relations in the MMAT "
    "research graph as required by the original request: "
    "使用研究图记录算法、命题、实验、证据及关系。"
)
constraints["execution_evidence_controls"] = {
    "artifact_sha256": "b3de38fcc2d92ce83290d17cb250dde61f95d3326a49ada36fad3c578f2fc509",
    "implementation_controls": [
        "exact source file and function",
        "exact submitted implementation version",
        "exact supported parameters",
        "build and environment",
        "execution trace and full actual output",
        "positive and negative controls",
        "no harness substitution or toy-only parameter substitution",
    ],
    "theory_only_result": (
        "A theorem-only result must explicitly state that it makes no implementation claim."
    ),
}
constraints["ngcc_low_classification"] = {
    "authoritative_source": "the original call's classification protocol",
    "numeric_threshold": None,
    "rule": (
        "Do not invent a numerical NGCC Low threshold. For an impact near the boundary, "
        "use the original call's classification protocol."
    ),
    "near_boundary_protocol": (
        "Report the evidence needed for the original call to classify the impact and do not "
        "upgrade a near-boundary or unclassified result to an accepted attack."
    ),
}
constraints["specification_access"] = {
    "allowed_pdf_url": (
        "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/"
        "sign-10/sign-10-spec.pdf"
    ),
    "repository_boundary": (
        "Read only this fixed harness PDF URL. Do not browse the rest of the ngcc-dev/ngcc-harness "
        "repository, its reports, reproduction tools, issues, pull requests, or history."
    ),
}
constraints["literature_backup_policy"] = {
    "local_source": "G:\\存档\\Data\\文章\\ePrint",
    "contents": (
        "ePrint and partial top-conference/top-journal backups; prohibited works in the backup "
        "remain prohibited."
    ),
    "request_protocol": (
        "Because the Windows disk is not mounted in WSL, request a needed paper by literature ID/DOI "
        "and stated purpose through literature-requests.json for the planner to provide a copy."
    ),
    "network_and_turnstile": (
        "Do not bypass Turnstile. If a network download fails, use the local-copy request route."
    ),
    "integrity_status": (
        "The backup's current completeness and freshness were not revalidated in this run."
    ),
}

outputs = payload["outputs"]["value"]
outputs["accepted_result_forms"] = [
    "complete independently reviewed theoretical evidence for a causally supported attack or security defect",
    "complete independently reviewed implementation evidence for a causally supported attack or security defect using the exact original artifact and supported parameters",
    "an honest unresolved or failed research report that makes no successful-attack claim",
]
outputs["unresolved_report_status"] = (
    "An honest unresolved or failed report fulfills truthful delivery but is not a successful research result."
)
outputs["required_impact"] = (
    "At least the impact expected by the original NGCC Low threshold; a stronger result is accepted. "
    "No numerical threshold is invented; for a near-boundary result, use the original call's "
    "authoritative classification protocol."
)

for obligation in payload["obligations"]:
    if obligation["key"] == "required_artifacts":
        obligation["scope"] = {
            "required_files": [
                "research-report.md",
                "results.json",
                "sources.jsonl",
                "contamination.json",
            ],
            "task_workspace": "current task workspace only",
            "required_research_graph": True,
            "required_workspace_artifacts": [
                "experiment files",
                "failed attempts",
                "reproduction steps",
                "contamination status",
                "system obstacles",
            ],
        }
        obligation["statement"] = (
            "Deliver research-report.md, results.json, sources.jsonl, contamination.json, "
            "experiment files, failed attempts, reproduction steps, contamination status, and "
            "system obstacles in the current task workspace; record algorithms, propositions, "
            "experiments, evidence, and their relations in the MMAT research graph. Preserve "
            "truthful labels for unresolved or failed work."
        )

payload["obligations"].append({
    "key": "supported_attack_or_defect_at_least_ngcc_low",
    "statement": (
        "Prove or experimentally demonstrate at least one causally evidenced attack, security "
        "compromise, or bounded degradation of a declared security property in one exact supported "
        "Facto-DSA instance or its original submitted implementation, with impact at least "
        "equivalent to NGCC Low under the original call's classification protocol. The result must "
        "retain the declared verification relation and security model, supported parameters and "
        "calling conditions, adversary powers, data/oracle queries, time/memory resources, success "
        "probability or advantage, and all failed or contrary controls. A near-boundary or "
        "unclassified result must not be accepted as satisfying this obligation."
    ),
    "scope": {
        "instances": ["Facto-DSA-128", "Facto-DSA-256", "Facto-DSA-512"],
        "implementation_families": ["Reference", "Optimized", "Resource"],
        "accepted_evidence": [
            "reviewed mathematical proof",
            "exact computation",
            "repeatable local measurement",
        ],
        "impact_floor": "at least equivalent to NGCC Low under the original classification protocol",
        "near_boundary_rule": "near-boundary or unclassified results are not accepted",
    },
    "allowed_evidence": ["reviewed_proof", "exact_computation", "measurement"],
    "requires_formalization": False,
    "required": True,
})

payload["decision_rules"] = {
    "schema": "mmat.decision-rules/v1",
    "coverage_note": (
        "The required conclusion is existential over the exact supported instances and submitted "
        "implementation families under the full authorized scope. The enumerated attack forms are "
        "illustrative, not exhaustive: any causally evidenced attack, compromise, or bounded "
        "degradation of a declared security property at the exact declared model and supported "
        "scope is eligible only when its impact is at least equivalent to NGCC Low under the "
        "original call's classification protocol, including a non-forging cryptanalytic advantage "
        "or bounded secret-information/security-level loss when its adversary, data/queries, "
        "resources, success probability or advantage, and supported parameters are quantified. "
        "A near-boundary or unclassified result is not accepted. A complete independently reviewed "
        "theoretical or implementation evidence package can establish the result; an honest "
        "unresolved or failed report is retained but does not establish it. The numerical NGCC Low "
        "threshold is not invented."
    ),
    "rules": [
        {
            "id": "supported_attack_scope",
            "requirement_paths": [
                "/outputs/value/accepted_attack_forms",
                "/outputs/value/required_impact",
                "/security/value/target_definition",
                "/constraints/value/instances",
            ],
            "obligation_key": "supported_attack_or_defect",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "successful_result_form_scope",
            "requirement_paths": [
                "/outputs/value/accepted_result_forms/0",
                "/outputs/value/accepted_result_forms/1",
                "/constraints/value/task_modes",
            ],
            "obligation_key": "supported_attack_or_defect",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "generic_declared_security_defect_scope",
            "requirement_paths": [
                "/scope",
                "/security/value/target_definition",
                "/security/value/claimed_instances",
                "/outputs/value/required_impact",
                "/constraints/value/ngcc_low_classification",
            ],
            "obligation_key": "supported_attack_or_defect",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "ngcc_low_impact_floor_scope",
            "requirement_paths": [
                "/scope",
                "/security/value/target_definition",
                "/security/value/claimed_instances",
                "/outputs/value/required_impact",
                "/constraints/value/ngcc_low_classification",
                "/constraints/value/instances",
            ],
            "obligation_key": "supported_attack_or_defect_at_least_ngcc_low",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "unresolved_report_scope",
            "requirement_paths": [
                "/outputs/value/accepted_result_forms/2",
                "/outputs/value/unresolved_report_status",
            ],
            "obligation_key": "required_artifacts",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "required_quantification_scope",
            "requirement_paths": [
                "/outputs/value/required_quantification",
                "/security/value/target_definition",
                "/constraints/value/instances",
                "/constraints/value/ngcc_low_classification",
            ],
            "obligation_key": "required_quantification",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "original_artifact_scope",
            "requirement_paths": [
                "/inputs/value/official_zip_sha256",
                "/inputs/value/submitted_implementation_families",
                "/constraints/value/execution_evidence_controls",
                "/constraints/value/allowed_access",
                "/constraints/value/specification_access",
            ],
            "obligation_key": "original_artifact_and_controls_required",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "contamination_scope",
            "requirement_paths": [
                "/constraints/value/prohibited_access",
                "/constraints/value/contamination",
                "/constraints/value/research_deliverables",
                "/constraints/value/literature_backup_policy",
            ],
            "obligation_key": "contamination_disclosure_required",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
        {
            "id": "deliverable_scope",
            "requirement_paths": [
                "/constraints/value/research_deliverables",
                "/constraints/value/research_graph_requirement",
            ],
            "obligation_key": "required_artifacts",
            "counterexample_obligation_key": None,
            "predicate": {"kind": "semantic"},
        },
    ],
}

OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
print(OUTPUT)
print(len(OUTPUT.read_bytes()))
