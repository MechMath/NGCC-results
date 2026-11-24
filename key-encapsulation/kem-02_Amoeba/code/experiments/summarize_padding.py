#!/usr/bin/env python3
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PROFILES = [
    ("Amoeba-576", 576, 128),
    ("Amoeba-864", 864, 192),
    ("Amoeba-1152", 1152, 256),
    ("Amoeba-1728", 1728, 384),
    ("Amoeba-2304", 2304, 512),
]
IMPLEMENTATIONS = [("reference", "ref"), ("optimized", "opt")]


def parse_output(path):
    values = {}
    for token in path.read_text().split():
        if "=" in token:
            key, value = token.split("=", 1)
            values[key] = int(value)
    return values


result = {
    "schema": "amoeba-padding-comparator-audit/v1",
    "submission_sha256": "719c438a30cccd72c9d83da4b5150fee0c55351f2c13e7a66fd61bf653ca5c24",
    "specification_sha256": "ffca61c5470298f3a173b76a8ead43299a04d990b0bbb913397f910285d4d247",
    "formula": {
        "c1_bytes": "(d1*k*288+7)//8",
        "c2_bytes": "(d2*523+7)//8",
        "ciphertext_bytes": "c1_bytes+c2_bytes",
        "comparator_indices": "i=0,4,...,ciphertext_bytes-1",
        "unused_bits": "8*c2_bytes-d2*523 in the low bits of the final byte",
    },
    "profiles": [],
}

for name, profile, level in PROFILES:
    observations = {}
    for impl, prefix in IMPLEMENTATIONS:
        path = ROOT / f"padding_probe_{prefix}_{profile}.out"
        values = parse_output(path)
        expected_nonzero = (1 << values["c2_unused_low_bits"]) - 1
        assert values["nonzero_padding_variants"] == expected_nonzero + 1
        assert values["accepted_variants"] + values["rejected_variants"] == expected_nonzero
        assert values["canonical_difference_count"] == 1
        assert values["decap_rc"] == 0
        accepts = values["accepted_variants"] > 0
        assert accepts == (values["final_index_mod4"] != 0)
        observations[impl] = values
    assert observations["reference"] == observations["optimized"]
    values = observations["reference"]
    result["profiles"].append(
        {
            "profile": name,
            "security_level": level,
            "d2": values["d2"],
            "ell": values["ell"],
            "c1_bytes": values["c1_bytes"],
            "c2_significant_bits": values["significant_c2_bits"],
            "c2_bytes": values["c2_bytes"],
            "c2_unused_low_padding_bits": values["c2_unused_low_bits"],
            "cca_ciphertext_bytes": values["ct_len"],
            "final_byte_index": values["ct_len"] - 1,
            "final_byte_index_mod4": values["final_index_mod4"],
            "final_byte_checked_by_cmp": values["final_index_mod4"] == 0,
            "nonzero_padding_variants": values["nonzero_padding_variants"] - 1,
            "accepted_padding_variants": values["accepted_variants"],
            "rejected_padding_variants": values["rejected_variants"],
            "reference_and_optimized_equal": True,
        }
    )

print(json.dumps(result, indent=2, sort_keys=True))
