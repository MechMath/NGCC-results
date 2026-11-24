#!/usr/bin/env python3
import hashlib
import json

XOF = {1: hashlib.shake_128, 2: hashlib.shake_256, 3: None}
all_results = []

for param in (1, 2, 3):
    with open(f"ordinary_p{param}.json", encoding="utf-8") as f:
        lines = f.readlines()
    records = [json.loads(line) for line in lines if line.startswith('{"case"')]
    artifact = next(
        json.loads(line)["artifact"] for line in lines
        if line.startswith('{"artifact"')
    )

    sk = bytes.fromhex(artifact["sk"])
    base_ct = bytes.fromhex(artifact["valid_ct"])
    valid_ss = bytes.fromhex(artifact["valid_ss"])
    z = sk[-len(valid_ss):]
    mutations = {
        "genuine": base_ct,
        "flip_first_bit": bytes([base_ct[0] ^ 1]) + base_ct[1:],
        "repeat_flip_first_bit_1": bytes([base_ct[0] ^ 1]) + base_ct[1:],
        "repeat_flip_first_bit_2": bytes([base_ct[0] ^ 1]) + base_ct[1:],
        "flip_last_bit": base_ct[:-1] + bytes([base_ct[-1] ^ 1]),
        "all_zero": bytes(len(base_ct)),
        "all_ff": bytes([255]) * len(base_ct),
        "fixed_structural": bytes((i * 29 + 7) & 255 for i in range(len(base_ct))),
    }

    out = []
    for row in records:
        ct = mutations[row["case"]]
        if XOF[param] is None:
            independent = row["expected_H3_s_c"]
            method = "C source shake512; Python hashlib has no SHAKE512"
        else:
            independent = XOF[param](z + ct).digest(len(valid_ss)).hex()
            assert independent == row["expected_H3_s_c"], (param, row["case"])
            method = "independent Python hashlib"
        out.append({
            "case": row["case"],
            "H3_check": method,
            "sha3_H3_match_c_and_python": XOF[param] is not None,
            "decoded_equals_valid": row["decoded_equals_valid"],
            "returned_equals_valid": row["returned_ss"] == valid_ss.hex(),
            "returned_equals_H3": row["returned_ss"] == independent,
            "returned_ss": row["returned_ss"],
            "independent_H3_s_c": independent,
        })

    all_results.append({
        "parameter_set": param,
        "H3": {1: "SHAKE128", 2: "SHAKE256", 3: "SHAKE512"}[param],
        "z": z.hex(),
        "records": out,
    })

print(json.dumps({"parameter_sets": all_results}, indent=2))
