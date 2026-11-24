#!/usr/bin/env python3
import hashlib
import json

with open("ordinary_p1.json", "r", encoding="utf-8") as f:
    records = [json.loads(line) for line in f if line.startswith('{"case"')]
with open("ordinary_p1.json", encoding="utf-8") as f:
    artifact = next(json.loads(line) for line in f if line.startswith('{"artifact"'))["artifact"]

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
    independent = hashlib.shake_128(z + ct).digest(len(valid_ss)).hex()
    assert independent == row["expected_H3_s_c"], row["case"]
    assert bytes.fromhex(row["returned_ss"]).hex() == row["returned_ss"]
    out.append({
        "case": row["case"],
        "sha3_H3_match_c_and_python": True,
        "decoded_equals_valid": row["decoded_equals_valid"],
        "returned_equals_valid": row["returned_ss"] == valid_ss.hex(),
        "returned_equals_H3": row["returned_ss"] == independent,
        "returned_ss": row["returned_ss"],
        "independent_H3_s_c": independent,
    })

print(json.dumps({"z": z.hex(), "records": out}, indent=2))
