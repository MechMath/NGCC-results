#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys


def same(a, b):
    return a.read_bytes() == b.read_bytes()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


root = pathlib.Path(sys.argv[1])
scenarios = {}

kg = root / "fork-keygen"
scenarios["fork_keygen"] = {
    "pre_child_state_equal": same(kg / "state.pre", kg / "state.child.before"),
    "pre_parent_state_equal": same(kg / "state.pre", kg / "state.parent.before"),
    "public_keys_equal": same(kg / "parent.keygen.pk", kg / "child.keygen.pk"),
    "secret_keys_equal": same(kg / "parent.keygen.sk", kg / "child.keygen.sk"),
    "parent_pk_sha256": digest(kg / "parent.keygen.pk"),
    "parent_sk_sha256": digest(kg / "parent.keygen.sk"),
}

fs = root / "fork-sign"
scenarios["fork_sign"] = {
    "pre_child_state_equal": same(fs / "state.pre", fs / "state.child.before"),
    "pre_parent_state_equal": same(fs / "state.pre", fs / "state.parent.before"),
    "signatures_equal": same(fs / "parent.sign.signature.bin",
                             fs / "child.sign.signature.bin"),
    "parent_signature_sha256": digest(fs / "parent.sign.signature.bin"),
}

fr = root / "fork-reseed"
scenarios["fork_reseed"] = {
    "reseeded_states_differ": not same(fr / "state.parent.reseed",
                                       fr / "state.child.reseed"),
    "public_keys_differ": not same(fr / "parent.keygen.pk",
                                   fr / "child.keygen.pk"),
    "secret_keys_differ": not same(fr / "parent.keygen.sk",
                                   fr / "child.keygen.sk"),
}

seq = root / "sequential"
scenarios["sequential_same_process"] = {
    "public_keys_differ": not same(seq / "first.keygen.pk",
                                   seq / "second.keygen.pk"),
    "secret_keys_differ": not same(seq / "first.keygen.sk",
                                   seq / "second.keygen.sk"),
}

startup_a = root / "startup-a"
startup_b = root / "startup-b"
scenarios["independent_startups"] = {
    "public_keys_differ": not same(startup_a / "startup.keygen.pk",
                                   startup_b / "startup.keygen.pk"),
    "secret_keys_differ": not same(startup_a / "startup.keygen.sk",
                                   startup_b / "startup.keygen.sk"),
}

(root / "summary.json").write_text(json.dumps(scenarios, indent=2) + "\n")
print(json.dumps(scenarios, indent=2))
