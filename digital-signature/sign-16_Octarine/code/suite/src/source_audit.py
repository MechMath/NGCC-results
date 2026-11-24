#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re

root = pathlib.Path(__file__).resolve().parent.parent
impl = root / "src" / "original" / "Implementations"
profiles = (128, 256, 512)
families = ("Reference", "Optimized", "Additional")
tau_by_profile = {128: 16, 256: 36, 512: 87}
rows = []

for family in families:
    for profile in profiles:
        directory = impl / f"{family}_Implementation" / f"Octarine-{profile}"
        ring = (directory / "sign_ring.c").read_text()
        params = (directory / "parameters.h").read_text()
        domain = (directory / "hash_domain.h").read_text()
        call = re.search(
            r"RRLWR_SIGN_HASH_SAMPLE_C_DOMAIN\(signs_buffer,\s*([^,]+),",
            ring,
        )
        max_bytes = re.search(
            r"#define RRLWR_SIGN_MAX_TAU_BYTES\s+\((\d+)\)", params
        )
        domain_length = (
            "rrlwr_store32_le(buf + pos, (uint32_t)outlen);" in domain
        )
        tree_hash = hashlib.sha256()
        for path in sorted(
            p for p in directory.rglob("*") if p.is_file() and p.name != ".DS_Store"
        ):
            rel = path.relative_to(directory).as_posix().encode()
            tree_hash.update(rel + b"\0")
            tree_hash.update(hashlib.sha256(path.read_bytes()).digest())
        row = {
            "family": family,
            "profile": profile,
            "tau": tau_by_profile[profile],
            "ceil_tau_bytes": (tau_by_profile[profile] + 7) // 8,
            "max_tau_bytes": int(max_bytes.group(1)),
            "original_call_argument": call.group(1).strip(),
            "domain_encodes_outlen": domain_length,
            "sign_ring_sha256": hashlib.sha256(
                (directory / "sign_ring.c").read_bytes()
            ).hexdigest(),
            "tree_sha256_with_relative_names": tree_hash.hexdigest(),
        }
        rows.append(row)

print(json.dumps(rows, indent=2))
