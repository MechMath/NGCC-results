#!/usr/bin/env python3
"""Audit the 16 GreatWall source copies directly inside the authorized ZIP."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path


ZIP_PATH = Path(
    "/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01/insights/"
    "997c4414743d45af/authors/main-997c4414743d45af/native/original/GreatWall.zip"
)
EXPECTED_ZIP_SHA256 = "814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d"
EXPECTED_API_SHA256 = "1dc6dcf46227d0e6db7a5e5f3f066314ac53c60e373059162f00ce4cbe1c526b"
EXPECTED_SIG_SHA256 = "27129256ac1fe167a682278079ae303737f0a5f5b02d74b09b38f41ea4fb78dd"
FAMILIES = ("Reference_Implementation", "Optimized_Implementation")
PROFILES = (
    "GreatWall128f",
    "GreatWall128s",
    "GreatWall192f",
    "GreatWall192s",
    "GreatWall256f",
    "GreatWall256s",
    "GreatWall512f",
    "GreatWall512s",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compiled_constants(
    archive: zipfile.ZipFile, rel: str, compiler_flags: list[str]
) -> dict[str, int]:
    """Evaluate the two macros with the profile's own headers."""
    source = r'''
#include <stdio.h>
#include "api.h"
#include "faest.h"
int main(void) {
    printf("%llu %d\n",
           (unsigned long long)(FAEST_SIGNATURE_BYTES),
           (int)CRYPTO_BYTES);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="greatwall-constants-") as td:
        root = Path(td)
        for name in archive.namelist():
            if (
                not name.endswith("/")
                and name.startswith(rel + "/")
                and "/" not in name[len(rel) + 1 :]
            ):
                (root / name.rsplit("/", 1)[1]).write_bytes(archive.read(name))
        exe = root / "probe"
        result = subprocess.run(
            ["gcc", "-w", *compiler_flags, f"-I{root}", "-x", "c", "-o", str(exe), "-"],
            input=source.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        assert result.stdout == b""
        value = subprocess.run(
            [str(exe)], check=True, stdout=subprocess.PIPE, text=True
        ).stdout.strip().split()
        return {
            "FAEST_SIGNATURE_BYTES": int(value[0]),
            "CRYPTO_BYTES": int(value[1]),
        }


def main() -> None:
    zip_bytes = ZIP_PATH.read_bytes()
    records = []
    with zipfile.ZipFile(ZIP_PATH) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        for family in FAMILIES:
            flags = (
                ["-O2", "-ffunction-sections", "-fdata-sections",
                 "-Wl,--gc-sections", "-mavx2", "-maes", "-mpclmul"]
                if family == "Optimized_Implementation"
                else []
            )
            for profile in PROFILES:
                rel = f"Implementations/{family}/{profile}"
                target_names = (
                    "api.c",
                    "SIG_AlgorithmInstance.c",
                    "api.h",
                    "config.h",
                    "faest.h",
                )
                files = {name: archive.read(f"{rel}/{name}") for name in target_names}
                assert all(f"{rel}/{name}" in names for name in target_names)
                constants = compiled_constants(archive, rel, flags)
                api_text = files["api.c"].decode("utf-8")
                sig_text = files["SIG_AlgorithmInstance.c"].decode("utf-8")
                config_text = files["config.h"].decode("utf-8")
                api_h_text = files["api.h"].decode("utf-8")
                faest_text = files["faest.h"].decode("utf-8")
                records.append(
                    {
                        "family": family,
                        "profile": profile,
                        "directory": rel,
                        "api.c": {
                            "sha256": sha256(files["api.c"]),
                            "bytes": len(files["api.c"]),
                            "sign_line": api_text.splitlines()[31].strip(),
                            "sign_failure_calls": {
                                "rand_bytes": api_text.splitlines()[35].strip(),
                                "faest_sign": api_text.splitlines()[36].strip(),
                                "return": api_text.splitlines()[37].strip(),
                            },
                            "open_underflow_line": api_text.splitlines()[45].strip(),
                            "open_call_line": api_text.splitlines()[46].strip(),
                            "preprocessor_lines": [
                                f"{i}:{line}"
                                for i, line in enumerate(api_text.splitlines(), 1)
                                if line.lstrip().startswith("#")
                            ],
                        },
                        "SIG_AlgorithmInstance.c": {
                            "sha256": sha256(files["SIG_AlgorithmInstance.c"]),
                            "bytes": len(files["SIG_AlgorithmInstance.c"]),
                            "sign_return_check_lines": sig_text.splitlines()[52:67],
                            "verify_length_rejection_line": sig_text.splitlines()[78].strip(),
                            "verify_total_length_line": sig_text.splitlines()[94].strip(),
                            "preprocessor_line_count": sum(
                                line.lstrip().startswith("#")
                                for line in sig_text.splitlines()
                            ),
                        },
                        "config.h": {
                            "sha256": sha256(files["config.h"]),
                            "SECURITY_PARAM": int(
                                re.search(
                                    r"^#define\s+SECURITY_PARAM\s+(\d+)",
                                    config_text,
                                    re.MULTILINE,
                                ).group(1)
                            ),
                        },
                        "api.h": {
                            "sha256": sha256(files["api.h"]),
                            "CRYPTO_BYTES_definition": re.search(
                                r"^#define\s+CRYPTO_BYTES\s+\d+",
                                api_h_text,
                                re.MULTILINE,
                            ).group(0),
                        },
                        "faest.h": {
                            "sha256": sha256(files["faest.h"]),
                            "FAEST_SIGNATURE_BYTES_definition_lines": "\n".join(
                                faest_text.splitlines()[34:42]
                            ),
                        },
                        "compiled_constants": constants,
                        "lengths_equal": (
                            constants["FAEST_SIGNATURE_BYTES"]
                            == constants["CRYPTO_BYTES"]
                        ),
                    }
                )

    all_api_equal = all(
        row["api.c"]["sha256"] == EXPECTED_API_SHA256 for row in records
    )
    all_sig_equal = all(
        row["SIG_AlgorithmInstance.c"]["sha256"] == EXPECTED_SIG_SHA256
        for row in records
    )
    all_lengths_equal = all(row["lengths_equal"] for row in records)
    output = {
        "schema": "greatwall-source-identity-audit/v1",
        "authorized_zip": str(ZIP_PATH),
        "zip_sha256": sha256(zip_bytes),
        "zip_expected": EXPECTED_ZIP_SHA256,
        "zip_matches": sha256(zip_bytes) == EXPECTED_ZIP_SHA256,
        "zip_members": len(zipfile.ZipFile(ZIP_PATH).namelist()),
        "profile_directory_count": len(records),
        "all_api_c_match": all_api_equal,
        "all_SIG_AlgorithmInstance_c_match": all_sig_equal,
        "all_profile_lengths_equal": all_lengths_equal,
        "api_c_expected_sha256": EXPECTED_API_SHA256,
        "SIG_AlgorithmInstance_c_expected_sha256": EXPECTED_SIG_SHA256,
        "compiler": subprocess.run(
            ["gcc", "--version"], check=True, stdout=subprocess.PIPE, text=True
        ).stdout.splitlines()[0],
        "records": records,
    }
    assert output["zip_matches"]
    assert output["profile_directory_count"] == 16
    assert output["all_api_c_match"]
    assert output["all_SIG_AlgorithmInstance_c_match"]
    assert output["all_profile_lengths_equal"]
    Path("source_identity_audit.json").write_text(
        json.dumps(output, indent=2) + "\n", encoding="utf-8"
    )
    lines = []
    for row in records:
        c = row["compiled_constants"]
        lines.append(
            f"{row['family']}/{row['profile']} "
            f"api={row['api.c']['sha256']} "
            f"sig={row['SIG_AlgorithmInstance.c']['sha256']} "
            f"FAEST={c['FAEST_SIGNATURE_BYTES']} "
            f"CRYPTO={c['CRYPTO_BYTES']} equal={row['lengths_equal']}"
        )
    lines.append(f"ZIP {output['zip_sha256']} members={output['zip_members']}")
    lines.append("all 16 api.c and SIG_AlgorithmInstance.c copies match")
    lines.append("all 16 FAEST_SIGNATURE_BYTES and CRYPTO_BYTES values match")
    stdout = "\n".join(lines) + "\n"
    Path("source_identity_audit.stdout.txt").write_text(stdout, encoding="utf-8")
    Path("source_identity_audit.command.txt").write_text(
        "python3 audit_source_identity.py\n", encoding="utf-8"
    )
    print(stdout, end="")


if __name__ == "__main__":
    main()
