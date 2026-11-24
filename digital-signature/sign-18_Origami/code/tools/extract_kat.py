#!/usr/bin/env python3
import pathlib
import re

kat = pathlib.Path(
    "source/Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Origami-128.txt"
).read_text()
fields = {}
for line in kat.splitlines():
    if " = " in line:
        key, value = line.split(" = ", 1)
        fields[key] = value.strip()
for key, name in (("PK", "pk.bin"), ("M", "msg.bin"), ("Sn", "sig.bin")):
    pathlib.Path(name).write_bytes(bytes.fromhex(fields[key]))
print({k: len(v) // 2 for k, v in fields.items() if k in ("PK", "SK", "M", "Sn")})
