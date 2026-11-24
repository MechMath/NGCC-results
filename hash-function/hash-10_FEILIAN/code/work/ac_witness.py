#!/usr/bin/env python3
"""Compare normative FEILIAN AC placement with the submitted C/RTL placement."""

from __future__ import annotations

from feilian import compression


def main() -> None:
    h_in = [0x6162630000000000] + [0] * 15
    message = h_in.copy()
    outputs = {}
    for ac_mode in ("normative", "submitted"):
        outputs[ac_mode], _ = compression(
            h_in,
            message,
            0x400,
            True,
            24,
            ac_mode=ac_mode,
        )
        print(
            f"{ac_mode:9s}",
            " ".join(f"{word:016x}" for word in outputs[ac_mode]),
        )
    assert outputs["normative"] != outputs["submitted"]
    assert outputs["normative"][0] == 0xE31966F5B5852992
    assert outputs["submitted"][0] == 0x86D8F83B988CE663


if __name__ == "__main__":
    main()
