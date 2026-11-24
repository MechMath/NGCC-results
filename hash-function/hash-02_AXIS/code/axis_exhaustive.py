#!/usr/bin/env python3
"""Exhaustive separation check after AXIS-512's message phase.

This checks every message of length at most 12 under the ascending in-place
reading of UpFull.  A collision here would force equal final digests because
the padded lengths and subsequent finalization inputs are then identical.
"""

import axis_semantics as a


def message_state(message: str) -> tuple[int, ...]:
    padded = a.pad(message, len(message))
    state = a.CONSTS[:]
    for i_mu, i_nu in a.message_positions(512, len(padded)):
        state = a.up_full(
            state, padded[i_mu], padded[i_nu], "ascending"
        )
    return tuple(state)


def main() -> None:
    seen = {}
    count = 0
    for length in range(13):
        for value in range(1 << length):
            message = "".join(
                "1" if (value >> (length - 1 - i)) & 1 else "0"
                for i in range(length)
            )
            state = message_state(message)
            if state in seen:
                raise AssertionError((seen[state], (length, message)))
            seen[state] = (length, message)
            count += 1
    print(f"no message-state collision among {count} messages")

    digests = {}
    digest_count = 0
    for length in range(9):
        for value in range(1 << length):
            message = "".join(
                "1" if (value >> (length - 1 - i)) & 1 else "0"
                for i in range(length)
            )
            digest, _, _ = a.axis(message, 512, "ascending", length)
            key = tuple(digest)
            if key in digests:
                raise AssertionError((digests[key], (length, message)))
            digests[key] = (length, message)
            digest_count += 1
    print(f"no digest collision among {digest_count} messages")


if __name__ == "__main__":
    main()
