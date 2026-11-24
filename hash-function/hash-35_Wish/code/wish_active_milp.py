#!/usr/bin/env python3
"""Independent MILP check for Wish byte-activity differential bounds."""

from __future__ import annotations

import argparse
import sys

sys.path.insert(0, "/tmp/wish-highspy")

import highspy
import numpy as np

from wish_structure_check import butterfly


def solve(
    lanes: int,
    rounds: int,
    time_limit: float,
    start_index: int | None,
    skip_mix_at: set[int],
    reverse_shift_rows: bool,
    max_active: int | None,
) -> None:
    n = 16 * lanes
    mix = butterfly(lanes, (1, 2, 8) if lanes == 8 else (1, 2, 4, 8))
    names: list[str] = []
    cost: list[float] = []
    bounds: dict[str, int] = {}

    def add(name: str, obj: int) -> int:
        bounds[name] = len(names)
        names.append(name)
        cost.append(obj)
        return bounds[name]

    for r in range(rounds):
        for i in range(n):
            add(f"x_{r}_{i}", 1)
        for i in range(n):
            add(f"z_{r}_{i}", 0)
        for c in range(4 * lanes):
            add(f"y_{r}_{c}", 0)

    rows: list[list[tuple[int, float]]] = []
    lower: list[float] = []
    upper: list[float] = []

    def row(terms: list[tuple[int, float]], lo: float, hi: float) -> None:
        rows.append(terms)
        lower.append(lo)
        upper.append(hi)

    # At least one active S-box at the initial state.
    if start_index is None:
        row([(bounds[f"x_0_{i}"], 1) for i in range(n)], 1, highspy.kHighsInf)
    else:
        row([(bounds[f"x_0_{start_index}"], 1)], 1, 1)
        row([(bounds[f"x_0_{i}"], 1) for i in range(n) if i != start_index], 0, 0)
    if max_active is not None:
        row(
            [(bounds[f"x_{r}_{i}"], 1) for r in range(rounds) for i in range(n)],
            -highspy.kHighsInf,
            max_active,
        )

    for r in range(rounds):
        def sr_input(i: int) -> int:
            lane, within = divmod(i, 16)
            row_, col = within % 4, within // 4
            shift = col + row_ if reverse_shift_rows else col - row_
            return lane * 16 + row_ + 4 * (shift % 4)

        for c in range(4 * lanes):
            y = bounds[f"y_{r}_{c}"]
            xs = [bounds[f"x_{r}_{sr_input(4 * c + t)}"] for t in range(4)]
            zs = [bounds[f"z_{r}_{4 * c + t}"] for t in range(4)]
            for x in xs:
                row([(x, 1), (y, -1)], -highspy.kHighsInf, 0)
            row([(y, 1)] + [(x, -1) for x in xs], -highspy.kHighsInf, 0)
            row([(y, 1)] + [(z, -1) for z in zs], -highspy.kHighsInf, 0)
            for z in zs:
                row([(z, 1), (y, -1)], -highspy.kHighsInf, 0)
            # AES MixColumns differential branch number five.
            row([(v, 1) for v in xs + zs] + [(y, -5)], 0, highspy.kHighsInf)

        if r + 1 < rounds:
            for i in range(n):
                src = mix[i] if r % 2 == 1 and r not in skip_mix_at else i
                a, b = bounds[f"x_{r + 1}_{i}"], bounds[f"z_{r}_{src}"]
                row([(a, 1), (b, -1)], 0, 0)

    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("time_limit", time_limit)
    h.addVars(
        len(names),
        np.zeros(len(names), dtype=np.float64),
        np.ones(len(names), dtype=np.float64),
    )
    starts = np.zeros(len(rows) + 1, dtype=np.int32)
    indices: list[int] = []
    values: list[float] = []
    for r, terms in enumerate(rows):
        for i, v in terms:
            indices.append(i)
            values.append(v)
        starts[r + 1] = len(indices)
    h.addRows(
        len(rows),
        np.asarray(lower, dtype=np.float64),
        np.asarray(upper, dtype=np.float64),
        len(indices),
        starts,
        np.asarray(indices, dtype=np.int32),
        np.asarray(values, dtype=np.float64),
    )
    h.changeColsCost(len(names), np.arange(len(names), dtype=np.int32), np.asarray(cost))
    h.changeObjectiveSense(highspy.ObjSense.kMinimize)
    h.changeColsIntegrality(
        len(names),
        np.arange(len(names), dtype=np.int32),
        np.full(len(names), highspy.HighsVarType.kInteger),
    )
    h.writeModel("/tmp/wish-activity.lp")
    h.run()
    status = h.getModelStatus()
    print("status", h.modelStatusToString(status))
    print("objective", h.getObjectiveValue())
    if status == highspy.HighsModelStatus.kInfeasible:
        iis = h.getIis()
        print("iis rows", getattr(iis[1], "row_index_", None))
        print("iis cols", getattr(iis[1], "col_index_", None))
    if status not in (
        highspy.HighsModelStatus.kOptimal,
        highspy.HighsModelStatus.kTimeLimit,
    ):
        return
    sol = h.getSolution().col_value
    trail = [
        [i for i in range(n) if sol[bounds[f"x_{r}_{i}"]] > 0.5]
        for r in range(rounds)
    ]
    print("active_total", sum(map(len, trail)))
    print(
        "active_postmix_by_round",
        [
            [i for i in range(n) if sol[bounds[f"z_{r}_{i}"]] > 0.5]
            for r in range(rounds)
        ],
    )
    print("active_sbox_inputs_by_round", trail)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("lanes", type=int, choices=(8, 16))
    ap.add_argument("rounds", type=int)
    ap.add_argument("--time", type=float, default=60.0)
    ap.add_argument("--start-index", type=int)
    ap.add_argument("--skip-mix-at", type=int, action="append", default=[])
    ap.add_argument("--reverse-shift-rows", action="store_true")
    ap.add_argument("--max-active", type=int)
    args = ap.parse_args()
    solve(
        args.lanes,
        args.rounds,
        args.time,
        args.start_index,
        set(args.skip_mix_at),
        args.reverse_shift_rows,
        args.max_active,
    )


if __name__ == "__main__":
    main()
