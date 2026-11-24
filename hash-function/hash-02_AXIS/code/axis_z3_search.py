"""Search for an admissible control prefix reaching 0^1536 or 1^1536."""

import argparse
import time

import z3
from axis_model import EXL, INIT_HEX, UPL


def bvbit(x, i):
    return z3.Extract(i, i, x)


def bvxor(xs):
    out = xs[0]
    for x in xs[1:]:
        out = out ^ x
    return out


def bv_extract(x, idx):
    out = bvbit(x, idx[0])
    for i in idx[1:]:
        out = z3.Concat(out, bvbit(x, i))
    return out


def bv_sbox(x):
    x5 = z3.Extract(5, 5, x)
    x4 = z3.Extract(4, 4, x)
    x3 = z3.Extract(3, 3, x)
    x2 = z3.Extract(2, 2, x)
    x1 = z3.Extract(1, 1, x)
    x0 = z3.Extract(0, 0, x)
    return (x5 & x4) ^ (x3 & x2) ^ (x1 & x0)


def bv_up_res(regs, j, m):
    sj = regs[j]
    sm5 = regs[(j + 5) & 7]
    sm3 = regs[(j + 3) & 7]
    sm1 = regs[(j - 1) & 7]
    sp1 = regs[(j + 1) & 7]
    tau = bv_sbox(
        z3.Concat(
            bv_extract(sm5, (EXL[3], EXL[2])),
            bv_extract(sm3, (EXL[5], EXL[1])),
            bv_extract(sp1, (EXL[4], EXL[0])),
        )
    )
    b = (
        m
        ^ bv_sbox(bv_extract(sj, (EXL[5], EXL[2], EXL[4], EXL[1], EXL[3], EXL[0])))
        ^ tau
        ^ bvbit(sm1, EXL[6])
    )
    t0 = bvxor([bvbit(sj, i) for i in EXL[:3]] + [b])
    t1 = bvxor([bvbit(sj, i) for i in EXL[3:6]] + [b])
    rotated = z3.Concat(bvbit(sj, 0), z3.Extract(191, 1, sj))
    out = rotated
    for i in UPL[:3]:
        out = out ^ (z3.ZeroExt(191, t1) << i)
    for i in UPL[3:]:
        out = out ^ (z3.ZeroExt(191, t0) << i)
    regs[j] = out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--beats", type=int, required=True)
    ap.add_argument("--target", choices=("zero", "one"), required=True)
    ap.add_argument("--timeout-ms", type=int, default=120000)
    a = ap.parse_args()

    regs = [z3.BitVecVal(int(x, 16), 192) for x in INIT_HEX]
    controls = []
    for t in range(a.beats):
        mu = z3.BitVec(f"mu_{t}", 1)
        nu = z3.BitVec(f"nu_{t}", 1)
        controls.append((mu, nu))
        for j in range(8):
            bv_up_res(regs, j, mu if j % 2 == 0 else nu)

    want = 0 if a.target == "zero" else (1 << 192) - 1
    solver = z3.Solver()
    solver.set(timeout=a.timeout_ms)
    solver.add(*(r == want for r in regs))
    start = time.monotonic()
    result = solver.check()
    print("result", result, "seconds", time.monotonic() - start)
    if result == z3.sat:
        model = solver.model()
        word = [(model.eval(mu).as_long(), model.eval(nu).as_long()) for mu, nu in controls]
        print("controls", "".join(f"{x}{y}" for x, y in word))
        print("controls_json", word)


if __name__ == "__main__":
    main()
