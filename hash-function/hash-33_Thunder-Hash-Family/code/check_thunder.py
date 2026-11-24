def ix(x, y, z):
    return 64 * (5 * y + x) + z


TAU = [
    (45, 33, 13, 1, 27),
    (40, 52, 19, 47, 9),
    (34, 5, 0, 2, 37),
    (48, 30, 61, 8, 38),
    (6, 18, 49, 17, 43),
]
TY = [41, 50, 6, 10, 27]


def dependencies(j, i):
    changed = False
    for assignment in range(16):
        values = []
        for xi in (0, 1):
            bits = []
            cursor = 0
            for h in range(5):
                if h == i:
                    bits.append(xi)
                else:
                    bits.append((assignment >> cursor) & 1)
                    cursor += 1
            out = bits[(j + 3) % 5] ^ (
                (1 ^ bits[(j + 1) % 5])
                & bits[(j + 2) % 5]
                & bits[(j + 4) % 5]
            )
            values.append(out)
        if values[0] != values[1]:
            changed = True
            break
    return changed


DEPS = [[dependencies(j, i) for i in range(5)] for j in range(5)]


def rho(deps):
    out = set()
    for q in deps:
        z = q % 64
        xy = q // 64
        x, y = xy % 5, xy // 5
        out.add(ix(x, y, (z - TAU[y][x]) % 64))
    return out


def theta(deps):
    out = set()
    for x in range(5):
        for y in range(5):
            for z in range(64):
                inputs = [ix(x, y, z)]

                z_e = (z + 26) % 64
                inputs += [ix(x, yy, z_e) for yy in range(5)]
                inputs += [ix((x - 1) % 5, yy, (z_e + 1) % 64) for yy in range(5)]

                z_f = (z + 26 + TY[y]) % 64
                inputs += [
                    ix((x + 1) % 5, yy, (z_f + TY[yy]) % 64)
                    for yy in range(5)
                ]
                inputs += [
                    ix((x - 2) % 5, yy, (z_f + 36 + TY[yy]) % 64)
                    for yy in range(5)
                ]
                if any(q in deps for q in inputs):
                    out.add(ix(x, y, z))
    return out


def pi(deps):
    out = set()
    for q in deps:
        z = q % 64
        xy = q // 64
        x, y = xy % 5, xy // 5
        out.add(ix(y, (2 * x + 3 * y + 2) % 5, z))
    return out


def psi(deps):
    out = set()
    for x in range(5):
        for z in range(64):
            for j in range(5):
                sources = [
                    (j + 3) % 5,
                    (j + 1) % 5,
                    (j + 2) % 5,
                    (j + 4) % 5,
                ]
                for source_y in sources:
                    if DEPS[j][source_y] and ix(x, source_y, z) in deps:
                        out.add(ix(x, j, z))
    return out


def round_support(deps):
    return psi(pi(theta(rho(deps))))


if __name__ == "__main__":
    print("dependency masks", DEPS)
    values = []
    for bit in range(1600):
        deps = {bit}
        counts = []
        for _ in range(3):
            deps = round_support(deps)
            counts.append(len(deps))
        values.append(counts)
    for r in range(3):
        print(
            f"round {r + 1}: min {min(v[r] for v in values)}, "
            f"fully diffused {sum(v[r] == 1600 for v in values)}"
        )
