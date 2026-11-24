signatures = {
    "Duet-512": [3, 0, 5, 1, 4, 2],
    "Duet-768": [9, 2, 15, 0, 6, 12, 4, 16, 1, 10, 7, 14, 3, 11, 5, 13, 8],
    "Duet-1024": [8, 2, 11, 0, 5, 9, 3, 10, 1, 7, 4, 6],
}

for name, permutation in signatures.items():
    seen = set()
    cycles = []
    for start in range(len(permutation)):
        if start in seen:
            continue
        cycle = []
        cursor = start
        while cursor not in seen:
            seen.add(cursor)
            cycle.append(cursor)
            cursor = permutation[cursor]
        cycles.append(cycle)
    print(name, cycles, len(cycles) * 64)
