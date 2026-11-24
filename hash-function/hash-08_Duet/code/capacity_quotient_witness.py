def swap(x, bits=2):
    mask = (1 << bits) - 1
    return ((x & mask) << bits) | (x >> bits)


def block(a, b, c, m=0):
    d1 = swap((a ^ m) << 2 | c) & 3
    c1 = d1 ^ c
    d2 = swap(b << 2 | c1) & 3
    return c1, d2 ^ c1


assert block(0, 0, 0) == (0, 0)
assert block(1, 0, 0) == (1, 1)
print("state (00,00,00): next capacity 00")
print("state (01,00,00): next capacity 01")
