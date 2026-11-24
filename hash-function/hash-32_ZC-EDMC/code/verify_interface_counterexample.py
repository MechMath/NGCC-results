"""Exact check of the generic EDM interface counterexample in zero_sum_interface.md."""

from functools import reduce
from operator import xor


def main() -> None:
    # g is the identity; h swaps 7<->8 and 14<->15 and fixes all other states.
    h = list(range(16))
    for left, right in ((7, 8), (14, 15)):
        h[left], h[right] = h[right], h[left]
    g = list(range(16))
    states = (7, 8, 14)

    # r=c=2, so L(X) retains only the low two bits of X.
    def edm(k: list[int], x: int) -> int:
        return h[k[x] ^ (x & 3)]

    p_images = [h[g[x]] for x in states]
    fg_images = [edm(g, x) for x in states]
    fh_images = [edm(h, x) for x in states]

    assert p_images == [8, 7, 15]
    assert reduce(xor, p_images) == 0
    assert fg_images == [4, 7, 12]
    assert reduce(xor, fg_images) == 15
    assert fh_images == [11, 8, 13]
    assert reduce(xor, fh_images) == 14
    assert len(set((*fg_images, *fh_images))) == 6
    print("counterexample verified")


if __name__ == "__main__":
    main()
