D = 1681
D2 = D * D
D4 = D ** 4
OLD_V = 546187540259
NEW_V = 8531112769380

print("D =", D)
print("D^2 =", D2)
print("D^4 =", D4)
print("2^43 =", 2 ** 43)
print("old v =", OLD_V, "new v =", NEW_V, "delta =", NEW_V - OLD_V)

for label, value in (("old", OLD_V), ("new", NEW_V)):
    x = value
    c0 = x % D
    x //= D
    c1 = x % D
    x //= D
    c2 = x % D
    x //= D
    # x = c3 + fifth * D. Reference applies a remainder for c3.
    # AVX2 obtains v1 = floor(value / D^2) and c3 = floor(v1 / D) = x.
    print(
        label,
        "c0,c1,c2=", c0, c1, c2,
        "pre-final x=c3+fifth*D=", x,
        "reference c3=x%D=", x % D,
        "avx2 c3=x (already v1/D)=", x,
    )

assert NEW_V - OLD_V == D4
assert NEW_V < 2 ** 43
print("new < 2^43:", NEW_V < 2 ** 43)
