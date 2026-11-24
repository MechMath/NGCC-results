"""Exact symbolic check of the BRA public-linear-elimination coefficients."""

import sympy as sp


A, B, h, s, r1, r2, e, mG = sp.symbols(
    "A B h s r1 r2 e mG", commutative=True
)

u = r1 + h * r2
v = mG + s * r2 + e
L = sp.expand(A * u + B * v)

coeff_r1 = sp.factor(L.coeff(r1))
coeff_r2 = sp.factor(L.coeff(r2))

assert coeff_r1 == A
assert sp.expand(coeff_r2 - (A * h + B * s)) == 0

# Over a field with h != 0 and s != 0, simultaneous vanishing forces A=B=0.
solutions = sp.solve(
    [coeff_r1, coeff_r2],
    [A, B],
    dict=True,
)
assert solutions == [{A: 0, B: 0}]

# The public h^{-1} cancellation leaves a nonzero r1 coefficient -s/h
# (over characteristic two this is the same as s/h).
residual = sp.expand(v - s * u / h)
assert sp.factor(residual.coeff(r1) + s / h) == 0

print("coeff_r1 =", coeff_r1)
print("coeff_r2 =", sp.factor(coeff_r2))
print("ring-linear solution:", solutions)
print("r2 eliminated; r1 coefficient =", sp.factor(residual.coeff(r1)))
