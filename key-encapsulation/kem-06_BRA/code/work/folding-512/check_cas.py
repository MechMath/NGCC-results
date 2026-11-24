#!/usr/bin/env python3
"""Cross-check the BRA-512 modulus with two independent exact CAS stacks."""

from flint import fmpz_mod_poly_ctx
from sympy import Poly, factor_list, symbols


def main() -> None:
    x = symbols("x")
    p_expr = x**221 + x**8 + x**6 + x**2 + 1

    sympy_result = factor_list(Poly(p_expr, x, modulus=2))
    assert sympy_result == (1, [(Poly(p_expr, x, modulus=2), 1)])

    ctx = fmpz_mod_poly_ctx(2)
    z = ctx.gen()
    p_flint = z**221 + z**8 + z**6 + z**2 + 1
    assert p_flint.is_irreducible()
    unit, factors = p_flint.factor()
    assert unit == 1
    assert len(factors) == 1
    assert factors[0][1] == 1

    print("sympy_factor_list =", sympy_result)
    print("flint_is_irreducible =", p_flint.is_irreducible())
    print("flint_factor =", p_flint.factor())
    print("CROSS_CHECK: irreducible")


if __name__ == "__main__":
    main()
