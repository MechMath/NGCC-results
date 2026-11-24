from flint import fq_default_ctx, fq_default_poly_ctx, nmod_poly


coefficients = [0] * 222
for exponent in (0, 2, 6, 8, 221):
    coefficients[exponent] = 1

print("over F_2:")
print(nmod_poly(coefficients, 2).factor())

field = fq_default_ctx(2, 127, "a")
print("over F_(2^127):")
print(fq_default_poly_ctx(field)(coefficients).factor())
