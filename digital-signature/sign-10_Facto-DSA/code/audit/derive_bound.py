#!/usr/bin/env python3
import json
from decimal import Decimal, getcontext


getcontext().prec = 80
Q = Decimal(65519)
N = 10
SPLIT_LOWER = Decimal("0.26")
SCALES = 64
RMAX = 512

# PDF Section 2.3: g(x) = (q-1)/(2q) + x/q + ((q-1)/(2q))*x^2,
# pQ = 1 - g composed n times at zero.
a = (Q - 1) / (2 * Q)
x = Decimal(0)
for _ in range(N):
    x = a + x / Q + a * x * x
p_q = 1 - x
p_lambda = 1 - (1 - p_q) ** SCALES
p_trial = SPLIT_LOWER * p_lambda
failure = (1 - p_trial) ** RMAX
log2_failure = failure.ln() / Decimal(2).ln()

print(
    json.dumps(
        {
            "assumptions": (
                "PDF conservative split probability p_split>=0.26 and its "
                "independent-rescaling triangular-survival model."
            ),
            "q": str(Q),
            "n": N,
            "scale_cap": SCALES,
            "Rmax": RMAX,
            "pQ": str(p_q),
            "p_lambda_64": str(p_lambda),
            "p_trial_lower": str(p_trial),
            "sign_failure_upper": str(failure),
            "sign_failure_upper_log2": str(log2_failure),
            "pdf_declared_upper_log2": -222,
            "within_pdf_declared_bound": log2_failure < Decimal(-222),
        },
        indent=2,
    )
)
