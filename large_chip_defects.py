import math
from decimal import Decimal
def p_at_least_three_defects(k,n):
    lam=Decimal(k)/Decimal(n)
    q=Decimal(math.exp(-lam))*(1+lam+lam**2/2)
    prob=Decimal(1)-q**Decimal(n)
    return prob
# Parameters
k = 20000
n = 1000000
result = p_at_least_three_defects(k, n)
print(f"p({k},{n}) = {result:.10f}")

