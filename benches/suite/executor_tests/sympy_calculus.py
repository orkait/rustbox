from sympy import symbols, diff, integrate, sin, cos, limit, oo, simplify
x = symbols("x")
deriv = diff(sin(x)**2, x)
integral = integrate(x**2, (x, 0, 1))
lim = limit(sin(x)/x, x, 0)
simplified = simplify(sin(x)**2 + cos(x)**2)
print(f"d/dx(sin^2)={deriv} integral={integral} limit={lim} identity={simplified}")
