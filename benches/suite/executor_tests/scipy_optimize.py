from scipy.optimize import minimize
result = minimize(lambda x: (x[0]-1)**2 + (x[1]-2.5)**2, [0,0], method="Nelder-Mead")
print(f"minimum={result.x.round(4).tolist()} value={result.fun:.6f} success={result.success}")
