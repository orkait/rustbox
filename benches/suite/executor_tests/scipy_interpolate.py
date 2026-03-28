import numpy as np
from scipy.interpolate import interp1d
x = np.array([0, 1, 2, 3, 4, 5])
y = np.array([0, 1, 4, 9, 16, 25])
f = interp1d(x, y, kind="cubic")
x_new = np.linspace(0, 5, 50)
y_new = f(x_new)
print(f"f(2.5)={f(2.5):.2f} min={y_new.min():.2f} max={y_new.max():.2f}")
