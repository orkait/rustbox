import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import io
fig, axes = plt.subplots(2, 2, figsize=(10, 10))
x = np.linspace(0, 2*np.pi, 100)
axes[0,0].plot(x, np.sin(x))
axes[0,1].bar([1,2,3], [4,5,6])
axes[1,0].scatter(np.random.rand(50), np.random.rand(50))
axes[1,1].hist(np.random.normal(0, 1, 1000), bins=30)
buf = io.BytesIO()
fig.savefig(buf, format="png", dpi=100)
print(f"subplot_png={len(buf.getvalue())} bytes")
