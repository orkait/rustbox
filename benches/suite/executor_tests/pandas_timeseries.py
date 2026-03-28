import pandas as pd
import numpy as np
dates = pd.date_range("2024-01-01", periods=365, freq="D")
np.random.seed(42)
ts = pd.Series(np.cumsum(np.random.randn(365)), index=dates)
monthly = ts.resample("ME").mean()
print(f"months={len(monthly)} final={ts.iloc[-1]:.2f} max={ts.max():.2f}")
