import numpy as np
import pandas as pd
from scipy import stats
from sklearn.linear_model import LinearRegression
np.random.seed(42)
n = 500
age = np.random.normal(35, 10, n).clip(18, 65)
income = 20000 + 1500 * age + np.random.normal(0, 10000, n)
df = pd.DataFrame({"age": age, "income": income})
correlation = df["age"].corr(df["income"])
model = LinearRegression().fit(df[["age"]], df["income"])
slope = model.coef_[0]
r_squared = model.score(df[["age"]], df["income"])
t_stat, p_value = stats.ttest_ind(
    df[df["age"] > 35]["income"],
    df[df["age"] <= 35]["income"]
)
print(f"corr={correlation:.3f} slope={slope:.0f} r2={r_squared:.3f} p={p_value:.4f}")
