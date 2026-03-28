import pandas as pd
import numpy as np
np.random.seed(42)
df = pd.DataFrame({
    "dept": np.random.choice(["eng","sales","hr"], 1000),
    "salary": np.random.normal(80000, 20000, 1000),
    "years": np.random.randint(1, 20, 1000)
})
result = df.groupby("dept").agg({"salary":["mean","std"], "years":"median"})
print(f"groups={sorted(df.dept.unique().tolist())} shape={result.shape}")
