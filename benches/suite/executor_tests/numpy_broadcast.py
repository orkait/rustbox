import numpy as np
a = np.arange(12).reshape(3,4)
b = np.array([10,20,30,40])
c = a + b
assert c.shape == (3,4)
assert c[2,3] == 11 + 40
row_means = a.mean(axis=1)
col_sums = a.sum(axis=0)
print(f"broadcast_ok shape={c.shape} row_means={row_means.tolist()} col_sums={col_sums.tolist()}")
