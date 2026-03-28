import numpy as np
A = np.array([[3,1],[1,2]])
eigenvalues, eigenvectors = np.linalg.eig(A)
det = np.linalg.det(A)
inv = np.linalg.inv(A)
assert abs(det - 5.0) < 1e-10
assert np.allclose(A @ inv, np.eye(2))
print(f"det={det:.1f} eig={sorted(eigenvalues.round(2).tolist())} inv_check=OK")
