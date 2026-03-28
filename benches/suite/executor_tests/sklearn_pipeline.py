from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.datasets import make_classification
from sklearn.model_selection import cross_val_score
import numpy as np
X, y = make_classification(n_samples=200, n_features=20, random_state=42)
pipe = Pipeline([("scaler", StandardScaler()), ("svc", SVC(kernel="rbf"))])
scores = cross_val_score(pipe, X, y, cv=5)
print(f"cv_mean={scores.mean():.3f} cv_std={scores.std():.3f}")
