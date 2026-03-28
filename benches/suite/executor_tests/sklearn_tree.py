from sklearn.tree import DecisionTreeClassifier
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
X, y = load_iris(return_X_y=True)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
clf = DecisionTreeClassifier(random_state=42).fit(X_train, y_train)
acc = clf.score(X_test, y_test)
print(f"accuracy={acc:.3f} depth={clf.get_depth()} leaves={clf.get_n_leaves()}")
