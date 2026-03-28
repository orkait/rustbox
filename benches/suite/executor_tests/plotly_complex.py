import plotly.graph_objects as go
import plotly.express as px
import numpy as np
np.random.seed(42)
fig = go.Figure()
fig.add_trace(go.Scatter(x=list(range(100)), y=np.cumsum(np.random.randn(100)).tolist(), name="walk"))
fig.add_trace(go.Bar(x=list(range(10)), y=np.random.randint(1,100,10).tolist(), name="bars"))
fig.update_layout(title="Test")
j = fig.to_json()
print(f"traces={len(fig.data)} json={len(j)}")
