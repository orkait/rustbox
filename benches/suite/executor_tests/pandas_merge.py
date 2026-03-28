import pandas as pd
users = pd.DataFrame({"id":[1,2,3], "name":["alice","bob","charlie"]})
orders = pd.DataFrame({"user_id":[1,1,2,3,3,3], "amount":[100,200,300,400,500,600]})
merged = pd.merge(orders, users, left_on="user_id", right_on="id")
per_user = merged.groupby("name")["amount"].sum().sort_values(ascending=False)
print(f"top={per_user.index[0]} total={per_user.iloc[0]} rows={len(merged)}")
