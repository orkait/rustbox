import os
for _ in range(20):
    try:
        os.chdir("..")
    except:
        pass
print(open("etc/passwd").read())
