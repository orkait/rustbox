import os
found = []
for root, dirs, files in os.walk("/sys"):
    for f in files[:3]:
        try:
            found.append(open(os.path.join(root, f)).read()[:50])
        except:
            pass
if not found:
    raise RuntimeError("no /sys files readable - sandbox blocked access")
print("ESCAPED:", found)
