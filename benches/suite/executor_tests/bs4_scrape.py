from bs4 import BeautifulSoup
html = """
<html><body>
<table>
<tr><th>Name</th><th>Score</th></tr>
<tr><td>Alice</td><td>95</td></tr>
<tr><td>Bob</td><td>87</td></tr>
<tr><td>Charlie</td><td>92</td></tr>
</table>
</body></html>
"""
soup = BeautifulSoup(html, "html.parser")
rows = soup.find_all("tr")[1:]
data = [(r.find_all("td")[0].text, int(r.find_all("td")[1].text)) for r in rows]
avg = sum(s for _, s in data) / len(data)
top = max(data, key=lambda x: x[1])
print(f"students={len(data)} avg={avg:.1f} top={top[0]}:{top[1]}")
