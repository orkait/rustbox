import requests
s = requests.Session()
s.headers.update({"User-Agent": "RustboxTest/1.0", "Accept": "application/json"})
req = requests.Request("POST", "https://api.example.com/data", json={"key": "value"})
prepared = s.prepare_request(req)
assert prepared.method == "POST"
assert "application/json" in prepared.headers.get("Content-Type", "")
assert prepared.headers["User-Agent"] == "RustboxTest/1.0"
print(f"method={prepared.method} content_type={prepared.headers['Content-Type']} body_len={len(prepared.body)}")
