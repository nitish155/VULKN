import requests

# GET request
response = requests.get("https://httpbin.org/get")
print("Status:", response.status_code)
print("Body:", response.json())

# POST request with JSON body
payload = {"target": "http://example.com", "scan_type": "sqli"}
response = requests.post("https://httpbin.org/post", json=payload)
print("Status:", response.status_code)
print("Body:", response.json())