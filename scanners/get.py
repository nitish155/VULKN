import requests

# Make a GET request
response = requests.get("https://httpbin.org/get")

# Print the status code
print("Status Code:", response.status_code)

# Print the full response body
# print("Response Body:", response.json())
print("Response Body:", response.content)