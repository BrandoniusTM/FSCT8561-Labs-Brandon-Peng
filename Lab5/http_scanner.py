import requests
import csv

BASE_URL = "http://localhost:3000"
TIMEOUT = 5

records = []

tests = [
    {"method": "GET", "endpoint": "/", "input": ""},
    {"method": "GET", "endpoint": "/rest/products/search", "input": "apple"},
    {"method": "GET", "endpoint": "/rest/products/search", "input": "banana"},
    {"method": "POST", "endpoint": "/rest/products/search", "input": "apple"}
]

for test in tests:
    method = test["method"]
    endpoint = test["endpoint"]
    input_value = test["input"]

    url = BASE_URL + endpoint

    try:
        if method == "GET":
            if input_value == "":
                response = requests.get(url, timeout=TIMEOUT)
            else:
                response = requests.get(
                    url, params={"q": input_value}, timeout=TIMEOUT
                )
        else:
            response = requests.post(
                url, data={"q": input_value}, timeout=TIMEOUT
            )

        record = {
            "endpoint": endpoint,
            "method": method,
            "input": input_value,
            "status_code": response.status_code,
            "response_length": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
            "server": response.headers.get("Server", "")
        }

    except requests.RequestException as error:
        record = {
            "endpoint": endpoint,
            "method": method,
            "input": input_value,
            "status_code": "Error",
            "response_length": 0,
            "content_type": "",
            "server": ""
        }

        print("Request failed:", error)

    records.append(record)
    print(record)

with open("http_scan_results.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)

print("\nResults saved to http_scan_results.csv")
