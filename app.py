import os
import requests
from flask import Flask

app = Flask(__name__)

URLS = [
    "https://choir-p1h3.onrender.com",
    "https://timings-requests.onrender.com"
]

@app.route('/')
def ping_service():
    summary = []
    for url in URLS:
        try:
            response = requests.get(url, timeout=10)
            summary.append(f"{url}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            summary.append(f"{url}: Failed ({e})")
            
    return {"status": "completed", "results": summary}, 200

if __name__ == "__main__":
    # Render provides the port dynamically via an environment variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
