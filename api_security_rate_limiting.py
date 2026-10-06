from flask import Flask, request, jsonify, render_template_string
from functools import wraps
from time import time
import secrets
from collections import defaultdict, deque

app = Flask(__name__)

# ============================================================
# API SECURITY & RATE LIMITING SYSTEM
# ============================================================

# Demo API keys.
# In a real application, store hashed API keys in a database.
API_KEYS = {
    "demo-key-123": {
        "name": "Demo Application",
        "active": True
    },
    "admin-key-456": {
        "name": "Admin Application",
        "active": True
    }
}

# Rate limit: maximum requests allowed in the time window.
RATE_LIMIT = 10
WINDOW_SECONDS = 60

# Stores request timestamps for each API key.
REQUEST_LOG = defaultdict(deque)

# Monitoring statistics.
TOTAL_REQUESTS = 0
BLOCKED_REQUESTS = 0


# ============================================================
# API KEY FUNCTIONS
# ============================================================

def generate_api_key():
    return "sk-" + secrets.token_urlsafe(24)


def create_api_key(name):
    key = generate_api_key()

    API_KEYS[key] = {
        "name": name,
        "active": True
    }

    return key


def check_api_key(key):
    if not key:
        return False

    if key not in API_KEYS:
        return False

    return API_KEYS[key]["active"]


# ============================================================
# RATE LIMITING
# ============================================================

def check_rate_limit(api_key):
    now = time()
    requests = REQUEST_LOG[api_key]

    # Remove requests outside the current time window.
    while requests and now - requests[0] >= WINDOW_SECONDS:
        requests.popleft()

    if len(requests) >= RATE_LIMIT:
        return False, 0

    requests.append(now)

    remaining = RATE_LIMIT - len(requests)

    return True, remaining


# ============================================================
# SECURITY DECORATOR
# ============================================================

def secure_api(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        global TOTAL_REQUESTS
        global BLOCKED_REQUESTS

        TOTAL_REQUESTS += 1

        api_key = request.headers.get("X-API-Key")

        # Check API key.
        if not check_api_key(api_key):
            BLOCKED_REQUESTS += 1

            return jsonify({
                "success": False,
                "error": "Invalid or missing API key"
            }), 401

        # Check rate limit.
        allowed, remaining = check_rate_limit(api_key)

        if not allowed:
            BLOCKED_REQUESTS += 1

            return jsonify({
                "success": False,
                "error": "Rate limit exceeded",
                "limit": RATE_LIMIT,
                "window_seconds": WINDOW_SECONDS,
                "message": "Please try again later."
            }), 429

        response = function(*args, **kwargs)

        # Add rate-limit headers.
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response

    return wrapper


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route("/api/data")
@secure_api
def protected_data():

    return jsonify({
        "success": True,
        "message": "Secure API request successful!",
        "data": {
            "project": "API Security & Rate Limiting",
            "status": "Protected"
        }
    })


@app.route("/api/status")
@secure_api
def api_status():

    return jsonify({
        "success": True,
        "status": "API is running",
        "security": "API key authentication enabled",
        "rate_limit": RATE_LIMIT,
        "window_seconds": WINDOW_SECONDS
    })


# ============================================================
# API KEY MANAGEMENT
# ============================================================

@app.route("/admin/create-key", methods=["POST"])
def create_key():

    name = request.json.get("name", "Unnamed Application")

    key = create_api_key(name)

    return jsonify({
        "success": True,
        "application": name,
        "api_key": key,
        "warning": "Store this API key securely."
    })


@app.route("/admin/keys")
def list_keys():

    keys = []

    for key, details in API_KEYS.items():

        keys.append({
            "key": key,
            "name": details["name"],
            "active": details["active"]
        })

    return jsonify(keys)


@app.route("/admin/revoke-key/<path:key>", methods=["POST"])
def revoke_key(key):

    if key not in API_KEYS:

        return jsonify({
            "success": False,
            "error": "API key not found"
        }), 404

    API_KEYS[key]["active"] = False

    return jsonify({
        "success": True,
        "message": "API key revoked"
    })


# ============================================================
# MONITORING DASHBOARD
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>

<head>

<title>API Security Dashboard</title>

<style>

body {
    font-family: Arial;
    background: #f4f6f8;
    margin: 0;
}

.header {
    background: #222;
    color: white;
    padding: 22px;
    text-align: center;
}

.container {
    width: 90%;
    max-width: 1000px;
    margin: 30px auto;
}

.cards {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}

.card {
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 3px 10px #ccc;
    flex: 1;
    min-width: 200px;
}

.number {
    font-size: 32px;
    font-weight: bold;
}

.green {
    color: green;
}

.red {
    color: red;
}

.blue {
    color: #007bff;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 12px;
    border-bottom: 1px solid #ddd;
    text-align: left;
}

.status {
    padding: 5px 10px;
    border-radius: 10px;
    background: #d4edda;
    color: #155724;
}

</style>

</head>

<body>

<div class="header">

<h1>🔐 API Security Dashboard</h1>

<p>API Key Management • Rate Limiting • Monitoring</p>

</div>

<div class="container">

<div class="cards">

<div class="card">

<h3>Total Requests</h3>

<div class="number blue">
{{ total_requests }}
</div>

</div>

<div class="card">

<h3>Blocked Requests</h3>

<div class="number red">
{{ blocked_requests }}
</div>

</div>

<div class="card">

<h3>Rate Limit</h3>

<div class="number green">
{{ rate_limit }}
</div>

<p>requests / minute</p>

</div>

</div>


<div class="card" style="margin-top:25px;">

<h2>🔑 API Keys</h2>

<table>

<tr>

<th>Application</th>
<th>API Key</th>
<th>Status</th>

</tr>

{% for key, details in keys.items() %}

<tr>

<td>{{ details.name }}</td>

<td>{{ key }}</td>

<td>

{% if details.active %}

<span class="status">Active</span>

{% else %}

<span style="color:red;">Revoked</span>

{% endif %}

</td>

</tr>

{% endfor %}

</table>

</div>


<div class="card" style="margin-top:25px;">

<h2>📡 API Test</h2>

<p>
Use the following endpoint with an API key:
</p>

<code>
GET /api/data
</code>

<p>

Header:

</p>

<code>
X-API-Key: demo-key-123
</code>

</div>

</div>

</body>

</html>
"""


@app.route("/")
def dashboard():

    return render_template_string(
        DASHBOARD_HTML,
        total_requests=TOTAL_REQUESTS,
        blocked_requests=BLOCKED_REQUESTS,
        rate_limit=RATE_LIMIT,
        keys=API_KEYS
    )


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("API SECURITY & RATE LIMITING SYSTEM")
    print("=" * 60)

    print()
    print("Dashboard:")
    print("http://127.0.0.1:5000")

    print()
    print("Protected API:")
    print("GET http://127.0.0.1:5000/api/data")

    print()
    print("Demo API Key:")
    print("demo-key-123")

    print()
    print("Rate Limit:")
    print(f"{RATE_LIMIT} requests per {WINDOW_SECONDS} seconds")

    print("=" * 60)

    app.run(debug=True)
