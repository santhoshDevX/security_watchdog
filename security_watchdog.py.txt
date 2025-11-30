from flask import Flask, request, jsonify
import requests
import datetime
import hashlib

app = Flask(__name__)

# ============================
# CONFIGURATION
# ============================

CLIQ_BOT_WEBHOOK = "https://cliq.zoho.com/api/v2/bots/<your_bot>/message"
AUTH_TOKEN = "<your_cliq_auth_token>"   # OAuth or Bot Token


# ============================
# HELPER FUNCTIONS
# ============================

def send_cliq_message(text, channel=None):
    payload = {
        "text": text
    }

    if channel:
        payload["channel"] = channel

    headers = {
        "Authorization": f"Zoho-oauthtoken {AUTH_TOKEN}",
        "Content-Type": "application/json"
    }

    requests.post(CLIQ_BOT_WEBHOOK, json=payload, headers=headers)


def risk_score(event):
    """Simple threat scoring logic."""
    score = 0

    if event.get("failed_attempts", 0) > 5:
        score += 40
    
    if event.get("geo_mismatch"):
        score += 30
    
    if event.get("device_change"):
        score += 20
    
    if event.get("ip_reputation") == "bad":
        score += 50

    return score


def password_is_weak(password):
    """Check weak passwords (demo logic)."""
    weak_patterns = ["123", "admin", "password", "qwerty", "111"]
    if len(password) < 8:
        return True
    for p in weak_patterns:
        if p in password.lower():
            return True
    return False


def log_event(event_type, details):
    print(f"[{datetime.datetime.now()}] {event_type} → {details}")


# ============================
# ROUTES
# ============================

@app.route("/", methods=["GET"])
def home():
    return "Security Watchdog Bot is running."


# ------------------------------------
# 1. Suspicious Login Detection Handler
# ------------------------------------
@app.route("/login_event", methods=["POST"])
def login_event():
    data = request.json

    user = data.get("user")
    failed_attempts = data.get("failed_attempts", 0)
    geo_mismatch = data.get("geo_mismatch", False)
    device_change = data.get("device_change", False)
    ip_reputation = data.get("ip_reputation", "unknown")

    event_data = {
        "failed_attempts": failed_attempts,
        "geo_mismatch": geo_mismatch,
        "device_change": device_change,
        "ip_reputation": ip_reputation
    }

    score = risk_score(event_data)
    log_event("LOGIN_CHECK", event_data)

    # Critical alert
    if score >= 60:
        send_cliq_message(
            f"⚠️ *Critical Security Alert*\nUser: {user}\nRisk Score: {score}\nUnusual login behavior detected!"
        )
    # Medium alert
    elif score >= 30:
        send_cliq_message(
            f"⚠️ *Warning*: Suspicious login attempt detected for user {user}. Score: {score}"
        )

    return jsonify({"status": "processed", "risk_score": score})


# ------------------------------------
# 2. Password Policy Checker
# ------------------------------------
@app.route("/password_check", methods=["POST"])
def password_check():
    data = request.json
    user = data.get("user")
    password = data.get("password")

    # Hash password (never store plain)
    hashed = hashlib.sha256(password.encode()).hexdigest()

    if password_is_weak(password):
        send_cliq_message(
            f"🔐 Weak password detected for user *{user}*. Please update your password immediately."
        )
        result = "weak"
    else:
        result = "strong"

    log_event("PASSWORD_CHECK", {"user": user, "hash": hashed, "result": result})

    return jsonify({"status": "checked", "password_strength": result})


# ------------------------------------
# 3. SIEM / Firewall Integration Example
# ------------------------------------
@app.route("/siem_event", methods=["POST"])
def siem_event():
    data = request.json

    threat_type = data.get("type")
    severity = data.get("severity")
    source_ip = data.get("source_ip")

    log_event("SIEM_EVENT", data)

    if severity == "high":
        send_cliq_message(
            f"🚨 *SIEM High-Severity Event Detected*\nThreat: {threat_type}\nSource: {source_ip}"
        )

    return jsonify({"status": "received"})


# ------------------------------------
# 4. Slash Command Handler (/watchdog help)
# ------------------------------------
@app.route("/command", methods=["POST"])
def command():
    message = request.json.get("text").strip().lower()

    if message == "help":
        reply = (
            "🛡️ *Security Watchdog Commands*\n"
            "/watchdog status – Show security status\n"
            "/watchdog logins – Recent suspicious login logs\n"
            "/watchdog firewall – Latest firewall alerts\n"
            "/watchdog report – Weekly summary\n"
            "/watchdog help – Show this menu\n"
        )
        send_cliq_message(reply)
    else:
        send_cliq_message("Unknown command. Try `/watchdog help`.")

    return jsonify({"status": "ok"})


# ============================
# MAIN ENTRY
# ============================
if __name__ == "__main__":
    app.run(port=5000, debug=True)
