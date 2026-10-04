
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


def analyze_url(url):
    url = url.strip()
    reasons = []
    score = 0

    if not url:
        return {
            "risk_score": 0,
            "risk_level": "Unknown",
            "reasons": ["Please enter a URL."]
        }

    candidate = url if "://" in url else "https://" + url
    parsed = urlparse(candidate)
    host = parsed.hostname or ""

    if parsed.scheme != "https":
        score += 15
        reasons.append("URL does not use HTTPS.")

    if not host or "." not in host:
        score += 40
        reasons.append("Unusual URL format.")

    if "@" in parsed.netloc:
        score += 35
        reasons.append("URL contains an @ symbol.")

    if len(url) > 100:
        score += 15
        reasons.append("URL is unusually long.")

    if host.count("-") >= 3:
        score += 15
        reasons.append("Domain contains many hyphens.")

    if re.search(
        r"login|verify|password|urgent|free-prize",
        url,
        re.IGNORECASE
    ):
        score += 20
        reasons.append("Potentially suspicious keyword detected.")

    score = min(score, 100)

    if not reasons:
        reasons.append("No configured warning rules were triggered.")

    level = (
        "High" if score >= 60
        else "Medium" if score >= 30
        else "Low"
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "note": "Rule-based prototype. A low score does not guarantee safety."
    }


@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    return jsonify(analyze_url(url))

@app.route("/api/scan-message", methods=["POST"])
def scan_message():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:5000].lower()

    if not message.strip():
        return jsonify({
            "risk_score": 0,
            "risk_level": "Unknown",
            "reasons": ["Please enter a message."]
        })

    patterns = {
        "Sensitive information request": [
            "share otp", "send otp", "password",
            "bank details", "card number", "pin"
        ],
        "Urgency or threat": [
            "account blocked", "act now",
            "immediately", "urgent", "account suspended"
        ],
        "Prize or reward claim": [
            "you won", "winner", "claim your prize",
            "lottery", "free prize"
        ],
        "Suspicious link request": [
            "click here", "verify your account",
            "click this link", "update your kyc"
        ]
    }

    reasons = []

    for category, keywords in patterns.items():
        if any(keyword in message for keyword in keywords):
            reasons.append(category)

    score = min(len(reasons) * 25, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    if not reasons:
        reasons.append("No configured scam patterns detected.")

    return jsonify({
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "note": "Rule-based prototype, not a trained ML model."
    })
    
@app.route("/api/analyze-login", methods=["POST"])
def analyze_login():
    data = request.get_json(silent=True) or {}

    try:
        failed_attempts = int(data.get("failed_attempts", 0))
    except (TypeError, ValueError):
        failed_attempts = 0

    failed_attempts = max(0, min(failed_attempts, 100))

    new_device = data.get("new_device") is True
    unusual_location = data.get("unusual_location") is True

    score = 0
    reasons = []

    if failed_attempts >= 3:
        score += 40
        reasons.append("Multiple failed login attempts detected.")

    if new_device:
        score += 30
        reasons.append("Login is from an unrecognized device.")

    if unusual_location:
        score += 30
        reasons.append("Login is from an unusual location.")

    score = min(score, 100)

    if score >= 60:
        level = "High"
        recommendation = "Block or pause the login and verify the user."
    elif score >= 30:
        level = "Medium"
        recommendation = "Request additional identity verification."
    else:
        level = "Low"
        recommendation = "No configured warning signals detected."

    if not reasons:
        reasons.append("No suspicious signals were selected.")

    return jsonify({
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "recommendation": recommendation,
        "note": "Demo analysis using simulated login activity."
    })


if __name__ == "__main__":
    app.run(debug=True)