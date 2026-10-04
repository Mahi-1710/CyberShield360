import joblib
import ipaddress
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)
# Load the trained scam message model
model = joblib.load("scam_message_model.joblib")
url_model = joblib.load("url_model.joblib")


@app.route("/")
def home():
    return render_template("index.html")



def extract_url_features(url):
    url = str(url).strip()
    candidate = url if "://" in url else "https://" + url
    parsed = urlparse(candidate)

    host = parsed.hostname or ""
    path = parsed.path or ""
    lower_url = url.lower()

    try:
        ipaddress.ip_address(host)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    suspicious_words = [
        "login", "verify", "password", "urgent",
        "free-prize", "account", "secure", "update"
    ]

    return {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(path),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equals_count": url.count("="),
        "digit_count": sum(char.isdigit() for char in url),
        "uses_https": int(parsed.scheme == "https"),
        "uses_ip_address": uses_ip,
        "has_suspicious_word": int(
            any(word in lower_url for word in suspicious_words)
        ),
    }


def analyze_url(url):
    url = str(url).strip()

    if not url:
        return {
            "risk_score": 0,
            "risk_level": "Unknown",
            "reasons": ["Please enter a URL."]
        }

    features = extract_url_features(url)

    prediction = int(url_model.predict([features])[0])
    probabilities = url_model.predict_proba([features])[0]
    suspicious_index = list(url_model.classes_).index(1)
    score = round(float(probabilities[suspicious_index]) * 100)

    if score >= 75:
        level = "High"
    elif score >= 45:
        level = "Medium"
    else:
        level = "Low"

    if prediction == 1:
        reasons = [
            "The ML model found patterns similar to suspicious URLs."
        ]
    else:
        reasons = [
            "The ML model classified this URL as likely legitimate."
        ]

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "note": (
            "Experimental ML prediction based on a small demo dataset. "
            "A low score does not guarantee that a URL is safe."
        )
    }

@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    return jsonify(analyze_url(url))


@app.route("/api/scan-message", methods=["POST"])
def scan_message():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:5000].strip()

    if not message:
        return jsonify({
            "risk_score": 0,
            "risk_level": "Unknown",
            "reasons": ["Please enter a message."]
        })

    # Predict using the trained ML model
    prediction = int(model.predict([message])[0])
    probabilities = model.predict_proba([message])[0]
    scam_index = list(model.classes_).index(1)
    scam_probability = float(probabilities[scam_index])

    # Convert model probability to a demo risk score
    score = round(scam_probability * 100)

    if prediction == 1:
        level = (
            "High" if score >= 75
            else "Medium" if score >= 45
            else "Low"
        )
        reasons = [
            "The ML model found patterns similar to scam messages."
        ]
    else:
        level = (
            "High" if score >= 75
            else "Medium" if score >= 45
            else "Low"
        )
        reasons = [
            "The ML model classified this message as likely genuine."
        ]

    return jsonify({
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "note": (
            "Experimental ML prediction based on a small starter dataset. "
            "This result is not proof that a message is safe or fraudulent."
        )
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