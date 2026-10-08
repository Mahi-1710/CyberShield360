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

    score = round(
        float(probabilities[suspicious_index]) * 100
    )

    if score >= 75:
        level = "High"
    elif score >= 45:
        level = "Medium"
    else:
        level = "Low"

    # -----------------------------------------
    # EXPLAINABLE URL ANALYSIS
    # -----------------------------------------
    reasons = []

    lower_url = url.lower()

    # Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "password",
        "urgent",
        "free-prize",
        "account",
        "secure",
        "update"
    ]

    found_words = [
        word for word in suspicious_words
        if word in lower_url
    ]

    if found_words:
        reasons.append(
            "Suspicious keyword detected: "
            + ", ".join(found_words)
        )

    # IP address instead of domain
    if features["uses_ip_address"] == 1:
        reasons.append(
            "URL uses an IP address instead of a normal domain name."
        )

    # HTTPS check
    if features["uses_https"] == 0:
        reasons.append(
            "URL does not use HTTPS encryption."
        )

    # Special characters
    special_count = (
        features["at_count"]
        + features["question_count"]
        + features["equals_count"]
    )

    if special_count >= 3:
        reasons.append(
            "URL contains multiple special characters."
        )

    # Long URL
    if features["url_length"] > 100:
        reasons.append(
            "URL is unusually long."
        )

    # Many dots
    if features["dot_count"] >= 4:
        reasons.append(
            "URL contains an unusually high number of dots."
        )

    # Many hyphens
    if features["hyphen_count"] >= 3:
        reasons.append(
            "URL contains multiple hyphens."
        )

    # Many digits
    if features["digit_count"] >= 6:
        reasons.append(
            "URL contains an unusually high number of digits."
        )

    # @ symbol
    if features["at_count"] > 0:
        reasons.append(
            "URL contains an @ symbol, which can be used to hide the actual destination."
        )

    # If no rule-based reason found
    if not reasons:
        if prediction == 1:
            reasons.append(
                "The ML model found patterns similar to suspicious URLs."
            )
        else:
            reasons.append(
                "No major suspicious URL patterns were detected."
            )

    # Limit reasons so result does not become too long
    reasons = reasons[:6]

    # Recommended action
    if level == "High":
        recommendation = (
            "Do not enter passwords, OTPs or banking details. "
            "Verify the website through its official domain."
        )
    elif level == "Medium":
        recommendation = (
            "Be cautious before opening this link. "
            "Verify the domain and avoid entering sensitive information."
        )
    else:
        recommendation = (
            "No major warning signals were detected, "
            "but always verify important links independently."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "recommendation": recommendation,
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

    # -----------------------------------------
    # ML MODEL PREDICTION
    # -----------------------------------------
    prediction = int(model.predict([message])[0])

    probabilities = model.predict_proba([message])[0]
    scam_index = list(model.classes_).index(1)

    scam_probability = float(probabilities[scam_index])
    score = round(scam_probability * 100)

    if score >= 75:
        level = "High"
    elif score >= 45:
        level = "Medium"
    else:
        level = "Low"

    # -----------------------------------------
    # EXPLAINABLE MESSAGE ANALYSIS
    # -----------------------------------------
    reasons = []
    lower_message = message.lower()

    # Urgency
    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "hurry",
        "last chance",
        "within 24 hours",
        "expire"
    ]

    if any(word in lower_message for word in urgent_words):
        reasons.append(
            "Urgent or pressure-based language detected."
        )

    # OTP / verification code
    if re.search(
        r"\b(otp|one time password|verification code|security code)\b",
        lower_message
    ):
        reasons.append(
            "OTP or verification-code request detected."
        )

    # Password
    if re.search(
        r"\b(password|passcode|pin|login details)\b",
        lower_message
    ):
        reasons.append(
            "Password, PIN or login information request detected."
        )

    # Banking / financial context
    financial_words = [
        "bank",
        "account",
        "upi",
        "payment",
        "transaction",
        "credit card",
        "debit card",
        "refund",
        "wallet"
    ]

    found_financial = [
        word for word in financial_words
        if word in lower_message
    ]

    if found_financial:
        reasons.append(
            "Financial or banking-related content detected."
        )

    # KYC / identity verification
    kyc_words = [
        "kyc",
        "verify your identity",
        "identity verification",
        "aadhaar",
        "pan card",
        "document verification"
    ]

    if any(word in lower_message for word in kyc_words):
        reasons.append(
            "KYC or identity-verification request detected."
        )

    # Link detection
    if re.search(
        r"(https?://|www\.|bit\.ly|tinyurl|t\.co/)",
        lower_message
    ):
        reasons.append(
            "A website link or shortened URL is present."
        )

    # Prize / reward / lottery
    reward_words = [
        "winner",
        "won",
        "prize",
        "reward",
        "lottery",
        "cashback",
        "free gift",
        "congratulations"
    ]

    if any(word in lower_message for word in reward_words):
        reasons.append(
            "Prize, reward or unexpected-benefit language detected."
        )

    # Threat / account blocking
    threat_words = [
        "blocked",
        "suspended",
        "deactivated",
        "legal action",
        "police",
        "arrest",
        "penalty"
    ]

    if any(word in lower_message for word in threat_words):
        reasons.append(
            "Threat or account-blocking language detected."
        )

    # If no specific reason was found
    if not reasons:
        if prediction == 1:
            reasons.append(
                "The ML model found patterns similar to scam messages."
            )
        else:
            reasons.append(
                "No major scam indicators were detected."
            )

    # Keep result clean
    reasons = reasons[:6]

    # -----------------------------------------
    # RECOMMENDATION
    # -----------------------------------------
    if level == "High":
        recommendation = (
            "Do not click links or share OTPs, passwords or banking details. "
            "Verify the sender through an official channel."
        )
    elif level == "Medium":
        recommendation = (
            "Be cautious. Verify the sender and avoid sharing sensitive "
            "information until the message is confirmed."
        )
    else:
        recommendation = (
            "No major warning signals were detected, but verify "
            "unexpected messages independently."
        )

    return jsonify({
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "recommendation": recommendation,
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
    # -----------------------------------------
# UNIFIED CYBER RISK ENGINE
# -----------------------------------------
def calculate_cyber_risk(
    url_score=0,
    message_score=0,
    login_score=0
):
    """
    Calculate a combined cybersecurity risk score.

    This is a demo weighted score:
    URL      = 35%
    Message  = 35%
    Login    = 30%
    """

    # Make sure scores stay between 0 and 100
    url_score = max(0, min(float(url_score), 100))
    message_score = max(0, min(float(message_score), 100))
    login_score = max(0, min(float(login_score), 100))

    # Weighted combined score
    overall_score = round(
        (url_score * 0.35)
        + (message_score * 0.35)
        + (login_score * 0.30)
    )

    # Overall risk level
    if overall_score >= 75:
        risk_level = "High"
    elif overall_score >= 45:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Identify the strongest risk signals
    risks = []

    if url_score >= 75:
        risks.append("High URL risk detected.")
    elif url_score >= 45:
        risks.append("Suspicious URL activity detected.")

    if message_score >= 75:
        risks.append("High scam-message risk detected.")
    elif message_score >= 45:
        risks.append("Suspicious message patterns detected.")

    if login_score >= 60:
        risks.append("Unusual login activity detected.")
    elif login_score >= 30:
        risks.append("Some login warning signals detected.")

    if not risks:
        risks.append(
            "No major risk signals were detected "
            "from the available inputs."
        )

    # Recommendation
    if risk_level == "High":
        recommendation = (
            "Take immediate caution. Avoid suspicious links, "
            "do not share OTPs or passwords, and verify unusual "
            "login activity through official channels."
        )

    elif risk_level == "Medium":
        recommendation = (
            "Proceed with caution. Verify links and messages "
            "before sharing sensitive information."
        )

    else:
        recommendation = (
            "No major warning signals were detected, "
            "but continue following basic cybersecurity practices."
        )

    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "component_scores": {
            "url": round(url_score),
            "message": round(message_score),
            "login": round(login_score)
        },
        "risks": risks,
        "recommendation": recommendation,
        "note": (
            "This is a demo weighted composite score combining "
            "the three CyberShield 360 security modules. "
            "It is not a certified security rating."
        )
    }


@app.route("/api/cyber-risk", methods=["POST"])
def cyber_risk():
    data = request.get_json(silent=True) or {}

    try:
        url_score = float(data.get("url_score", 0))
    except (TypeError, ValueError):
        url_score = 0

    try:
        message_score = float(data.get("message_score", 0))
    except (TypeError, ValueError):
        message_score = 0

    try:
        login_score = float(data.get("login_score", 0))
    except (TypeError, ValueError):
        login_score = 0

    return jsonify(
        calculate_cyber_risk(
            url_score,
            message_score,
            login_score
        )
    )


if __name__ == "__main__":
    app.run(debug=True)