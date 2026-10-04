# CyberShield 360 🛡️

### Digital Safety & Cybersecurity Toolkit

CyberShield 360 is a beginner-friendly cybersecurity web application designed to help users identify potentially suspicious URLs, scam messages, and unusual login activity.

## Features

* **URL Scanner:** Checks URLs for suspicious patterns and assigns a risk score.
* **Scam Message Detector:** Identifies potentially suspicious words and scam-related patterns in messages.
* **Login Security Analyzer:** Evaluates failed login attempts, unknown devices, and unusual locations.
* **Cyber Risk Dashboard:** Displays total scans, high-risk results, and recent scan activity.

## Technology Stack

* Python
* Flask
* HTML
* CSS
* JavaScript

## Installation and Setup

1. Clone or download this repository.

2. Open the project folder in VS Code.

3. Create and activate a Python virtual environment.

4. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Start the application:

   ```bash
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

## Project Structure

```text
CyberShield360/
├── app.py
├── requirements.txt
├── templates/
│   └── index.html
└── README.md
```

## Limitations

This prototype uses rule-based detection. Its risk scores are indicative and do not guarantee that a URL or message is safe or malicious. The dashboard currently tracks scans in the current page session.

## Future Scope

* Machine-learning-based phishing and scam detection
* Threat intelligence integration
* Persistent scan history and analytics
* User authentication and security alerts
* Improved detection using trusted external security APIs

## Disclaimer

CyberShield 360 is an educational cybersecurity prototype. Do not enter real passwords, OTPs, or confidential information.
