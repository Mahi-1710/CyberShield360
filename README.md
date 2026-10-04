# 🛡️ CyberShield 360 — Digital Safety & Cybersecurity

**CyberShield 360** is a web-based cybersecurity awareness and threat-analysis platform designed to help users identify potentially suspicious URLs, detect scam messages, and understand login security risks through a simple dashboard.

## 🌐 Live Demo

**Live Website:** https://cybershield360-59sj.onrender.com

## 🎯 Problem Statement

Online users face cybersecurity threats such as phishing links, fraudulent messages, suspicious login activity, and attempts to steal sensitive information. Many users find it difficult to recognize these threats.

CyberShield 360 provides a single platform for basic threat analysis and cybersecurity awareness.

## ✨ Key Features

### 1. URL Scanner

* Analyzes submitted URLs using a machine-learning classifier.
* Extracts URL-related features for classification.
* Displays a prediction to help users identify potentially suspicious links.

### 2. Scam Message Detector

* Analyzes text messages using TF-IDF and Logistic Regression.
* Classifies messages based on patterns learned from the training examples.
* Helps users recognize potentially fraudulent messages.

### 3. Login Security Analyzer

* Evaluates login-related risk indicators.
* Considers factors such as failed login attempts, unfamiliar devices, and unusual locations.
* Displays a risk assessment based on configured rules.

### 4. Cybersecurity Assistant

* Provides predefined answers to common cybersecurity questions.
* Covers phishing, OTP safety, passwords, suspicious links, compromised accounts, Wi-Fi security, malware, and privacy.

### 5. Security Dashboard

* Provides a centralized interface for accessing the security tools.
* Displays scan results and session-based dashboard statistics.

## 🧰 Technologies Used

* **Frontend:** HTML, CSS, JavaScript
* **Backend:** Python, Flask
* **Machine Learning:** Scikit-learn
* **Text Processing:** TF-IDF
* **Classification Models:** Random Forest and Logistic Regression
* **Model Storage:** Joblib
* **Deployment:** Render
* **Version Control:** Git and GitHub

## 🏗️ System Architecture

```text
             User
               |
               v
      CyberShield Dashboard
       (HTML, CSS, JavaScript)
               |
               v
         Flask Backend
               |
       +-------+--------+
       |       |        |
       v       v        v
      URL    Message   Login Risk
    Scanner  Detector  Analyzer
       |       |        |
       v       v        v
    Random   TF-IDF    Rule-Based
    Forest   + Logistic  Scoring
             Regression
       |
       v
     Results
       |
       v
   Dashboard UI
```

The Cybersecurity Assistant provides predefined responses through frontend JavaScript.

## 🚀 Run Locally

### Prerequisites

* Python 3.10 or a compatible Python version
* pip

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Mahi-1710/CyberShield360.git
   ```

2. Open the project directory:

   ```bash
   cd CyberShield360
   ```

3. Create and activate a virtual environment on Windows:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Start the application:

   ```bash
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

The trained model files must be present in the project directory for the application to load successfully.

## 🧪 Testing

The deployed application has been manually tested for:

* Website availability
* URL Scanner
* Scam Message Detector
* Login Security Analyzer
* Cybersecurity Assistant

All five checks were reported as working during live testing.

## 🔮 Future Scope

* Train and evaluate models using larger, diverse, verified datasets.
* Integrate trusted threat-intelligence feeds for URL analysis.
* Add user authentication and persistent scan history.
* Improve detection performance through rigorous testing and evaluation.
* Integrate a generative AI assistant with appropriate safety controls.
* Add automated tests, logging, and monitoring.

## ⚠️ Limitations and Disclaimer

CyberShield 360 is an educational prototype. Its machine-learning models were trained on small illustrative datasets, and its login analyzer uses rule-based scoring. Predictions may be incorrect and must not be treated as definitive proof that a URL or message is safe or malicious.

Do not enter real passwords, OTPs, confidential information, or sensitive personal data. Verify suspicious links and messages independently.

## 👩‍💻 Project

**Project Name:** CyberShield 360
**Domain:** Digital Safety & Cybersecurity
**Repository:** https://github.com/Mahi-1710/CyberShield360
**Live Demo:** https://cybershield360-59sj.onrender.com
