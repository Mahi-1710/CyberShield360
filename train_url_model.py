
import re
import ipaddress
import joblib
import pandas as pd

from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


def extract_features(url):
    """Convert a URL into features the model can learn from."""
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


# Demo dataset: 1 = suspicious, 0 = legitimate.
# These are illustrative examples, not a verified threat feed.
data = [
    ("http://secure-login-verify-account.example/login", 1),
    ("http://192.0.2.10/verify-account", 1),
    ("http://free-prize-claim.example/winner", 1),
    ("https://account-password-urgent.example/verify", 1),
    ("http://bank-login-update.example/secure", 1),
    ("https://verify-account.example/login?user=123", 1),
    ("http://claim-free-prize.example/reward", 1),
    ("http://192.0.2.20/update-password", 1),
    ("https://urgent-account-check.example/verify", 1),
    ("http://secure-login.example/account/update", 1),
    ("http://free-gift-winner.example/claim", 1),
    ("https://password-verify.example/login", 1),
    ("http://account-suspended.example/urgent", 1),
    ("https://claim-reward.example/free-prize", 1),
    ("http://verify-bank-account.example/update", 1),
    ("https://login-account.example/confirm?code=12345", 1),
    ("http://192.0.2.30/secure-login", 1),
    ("http://urgent-prize.example/claim-now", 1),
    ("https://update-password.example/verify", 1),
    ("http://account-check.example/login?verify=true", 1),

    ("https://www.wikipedia.org/", 0),
    ("https://www.python.org/", 0),
    ("https://www.google.com/", 0),
    ("https://www.microsoft.com/", 0),
    ("https://www.openai.com/", 0),
    ("https://www.mozilla.org/", 0),
    ("https://www.github.com/", 0),
    ("https://www.nasa.gov/", 0),
    ("https://www.bbc.com/news", 0),
    ("https://www.un.org/", 0),
    ("https://www.apple.com/", 0),
    ("https://www.amazon.com/", 0),
    ("https://www.who.int/", 0),
    ("https://www.python.org/downloads/", 0),
    ("https://docs.python.org/3/", 0),
    ("https://support.microsoft.com/", 0),
    ("https://www.mozilla.org/firefox/", 0),
    ("https://github.com/explore", 0),
    ("https://www.nature.com/", 0),
    ("https://www.nationalgeographic.com/", 0),
]

df = pd.DataFrame(data, columns=["url", "label"])
X = [extract_features(url) for url in df["url"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = Pipeline([
    ("vectorizer", DictVectorizer()),
    ("classifier", RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42
    ))
])

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("URL model training completed!")
print(
    "Test accuracy:",
    round(accuracy_score(y_test, predictions) * 100, 2),
    "%"
)
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Suspicious"],
    zero_division=0
))

joblib.dump(model, "url_model.joblib")
print("Saved model as url_model.joblib")