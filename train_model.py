
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# Small starter dataset for demonstration.
# 1 = Scam, 0 = Genuine
data = [
    ("Your account is blocked. Verify your account immediately.", 1),
    ("Congratulations you won a free prize. Click here to claim.", 1),
    ("Share your OTP to receive your reward.", 1),
    ("Urgent! Update your bank details now.", 1),
    ("Your KYC has expired. Click this link immediately.", 1),
    ("You won a lottery. Send your card number to claim.", 1),
    ("Your account is suspended. Verify your password.", 1),
    ("Send OTP now to avoid account closure.", 1),
    ("Claim your free gift by clicking this link.", 1),
    ("Your bank account needs immediate verification.", 1),
    ("We detected unusual activity. Confirm your PIN now.", 1),
    ("You are selected as a winner. Claim your prize.", 1),
    ("Please share your password to unlock your account.", 1),
    ("Your payment failed. Update your card details here.", 1),
    ("Act now to receive your free reward.", 1),
    ("Your package is held. Pay the fee using this link.", 1),
    ("Your account will be blocked. Verify your details.", 1),
    ("Send your bank details to receive the lottery money.", 1),
    ("Click here to update your KYC immediately.", 1),
    ("Your account has a problem. Share your OTP.", 1),

    ("Hi, are we still meeting for lunch today?", 0),
    ("Your appointment is confirmed for tomorrow.", 0),
    ("The class starts at 10 AM in room 204.", 0),
    ("Please send me the assignment when you can.", 0),
    ("Thank you for your help with the project.", 0),
    ("Your order has been shipped by the store.", 0),
    ("The meeting has been moved to Friday.", 0),
    ("Can you call me when you are available?", 0),
    ("Please find the notes attached to this email.", 0),
    ("Your electricity bill is available in the official app.", 0),
    ("I will reach college in fifteen minutes.", 0),
    ("The project presentation is scheduled for Monday.", 0),
    ("Thanks for attending today's online class.", 0),
    ("Your library book is due next week.", 0),
    ("Let's discuss the project after the lecture.", 0),
    ("Your ticket booking confirmation is ready.", 0),
    ("Please review the document before the meeting.", 0),
    ("I have shared the study material with you.", 0),
    ("The exam timetable is available on the college website.", 0),
    ("Happy birthday! Hope you have a great day.", 0),
]

df = pd.DataFrame(data, columns=["message", "label"])

X_train, X_test, y_train, y_test = train_test_split(
    df["message"],
    df["label"],
    test_size=0.25,
    random_state=42,
    stratify=df["label"]
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        sublinear_tf=True
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    ))
])

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("Model training completed!")
print("Test accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Genuine", "Scam"],
    zero_division=0
))

# Save the trained model in the project folder.
joblib.dump(model, "scam_message_model.joblib")
print("\nSaved model as scam_message_model.joblib")python train_model.py