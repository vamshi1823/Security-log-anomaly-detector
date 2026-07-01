"""
Train an Isolation Forest anomaly detector on security log features.

Isolation Forest is well-suited here because:
  - It doesn't require labeled anomalies to train (unsupervised) - realistic,
    since real security teams rarely have clean labeled attack data
  - It scales well to streaming/high-volume log data
  - It naturally handles the "rare event" nature of security anomalies

We DO have labels in this synthetic set (since we generated them), so we use
them only for evaluation - the model itself trains unsupervised, which mirrors
how this would work on real, mostly-unlabeled production log data.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib

df = pd.read_csv("data/security_logs.csv", parse_dates=["timestamp"])

# --- Feature engineering ---
le_event = LabelEncoder()
df["event_type_enc"] = le_event.fit_transform(df["event_type"])

FEATURES = [
    "bytes_transferred",
    "failed_logins_last_hour",
    "session_duration_min",
    "hour_of_day",
    "is_foreign_rare",
    "event_type_enc",
]

X = df[FEATURES]

# contamination = expected anomaly proportion; matches our known injection rate
model = IsolationForest(
    n_estimators=200,
    contamination=300 / 4800,
    random_state=42,
    n_jobs=-1,
)
model.fit(X)

# -1 = anomaly, 1 = normal (sklearn convention) -> flip to match our labels
df["predicted"] = np.where(model.predict(X) == -1, "anomaly", "normal")
df["anomaly_score"] = -model.decision_function(X)  # higher = more anomalous

print("=== Evaluation against known synthetic labels ===")
print(classification_report(df["label"], df["predicted"]))
print("Confusion matrix (rows=actual, cols=predicted):")
print(confusion_matrix(df["label"], df["predicted"], labels=["normal", "anomaly"]))

# Save model + encoder + feature list together
joblib.dump({
    "model": model,
    "event_encoder": le_event,
    "features": FEATURES,
}, "model/anomaly_model.pkl")

# Save scored dataset for the dashboard to serve
df.to_csv("data/scored_logs.csv", index=False)

print("\nModel saved to model/anomaly_model.pkl")
print("Scored logs saved to data/scored_logs.csv")
