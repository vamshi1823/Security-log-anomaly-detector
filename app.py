"""
Flask backend for the Security Log Anomaly Detector.

Serves:
  GET  /                  -> dashboard (index.html)
  GET  /api/logs          -> paginated scored logs (JSON)
  GET  /api/stats         -> summary stats for the dashboard header
  POST /api/score         -> score a single new log record on demand
"""

from flask import Flask, jsonify, request, render_template
import pandas as pd
import numpy as np
import joblib
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
bundle = joblib.load(os.path.join(BASE_DIR, "model", "anomaly_model.pkl"))
MODEL = bundle["model"]
EVENT_ENCODER = bundle["event_encoder"]
FEATURES = bundle["features"]

logs_df = pd.read_csv(os.path.join(BASE_DIR, "data", "scored_logs.csv"), parse_dates=["timestamp"])
logs_df = logs_df.sort_values("timestamp", ascending=False).reset_index(drop=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    total = len(logs_df)
    anomalies = int((logs_df["predicted"] == "anomaly").sum())
    return jsonify({
        "total_logs": total,
        "anomalies_detected": anomalies,
        "anomaly_rate": round(anomalies / total * 100, 2) if total else 0,
        "unique_users": int(logs_df["user_id"].nunique()),
    })


@app.route("/api/logs")
def get_logs():
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 50))
    filter_type = request.args.get("filter", "all")  # all | anomaly | normal

    filtered = logs_df
    if filter_type in ("anomaly", "normal"):
        filtered = logs_df[logs_df["predicted"] == filter_type]

    start = (page - 1) * page_size
    end = start + page_size
    page_data = filtered.iloc[start:end].copy()
    page_data["timestamp"] = page_data["timestamp"].astype(str)

    return jsonify({
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "records": page_data.to_dict(orient="records"),
    })


@app.route("/api/score", methods=["POST"])
def score_record():
    """Score an arbitrary new log record submitted as JSON."""
    payload = request.get_json(force=True)
    try:
        event_enc = EVENT_ENCODER.transform([payload["event_type"]])[0]
    except ValueError:
        event_enc = 0  # unseen event type, default bucket

    row = pd.DataFrame([{
        "bytes_transferred": payload.get("bytes_transferred", 0),
        "failed_logins_last_hour": payload.get("failed_logins_last_hour", 0),
        "session_duration_min": payload.get("session_duration_min", 1),
        "hour_of_day": payload.get("hour_of_day", 12),
        "is_foreign_rare": payload.get("is_foreign_rare", 0),
        "event_type_enc": event_enc,
    }])[FEATURES]

    pred = MODEL.predict(row)[0]
    score = float(-MODEL.decision_function(row)[0])

    return jsonify({
        "prediction": "anomaly" if pred == -1 else "normal",
        "anomaly_score": round(score, 4),
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
