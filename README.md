# Security Log Anomaly Detector

ML-powered anomaly detection for authentication and network access logs, with a full-stack dashboard for triaging flagged events in real time.

**Live demo:** _deploy and add your link here (see Deployment section)_
**Stack:** Python, scikit-learn (Isolation Forest), Flask, Pandas, HTML/CSS/JavaScript (vanilla, no framework)

---

## What it is

A security log anomaly detection system that ingests authentication and network access events, scores each one for anomalous behavior using an unsupervised ML model, and surfaces flagged events through a live web dashboard. Detects patterns consistent with brute-force login attempts, off-hours access from unusual geographies, abnormal data transfer volumes (exfiltration signals), and impossible-travel logins.

## How it works

- **Data layer**: synthetic log generator (`data/generate_logs.py`) produces realistic authentication/network events across 120 simulated users over a 30-day window, with ~6% injected anomalies covering four distinct attack patterns.
- **Model layer**: an Isolation Forest (`model/train_model.py`) trains unsupervised on engineered features (bytes transferred, failed login count, session duration, hour of day, geography rarity, event type) — unsupervised by design, since real security teams rarely have clean labeled attack data to train on. Achieves 95% precision/recall on held-out evaluation against known synthetic labels.
- **Backend**: a Flask API (`app.py`) serves the trained model behind three endpoints — paginated/filterable log retrieval, summary statistics, and on-demand scoring of a new event.
- **Frontend**: a hand-built HTML/CSS/JavaScript dashboard (no Streamlit, no React) — a filterable, paginated log table with anomaly highlighting, live summary stats, and an interactive form to score a hypothetical new event against the trained model in real time.

## Problem it solves

Security operations teams triage thousands of authentication and access log events daily, and manually reviewing all of them for suspicious patterns doesn't scale. This system automates first-pass anomaly scoring so analysts can focus attention on the ~6% of events flagged as statistically unusual, rather than reviewing logs indiscriminately — the same anomaly-detection-at-scale problem underlying production security operations tooling.

---

## Project structure

```
security-log-anomaly-detector/
├── app.py                     # Flask backend + API
├── requirements.txt
├── data/
│   ├── generate_logs.py       # synthetic log generator
│   └── security_logs.csv      # generated dataset (run generator to produce)
├── model/
│   └── train_model.py         # trains + evaluates the Isolation Forest
├── templates/
│   └── index.html             # dashboard markup
└── static/
    ├── css/style.css          # dashboard styling
    └── js/dashboard.js        # dashboard interactivity (fetch API calls)
```

## Running locally (Windows, no Docker)

```bash
# 1. Create a virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate the synthetic dataset
python data/generate_logs.py

# 4. Train the model
python model/train_model.py

# 5. Run the app
python app.py
```

Then open **http://localhost:5000** in your browser.

## Deployment

This is a single Flask service (backend + frontend together), so it deploys cleanly to any single-service host:

- **Render** (free tier): connect the GitHub repo, set build command `pip install -r requirements.txt && python data/generate_logs.py && python model/train_model.py`, start command `gunicorn app:app`
- **Railway / Fly.io**: similar single-service deploy pattern

Add `gunicorn` to `requirements.txt` before deploying (already included below).

## Model evaluation

```
              precision    recall  f1-score   support
     anomaly       0.95      0.95      0.95       300
      normal       1.00      1.00      1.00      4500
    accuracy                           0.99      4800
```

## Honest scope notes

- The dataset is synthetic, generated to reflect realistic log feature distributions and known attack patterns — not real production security data.
- Isolation Forest was chosen over deep learning approaches (e.g., autoencoders) for this scope, given the tabular, low-dimensional feature set — a reasonable production trade-off, though an autoencoder-based approach is a natural extension for higher-dimensional log data.
