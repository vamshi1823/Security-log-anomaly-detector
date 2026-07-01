"""
Synthetic security log generator.

Simulates authentication and network access logs for a mid-size org,
with ~6% injected anomalies representing real attack patterns:
  - Brute force login attempts (many failed logins, short time window)
  - Off-hours access from unusual geographies
  - Data exfiltration (abnormally large outbound transfer)
  - Impossible travel (same user, two distant locations, short time gap)

Output: data/security_logs.csv
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random

random.seed(42)
np.random.seed(42)

N_NORMAL = 4500
N_ANOMALY = 300  # ~6.25% anomaly rate, realistic for a labeled training set

USERS = [f"user_{i:03d}" for i in range(1, 121)]
COUNTRIES = ["US", "US", "US", "US", "CA", "GB", "DE", "IN", "AU"]  # weighted toward US (home base)
RARE_COUNTRIES = ["RU", "KP", "IR", "BR", "NG", "CN"]
EVENT_TYPES = ["login", "file_access", "api_call", "vpn_connect", "data_transfer"]

START = datetime(2026, 6, 1)
DAYS = 30


def business_hours_timestamp():
    day_offset = random.randint(0, DAYS - 1)
    hour = np.random.normal(loc=13, scale=3)  # centered on 1pm, business hours
    hour = int(np.clip(hour, 6, 22))
    minute = random.randint(0, 59)
    return START + timedelta(days=day_offset, hours=hour, minutes=minute)


def off_hours_timestamp():
    day_offset = random.randint(0, DAYS - 1)
    hour = random.choice(list(range(0, 5)) + list(range(23, 24)))
    minute = random.randint(0, 59)
    return START + timedelta(days=day_offset, hours=hour, minutes=minute)


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


rows = []

# --- Normal traffic ---
for _ in range(N_NORMAL):
    user = random.choice(USERS)
    ts = business_hours_timestamp()
    event = random.choice(EVENT_TYPES)
    bytes_transferred = int(np.random.lognormal(mean=8, sigma=1.2))  # small-to-moderate transfers
    failed_logins = np.random.poisson(0.15)  # occasional single fumbled password
    country = random.choice(COUNTRIES)
    rows.append({
        "timestamp": ts,
        "user_id": user,
        "source_ip": random_ip(),
        "country": country,
        "event_type": event,
        "bytes_transferred": bytes_transferred,
        "failed_logins_last_hour": min(failed_logins, 2),
        "session_duration_min": max(1, int(np.random.normal(25, 15))),
        "label": "normal",
    })

# --- Anomalies ---
anomaly_types = ["brute_force", "off_hours_foreign", "data_exfil", "impossible_travel"]
for _ in range(N_ANOMALY):
    kind = random.choice(anomaly_types)
    user = random.choice(USERS)

    if kind == "brute_force":
        ts = business_hours_timestamp()
        rows.append({
            "timestamp": ts, "user_id": user, "source_ip": random_ip(),
            "country": random.choice(COUNTRIES), "event_type": "login",
            "bytes_transferred": int(np.random.lognormal(6, 1)),
            "failed_logins_last_hour": random.randint(8, 40),
            "session_duration_min": random.randint(1, 5),
            "label": "anomaly",
        })
    elif kind == "off_hours_foreign":
        ts = off_hours_timestamp()
        rows.append({
            "timestamp": ts, "user_id": user, "source_ip": random_ip(),
            "country": random.choice(RARE_COUNTRIES), "event_type": random.choice(["login", "vpn_connect", "file_access"]),
            "bytes_transferred": int(np.random.lognormal(9, 1.5)),
            "failed_logins_last_hour": np.random.poisson(1),
            "session_duration_min": random.randint(1, 10),
            "label": "anomaly",
        })
    elif kind == "data_exfil":
        ts = random.choice([business_hours_timestamp(), off_hours_timestamp()])
        rows.append({
            "timestamp": ts, "user_id": user, "source_ip": random_ip(),
            "country": random.choice(COUNTRIES), "event_type": "data_transfer",
            "bytes_transferred": int(np.random.lognormal(15, 1)),  # huge transfer, orders of magnitude above normal
            "failed_logins_last_hour": 0,
            "session_duration_min": random.randint(30, 120),
            "label": "anomaly",
        })
    else:  # impossible_travel
        ts = business_hours_timestamp()
        rows.append({
            "timestamp": ts, "user_id": user, "source_ip": random_ip(),
            "country": random.choice(RARE_COUNTRIES), "event_type": "login",
            "bytes_transferred": int(np.random.lognormal(7, 1)),
            "failed_logins_last_hour": 0,
            "session_duration_min": random.randint(1, 8),
            "label": "anomaly",
        })

df = pd.DataFrame(rows)
df = df.sort_values("timestamp").reset_index(drop=True)
df["hour_of_day"] = df["timestamp"].dt.hour
df["is_foreign_rare"] = df["country"].isin(RARE_COUNTRIES).astype(int)

out_path = "data/security_logs.csv"
df.to_csv(out_path, index=False)
print(f"Generated {len(df)} log records ({N_ANOMALY} anomalies, {N_NORMAL} normal) -> {out_path}")
print(df["label"].value_counts())
