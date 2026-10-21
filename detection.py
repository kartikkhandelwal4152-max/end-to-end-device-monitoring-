"""Explicitly trained per-device Isolation Forest; no automatic baseline poisoning."""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

COLUMNS = ['cpu', 'ram', 'process_count', 'connections', 'bytes_per_second']
FEATURES = COLUMNS + ['cpu_delta', 'connections_delta']


def feature_frame(samples):
    frame = pd.DataFrame(samples)[COLUMNS].astype(float)
    frame['cpu_delta'] = frame.cpu.diff().fillna(0)
    frame['connections_delta'] = frame.connections.diff().fillna(0)
    return frame[FEATURES]


def train(samples):
    if len(samples) < 30:
        raise ValueError('At least 30 complete samples are required for training.')
    model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42, n_jobs=1)
    model.fit(feature_frame(samples))
    return model


def score(model, sample, previous=None):
    frame = feature_frame([previous, sample] if previous else [sample]).iloc[[-1]]
    value = float(model.decision_function(frame)[0])
    if not np.isfinite(value):
        raise ValueError('Non-finite model score')
    return value, bool(model.predict(frame)[0] == -1)
