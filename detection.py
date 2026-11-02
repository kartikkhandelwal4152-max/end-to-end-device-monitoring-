"""Explicitly trained per-device Isolation Forest; no automatic baseline poisoning.

Note on ML Interpretation:
- Isolation Forest anomaly scores (decision_function) measure outlier distance from baseline telemetry.
- Anomaly scores are NOT attack probabilities or confidence scores.
- The contamination parameter (e.g., 0.03) represents an assumption regarding outlier prevalence in
  the training baseline; it MUST NOT be represented as '97% accuracy'.
- Without ground-truth labelled evaluation datasets, real-world detection accuracy remains unverified.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

COLUMNS = ['cpu', 'ram', 'process_count', 'connections', 'bytes_per_second']
FEATURES = COLUMNS + ['cpu_delta', 'connections_delta']


def feature_frame(samples):
    df = pd.DataFrame(samples)
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    frame = df[COLUMNS].astype(float).fillna(0.0)

    # Time-aware delta: if 'observed' timestamps are provided, normalize by dt
    if 'observed' in df.columns:
        dt = df['observed'].diff().fillna(15.0).clip(lower=1.0)
    else:
        dt = 15.0

    frame['cpu_delta'] = (frame['cpu'].diff().fillna(0.0) / dt).clip(-100.0, 100.0)
    frame['connections_delta'] = (frame['connections'].diff().fillna(0.0) / dt).clip(-1000.0, 1000.0)
    return frame[FEATURES]


def train(samples, contamination=0.03, random_state=42):
    if len(samples) < 30:
        raise ValueError('At least 30 complete samples are required for training.')
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=1
    )
    model.fit(feature_frame(samples))
    return model


def score(model, sample, previous=None):
    """
    Score a single telemetry sample against the Isolation Forest model.
    Returns (anomaly_score, is_anomalous).
    - anomaly_score: float decision_function value (lower/negative = more anomalous outlier).
    - is_anomalous: bool indicating whether the sample falls outside the model's inlier boundary.
    Note: is_anomalous denotes an unsupervised metric outlier, NOT a confirmed security intrusion.
    """
    frame = feature_frame([previous, sample] if previous else [sample]).iloc[[-1]]
    value = float(model.decision_function(frame)[0])
    if not np.isfinite(value):
        raise ValueError('Non-finite model score')
    is_anomaly = bool(model.predict(frame)[0] == -1)
    return value, is_anomaly


def evaluate_model(model, eval_samples, ground_truth_labels=None):
    """
    Evaluate Isolation Forest model against a test dataset.
    If ground_truth_labels (binary list: 0=normal, 1=attack) are provided, calculates
    precision, recall, F1-score, false positive rate, and estimated false alerts per device/day.
    If unlabelled, explicitly returns that accuracy remains unverified.
    """
    features = feature_frame(eval_samples)
    preds = model.predict(features)
    pred_anomalies = (preds == -1).astype(int)
    scores = model.decision_function(features)

    if ground_truth_labels is None:
        return {
            'accuracy_verified': False,
            'evaluation_status': 'UNVERIFIED',
            'sample_count': len(features),
            'anomaly_ratio': round(float(np.mean(pred_anomalies)), 4),
            'mean_anomaly_score': round(float(np.mean(scores)), 4),
            'accuracy_disclaimer': (
                "Detection accuracy remains unverified: no ground-truth labelled attack dataset was provided. "
                "Contamination parameter represents an outlier threshold assumption, NOT a 97% detection accuracy."
            )
        }

    y_true = np.array(ground_truth_labels, dtype=int)
    if len(y_true) != len(features):
        raise ValueError(f"Label count ({len(y_true)}) must match sample count ({len(features)})")

    tp = int(np.sum((pred_anomalies == 1) & (y_true == 1)))
    fp = int(np.sum((pred_anomalies == 1) & (y_true == 0)))
    fn = int(np.sum((pred_anomalies == 0) & (y_true == 1)))
    tn = int(np.sum((pred_anomalies == 0) & (y_true == 0)))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # 15s sampling cadence = 5760 samples per device/day
    est_false_alerts_per_day = float(fpr * 5760)

    return {
        'accuracy_verified': True,
        'evaluation_status': 'VERIFIED_LABELLED',
        'sample_count': len(features),
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn,
        'true_negatives': tn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1_score': round(f1, 4),
        'false_positive_rate': round(fpr, 4),
        'estimated_false_alerts_per_device_day': round(est_false_alerts_per_day, 1)
    }
