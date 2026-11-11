"""Behavioural anomaly detection.

A hybrid detector is used:

1. An IsolationForest learns the shape of normal behaviour from a synthetic
   baseline of access sessions (login hour, request rate, geo distance,
   failures, device trust, egress volume, session length, resource
   sensitivity, new-device flag).
2. Contextual rules raise the score for behaviours that are unambiguous
   indicators of attack regardless of the model's density estimate
   (impossible travel, high failure counts, mass egress, request floods).

Rule contributions are surfaced as human-readable factors, which is important
for a risk-adaptive engine: the decision must be explainable to an analyst.
"""

from __future__ import annotations

import logging
import math
import operator
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from . import config

logger = logging.getLogger(__name__)

FEATURES = [
    "hour",
    "requests_last_5m",
    "geo_distance_km",
    "failed_attempts_24h",
    "device_trust",
    "bytes_out_mb",
    "session_minutes",
    "sensitivity",
    "new_device",
]

FEATURE_LABELS = {
    "hour": "Login hour",
    "requests_last_5m": "Requests / 5 min",
    "geo_distance_km": "Geo distance from home",
    "failed_attempts_24h": "Failed logins (24 h)",
    "device_trust": "Device trust score",
    "bytes_out_mb": "Egress volume (MB)",
    "session_minutes": "Session duration (min)",
    "sensitivity": "Resource sensitivity",
    "new_device": "New device",
}

SENSITIVITY_LEVEL = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Default contextual rule overrides. Each tuple is (condition, floor, reason).
RULES: list[tuple[str, float, str]] = [
    ("geo_distance_km>=1500", 0.80, "Impossible-travel distance from the usual location"),
    ("geo_distance_km>=3000", 0.92, "Intercontinental access from an unexpected location"),
    ("failed_attempts_24h>=6", 0.78, "High failed-authentication count in the last 24 hours"),
    ("requests_last_5m>=40", 0.74, "Access-request rate far above the user baseline"),
    ("bytes_out_mb>=250", 0.82, "Mass data egress compared with the baseline"),
    ("hour<=5", 0.55, "Access outside the user's normal working hours"),
    ("new_device==1", 0.42, "Unrecognised device fingerprint"),
]


def baseline_samples(n: int = 1200, seed: int = 7) -> np.ndarray:
    """Deterministic synthetic corpus of *normal* access sessions.

    Values are drawn from realistic office-usage distributions. The generator
    is seeded so that reported metrics are reproducible.
    """
    rng = np.random.default_rng(seed)
    # The baseline deliberately includes the legitimate spread of the estate:
    # occasional early shifts, travel to the secondary office, and older or
    # unmanaged devices. A narrow "perfect employee" baseline would label most
    # real users as anomalies.
    hour = np.where(
        rng.random(n) < 0.12,
        rng.uniform(1, 6, n),
        np.clip(rng.normal(13.5, 2.4, n), 7, 21),
    )
    requests = np.clip(rng.lognormal(1.45, 0.5, n), 1, 25)
    geo = np.where(
        rng.random(n) < 0.16,
        np.clip(rng.normal(290, 40, n), 0, 420),
        np.clip(rng.exponential(30, n), 0, 220),
    )
    failed = np.clip(rng.poisson(0.35, n), 0, 4)
    low_trust = rng.random(n) < 0.20
    trust = np.where(
        low_trust,
        np.clip(rng.normal(60, 16, n), 25, 100),
        np.clip(rng.normal(88, 7, n), 55, 100),
    )
    egress = np.clip(rng.lognormal(2.9, 0.55, n), 2, 150)
    session = np.clip(rng.lognormal(3.6, 0.5, n), 5, 200)
    sensitivity = rng.integers(1, 5, n).astype(float)
    new_device = (rng.random(n) < 0.03).astype(float)
    return np.column_stack(
        [hour, requests, geo, failed, trust, egress, session, sensitivity, new_device]
    )


class BehaviourModel:
    def __init__(self, payload: dict[str, Any]):
        self.model: IsolationForest = payload["model"]
        self.min_score: float = float(payload["min_score"])
        self.max_score: float = float(payload["max_score"])
        self.baseline_mean: np.ndarray = np.asarray(payload["baseline_mean"], dtype=float)
        self.baseline_std: np.ndarray = np.asarray(payload["baseline_std"], dtype=float)
        self.threshold: float = float(payload["threshold"])
        self.trained_at: str = str(payload["trained_at"])
        self.samples: int = int(payload["samples"])
        self.contamination: float = float(payload.get("contamination", 0.04))

    # -- persistence -----------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None) -> "BehaviourModel | None":
        target = path or config.MODEL_PATH
        if not target.exists():
            return None
        try:
            payload = joblib.load(target)
        except Exception:
            return None
        if not isinstance(payload, dict) or "model" not in payload:
            return None
        return cls(payload)

    def save(self, path: Path | None = None) -> None:
        target = path or config.MODEL_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "min_score": self.min_score,
                "max_score": self.max_score,
                "baseline_mean": self.baseline_mean,
                "baseline_std": self.baseline_std,
                "threshold": self.threshold,
                "trained_at": self.trained_at,
                "samples": self.samples,
                "contamination": self.contamination,
                "features": FEATURES,
            },
            target,
        )

    # -- scoring ---------------------------------------------------------
    def score(self, vector: dict[str, float]) -> dict[str, Any]:
        x = np.array([float(vector.get(name, 0.0)) for name in FEATURES], dtype=float)
        raw = -float(self.model.score_samples(x.reshape(1, -1))[0])
        span = max(self.max_score - self.min_score, 1e-9)
        isolation = float(np.clip((raw - self.min_score) / span, 0.0, 1.0))

        score = isolation
        triggered: list[dict[str, Any]] = []
        for expression, floor, reason in RULES:
            if _rule_matches(expression, vector) and floor > score:
                score = floor
                triggered.append({"rule": expression, "reason": reason, "floor": floor})

        z = (x - self.baseline_mean) / np.where(self.baseline_std < 1e-9, 1.0, self.baseline_std)
        contributions = []
        for index, (name, z_value) in enumerate(zip(FEATURES, z)):
            if z_value > 0.75:
                contributions.append(
                    {
                        "feature": name,
                        "label": FEATURE_LABELS[name],
                        "value": round(float(x[index]), 2),
                        "baseline": round(float(self.baseline_mean[index]), 2),
                        "z": round(float(z_value), 2),
                    }
                )
        contributions.sort(key=lambda item: item["z"], reverse=True)

        return {
            "score": round(float(np.clip(score, 0.0, 1.0)), 4),
            "isolation_score": round(isolation, 4),
            "threshold": round(self.threshold, 4),
            "is_anomaly": bool(score >= self.threshold),
            "rule_hits": triggered,
            "top_factors": contributions[:5],
        }

    def metadata(self) -> dict[str, Any]:
        return {
            "algorithm": "IsolationForest + contextual rules",
            "features": FEATURES,
            "feature_labels": FEATURE_LABELS,
            "samples": self.samples,
            "contamination": self.contamination,
            "threshold": round(self.threshold, 4),
            "trained_at": self.trained_at,
        }


# Rule expressions have the form ``<feature><operator><number>``. They are
# parsed with a strict pattern and a fixed operator table, never evaluated as
# Python, so a malformed rule cannot execute code. Two-character operators come
# first in the alternation so ">=" is not read as ">" followed by "=...".
_RULE_OPERATORS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    ">": operator.gt,
    "<": operator.lt,
}
_RULE_PATTERN = re.compile(
    r"^\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>>=|<=|==|>|<)\s*(?P<value>[-+]?\d+(?:\.\d+)?)\s*$"
)


@lru_cache(maxsize=128)
def _parse_rule(expression: str) -> tuple[str, Callable[[float, float], bool], float] | None:
    """Parse a rule expression into ``(feature, comparison, threshold)``.

    Returns None (and logs once per distinct expression) when the expression
    does not match the supported grammar.
    """
    match = _RULE_PATTERN.match(expression)
    if not match:
        logger.warning("Ignoring malformed anomaly rule expression: %r", expression)
        return None
    return match["field"], _RULE_OPERATORS[match["op"]], float(match["value"])


def _rule_matches(expression: str, vector: dict[str, float]) -> bool:
    """Return True when ``vector`` satisfies the comparison in ``expression``.

    Malformed expressions, missing features and non-numeric or NaN values never
    match, so a bad rule or input cannot crash scoring; it simply applies no
    floor.
    """
    if not isinstance(expression, str):
        return False
    parsed = _parse_rule(expression)
    if parsed is None:
        return False
    field, compare, threshold = parsed
    if field not in vector:
        return False
    try:
        value = float(vector[field])
    except (TypeError, ValueError):
        return False
    if math.isnan(value):
        return False
    return compare(value, threshold)


# Surface malformed built-in rules in the log at import time rather than on the
# first scored request.
for _expression, _floor, _reason in RULES:
    _parse_rule(_expression)


def train(samples: int = 1200, contamination: float = 0.04, seed: int = 7) -> BehaviourModel:
    data = baseline_samples(samples, seed)
    forest = IsolationForest(
        n_estimators=180,
        max_samples="auto",
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    forest.fit(data)
    raw = -forest.score_samples(data)
    # Robust normalisation bounds; avoids a single outlier flattening the scale.
    min_score = float(np.quantile(raw, 0.01))
    max_score = float(np.quantile(raw, 0.99))
    span = max(max_score - min_score, 1e-9)
    normalised = np.clip((raw - min_score) / span, 0.0, 1.0)
    threshold = float(np.clip(np.quantile(normalised, 0.95), 0.35, 0.85))
    model = BehaviourModel(
        {
            "model": forest,
            "min_score": min_score,
            "max_score": max_score,
            "baseline_mean": data.mean(axis=0),
            "baseline_std": data.std(axis=0),
            "threshold": threshold,
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "samples": int(samples),
            "contamination": contamination,
        }
    )
    model.save()
    return model


_MODEL: BehaviourModel | None = None


def get_model() -> BehaviourModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = BehaviourModel.load()
        if _MODEL is None:
            _MODEL = train()
    return _MODEL


def reload_model() -> BehaviourModel:
    global _MODEL
    _MODEL = None
    return get_model()


def retrain(samples: int = 1200, contamination: float = 0.04) -> BehaviourModel:
    global _MODEL
    _MODEL = train(samples=samples, contamination=contamination)
    return _MODEL
