"""Quantitative evaluation of the prototype.

Runs a labelled mix of normal sessions and attack scenarios through the live
decision engine (without persisting the evaluation traffic), computes binary
detection metrics, and measures real local timings:

* decision latency - wall-clock time inside the risk engine;
* authentication overhead - PBKDF2 verification cost for the configured work
  factor;
* protected-service latency - a local read-only resource lookup performing the
  same database work a protected handler would.

Availability is the proportion of evaluation requests that produced a decision
without an engine error. These are single-process, single-host measurements;
they are useful for comparing normal vs. attack conditions, not as absolute
production SLAs.
"""

from __future__ import annotations

import json
import statistics
import time
from datetime import datetime, timezone
from typing import Any

from . import anomaly, database, security, simulator


def _binary_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    tp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 1)
    fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 1)
    tn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 0)
    fn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 0)
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else 0.0,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total": total,
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def _auth_overhead_ms(rounds: int = 8) -> float:
    with database.get_db() as conn:
        user = database.row(conn, "SELECT password_hash FROM users ORDER BY id LIMIT 1")
    if not user:
        return 0.0
    started = time.perf_counter()
    for _ in range(rounds):
        security.verify_password("not-the-real-password", user["password_hash"])
    return round((time.perf_counter() - started) * 1000 / rounds, 3)


def _service_latency_ms(rounds: int = 25) -> float:
    started = time.perf_counter()
    for _ in range(rounds):
        with database.get_db() as conn:
            payload = database.rows(
                conn,
                "SELECT id, name, zone, sensitivity, service FROM resources ORDER BY id",
            )
        json.dumps({"count": len(payload), "items": payload[:6]})
    return round((time.perf_counter() - started) * 1000 / rounds, 3)


def run_evaluation(
    name: str = "Baseline evaluation",
    *,
    normal_samples: int = 140,
    variants: int = 3,
    persist_run: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    model = anomaly.get_model()
    normal_results = simulator.run_normal(normal_samples, persist=False, seed=2026)
    attack_results: list[dict[str, Any]] = []
    per_scenario: list[dict[str, Any]] = []
    engine_errors = 0
    total_requests = 0

    for scenario in simulator.SCENARIOS:
        try:
            results = simulator.run_scenario(scenario["id"], variants=variants, persist=False)
        except Exception:  # pragma: no cover - defensive, surfaced in availability
            engine_errors += 1
            continue
        total_requests += len(results)
        attack_results.extend(results)
        primary = results[0]
        per_scenario.append(
            {
                "id": scenario["id"],
                "name": scenario["name"],
                "technique": scenario["technique"],
                "severity": scenario["severity"],
                "decision": primary["decision"],
                "risk_score": primary["risk_score"],
                "anomaly_score": primary["anomaly_score"],
                "detected": primary["decision"] != "ALLOW",
                "contained": primary["decision"] in ("RESTRICT", "BLOCK"),
            }
        )

    total_requests += len(normal_results)
    all_results = normal_results + attack_results
    y_true = [0] * len(normal_results) + [1] * len(attack_results)
    y_pred = [1 if result["decision"] != "ALLOW" else 0 for result in all_results]
    y_anomaly = [
        1 if result["anomaly_score"] >= model.threshold else 0 for result in all_results
    ]
    decisions = {key: 0 for key in ("ALLOW", "CHALLENGE", "RESTRICT", "BLOCK")}
    for result in all_results:
        decisions[result["decision"]] = decisions.get(result["decision"], 0) + 1

    latencies = [result["latency_ms"] for result in all_results]
    threshold = model.threshold
    metrics = {
        "name": name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "samples": {
            "total": len(all_results),
            "normal": len(normal_results),
            "attack": len(attack_results),
        },
        "detection": _binary_metrics(y_true, y_pred),
        "anomaly_detection": _binary_metrics(y_true, y_anomaly),
        "decisions": decisions,
        "latency": {
            "decision_avg_ms": round(statistics.fmean(latencies), 2) if latencies else 0.0,
            "decision_p50_ms": round(_percentile(latencies, 0.50), 2),
            "decision_p95_ms": round(_percentile(latencies, 0.95), 2),
            "decision_max_ms": round(max(latencies), 2) if latencies else 0.0,
            "auth_overhead_ms": _auth_overhead_ms(),
            "service_latency_ms": _service_latency_ms(),
        },
        "availability": {
            "successful": total_requests - engine_errors,
            "total": total_requests,
            "rate": round((total_requests - engine_errors) / total_requests * 100, 2)
            if total_requests else 0.0,
            "engine_errors": engine_errors,
        },
        "model": {
            "algorithm": "IsolationForest + contextual rules",
            "threshold": round(threshold, 4),
            "trained_at": model.trained_at,
            "baseline_samples": model.samples,
        },
        "per_scenario": per_scenario,
    }
    metrics["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)

    if persist_run:
        with database.get_db() as conn:
            cursor = conn.execute(
                """INSERT INTO eval_runs (ts, name, samples, metrics, config, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    metrics["generated_at"],
                    name,
                    len(all_results),
                    json.dumps(metrics),
                    json.dumps(
                        {
                            "normal_samples": normal_samples,
                            "variants": variants,
                            "thresholds": database.engine_config()["thresholds"],
                        }
                    ),
                    metrics["duration_ms"],
                ),
            )
            metrics["run_id"] = int(cursor.lastrowid)
            # The full per-scenario detail is included so the admin can audit a
            # historical run without re-executing the simulation.
    return metrics


def list_runs(limit: int = 20) -> list[dict[str, Any]]:
    with database.get_db() as conn:
        rows = database.rows(
            conn,
            "SELECT id, ts, name, samples, duration_ms, metrics FROM eval_runs "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    results = []
    for row in rows:
        try:
            metrics = json.loads(row["metrics"])
        except json.JSONDecodeError:
            metrics = {}
        detection = metrics.get("detection", {})
        results.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "name": row["name"],
                "samples": row["samples"],
                "duration_ms": row["duration_ms"],
                "accuracy": detection.get("accuracy"),
                "false_positive_rate": detection.get("false_positive_rate"),
                "false_negative_rate": detection.get("false_negative_rate"),
            }
        )
    return results


def get_run(run_id: int) -> dict[str, Any] | None:
    with database.get_db() as conn:
        row = database.row(conn, "SELECT * FROM eval_runs WHERE id = ?", (run_id,))
    if not row:
        return None
    try:
        metrics = json.loads(row["metrics"])
    except json.JSONDecodeError:
        metrics = {}
    metrics["run_id"] = row["id"]
    metrics["duration_ms"] = row["duration_ms"]
    return metrics
