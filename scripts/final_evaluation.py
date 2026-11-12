"""Final evaluation run (Task D). Uses the project's own evaluation.run_evaluation
on a fresh throw-away data directory, plus a per-variant dump of every attack
scenario (same generator, persist=False). Writes JSON to argv[2].

usage (from the repository root):  python scripts/final_evaluation.py [out.json] [label]

Nothing in data/ is read or written: a temporary data directory is used.
"""
import json
import os
import platform
import sys
import tempfile
from pathlib import Path
import time
from datetime import datetime, timezone

root = str(Path(__file__).resolve().parent.parent)
out = sys.argv[1] if len(sys.argv) > 1 else "docs/evidence/final_evaluation.json"
label = sys.argv[2] if len(sys.argv) > 2 else "run"
for k in [k for k in os.environ if k.startswith("ZT_")]:
    del os.environ[k]
data = tempfile.mkdtemp(prefix="zt-final-eval-")
os.environ["ZT_DATA_DIR"] = data  # default PBKDF2 work factor (120,000) on purpose
sys.path.insert(0, root)
from app import anomaly, config, database, evaluation, risk, seed, simulator  # noqa: E402

seed.seed_identity()
model = anomaly.get_model()
t0 = time.perf_counter()
metrics = evaluation.run_evaluation("Final evaluation", normal_samples=140, variants=3, persist_run=False)
wall = time.perf_counter() - t0

scenarios = []
for scenario in simulator.SCENARIOS:
    results = simulator.run_scenario(scenario["id"], variants=3, persist=False)
    variants = []
    for r in results:
        ctx = {k: r["context"][k] for k in ("geo", "hour", "requests_last_5m", "failed_attempts_24h", "bytes_out_mb",
                                            "session_minutes", "concurrent_sessions", "new_device", "mfa_verified",
                                            "threat_intel")}
        variants.append({
            "context": ctx,
            "risk_score": r["risk_score"],
            "base_risk": r["base_risk"],
            "anomaly_score": r["anomaly_score"],
            "anomaly_flag": bool(r["anomaly_score"] >= model.threshold),
            "isolation_score": r["anomaly"]["isolation_score"],
            "isolation_flag": bool(r["anomaly"]["isolation_score"] >= model.threshold),
            "rule_hits": [h["reason"] for h in r["anomaly"]["rule_hits"]],
            "decision": r["decision"],
            "detected": r["decision"] != "ALLOW",
            "contained": r["decision"] in ("RESTRICT", "BLOCK"),
            "top_reasons": [x["text"] for x in r["reasons"][:3]],
        })
    scenarios.append({
        "id": scenario["id"], "name": scenario["name"], "technique": scenario["technique"],
        "severity": scenario["severity"], "ground_truth": "attack (1)",
        "subject": scenario["user_email"].split("@")[0], "device": scenario["device_name"],
        "resource": scenario["resource"], "hour_fixed_in_scenario": "hour" in scenario["context"],
        "variants": variants,
    })

normal = simulator.run_normal(140, persist=False, seed=2026)
attack_all = [r for s in simulator.SCENARIOS for r in simulator.run_scenario(s["id"], variants=3, persist=False)]
iso_metrics = evaluation._binary_metrics([0] * len(normal) + [1] * len(attack_all),
                                         [1 if r["anomaly"]["isolation_score"] >= model.threshold else 0
                                          for r in normal + attack_all])
normal_fp = [{"subject": r["user"]["role"], "resource": r["resource"]["name"], "decision": r["decision"],
              "risk_score": r["risk_score"]} for r in normal if r["decision"] != "ALLOW"]

json.dump({
    "label": label,
    "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "environment": {"python": platform.python_version(), "platform": platform.platform(),
                    "processor": platform.processor(), "pbkdf2_iterations": config.PBKDF2_ITERATIONS},
    "configuration": {"normal_samples": 140, "variants_per_scenario": 3, "normal_seed": 2026,
                      "model_seed": 7, "model_samples": model.samples, "model_contamination": model.contamination,
                      "anomaly_threshold": round(model.threshold, 4),
                      "thresholds": database.engine_config()["thresholds"],
                      "weights": database.engine_config()["weights"]},
    "evaluation_wall_seconds": round(wall, 2),
    "metrics": metrics,
    "isolation_forest_only": iso_metrics,
    "scenarios": scenarios,
    "normal_false_positives": normal_fp,
}, open(out, "w", encoding="utf-8"), indent=2)
d = metrics["detection"]
a = metrics["anomaly_detection"]
print(label, "engine:", {k: d[k] for k in ("accuracy", "precision", "recall", "f1", "false_positive_rate",
                                           "false_negative_rate", "tp", "fp", "tn", "fn")})
print(label, "anomaly:", {k: a[k] for k in ("accuracy", "precision", "recall", "f1", "false_positive_rate",
                                            "false_negative_rate", "tp", "fp", "tn", "fn")})
print(label, "IF-only:", {k: iso_metrics[k] for k in ("accuracy", "precision", "recall", "f1", "false_positive_rate",
                                                     "false_negative_rate", "tp", "fp", "tn", "fn")})
print(label, "decisions:", metrics["decisions"], "latency:", metrics["latency"], "availability:", metrics["availability"])
