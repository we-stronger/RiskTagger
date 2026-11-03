"""Adapt saved Tracer results to the Evidence Explainer input files."""
import csv
import json
from collections import Counter
from pathlib import Path

from project_config import EXPLAINER_OUTPUT_ROOT, TRACER_OUTPUT_ROOT


def prepare_evidence_inputs(event_name: str, tracer_root: Path = TRACER_OUTPUT_ROOT,
                            output_root: Path = EXPLAINER_OUTPUT_ROOT):
    root = Path(tracer_root) / event_name
    results_dir = root / "LLM_result" / "llmResult"
    results = sorted(results_dir.glob("*.json"))
    if not results:
        raise FileNotFoundError(f"No Tracer judgments found under {results_dir}")
    layers = {}
    layer_totals = {}
    for seed_file in sorted((root / "data" / "src_addr_token").glob(f"{event_name}_source_addr*.csv")):
        layer = seed_file.stem.rsplit("source_addr", 1)[-1]
        if not layer.isdigit():
            continue
        with seed_file.open(encoding="utf-8-sig", newline="") as file:
            addresses = {row["address"].strip().lower() for row in csv.DictReader(file) if row.get("address")}
        layer_totals[f"Layer{layer}"] = len(addresses)
        for address in addresses:
            layers[address] = min(int(layer), layers.get(address, int(layer)))
    judgments = []
    matrix = {}
    for result_file in results:
        data = json.loads(result_file.read_text(encoding="utf-8"))
        address = data["address"]
        details = data.get("parsed_details", {})
        rationale = " | ".join(
            f"[{key}]: {details[key].get('evidence', '')}"
            for key in ("a_transaction_patterns", "b_fund_flows", "c_associated_addresses", "d_temporal_behavioral_signs")
            if isinstance(details.get(key), dict)
        )
        layer = layers.get(address.lower(), "Unknown")
        risk = data.get("risk_level", "Unknown")
        judgments.append({"address": address, "layer": layer, "risk_level": risk, "cot_rationale": rationale})
        counts = matrix.setdefault(f"Layer{layer}", {})
        counts[risk] = counts.get(risk, 0) + 1
    distribution = {
        "layer_totals": layer_totals,
        "global_risk_totals": dict(Counter(item["risk_level"] for item in judgments)),
        "layer_risk_matrix": matrix,
    }
    output = Path(output_root) / event_name
    output.mkdir(parents=True, exist_ok=True)
    distribution_path = output / "risk_distribution.json"
    reasoner_path = output / "reasoner_evidence.json"
    distribution_path.write_text(json.dumps(distribution, ensure_ascii=False, indent=2), encoding="utf-8")
    reasoner_path.write_text(json.dumps(judgments, ensure_ascii=False, indent=2), encoding="utf-8")
    return distribution_path, reasoner_path
