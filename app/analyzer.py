from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from math import ceil
from typing import Any

from .attack import AttackDataset
from .d3fend import D3fendDataset
from .heuristics import HEURISTIC_RULES


class MitreAnalyzer:
    def __init__(self, attack_dataset: AttackDataset, d3fend_dataset: D3fendDataset) -> None:
        self.attack_dataset = attack_dataset
        self.d3fend_dataset = d3fend_dataset
        self.compiled_rules = [
            {
                **rule,
                "compiled_patterns": [re.compile(pattern, re.IGNORECASE) for pattern in rule["match_any"]],
                "compiled_context_patterns": [
                    re.compile(pattern, re.IGNORECASE) for pattern in rule.get("context_any", [])
                ],
                "compiled_not_patterns": [
                    re.compile(pattern, re.IGNORECASE) for pattern in rule.get("not_patterns", [])
                ],
            }
            for rule in HEURISTIC_RULES
        ]

    def analyze_files(self, files: list[tuple[str, bytes]]) -> dict[str, Any]:
        aggregated = defaultdict(
            lambda: {
                "attack_id": "",
                "behavior": "",
                "severity": "low",
                "confidence": "low",
                "hits": 0,
                "score": 0.0,
                "raw_score": 0.0,
                "rules_matched": set(),
                "examples": [],
                "files": set(),
            }
        )

        total_lines = 0
        for file_name, raw_bytes in files:
            for line in _normalize_log_lines(raw_bytes):
                total_lines += 1
                for rule in self.compiled_rules:
                    if _line_matches_rule(line, rule):
                        bucket = aggregated[rule["attack_id"]]
                        bucket["attack_id"] = rule["attack_id"]
                        bucket["behavior"] = rule["behavior"]
                        bucket["severity"] = _max_level(bucket["severity"], rule["severity"], {"low": 1, "medium": 2, "high": 3})
                        bucket["confidence"] = _max_level(
                            bucket["confidence"], rule["confidence"], {"low": 1, "medium": 2, "high": 3}
                        )
                        bucket["hits"] += 1
                        bucket["raw_score"] += float(rule.get("score", 0.5))
                        bucket["rules_matched"].add(rule["rule_id"])
                        bucket["files"].add(file_name)
                        if len(bucket["examples"]) < 3:
                            bucket["examples"].append(line[:280])

        matched_techniques = []
        for attack_id, entry in aggregated.items():
            technique = self.attack_dataset.techniques.get(attack_id)
            aggregated_score = min(1.0, entry["raw_score"] / max(1, ceil(entry["hits"] / 2)))
            matched_techniques.append(
                {
                    **entry,
                    "files": sorted(entry["files"]),
                    "rules_matched": sorted(entry["rules_matched"]),
                    "score": round(aggregated_score, 3),
                    "name": technique.name if technique else attack_id,
                    "description": technique.description if technique else "",
                    "tactics": technique.tactics if technique else [],
                    "url": technique.url if technique else f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
                }
            )

        severity_order = {"high": 3, "medium": 2, "low": 1}
        matched_techniques.sort(
            key=lambda item: (item["hits"], severity_order.get(item["severity"], 0), item["attack_id"]),
            reverse=True,
        )
        observed_ids = [item["attack_id"] for item in matched_techniques]

        return {
            "summary": {
                "files_analyzed": len(files),
                "lines_analyzed": total_lines,
                "techniques_detected": len(matched_techniques),
                "high_confidence_techniques": sum(1 for item in matched_techniques if item["confidence"] == "high"),
            },
            "observed_techniques": matched_techniques,
            "attack_matrix": self.attack_dataset.build_attack_matrix(observed_ids),
            "navigator_layer": self.attack_dataset.navigator_layer(matched_techniques),
            "d3fend_mappings": self.d3fend_dataset.map_attack_techniques(observed_ids),
            "d3fend_matrix": self.d3fend_dataset.build_visual_matrix(observed_ids),
            "threat_actor_hypotheses": self.attack_dataset.build_group_overlap(matched_techniques),
        }


def _normalize_log_lines(raw_bytes: bytes) -> list[str]:
    text = raw_bytes.decode("utf-8", errors="ignore")
    stripped = text.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
        return _extract_json_lines(parsed)
    except json.JSONDecodeError:
        pass

    if "\n" in stripped:
        jsonl_lines = []
        parsed_count = 0
        for raw_line in stripped.splitlines():
            candidate = raw_line.strip()
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
                jsonl_lines.extend(_extract_json_lines(parsed))
                parsed_count += 1
            except json.JSONDecodeError:
                jsonl_lines = []
                parsed_count = 0
                break
        if parsed_count:
            return jsonl_lines

    if "," in stripped and "\n" in stripped:
        try:
            reader = csv.DictReader(io.StringIO(stripped))
            rows = [" ".join(f"{key}={value}" for key, value in row.items()) for row in reader]
            if rows:
                return rows
        except csv.Error:
            pass

    return [line.strip() for line in stripped.splitlines() if line.strip()]


def _extract_json_lines(payload: Any) -> list[str]:
    if isinstance(payload, list):
        lines = []
        for item in payload:
            lines.extend(_extract_json_lines(item))
        return lines
    if isinstance(payload, dict):
        return [" ".join(_flatten_json(payload))]
    return [str(payload)]


def _flatten_json(node: Any, prefix: str = "") -> list[str]:
    if isinstance(node, dict):
        parts = []
        for key, value in node.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            parts.extend(_flatten_json(value, next_prefix))
        return parts
    if isinstance(node, list):
        parts = []
        for index, value in enumerate(node):
            parts.extend(_flatten_json(value, f"{prefix}[{index}]"))
        return parts
    return [f"{prefix}={node}"]


def _line_matches_rule(line: str, rule: dict[str, Any]) -> bool:
    if any(pattern.search(line) for pattern in rule.get("compiled_not_patterns", [])):
        return False
    if not any(pattern.search(line) for pattern in rule["compiled_patterns"]):
        return False
    context_patterns = rule.get("compiled_context_patterns", [])
    if context_patterns and not any(pattern.search(line) for pattern in context_patterns):
        return False
    return True


def _max_level(left: str, right: str, order: dict[str, int]) -> str:
    return left if order.get(left, 0) >= order.get(right, 0) else right
