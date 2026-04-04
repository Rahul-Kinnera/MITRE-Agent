from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from math import log
from pathlib import Path
from typing import Any


@dataclass
class AttackTechnique:
    attack_id: str
    stix_id: str
    name: str
    description: str
    tactics: list[str]
    url: str
    is_subtechnique: bool


@dataclass
class AttackGroup:
    group_id: str
    stix_id: str
    name: str
    description: str
    url: str


class AttackDataset:
    def __init__(self, cache_file: Path) -> None:
        self.cache_file = cache_file
        self.techniques: dict[str, AttackTechnique] = {}
        self.techniques_by_stix: dict[str, AttackTechnique] = {}
        self.groups: dict[str, AttackGroup] = {}
        self.groups_by_stix: dict[str, AttackGroup] = {}
        self.group_to_techniques: dict[str, set[str]] = defaultdict(set)
        self.technique_to_groups: dict[str, set[str]] = defaultdict(set)
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        if not self.cache_file.exists():
            raise FileNotFoundError(
                f"ATT&CK cache not found at {self.cache_file}. Run MITRE data sync first."
            )

        bundle = json.loads(self.cache_file.read_text(encoding="utf-8"))
        objects = bundle.get("objects", [])

        for obj in objects:
            obj_type = obj.get("type")
            if obj_type == "attack-pattern":
                technique = self._parse_technique(obj)
                if technique:
                    self.techniques[technique.attack_id] = technique
                    self.techniques_by_stix[technique.stix_id] = technique
            elif obj_type == "intrusion-set":
                group = self._parse_group(obj)
                if group:
                    self.groups[group.group_id] = group
                    self.groups_by_stix[group.stix_id] = group

        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
                continue
            group = self.groups_by_stix.get(obj.get("source_ref"))
            technique = self.techniques_by_stix.get(obj.get("target_ref"))
            if group and technique:
                self.group_to_techniques[group.group_id].add(technique.attack_id)
                self.technique_to_groups[technique.attack_id].add(group.group_id)

        self._loaded = True

    def build_attack_matrix(self, observed_ids: list[str]) -> list[dict[str, Any]]:
        self.load()
        tactics: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for attack_id in observed_ids:
            technique = self.techniques.get(attack_id)
            if not technique:
                continue
            technique_payload = {
                "attack_id": technique.attack_id,
                "name": technique.name,
                "url": technique.url,
                "is_subtechnique": technique.is_subtechnique,
            }
            for tactic in technique.tactics or ["unassigned"]:
                tactics[tactic].append(technique_payload)

        matrix = []
        for tactic_name in sorted(tactics.keys()):
            seen = set()
            ordered = []
            for entry in sorted(tactics[tactic_name], key=lambda item: item["attack_id"]):
                if entry["attack_id"] in seen:
                    continue
                seen.add(entry["attack_id"])
                ordered.append(entry)
            matrix.append({"tactic": tactic_name, "techniques": ordered})
        return matrix

    def build_group_overlap(self, observed_techniques: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
        self.load()
        observed_ids = {item["attack_id"] for item in observed_techniques}
        if len(observed_ids) < 2:
            return []

        confidence_weight = {"high": 1.0, "medium": 0.7, "low": 0.45}
        observed_weights = {}
        total_groups = max(len(self.groups), 1)
        for item in observed_techniques:
            group_count = len(self.technique_to_groups.get(item["attack_id"], set()))
            rarity_weight = log(1 + (total_groups / (1 + group_count)))
            observed_weights[item["attack_id"]] = round(
                max(
                    0.2,
                    float(item.get("score", 0.5)) * confidence_weight.get(item.get("confidence", "low"), 0.45) * rarity_weight,
                ),
                4,
            )

        weighted_observed_total = sum(observed_weights.values()) or 1.0
        candidates = []
        for group_id, techniques in self.group_to_techniques.items():
            overlap = sorted(observed_ids & techniques)
            if len(overlap) < 2:
                continue
            group = self.groups[group_id]
            weighted_overlap = sum(observed_weights.get(attack_id, 0.0) for attack_id in overlap)
            normalized_score = round(weighted_overlap / weighted_observed_total, 3)
            if normalized_score < 0.3:
                continue
            support_ratio = round(len(overlap) / len(observed_ids), 3)
            confidence = _actor_confidence_label(len(overlap), normalized_score, support_ratio)
            if confidence == "suppressed":
                continue
            candidates.append(
                {
                    "group_id": group.group_id,
                    "name": group.name,
                    "url": group.url,
                    "overlap_count": len(overlap),
                    "score": normalized_score,
                    "support_ratio": support_ratio,
                    "confidence": confidence,
                    "summary": _actor_summary(confidence, len(overlap), normalized_score),
                    "matching_techniques": [
                        {
                            **self.techniques[attack_id].__dict__,
                            "weight": observed_weights.get(attack_id, 0.0),
                        }
                        for attack_id in overlap
                        if attack_id in self.techniques
                    ],
                }
            )
        return sorted(
            candidates,
            key=lambda item: (
                {"high": 3, "medium": 2, "low": 1}.get(item["confidence"], 0),
                item["score"],
                item["overlap_count"],
                item["name"],
            ),
            reverse=True,
        )[:limit]

    def navigator_layer(self, matched_techniques: list[dict[str, Any]]) -> dict[str, Any]:
        self.load()
        technique_entries = []
        for item in matched_techniques:
            technique_entries.append(
                {
                    "techniqueID": item["attack_id"],
                    "score": min(100, max(20, int(item.get("score", 0.4) * 100))),
                    "color": self._severity_color(item.get("severity", "low")),
                    "comment": (
                        f'{item["behavior"]}: {item["hits"]} matched log line(s), '
                        f'{item.get("confidence", "low")} confidence'
                    ),
                }
            )
        return {
            "name": "MITRE Agent Analysis",
            "description": "Generated locally by MITRE Agent from uploaded logs.",
            "domain": "enterprise-attack",
            "versions": {
                "attack": "18.1",
                "navigator": "5.1.0",
                "layer": "4.5",
            },
            "filters": {
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS",
                    "Office Suite",
                    "SaaS",
                    "IaaS",
                    "Network",
                    "Containers",
                    "Identity Provider",
                ]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
            },
            "hideDisabled": False,
            "techniques": technique_entries,
            "legendItems": [
                {"label": "High-confidence log evidence", "color": "#dc2626"},
                {"label": "Medium-confidence log evidence", "color": "#f97316"},
                {"label": "Low-confidence log evidence", "color": "#facc15"},
            ],
        }

    @staticmethod
    def _parse_technique(obj: dict[str, Any]) -> AttackTechnique | None:
        external_ref = _attack_external_reference(obj)
        if not external_ref:
            return None
        attack_id = external_ref.get("external_id")
        url = external_ref.get("url") or f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/"
        tactics = [
            phase.get("phase_name", "").replace("-", " ")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        return AttackTechnique(
            attack_id=attack_id,
            stix_id=obj["id"],
            name=obj.get("name", attack_id),
            description=obj.get("description", ""),
            tactics=tactics,
            url=url,
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
        )

    @staticmethod
    def _parse_group(obj: dict[str, Any]) -> AttackGroup | None:
        external_ref = _attack_external_reference(obj)
        if not external_ref:
            return None
        group_id = external_ref.get("external_id")
        return AttackGroup(
            group_id=group_id,
            stix_id=obj["id"],
            name=obj.get("name", group_id),
            description=obj.get("description", ""),
            url=external_ref.get("url") or "https://attack.mitre.org/groups/",
        )

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "high": "#dc2626",
            "medium": "#f97316",
            "low": "#facc15",
        }.get(severity, "#38bdf8")


def _attack_external_reference(obj: dict[str, Any]) -> dict[str, Any] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


def _actor_confidence_label(overlap_count: int, score: float, support_ratio: float) -> str:
    if overlap_count >= 4 and score >= 0.55 and support_ratio >= 0.5:
        return "high"
    if overlap_count >= 3 and score >= 0.42 and support_ratio >= 0.4:
        return "medium"
    if overlap_count >= 2 and score >= 0.3 and support_ratio >= 0.35:
        return "low"
    return "suppressed"


def _actor_summary(confidence: str, overlap_count: int, score: float) -> str:
    return (
        f"{confidence.title()} confidence overlap based on {overlap_count} matched ATT&CK techniques "
        f"and a weighted score of {score}."
    )
