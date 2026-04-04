from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


ATTACK_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
D3FEND_ID_PATTERN = re.compile(r"d3f:[A-Za-z0-9]+")
ONTOLOGY_ID_PATTERN = re.compile(r"#([A-Za-z][A-Za-z0-9-]+)$")


class D3fendDataset:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.mapping_csv = cache_dir / "d3fend-full-mappings.csv"
        self.technique_json = cache_dir / "technique-all.json"
        self.matrix_json = cache_dir / "matrix.json"
        self.techniques: dict[str, dict[str, Any]] = {}
        self.attack_to_d3fend: dict[str, set[str]] = defaultdict(set)
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        if self.technique_json.exists():
            payload = json.loads(self.technique_json.read_text(encoding="utf-8"))
            self.techniques.update(_extract_d3fend_techniques(payload))
        if self.matrix_json.exists():
            payload = json.loads(self.matrix_json.read_text(encoding="utf-8"))
            _attach_matrix_tactics(self.techniques, payload)
        if self.mapping_csv.exists():
            self._load_mappings_csv()
        else:
            raise FileNotFoundError(
                f"D3FEND mappings cache not found at {self.mapping_csv}. Run MITRE data sync first."
            )
        self._loaded = True

    def map_attack_techniques(self, attack_ids: list[str]) -> list[dict[str, Any]]:
        self.load()
        matches = []
        for attack_id in attack_ids:
            d3fend_ids = sorted(self.attack_to_d3fend.get(attack_id, []))
            source_url = f"https://d3fend.mitre.org/offensive-technique/attack/{attack_id}/"
            defenses = []
            for d3fend_id in d3fend_ids:
                metadata = self.techniques.get(d3fend_id, {})
                defenses.append(
                    {
                        "d3fend_id": d3fend_id,
                        "name": metadata.get("name", d3fend_id.replace("d3f:", "")),
                        "description": metadata.get("description", ""),
                        "tactic": metadata.get("tactic", "Mapped Defenses"),
                        "url": metadata.get("url", f"https://d3fend.mitre.org/dao/artifact/{d3fend_id}.json"),
                    }
                )
            matches.append({"attack_id": attack_id, "source_url": source_url, "defenses": defenses})
        return matches

    def build_visual_matrix(self, attack_ids: list[str]) -> list[dict[str, Any]]:
        self.load()
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        seen = set()
        for attack_id in attack_ids:
            for d3fend_id in sorted(self.attack_to_d3fend.get(attack_id, [])):
                key = (attack_id, d3fend_id)
                if key in seen:
                    continue
                seen.add(key)
                metadata = self.techniques.get(d3fend_id, {})
                tactic = metadata.get("tactic", "Mapped Defenses")
                grouped[tactic].append(
                    {
                        "attack_id": attack_id,
                        "d3fend_id": d3fend_id,
                        "name": metadata.get("name", d3fend_id.replace("d3f:", "")),
                        "url": metadata.get("url", f"https://d3fend.mitre.org/dao/artifact/{d3fend_id}.json"),
                    }
                )
        return [
            {"tactic": tactic, "defenses": sorted(items, key=lambda item: (item["name"], item["attack_id"]))}
            for tactic, items in sorted(grouped.items(), key=lambda item: item[0])
        ]

    def _load_mappings_csv(self) -> None:
        with self.mapping_csv.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                attack_id = (row.get("off_tech_id") or "").strip()
                if not attack_id:
                    content = " ".join(str(value) for value in row.values() if value)
                    candidates = ATTACK_ID_PATTERN.findall(content)
                    attack_id = candidates[0] if candidates else ""
                if not attack_id:
                    continue

                d3fend_uri = (row.get("def_tech") or "").strip()
                d3fend_name = (row.get("def_tech_label") or "").strip()
                d3fend_tactic = (row.get("def_tactic_label") or "").strip() or "Mapped Defenses"
                d3fend_id = _normalize_d3fend_id(d3fend_uri, d3fend_name)
                if not d3fend_id:
                    continue

                self.attack_to_d3fend[attack_id].add(d3fend_id)
                self.techniques.setdefault(
                    d3fend_id,
                    {
                        "name": d3fend_name or d3fend_id.replace("d3f:", ""),
                        "description": "",
                        "tactic": d3fend_tactic,
                        "url": _d3fend_url(d3fend_id),
                    },
                )
                if d3fend_name and not self.techniques[d3fend_id].get("name"):
                    self.techniques[d3fend_id]["name"] = d3fend_name
                if d3fend_tactic:
                    self.techniques[d3fend_id]["tactic"] = d3fend_tactic
                self.techniques[d3fend_id]["url"] = _d3fend_url(d3fend_id)


def _extract_d3fend_techniques(payload: Any) -> dict[str, dict[str, Any]]:
    techniques: dict[str, dict[str, Any]] = {}

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            raw_id = (
                node.get("id")
                or node.get("@id")
                or node.get("d3fend_id")
                or node.get("uri")
                or node.get("identifier")
            )
            if isinstance(raw_id, str) and raw_id.startswith("d3f:"):
                techniques.setdefault(
                    raw_id,
                    {
                        "name": node.get("name")
                        or node.get("label")
                        or node.get("rdfs:label")
                        or raw_id.replace("d3f:", ""),
                        "description": node.get("description")
                        or node.get("comment")
                        or node.get("definition")
                        or "",
                        "url": _d3fend_url(raw_id),
                    },
                )
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(payload)
    return techniques


def _attach_matrix_tactics(techniques: dict[str, dict[str, Any]], payload: Any) -> None:
    def infer_items(items: list[dict[str, Any]]) -> list[tuple[str, str]]:
        extracted = []
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_id = item.get("id") or item.get("@id") or item.get("uri")
            if isinstance(raw_id, str) and raw_id.startswith("d3f:"):
                name = item.get("name") or item.get("label") or raw_id.replace("d3f:", "")
                extracted.append((raw_id, name))
        return extracted

    columns = payload
    if isinstance(payload, dict):
        columns = payload.get("matrix") or payload.get("columns") or payload.get("data") or []

    if isinstance(columns, list):
        for column in columns:
            if not isinstance(column, dict):
                continue
            tactic_name = column.get("name") or column.get("label") or column.get("tactic") or "Mapped Defenses"
            techniques_list = column.get("techniques") or column.get("items") or column.get("children") or []
            for technique_id, technique_name in infer_items(techniques_list):
                techniques.setdefault(technique_id, {})
                techniques[technique_id]["name"] = techniques[technique_id].get("name") or technique_name
                techniques[technique_id]["tactic"] = tactic_name


def _normalize_d3fend_id(raw_uri: str, label: str = "") -> str:
    if raw_uri.startswith("d3f:"):
        return raw_uri
    match = ONTOLOGY_ID_PATTERN.search(raw_uri)
    if match:
        return f"d3f:{match.group(1)}"
    compact = re.sub(r"[^A-Za-z0-9]+", "", label)
    return f"d3f:{compact}" if compact else ""


def _d3fend_url(d3fend_id: str) -> str:
    short_id = d3fend_id.replace("d3f:", "")
    return f"https://d3fend.mitre.org/dao/artifact/d3f:{short_id}.json"
