from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any


def build_report_html(analysis_id: str, analysis: dict[str, Any]) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    summary = analysis["summary"]

    observed_rows = []
    for technique in analysis["observed_techniques"]:
        observed_rows.append(
            "<tr>"
            f"<td><a href=\"{escape(technique['url'])}\" target=\"_blank\" rel=\"noreferrer\">{escape(technique['attack_id'])}</a></td>"
            f"<td>{escape(technique['name'])}</td>"
            f"<td>{escape(', '.join(technique['tactics']) or 'Unassigned')}</td>"
            f"<td>{technique['hits']} ({escape(technique['confidence'])}, score {technique['score']})</td>"
            f"<td>{escape('; '.join(technique['files']))}</td>"
            "</tr>"
        )

    defense_rows = []
    for mapping in analysis["d3fend_mappings"]:
        if not mapping["defenses"]:
            continue
        for defense in mapping["defenses"]:
            defense_rows.append(
                "<tr>"
                f"<td>{escape(mapping['attack_id'])}</td>"
                f"<td><a href=\"{escape(defense['url'])}\" target=\"_blank\" rel=\"noreferrer\">{escape(defense['d3fend_id'])}</a></td>"
                f"<td>{escape(defense['name'])}</td>"
                f"<td>{escape(defense['tactic'])}</td>"
                "</tr>"
            )

    actor_rows = []
    for actor in analysis["threat_actor_hypotheses"]:
        actor_rows.append(
            "<tr>"
            f"<td><a href=\"{escape(actor['url'])}\" target=\"_blank\" rel=\"noreferrer\">{escape(actor['group_id'])}</a></td>"
            f"<td>{escape(actor['name'])}</td>"
            f"<td>{actor['overlap_count']}</td>"
            f"<td>{actor['score']} ({escape(actor['confidence'])})<br />{escape(actor['summary'])}</td>"
            "</tr>"
        )

    citations = [
        ("MITRE ATT&CK Data & Tools", "https://attack.mitre.org/resources/attack-data-and-tools/"),
        ("MITRE ATT&CK Enterprise Matrix", "https://attack.mitre.org/matrices/enterprise/"),
        ("MITRE D3FEND Resources", "https://d3fend.mitre.org/resources"),
        ("MITRE D3FEND API Documentation", "https://d3fend.mitre.org/api-docs"),
    ]

    for technique in analysis["observed_techniques"]:
        citations.append((f"{technique['attack_id']} {technique['name']}", technique["url"]))
    for actor in analysis["threat_actor_hypotheses"][:10]:
        citations.append((f"{actor['group_id']} {actor['name']}", actor["url"]))
    for mapping in analysis["d3fend_mappings"]:
        citations.append((f"D3FEND mapping for {mapping['attack_id']}", mapping["source_url"]))
        for defense in mapping["defenses"][:5]:
            citations.append((f"{defense['d3fend_id']} {defense['name']}", defense["url"]))

    unique_citations = []
    seen_urls = set()
    for label, url in citations:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        unique_citations.append((label, url))

    citation_rows = "".join(
        f"<li><a href=\"{escape(url)}\" target=\"_blank\" rel=\"noreferrer\">{escape(label)}</a></li>"
        for label, url in unique_citations
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MITRE Agent Report {escape(analysis_id)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #0f172a; }}
    h1, h2 {{ color: #111827; }}
    .meta {{ color: #475569; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px; vertical-align: top; text-align: left; }}
    th {{ background: #e2e8f0; }}
    .note {{ padding: 16px; background: #fff7ed; border: 1px solid #fdba74; margin-bottom: 24px; }}
  </style>
</head>
<body>
  <h1>MITRE Agent Report</h1>
  <p class="meta">Analysis ID: {escape(analysis_id)}<br />Generated: {generated_at}</p>
  <div class="note">
    This report is a local-first heuristic analysis. ATT&amp;CK technique detection and threat-actor hypotheses should be reviewed by an analyst before being used for attribution or operational decisions.
  </div>

  <h2>Summary</h2>
    <ul>
    <li>Files analyzed: {summary['files_analyzed']}</li>
    <li>Lines analyzed: {summary['lines_analyzed']}</li>
    <li>Observed ATT&amp;CK techniques: {summary['techniques_detected']}</li>
    <li>High-confidence ATT&amp;CK techniques: {summary['high_confidence_techniques']}</li>
  </ul>

  <h2>Observed ATT&amp;CK Techniques</h2>
  <table>
    <thead>
      <tr><th>ATT&amp;CK ID</th><th>Name</th><th>Tactic(s)</th><th>Hits</th><th>Files</th></tr>
    </thead>
    <tbody>
      {''.join(observed_rows) or '<tr><td colspan="5">No ATT&amp;CK techniques matched the current heuristic rules.</td></tr>'}
    </tbody>
  </table>

  <h2>D3FEND Countermeasure Mapping</h2>
  <table>
    <thead>
      <tr><th>ATT&amp;CK ID</th><th>D3FEND ID</th><th>Defense</th><th>D3FEND Tactic</th></tr>
    </thead>
    <tbody>
      {''.join(defense_rows) or '<tr><td colspan="4">No D3FEND mappings were identified for the currently observed ATT&amp;CK techniques.</td></tr>'}
    </tbody>
  </table>

  <h2>Threat Actor Overlap</h2>
  <table>
    <thead>
      <tr><th>Group ID</th><th>Name</th><th>Technique Overlap</th><th>Score</th></tr>
    </thead>
    <tbody>
      {''.join(actor_rows) or '<tr><td colspan="4">No ATT&amp;CK intrusion set overlap was identified.</td></tr>'}
    </tbody>
  </table>

  <h2>Citations</h2>
  <ol>
    {citation_rows}
  </ol>
</body>
</html>"""


def write_report(report_dir: Path, analysis_id: str, analysis: dict[str, Any]) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.html"
    report_path.write_text(build_report_html(analysis_id, analysis), encoding="utf-8")
    return report_path
