# MITRE Agent

MITRE Agent is a self-hosted project for people who want to analyze local logs with MITRE ATT&CK and MITRE D3FEND without giving up control of their data.

The idea behind the project is simple. A user runs the stack on their own machine, uploads or points the tool at local logs, and gets back a practical first-pass analysis. The application looks for behaviors that map to ATT&CK techniques, builds a visual ATT&CK-style view, maps related defensive countermeasures through D3FEND, and generates a downloadable report with citations back to official MITRE sources.

This project is meant to help with triage and investigation, not replace an analyst. The ATT&CK detections are heuristic, and the threat-actor section is intentionally conservative so the tool does not overstate attribution.

## Docker Image

The repository is set up to publish a container image to GitHub Container Registry.

Expected image:

```bash
ghcr.io/rahul-kinnera/mitre-agent:latest
```

Once the GitHub Actions workflow runs successfully, people will be able to pull it with:

```bash
docker pull ghcr.io/rahul-kinnera/mitre-agent:latest
```

Then run it with:

```bash
docker run -p 8000:8000 -e MITRE_AGENT_DATA_DIR=/data -v ./runtime:/data ghcr.io/rahul-kinnera/mitre-agent:latest
```

## What MITRE Agent Does

- Accepts local log files and extracts behavior evidence that may map to ATT&CK techniques.
- Produces a visual ATT&CK-style matrix and a downloadable ATT&CK Navigator layer JSON file.
- Uses official MITRE D3FEND data to map possible defensive countermeasures for observed behaviors.
- Generates a local HTML report with citations to official MITRE material.
- Provides an initial threat-actor overlap view based on ATT&CK group-to-technique relationships.

## Why It Exists

A lot of security tooling becomes less attractive the moment sensitive log data has to leave the environment. MITRE Agent was built to stay local-first. The user keeps control of the runtime, the cached data, and the analysis outputs. That makes it easier to test, share, and improve without turning the project into a hosted platform.

## Privacy Model

- Logs are processed locally by the running container.
- Cached ATT&CK and D3FEND reference data lives under `runtime/cache/`.
- Generated reports and analysis artifacts live under `runtime/reports/`.
- Uploaded files live under `runtime/uploads/`.
- No external database is required.

## Official Data Sources

MITRE Agent syncs and cites from MITRE-controlled sources:

- [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATT&CK STIX Data Repository](https://github.com/mitre-attack/attack-stix-data)
- [MITRE D3FEND Resources](https://d3fend.mitre.org/resources)
- [MITRE D3FEND API Documentation](https://d3fend.mitre.org/api-docs)

## Quick Start

Start the stack with:

```bash
docker compose up --build
```

Once the containers are up:

1. Open the app at `http://localhost:8000`
2. Open ATT&CK Navigator at `http://localhost:4200`
3. Click `Sync MITRE Data` before the first analysis run
4. Upload one or more local log files

After analysis, the app will give you:

- an ATT&CK-style visual view,
- a downloadable ATT&CK Navigator layer,
- a D3FEND countermeasure map,
- a downloadable HTML report,
- a conservative threat-actor overlap section.

## Project Layout

```text
app/
  analyzer.py
  attack.py
  d3fend.py
  heuristics.py
  main.py
  reporting.py
  static/
docs/
  RELEASE_CHECKLIST.md
runtime/
  cache/
  reports/
  uploads/
```

## Important Notes

- ATT&CK detections are heuristic and meant to support triage.
- Threat-actor overlap is not the same as attribution.
- Some ATT&CK techniques may not have a corresponding D3FEND mapping in the official dataset.
- The project is currently strongest as a transparent, self-hosted foundation that can be expanded over time.

## Release Prep

Before publishing a release or sharing the project more broadly, review [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## Roadmap

- Improve detection coverage for real-world Windows, Linux, and cloud log sources.
- Add better suppression for benign administrative activity.
- Support analyst-tunable detection packs instead of relying only on built-in heuristics.
- Add tests, CI, and release automation.
- Add demo datasets and reproducible walkthroughs for contributors and reviewers.
