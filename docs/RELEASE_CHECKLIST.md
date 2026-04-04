# MITRE Agent Release Checklist

## Product Readiness

- Confirm `docker compose up --build` works on a clean machine.
- Verify `Sync MITRE Data` completes successfully.
- Test analysis with representative Windows, Linux, and JSON log samples.
- Confirm ATT&CK Navigator layer import works at `http://localhost:4200`.
- Review D3FEND mappings for a few known ATT&CK techniques against the official CSV.
- Confirm generated HTML reports include ATT&CK and D3FEND citations.

## Privacy and Security

- Confirm all uploads, cache files, and reports remain under the local `runtime/` mount.
- Verify no external telemetry or analytics are enabled.
- Re-review wording around threat-actor overlap to avoid implying definitive attribution.
- Remove any accidental sample data that should not ship.

## Open Source Readiness

- Add the final license file you want for public release.
- Add contribution guidance if you want community PRs.
- Add a security policy or responsible disclosure contact if desired.
- Review MITRE trademark and naming guidance before formal upstream submission.

## GitHub Publication

- Create or choose the destination GitHub repository.
- Add screenshots/assets to the repo landing page.
- Tag the first release after validating the Docker workflow.
- Add GitHub topics such as `mitre-attack`, `d3fend`, `docker`, `threat-detection`, and `cybersecurity`.

## MITRE Submission Prep

- Replace heuristic-only language with a clearly documented roadmap for higher-fidelity detections.
- Document the official data sources and refresh flow.
- Provide architecture and privacy diagrams if you plan to share it with MITRE maintainers.
- Include a short demo dataset or reproducible walkthrough that contains no sensitive data.
