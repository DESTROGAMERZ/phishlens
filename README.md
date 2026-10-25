# PhishLens — Explainable URL Risk Triage

PhishLens is a small defensive cybersecurity project that inspects visible URL characteristics and explains the signals behind a risk score. It is designed as a learning and portfolio project, not as a production security product.

This starter implementation was prepared with AI assistance. Review the code, make changes you understand, and describe your own contributions accurately when presenting it.

## What it does

- Checks for URL patterns that can merit closer review, such as user-info tricks, encoded hostnames, URL shorteners, many subdomains, and brand names embedded in unrelated hostnames.
- Produces a bounded 0–100 heuristic score, a low/medium/high triage label, and human-readable findings.
- Accepts one URL or a CSV/text file with one URL per line.
- Prints readable output or JSON, and can save JSON Lines for later analysis.
- Works offline: it does not visit URLs, resolve DNS, fetch pages, or send submitted data anywhere.

## Run it

Requires Python 3.10 or later. No third-party packages are required.

```console
python phishlens.py https://example.com/login
python phishlens.py suspicious.example --json
python phishlens.py --file urls.csv --output results.jsonl
```

Input files should contain one URL per row/line. A header row is treated as an input value; omit headers. Lines beginning with `#` are ignored.

## How scoring works

Each detected rule adds a small number of points; the sum is capped at 100. Scores below 20 are labeled low, 20–44 medium, and 45 or above high. The rules and weights are intentionally visible in `phishlens.py` so they can be reviewed and changed. They are not trained model probabilities and have not been calibrated against a labeled dataset.

## Limitations and safe use

A low score does not mean a URL is safe, and a high score does not establish malicious intent. Legitimate sites can trigger signals and malicious links can evade them. Treat results as triage cues, verify destinations through trusted channels, and do not use this tool to make automatic blocking decisions. Only analyze links you are authorized to handle.

## Possible next steps

1. Add a labeled, responsibly sourced dataset and measure precision/recall before considering machine learning.
2. Add a dashboard and compare rule behavior on a documented sample set.
3. Add configurable rules and export a summary report.

## Suggested GitHub description

An offline Python tool for explainable URL risk triage, with transparent heuristic signals and JSON/CSV workflows.
