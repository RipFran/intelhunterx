# IntelHunterX

Python CLI tool to download IntelX Search exports and extract secrets/artifacts from them:

- Assets
- Hostnames
- Emails
- Endpoints
- Credentials

## Documentation references

- Official IntelX API docs: https://help.intelx.io/docs/api/
- API PDF manual: https://www.ginseg.com/wp-content/uploads/sites/2/2019/07/Manual-Intelligence-X-API.pdf

## Requirements: Paid IntelX account

**IntelX Search export access requires a paid IntelX account.**

> [!IMPORTANT]
> This tool was developed and tested using a paid IntelX account.
> To run exports you need:
> - An API key from https://intelx.io/account?tab=developer
> - The paid API base URL: `https://2.intelx.io`

## Why this exists

IntelX Search is designed to return items for a selector term (commonly a domain). The recommended flow is:

1. Start a search job: `POST /intelligent/search`
2. Poll results: `GET /intelligent/search/result` until completion
3. Export results to ZIP: `GET /intelligent/search/export`
4. Parse `Info.csv`, extract text, and scan for secrets

IntelX requires:
- Authentication via API key (recommended via the `x-key` header)
- A valid `User-Agent` identifying your application
- Respecting rate limits (default guidance is no more than 1 request per second)

## Installation

```bash
python -m venv .venv
# Windows:
# .venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

### Single domain (default: maximize findings)

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --input example.com
```

### Multiple domains from file

Create `domains.txt`:

```txt
example.com
example.org
# comments are allowed
sub.example.net
```

Run:

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --input domains.txt
```

### Offline mode (use existing ZIPs)

```bash
python intelhunterx.py --offline --downloads-dir ./intelx_exports --input example.com
```

### Reduce noise (only lines matching selector)

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --input example.com --selector-only
```

### Environment variable (optional)

```bash
export INTELX_API_KEY="YOUR_INTELX_KEY"
python intelhunterx.py --input example.com
```

## Online vs offline

- Online mode: uses the IntelX Search API to create a search job, polls results, and downloads export ZIPs.
- Offline mode: skips the API and only scans ZIPs already present under `--downloads-dir`.
- `--input` is still required in offline mode, because the selectors are used to filter findings.

## Parsing and extraction

- Each export includes `Info.csv`, which maps file names to bucket, media, content type, and system ID.
- The scanner uses `Info.csv` metadata to decide how to handle content and extracts printable strings from binaries when needed.
- Every endpoint contributes its hostname to `hostnames.jsonl` and its root to `assets.jsonl`.
- When `--input` contains multiple domains, all of them act as selectors during scanning.
- Selector behavior:
  - With `--selector-only`: selectors are full domains (e.g., `google.es`).
  - Without `--selector-only`: selectors are base keywords without TLD (e.g., `google`).

## Output structure

By default, the tool writes into `./results`:

```
results/
  example.com_YYYYMMDD_HHMMSS/
    findings/
      assets.jsonl
      hostnames.jsonl
      emails.jsonl
      endpoints.jsonl
      credentials.jsonl
    summary.json
    run_metadata.json
  findings/
    assets.jsonl
    hostnames.jsonl
    emails.jsonl
    endpoints.jsonl
    credentials.jsonl
  summary.json
  run_metadata.json

  intelx_exports/
    example.com_YYYYMMDD_HHMMSS/
      example.com_seg01.zip
      example.com_seg01_extracted/
        Info.csv
        ...
```

Each JSONL line includes the finding value and its source location, plus optional `context` and `source_meta`.
The root `results/findings` folder contains the merged, deduplicated, alphabetically sorted outputs across all scanned domains.

## Operational notes

- Default configuration aims for maximum coverage:
  - `--max-results` defaults to 1000 (ZIP cap).
  - Adaptive segmentation is enabled by default.
  - `--selector-only` is disabled, so all lines are scanned.
  - `--max-segments 0` means unlimited segmentation until IntelX reports no more results.
- IntelX export limits: 1000 files per ZIP, 2 GB uncompressed, 20 MB per file.
- The tool rate limits requests to 1 req/s by default to match IntelX guidance.

## Exit codes

- `0`: Success
- `1`: Completed with one or more domain failures
- `2`: Invalid CLI usage or missing inputs
