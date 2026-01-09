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

`--query` and `--selector` are both required to keep download scope and analysis selectors separate.

### Single domain

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --query example.com --selector example
```

This downloads IntelX exports for `example.com`, then scans those documents and keeps artifacts that match the selector `example` (keyword substring match).

### Multiple domains from file

Create `queries.txt`:

```txt
example.com
example.org
# comments are allowed
sub.example.net
```

Create `selectors.txt`:

```txt
example
test
```

Run:

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --query queries.txt --selector selectors.txt
```

This downloads exports for every domain listed in `queries.txt`, then scans those documents and keeps artifacts that match any selector from `selectors.txt`.

### Offline mode (use existing downloads)

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --offline --output-dir results/example --query queries.txt --selector example
```

This scans existing downloads under `results/example/intelx_exports` for the queries in `queries.txt` and keeps artifacts that match `example`. Any query without existing downloads is reported as a failure and skipped.

### Mixed mode (use existing downloads and make queries)

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --reuse-downloads --output-dir results/example --query queries.txt --selector example
```

This reuses existing downloads under `results/example/intelx_exports` when they are present for a query; if none exist for a query, it downloads new exports from IntelX, then scans everything and keeps artifacts that match `example`.


### Focused extraction

```bash
python intelhunterx.py --api-key YOUR_INTELX_KEY --query example.com --selector example.com --extract emails
python intelhunterx.py --api-key YOUR_INTELX_KEY --query example.com --selector example.com --extract credentials
python intelhunterx.py --api-key YOUR_INTELX_KEY --query example.com --selector example.com --extract surface
```

`surface` extracts endpoints, hostnames, and assets.

### Environment variable (optional)

```bash
export INTELX_API_KEY="YOUR_INTELX_KEY"
python intelhunterx.py --query example.com --selector example.com
```

## Parsing and extraction

- Each export includes `Info.csv`, which maps file names to bucket, media, content type, and system ID.
- The scanner uses `Info.csv` metadata to decide how to handle content and extracts printable strings from binaries when needed.
- Every endpoint contributes its hostname to `hostnames.jsonl` and its root to `assets.jsonl`.
- Selectors are provided via `--selector`.
- Domain selectors match subdomains; keyword selectors match substrings; email selectors match the full email.
- Use `--extract` to limit findings to `credentials`, `emails`, or `surface`.

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
  - All lines are scanned by default; selectors are literal unless you pass keywords.
  - `--max-segments 0` means unlimited segmentation until IntelX reports no more results.
- Execution runs in two phases: download all exports first, then scan.
- IntelX export limits: 1000 files per ZIP, 2 GB uncompressed, 20 MB per file.
- The tool rate limits requests to 1 req/s by default to match IntelX guidance.

## Exit codes

- `0`: Success
- `1`: Completed with one or more domain failures
- `2`: Invalid CLI usage or missing required flags
