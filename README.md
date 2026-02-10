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

IntelX Search is designed to return items for a query term (domain, url, email and more...). The recommended flow is:

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

IntelHunterX runs in two separate commands:

1. `download`: fetch IntelX exports into a database folder.
2. `search`: scan the downloaded documents later.

`search` requires at least one `--selector` (repeat the flag or provide a file with one selector per line).
`download --query` accepts any IntelX query (domains, emails, URLs, wildcards, etc).

### Create a database and download a query

```bash
python intelhunterx.py download --db dbs/acme --api-key YOUR_INTELX_KEY --query example.com
```

This creates `dbs/acme` (if needed) and stores the extracted documents under a single folder for the query.

You can also use wildcard queries:

```bash
python intelhunterx.py download --db dbs/acme --api-key YOUR_INTELX_KEY --query "*.example.com"
```

### Download multiple queries from a file

Create `queries.txt`:

```txt
example.com
*.example.org
# comments are allowed
sub.example.net
hello@acme.org
https://portal.example.net/login
```

Run:

```bash
python intelhunterx.py download --db dbs/acme --api-key YOUR_INTELX_KEY --query queries.txt
```

### Update a query (replace its documents)

```bash
python intelhunterx.py download --db dbs/acme --api-key YOUR_INTELX_KEY --query example.com --update
```

### Search across the database

```bash
python intelhunterx.py search --db dbs/acme --selector example
```

### Search within specific queries

```bash
python intelhunterx.py search --db dbs/acme --selector example.com --query b.com
python intelhunterx.py search --db dbs/acme --selector example --query queries.txt
```

### Focused extraction

```bash
python intelhunterx.py search --db dbs/acme --selector example.com --extract emails
python intelhunterx.py search --db dbs/acme --selector example.com --extract credentials
python intelhunterx.py search --db dbs/acme --selector example.com --extract surface
```

`surface` extracts endpoints, hostnames, and assets.

### Environment variable (optional)

```bash
export INTELX_API_KEY="YOUR_INTELX_KEY"
python intelhunterx.py download --db dbs/acme --query example.com
```

## Parsing and extraction

- Each export includes `Info.csv`, which maps file names to bucket, media, content type, and system ID.
- The scanner uses `Info.csv` metadata to decide how to handle content and extracts printable strings from binaries when needed.
- Every endpoint contributes its hostname to `hostnames.jsonl` and its root to `assets.jsonl`.
- Selectors are provided via `--selector`.
- Domain selectors match subdomains; keyword selectors match substrings; email selectors match the full email.
- Use `--extract` to limit findings to `credentials`, `emails`, or `surface`.

## Database layout

The database folder is a single directory tree. One query = one folder:

If a query contains filesystem-unsafe characters, the folder name is a readable slug plus a short hash.
Example: `*.example.com` becomes `_wildcard_.example.com__a1b2c3d4e5`. The exact query is stored in `query.json`.

```
dbs/
  acme/
    db.json
    queries/
      example.com/
        query.json
        segments/
          seg01/
            Info.csv
            ...
          seg02/
            Info.csv
            ...
    findings/
      assets.jsonl
      hostnames.jsonl
      emails.jsonl
      endpoints.jsonl
      credentials.jsonl
      summary.json
      run_metadata.json
    state/
      searches/
        <search_key>/
          search.json
          scanned.jsonl
```

Each JSONL line includes the finding value and its source location, plus optional `context` and `source_meta`.
The `findings` folder contains the merged, deduplicated, alphabetically sorted outputs across all scanned queries in the database.

## Operational notes

- Default configuration aims for maximum coverage:
  - `download --max-results` defaults to 1000 (ZIP cap).
  - Adaptive segmentation is enabled by default during downloads.
- `download --segment-days N` limits exports to documents between "now" and N days back (UTC).
- `--max-segments 0` means unlimited segmentation until IntelX reports no more results.
- `download` stores only extracted documents; ZIP files are removed after extraction.
- If you cancel `download` with Ctrl+C, the tool keeps already extracted segments and leaves the query in a resumable state.
- `search` keeps memory per selector set + extract mode and only scans new files for those selectors.
- Updating a query with `download --update` refreshes its content id so the new documents are scanned again.
- IntelX export limits: 1000 files per ZIP, 2 GB uncompressed, 20 MB per file.
- The tool rate limits requests to 1 req/s by default to match IntelX guidance.

## Exit codes

- `0`: Success
- `1`: Completed with one or more query failures
- `2`: Invalid CLI usage or missing required flags
