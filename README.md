# samples_push

Collects malware samples from public threat-intel feeds and uploads each one
to [filescan.io](https://www.filescan.io/) for analysis. Runs on Linux,
macOS, and Windows.

**Latest:** Account-identified uploads + rate-limiting + multi-machine state sync + unified setup script.

---

## Quick Start (2 minutes)

### Linux / macOS

```bash
cd samples_push
chmod +x run.sh
./run.sh --limit 10
```

The script automatically creates a venv, installs dependencies, and runs. On first run, it copies `.env.example` → `~/.local/share/samples_push/.env` for you to configure.

### Windows (PowerShell)

```powershell
cd samples_push
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
mkdir "$env:LOCALAPPDATA\samples_push" -Force
copy .env.example "$env:LOCALAPPDATA\samples_push\.env"
notepad "$env:LOCALAPPDATA\samples_push\.env"
python -m samples_push --limit 10
```

### Authentication (Choose One)

**Best: Auth Token** (account-identified uploads with priority 100)
```bash
# F12 → Network → any filescan.io request → Headers → Authorization: Bearer eyJ...
# Paste in ~/.local/share/samples_push/.env (Linux) or %LOCALAPPDATA%\samples_push\.env (Windows):
FILESCAN_AUTH_TOKEN=eyJ...

./run.sh --limit 10
```

**Alternative: API Key** (generic access, shows as guest)
```bash
export FILESCAN_API_KEY="your_key"
./run.sh --limit 10
```

---

## Features

✅ **Account-Identified Uploads** - Auth token for leaderboard attribution  
✅ **Rate Limiting** - `--delay 60` prevents queue overflow (default)  
✅ **Auto-Retry** - Failed uploads are retried on next run  
✅ **Upload Dashboard** - `--stats` shows uploads by day/source, file types, sizes  
✅ **Unified Setup** - Single `./run.sh` command (venv + deps)  
✅ **Vault Repair** - Fix unsupported zip compression  
✅ **Smart Replay** - Re-upload vault samples without re-fetching  
✅ **Encrypted Storage** - AES-256 vault, never decrypt to disk  
✅ **Auto-Dedup** - SQLite state tracking per target  
✅ **Bulk ZIP Import** - `--import-zip` for batch uploads  
✅ **Secrets Outside Repo** - `.env` stored in local data dir, not project folder  

---

## Sources (all free)

| ID | Provider | Key Required |
|-------|----------|--------------|
| `bazaar` | abuse.ch MalwareBazaar | none (public datalake) |
| `urlhaus` | abuse.ch URLhaus | `ABUSECH_API_KEY` |
| `malshare` | MalShare | `MALSHARE_API_KEY` |
| `vx` | Virus.Exchange | `VX_API_KEY` |
| `inquest` | InQuest Labs | `INQUEST_API_KEY` |
| `virusshare` | VirusShare | `VIRUSSHARE_API_KEY` |
| `hybrid` | Hybrid Analysis | `HYBRID_API_KEY` |
| `thezoo` | github.com/ytisf/theZoo | none (opt-in) |

**Sink:** filescan.io (free API key)

---

## Authentication

### Method 1: API Key

```bash
export FILESCAN_API_KEY="your_token"
python -m samples_push
```

Get token: Open https://www.filescan.io → DevTools → Network → Copy Authorization header

### Method 2: Browser Cookies (NEW - RECOMMENDED)

```bash
python -m samples_push --cookies ~/.filescan_cookies.json
```

**Advantages:** Most authentic, includes browser context, easy to rotate

**Supported formats (auto-detected):**
- Cookie Editor: `{"url": "...", "cookies": [...]}`
- Simple JSON: `{"name": "value", ...}`
- Netscape/cURL: Tab-separated format

### Method 3: Hybrid

```bash
export FILESCAN_API_KEY="token"
python -m samples_push --cookies ~/.filescan_cookies.json
# Priority: Cookies → API key → Error
```

---

## Storage & Config

All data and secrets are stored in a local (non-synced) directory — never in the project folder.

| OS | Data Path |
|----|-----------|
| Linux | `~/.local/share/samples_push/` |
| macOS | `~/Library/Application Support/samples_push/` |
| Windows | `%LOCALAPPDATA%\samples_push\` |

Contents: `.env` (API keys), `vault/` (encrypted samples), `state.db` (upload history)

### .env Configuration

On first run, `run.sh` copies `.env.example` to the data directory automatically. To configure manually:

```bash
# Linux / macOS
mkdir -p ~/.local/share/samples_push
cp .env.example ~/.local/share/samples_push/.env
nano ~/.local/share/samples_push/.env
```

```powershell
# Windows (PowerShell)
mkdir "$env:LOCALAPPDATA\samples_push" -Force
copy .env.example "$env:LOCALAPPDATA\samples_push\.env"
notepad "$env:LOCALAPPDATA\samples_push\.env"
```

Required fields in `.env`:
```
FILESCAN_API_KEY=your_api_key
FILESCAN_AUTH_TOKEN=eyJ...    # For account-identified uploads (priority 100)
```

App refuses to run if vault is under cloud-sync folders (OneDrive, Dropbox, etc.)

---

## Setup

### Linux / macOS (Automatic)

```bash
git clone <this-repo> samples_push && cd samples_push
chmod +x run.sh
./run.sh --help
```

First run auto-creates venv, installs deps, and copies `.env` to `~/.local/share/samples_push/.env`.

### Linux / macOS (Manual)

```bash
sudo apt install python3 python3-venv python3-pip git  # Debian/Ubuntu
# or: brew install python git  # macOS

git clone <this-repo> samples_push && cd samples_push
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
mkdir -p ~/.local/share/samples_push
cp .env.example ~/.local/share/samples_push/.env && $EDITOR ~/.local/share/samples_push/.env
python -m samples_push --limit 10
```

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
mkdir "$env:LOCALAPPDATA\samples_push" -Force
copy .env.example "$env:LOCALAPPDATA\samples_push\.env"
notepad "$env:LOCALAPPDATA\samples_push\.env"
python -m samples_push --limit 10
```

### VMware Shared Folders

Symlinks don't work in `/mnt/hgfs/`. Use native Linux path instead:

```bash
cp -r /mnt/hgfs/samples_push ~/samples_push
cd ~/samples_push
./run.sh --limit 10
```

### AV

**Linux:** If using ClamAV, exclude: `ExcludePath ^/home/<user>/.local/share/samples_push/.*`

**Windows:** Run as admin:
```powershell
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\samples_push"
```

---

## Usage

### Basic Commands

```bash
# First run (auto-setup on Linux/macOS)
./run.sh --limit 10

# Dry-run (no upload)
./run.sh --sources bazaar --limit 2 --dry-run

# Slow upload (avoid queue overflow)
./run.sh --replay --delay 90 --limit 100

# Wait for analysis reports
./run.sh --wait --limit 5

# Repair vault compression issues
./run.sh --repair-vault

# View upload statistics
./run.sh --stats

# Re-upload cleared samples with auth token
./run.sh --clear-target "https://www.filescan.io"
./run.sh --replay --delay 60 --limit 100
```

### CLI Flags

| Flag | Meaning |
|------|---------|
| `--sources` | Comma-separated source IDs (default: all except thezoo) |
| `--skip-sources` | Exclude specific sources |
| `--limit` | Max samples per source (default: 25) |
| `--delay` | Seconds between uploads (default: 60) |
| `--vault` | Vault directory |
| `--wait` | Poll filescan reports after upload |
| `--dry-run` | Download & dedup, no upload |
| `--replay` | Re-upload vault samples from scratch |
| `--staging` | Send to staging instead of prod |
| `--filescan-url` | Override filescan URL |
| `--import-zip` | Import zipped samples |
| `--zip-password` | Password for encrypted zips (default: infected) |
| `--repair-vault` | Repair unsupported compression (DEFLATE64, BZIP2, LZMA) |
| `--stats` | Show upload dashboard (by day/source, file types, sizes) |
| `--clear-cache` | Clear all upload history |
| `--clear-target URL` | Clear history for specific target |
| `--clear-cursors` | Re-fetch from sources |
| `-v` | Verbose logging |

---

## Advanced Features

### Repair Vault Compression

Fix unsupported compression methods (DEFLATE64, BZIP2, LZMA):

```bash
./run.sh --repair-vault -v       # Check compression
./run.sh --clear-target "https://www.filescan.io"
./run.sh --replay --limit 100    # Re-upload
```

### Import Zipped Samples

```bash
./run.sh --import-zip ~/Downloads/malware --zip-password "infected"

# Limit to 50 samples
./run.sh --import-zip ~/malware --limit 50
```

### Cache Management

```bash
# Clear all (will re-upload everything)
./run.sh --clear-cache

# Clear specific target
./run.sh --clear-target "https://staging.filescan.io"

# Clear cursors only (re-fetch from sources)
./run.sh --clear-cursors
```

### Staging vs Production

```bash
# Use staging
./run.sh --staging --limit 5

# Custom URL
./run.sh --filescan-url https://custom.filescan.io
# Persistent (in .env)
FILESCAN_BASE_URL=https://staging.filescan.io

# Re-upload to staging
./run.sh --staging --replay --limit 10
```

Set `FILESCAN_STAGING_API_KEY` in .env for staging uploads.

### theZoo (opt-in)

```bash
./run.sh --sources thezoo --limit 5
# Initial clone is multi-GB
```

---

## Authentication Guide

### Auth Token (Best - Account-Identified)

Get the JWT token from your browser:

1. Open https://www.filescan.io (logged in)
2. F12 → Network → click any request → Headers → copy `Authorization` value (after "Bearer ")
3. Add to `.env` (in local data dir, not project folder):
   ```
   FILESCAN_AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

This gives priority 100 and your uploads appear in the leaderboard.

### API Key (Alternative)

```bash
FILESCAN_API_KEY=your_key_from_account
./run.sh --limit 10
```

Uploads as generic access (priority 20, no leaderboard attribution).

### Comparison

| Method | Setup | Priority | Leaderboard | Notes |
|--------|-------|----------|-------------|-------|
| Auth Token | F12 → copy JWT | 100 | ✓ | Recommended |
| API Key | Account page | 20 | ✗ | Shows as guest |
| Cookies | F12 → export | 100 | ✓ | Deprecated (use token) |

---

## Scheduling

### Linux — cron (every 6h)

```cron
17 */6 * * * cd /opt/samples_push && ./run.sh --limit 10 --delay 60
```

### Linux — systemd timer

`/etc/systemd/system/samples-push.service`:
```ini
[Unit]
Description=Push malware samples to filescan.io
After=network-online.target

[Service]
Type=oneshot
User=samples
WorkingDirectory=/opt/samples_push
ExecStart=/opt/samples_push/run.sh --limit 10 --delay 60
```

`/etc/systemd/system/samples-push.timer`:
```ini
[Unit]
Description=Run samples_push every 6h

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now samples-push.timer
```

### Windows — Task Scheduler

```powershell
schtasks /Create /SC HOURLY /MO 6 /TN "samples_push" `
  /TR "py -m samples_push --limit 10 --delay 60" /SD 01/01/2026 /ST 03:00
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Operation not supported" on /mnt/hgfs | Copy to native Linux path: `cp -r /mnt/hgfs/samples_push ~/samples_push` |
| Uploads appear as "guest" | Set `FILESCAN_AUTH_TOKEN` in .env (F12 → Network → copy Authorization header) |
| Queue overflow errors | Increase `--delay` (default 60, try 90 or 120) |
| 401 Unauthorized | Check auth token is valid JWT (F12 → Network → verify token) |
| "Skipping source: missing env vars" | Set required API keys in .env or use `--skip-sources` |
| Vault files won't extract | Run `./run.sh --repair-vault` to fix compression issues |

---

## Security

### Credentials

`.env` is stored in a local-only directory (never in the project/repo folder):
- Linux: `~/.local/share/samples_push/.env`
- macOS: `~/Library/Application Support/samples_push/.env`
- Windows: `%LOCALAPPDATA%\samples_push\.env`

**Auth Token:** `FILESCAN_AUTH_TOKEN=eyJ...` — rotate if leaked  
**API Key:** `FILESCAN_API_KEY="..."` — never hardcode

### Best Practices

```bash
# DO: Restrict permissions on .env
chmod 600 ~/.local/share/samples_push/.env

# DO: Use unique tokens per environment
FILESCAN_STAGING_API_KEY="staging_key"

# DON'T: Store .env in project folder or git repo
# DON'T: Hardcode secrets in scripts
# DON'T: Share tokens
```

### .gitignore

```
__pycache__/
*.pyc
.venv/
```

---

## State & Dedup

`state.db` (SQLite) tracks uploaded SHA256s and flow_ids. Never re-uploads same hash to same target.

**Auto-retry:** Failed uploads (HTTP errors, crashes) are automatically retried on the next run. Only successfully uploaded samples are marked as "done".

Reset:
```bash
# Using CLI (recommended)
./run.sh --clear-cache
./run.sh --clear-target "https://staging.filescan.io"
./run.sh --clear-cursors
```

---

## Inspecting the Vault

```bash
# Linux/macOS
unzip -P infected -l ~/.local/share/samples_push/vault/samples/bazaar.zip

# Windows (7-Zip)
& "C:\Program Files\7-Zip\7z.exe" l -p"infected" "$env:LOCALAPPDATA\samples_push\vault\samples\bazaar.zip"
```

---

## Technical Details

### Upload Flow

1. Fetch samples from sources (bazaar, malshare, virusshare, etc.)
2. Deduplicate against SQLite state.db
3. Store encrypted (AES-256) in vault zips
4. Upload to FileScan with auth headers
5. Wait `--delay` seconds before next upload (prevents queue overflow)
6. Record flow_id in state.db

### Rate Limiting

FileScan has two rate limits:
- **Priority**: 100 if last request >60s ago, else 20
- **Queue**: Full after ~20 concurrent uploads

Default `--delay 60` ensures max priority + never fills queue.

### Authentication Headers

When auth token is set:
- `Authorization: Bearer {auth_token}` — account identity + priority 100
- `X-Api-Key: {api_key}` — API access
- Browser headers — match UI request format

When only API key:
- `Authorization: Bearer {api_key}` — generic access + priority 20
- Uploads appear as "guest"

### Recommended VM

**Debian 12 minimal:** Python 3.11, git, cron built-in. 20GB disk, 2GB RAM, 2 vCPU.

### File Layout

```
samples_push/
├── run.sh                       # Universal setup + run script
├── requirements.txt
├── .env.example
├── README.md
├── vault_repair.py              # Standalone repair tool
└── samples_push/
    ├── __main__.py              # Entry point
    ├── cli.py                   # CLI argument parsing
    ├── config.py                # Config + source registry
    ├── vault.py                 # Encrypted vault (AES-256)
    ├── state.py                 # SQLite dedup
    ├── pipeline.py              # Main upload/replay loop
    ├── sinks/filescan.py        # FileScan API (auth token + hybrid)
    └── sources/
        ├── base.py              # Source base class
        ├── malwarebazaar.py, urlhaus.py, malshare.py
        ├── virusexchange.py, inquest.py, virusshare.py
        ├── hybrid.py, thezoo.py
```

---

## FAQ

**Q: Where is .env stored?**  
A: In the local data dir (`~/.local/share/samples_push/.env` on Linux, `%LOCALAPPDATA%\samples_push\.env` on Windows). Never in the project folder.

**Q: One command to run everything?**  
A: `./run.sh --limit 10` (venv auto-created, deps auto-installed on Linux/macOS)

**Q: Auth token vs API key?**  
A: Auth token (F12 → Network header) — priority 100, account-identified. API key is fallback, shows as guest.

**Q: Why does replay re-upload?**  
A: `--replay` uploads from vault without re-fetching sources. Use after `--clear-target` to change auth method.

**Q: How to avoid queue overflow?**  
A: Default `--delay 60` paces uploads (1 per minute). Increase to 90-120 for larger batches.

**Q: Can I fix vault compression errors?**  
A: Yes — `./run.sh --repair-vault` fixes DEFLATE64, BZIP2, LZMA.

**Q: Can I schedule uploads?**  
A: Yes — cron (Linux) or Task Scheduler (Windows). See Scheduling section.

**Q: Multiple FileScan accounts?**  
A: Set different `FILESCAN_AUTH_TOKEN` in .env, or use separate data dirs.

**Q: What happens if upload fails?**  
A: Failed uploads are automatically retried on the next run. Only queue-full stops the run early.

---

## Status

✅ **Production Ready** - Account-identified uploads with rate limiting  
✅ **Auto-Retry** - Failed uploads retried on next run  
✅ **Secrets Safe** - .env stored outside project folder  

**Version:** 3.0 (Local .env + auto-retry)  
**Updated:** 2026-07-02  
**Status:** Ready for Production
