# PrivaseeAI.Security — State Assessment

**Date:** 2026-09-07
**Assessed commit:** `4ac5f5f` (main) — "Add VPN log timeline engine with observation/judgment separation (#19)"
**Assessor environment:** Linux, Python 3.11.15, clean venv from `requirements.txt` + `requirements-dev.txt`
**Scope:** Assessment only. No source files were modified.

---

## 0. Executive summary

The project **still runs**. Dependencies resolve, the test suite is green, the CLI works, and the
Alembic chain generates valid SQL. Six dormant months cost it nothing operationally.

What it cost is nothing, because the problem was never rot — the problem is that **the parts that
look finished are the parts nobody checked.** Three subsystems that the documentation lists as
complete are stubs that return success:

| Subsystem | Documented as | Actually |
|---|---|---|
| Telegram alerting | "✅ Real-time notifications" | `_send_to_telegram` logs and `return True`. Nothing is ever sent. |
| `CryptoHandler.encrypt` | "AES-256-GCM", "Encryption at Rest" | `base64.b64encode(data)`. The key is validated for length, then discarded. |
| Dashboard | "React dashboard", live threat view | FastAPI app serving module-level `mock_threats` literals. Imports nothing from `privaseeai_security`. |

Two of the three orchestrator monitor loops (`_monitor_vpn`, `_monitor_api`) are `await asyncio.sleep()`
with a comment saying a real implementation would tail logs. So the continuous-monitoring daemon that
`privasee start` launches performs exactly one class of detection: `monitor_esim_profiles`.

On calibration: `vpn_integrity.py` (PR #19, Aug 31) is genuinely good work and should be the template.
Every other detector predates it and none of them received the treatment. Of **55 detection rules**
inventoried below, **21 are sound as written — and 16 of those 21 are in `vpn_integrity.py`.**
Across the other five modules, 5 rules of 38 are sound. The calibration problem is not diffuse;
it is precisely "everything written before 2026-08-31."

**Verdict: refactor, don't archive — but narrow it hard first.** See §6.

---

## 1. Revival status

### 1.1 Dependencies — resolve cleanly

Every pin in `requirements.txt` resolved on Python 3.11. No yanked releases, no conflicts, no
build failures. Install took one pass with no intervention.

Notable resolutions (all floating to latest, see risk below): `cryptography 50.0.1`,
`pymobiledevice3 11.9.1`, `fastapi 0.141.1`, `sqlalchemy 2.0.52`, `pydantic 2.13.5`,
`python-telegram-bot 22.8`, `scapy 2.7.0`, `celery 5.6.3`.

**Risks, not breakage:**

- **Every constraint is `>=` with no upper bound, and there is no lockfile.** Today's clean install is
  luck, not reproducibility. `cryptography` went 41 → 50 during dormancy; `pymobiledevice3` went 3 → 11.
  A major-version jump under an unbounded floor is exactly how a dormant project dies silently.
- **`jinja2` is missing from `requirements.txt`** despite the dashboard importing
  `fastapi.templating.Jinja2Templates`. The CLI's own error text tells users to
  `pip install fastapi uvicorn jinja2 python-multipart websockets` — an admission the manifest is
  incomplete. Same for `python-multipart`.
- `python-telegram-bot` is installed but **never imported anywhere in `src/`**. It is a dependency for
  a feature that doesn't exist.
- The prompt mentioned Azure SDKs; there are **none** in the manifest. No Azure exposure to audit.

### 1.2 Test suite — green

```
277 passed, 10 skipped, 1 warning in 5.06s
```

**287 tests collected** under `testpaths = ["tests"]` (291 `def test_` across `tests/`; the delta is
parametrization and helpers). Not 196 (README) and not 293.

**Zero failures. No genuine regressions, no dependency rot, no never-green tests.** All 10 skips are
deliberate and declare their reason:

| Skips | Reason |
|---|---|
| 8 | `test_database.py` — "Database not available - set DATABASE_URL to run integration tests" |
| 1 | `test_carrier_detection.py:639` — "Python 3.12 version-specific failure - passes on 3.11, fails on 3.12" |
| 1 | `test_carrier_detection.py:691` — "Flaky timing issue in CI - needs refactoring" |

The 3.12 skip is worth flagging: `pyproject.toml` advertises
`Programming Language :: Python :: 3.12` as a supported classifier while carrying a test skipped
*because it fails on 3.12*. That's an unverified support claim.

**Six root-level `test_*.py` files are not collected** (they're outside `testpaths`). Two of them —
`test_imazing_backup.py`, `test_iphone_backup.py` — **fail at import** with
`NameError: name 'exit' is not defined`. They are interactive dev scripts wearing test filenames.
They have never run in CI and would break the suite if `testpaths` were widened.

### 1.3 Coverage — 73%, not 100%

```
TOTAL   2787 stmts   741 miss   73%
```

README claims **"Coverage-100%"** in a badge, in the status line, and in the stats table. The real
figure is 73%, and the distribution matters more than the number — the untested code is precisely
the delivery and persistence code:

| Module | Cover | Note |
|---|---|---|
| `database/queries.py` | **18%** | unreachable without a live DB |
| `daemon.py` | **26%** | the thing launchd runs |
| `cli.py` | **30%** | entry points |
| `database/repositories.py` | 31% | |
| `database/engine.py` | 37% | |
| `device_info.py` | 62% | |
| `monitors/carrier_detection.py` | 79% | |
| `monitors/vpn_integrity.py` | 91% | the well-tested one |

### 1.4 Alembic — chain is valid

`alembic upgrade head --sql` generates a complete, correct migration offline. Single revision:
`001_initial_threat_persistence`. Creates `devices` + `threat_events`, five indexes, an FK with
`ON DELETE CASCADE`, an `updated_at` trigger function.

**Caveat, not a defect:** the migration calls `create_hypertable(...)`, so it requires **TimescaleDB**,
not stock PostgreSQL. `docker-compose.yml` must supply a Timescale image or `upgrade head` fails at
that statement. I could not apply it against a live database in this sandbox (no PostgreSQL, and no
Docker daemon — see §1.6), so **"applies cleanly from empty" is verified only at SQL-generation level.**

### 1.5 CLI entry points

| Command | Result |
|---|---|
| `privasee --help` | ✅ Works. 9 commands registered. |
| `privasee scan` | ✅ Works. Exit 0. Degrades gracefully on Linux (no iOS backup dir), prints an empty threat table. |
| `privasee start` | ✅ Works. Runs until SIGTERM. (What it *does* while running is §2.4.) |
| `privasee dashboard` | ❌ **Broken out of the box.** |

`privasee dashboard` fails with `ModuleNotFoundError: No module named 'dashboard'`. Two independent bugs:

1. **`sys.path`.** The command calls `uvicorn.run("dashboard.api.main:app", ...)`. That string import
   requires the repo root on `sys.path`. Installed console scripts do **not** get CWD on `sys.path`,
   so this can only ever work via `python -m`, never via the installed `privasee` binary.
   The command even checks `dashboard_path.exists()` first — so it confirms the *file* is there,
   then fails to import it, which is why the error is confusing rather than actionable.
2. **Missing dependency.** With `PYTHONPATH` fixed, it then fails
   `ImportError: jinja2 must be installed to use Jinja2Templates`.

With both worked around (`PYTHONPATH=. ` + `pip install jinja2`), the app serves:
`/api/docs` → 200, `/api/threats` → 200 with data. `/` → **500** (template rendering error).
So even fully patched, the dashboard's actual HTML page does not render.

### 1.6 Docker — not verifiable here

**No Docker daemon in this environment** (`/var/run/docker.sock` absent), so `docker build` never
executed. I am not reporting a build result I did not obtain. Static review of the `Dockerfile`:

- Multi-stage, non-root `privasee` user, healthcheck, `--no-cache-dir` — structurally sound.
- **`COPY` never includes `dashboard/`.** The image physically cannot run `privasee dashboard`.
- **`LABEL version="0.1.0"`** in both stages, while `pyproject.toml` says `0.3.0`. Stale.
- `COPY src/privaseeai_security /app/privaseeai_security` installs by path, not `pip install .`, so
  the `privasee` console script is never created in the image. `ENTRYPOINT ["python", "-m"]` +
  `CMD ["privaseeai_security"]` works around this, but it means no CLI subcommands in-container.
- Only `requirements.txt` is installed — so the missing `jinja2` bites here too.

### 1.7 Dependency CVE audit — clean

`pip-audit` across the full resolved tree:

```
Found 2 known vulnerabilities in 1 package
setuptools 79.0.1  PYSEC-2026-3447  (fix: 83.0.0)
```

`setuptools` is a build-time tool in the venv, **not a runtime dependency** of this project.
**No CVEs in `cryptography`, `pyOpenSSL`, `pycryptodome`, `scapy`, `fastapi`, `sqlalchemy`, or any
runtime dependency.** Six dormant months produced no security debt in the dependency tree.

The crypto risk in this repo is not a CVE. It's §2.2.

### 1.8 Branches and PRs

**One open PR:**

| PR | Title | Verdict |
|---|---|---|
| **#18** | "Add Node.js coverage workflow template for **cloudhealthoffice** repo" | **Close.** A Node.js CI template for a *different repository*, sitting in a Python project. 7 commits, +1 behind main. Wrong repo. |

**Four stale branches:**

| Branch | Ahead/Behind | Last commit | Verdict |
|---|---|---|---|
| `copilot/add-benefit-plan-module` | 8 / 7 | 2026-02-04 | **Delete.** Adds a health-**benefit-plans** domain (`domain/benefit_plans/`, `benefit_plan_repository.py`, 3 test files, **2,668 lines**) to an iOS threat-detection tool. Unrelated scope creep, almost certainly wrong-repo work. |
| `copilot/add-code-coverage-report` | 7 / 1 | 2026-02-04 | Backing branch for PR #18. Close with it. |
| `copilot/setup-project-structure` | 20 / **93** | 2026-01-25 | **Delete.** 93 commits behind; superseded. |
| `copilot/setup-documentation-best-practices` | 4 / **93** | 2026-01-14 | **Delete.** 93 behind; contains only "Initial plan" / "Changes before error encountered". |

**Nothing worth recovering.** No branch contains unmerged detection work. The one genuinely valuable
recent change (the timeline engine) already landed as #19.

---

## 2. Ground truth — claims vs. reality

Legend: **Full** · **Partial** · **Scaffold** (structure exists, no working behaviour) · **Docs-only** · **False**

### 2.1 Headline numbers

| Claim | Source | Reality | Status |
|---|---|---|---|
| "9,879 lines of Python" | README ×3, ROADMAP | **7,363** lines in `src/` (5,593 in `tests/`) | **False** |
| "196 tests passing" | README ×4 | **287 collected, 277 pass, 10 skip** | **False** (stale low) |
| "Coverage 100%" | README badge + table | **73%** | **False** |
| "Production Ready" | README, ROADMAP status | Alerting, persistence, dashboard are stubs | **False** |
| "100% Local Processing" | README | True — no outbound calls exist (partly because delivery is a stub) | **Full** |
| Apache 2.0 | LICENSE | Present and correct | **Full** |

### 2.2 Security claims — the serious ones

| Claim | Source | Reality | Status |
|---|---|---|---|
| "**Encryption at Rest**: All sensitive data encrypted using industry-standard algorithms" | SECURITY.md | See below | **False** |
| "**Encrypted Storage**: End-to-end encryption for sensitive information" | SECURITY.md | No caller encrypts anything | **False** |

`CryptoHandler.encrypt` is documented as **"Encrypt data using AES-256-GCM"**. The implementation:

```python
# Stub implementation - just return base64 encoded data
nonce = secrets.token_bytes(12)
encrypted = base64.b64encode(data)
return nonce + encrypted
```

The 32-byte key is length-checked and then **never used**. The random nonce is prepended and then
**ignored on decrypt** (`encrypted_data[12:]`). This is base64 with 12 bytes of decoration. It
provides no confidentiality whatsoever, and `decrypt` will happily decode output from *any* key.

Mitigating fact: `CryptoHandler.encrypt` has **no callers** — `grep` finds no import of it outside
`crypto/`. Nothing in the product currently relies on it. Aggravating fact: it is a public API on a
class called `CryptoHandler` in a **security tool**, with a docstring naming a real AEAD cipher, and
SECURITY.md tells users their data is encrypted at rest. The orchestrator's actual persistence
(`_save_state`) writes **plaintext JSON**, protected only by `chmod 600`.

This is the highest-severity finding in the repository. It is a false security claim, not a bug.

### 2.3 Persistence layer (`database/`, documented "Phase 4 planned")

| Component | Reality | Status |
|---|---|---|
| `database/models.py` | Real SQLAlchemy models. **100% covered.** | **Full** |
| `alembic/versions/001_*.py` | Valid, generates correct SQL (§1.4) | **Full** |
| `database/engine.py` | Async engine/session factory. 37% cover. | **Partial** |
| `database/repositories.py` | CRUD written, 31% cover, all integration tests skipped | **Partial** |
| `database/queries.py` | **18% cover** — essentially unexercised | **Scaffold** |
| **Wired into the app** | **`grep` finds zero imports of `database` anywhere outside `database/`** | **Not wired** |

The persistence layer is better than "planned" — the schema and migration are real work. But **no
monitor, orchestrator, or CLI path ever writes a threat to it.** It is a well-built component
connected to nothing. Detections are counted in memory and lost on exit (apart from a JSON state file).

### 2.4 Dashboard (`dashboard/`, documented "Phase 5 planned" / "React dashboard")

| Claim | Reality | Status |
|---|---|---|
| "React dashboard" | **No React.** No `package.json`, no JS build, no `src/`. Three files total: `README.md`, `api/main.py`, `templates/dashboard.html`. | **False** |
| Live threat monitoring | **All data is fabricated.** | **Scaffold** |
| Monitor start/stop control | Flips a boolean on a mock object | **Scaffold** |

`dashboard/api/main.py` (31 KB, ~30 endpoints) **imports nothing from `privaseeai_security`.** Its
entire import block is stdlib + FastAPI + pydantic. Every endpoint reads module-level literals:

```python
mock_devices  = [...]   # device_name="Mark's iPhone"
mock_threats  = [...]   # id="threat-1", title="WireGuard forced to TCP (UDP blocked)"
mock_monitors = [...]
```

Confirmed live: `GET /api/threats` returns `{"id":"threat-1", "device_name":"Mark's iPhone", ...}`
on a machine with no iPhone, no backups, and no monitors running. There is even a
`POST /api/simulate/threat` endpoint that invents new ones with `random.choice`.

This is a UI prototype with a plausible API shape. It is not connected to the detection engine, and
nothing it displays is real. Anyone shown this dashboard would reasonably conclude the tool is
working.

### 2.5 Telegram alerting

| Claim | Source | Reality | Status |
|---|---|---|---|
| "✅ Real-time notifications" | ROADMAP | `_send_to_telegram` never sends | **False** |
| Severity filtering, dedup, throttling, formatting | ROADMAP | Genuinely implemented and tested | **Full** |

The surrounding machinery is real: `_is_throttled`, `_format_alert`, `should_alert`, dedup cache.
The delivery path is not:

```python
def _send_to_telegram(self, message: str) -> bool:
    """Send message to Telegram (stub for now - would use python-telegram-bot)."""
    self.logger.info(f"Sending Telegram alert to chat {self.chat_id}")
    # For now, simulate successful send
    return True
```

**Error handling: none, because there is no operation to fail.** It unconditionally returns `True`,
so every caller records a successful alert delivery. A user who configures a bot token and chat ID
gets log lines saying alerts were sent and never receives one. The failure is silent by construction.

Secondary bug: `should_alert`'s `severity_order` dict **omits `ThreatLevel.INFO`**, so INFO falls to
the `.get(level, 0)` default and is indistinguishable from `NONE`. Harmless at the default
`min_severity=HIGH`, but wrong, and it will bite as soon as detectors start emitting INFO — which is
exactly what the §5 remediation requires.

### 2.6 Orchestrator (`ORCHESTRATOR_GUIDE.md`)

| Claim | Reality | Status |
|---|---|---|
| Asyncio coordination, graceful shutdown, backoff, state persistence, dedup | Real, tested (78% cover) | **Full** |
| "Concurrent monitor coordination" — 3 monitors | 3 tasks spawn; **2 do nothing** | **Partial** |

```python
async def _monitor_vpn(self):
    while self._running:
        # Note: VPN monitor currently parses log files
        # In a real deployment, this would tail live logs
        await asyncio.sleep(self.monitor_interval)

async def _monitor_api(self):
    while self._running:
        # Real implementation would tail syslog or use API hooks
        await asyncio.sleep(self.monitor_interval)
```

Only `_monitor_carrier` performs detection — and it calls **only** `monitor_esim_profiles`, never
`detect_localhost_routing` (the module's headline capability), `analyze_dns_resolution`, or
`track_network_interfaces`.

So `privasee start` — the product's primary mode — runs one eSIM check on a loop. The best detector
in the codebase (`vpn_integrity`) is unreachable from the daemon; it is only reachable via
`privasee analyze <logfile>`, which is a manual, one-shot command.

### 2.7 launchd service

| Claim | Reality | Status |
|---|---|---|
| `com.privaseeai.security.plist` installs and runs as documented | Several blockers | **Partial** |
| `com.privaseeai.vpnmonitor.plist` installs as documented | **Not installable by anyone but the original author** | **False** |

`orchestrator` *is* runnable as a module (`__main__` block present, `python -m
privaseeai_security.orchestrator` starts and stays up). But the security plist:

- `WorkingDirectory` = **`/opt/privaseeai`**, while `LAUNCHD_QUICK_START.md` instructs `pip install -e .`
  from the repo. launchd fails the job outright if `WorkingDirectory` doesn't exist. Nothing in the
  docs creates `/opt/privaseeai`.
- `ProgramArguments` = **`/usr/bin/env python3`** — the *system* interpreter. A `pip install -e .`
  into a venv is invisible to it. The documented install and the plist disagree about which Python runs.
- `StandardOutPath` = **`/var/log/privaseeai/security.log`**, but `LimitLoadToSessionType = Aqua`
  (a user agent). A user agent cannot create `/var/log/privaseeai/`. The docs never create it.

The vpnmonitor plist is worse — it ships **another developer's absolute paths**:

```
/Users/karkusdog/git/PrivaseeAI.Security/.venv/bin/python3
/Users/karkusdog/git/PrivaseeAI.Security/vpn_monitor_daemon.py
--log-dir /Users/karkusdog/Library/Logs
--log-dir /Users/karkusdog/git/PrivaseeAI.Security     ← duplicated flag, second wins
```

It also passes `--log-dir` **twice**, which is a live argument bug independent of the paths.

**Why the tests didn't catch any of this:** `tests/unit/test_launchd_service.py` asserts on the plist
as *text*:

```python
assert f"<key>{key}</key>" in plist_text
assert "python3" in plist_text
assert "privaseeai_security.orchestrator" in plist_text
```

It verifies that strings appear in a file. It never resolves a path, checks a directory exists, or
loads the job. Nine passing tests, zero installation coverage. This is the clearest example of the
repo's central pattern: **tests that confirm the code says what it says, rather than that it does what it claims.**

---

## 3. Calibration audit

### 3.1 The reference standard

`monitors/vpn_integrity.py` is the only detector written with a working theory of false positives.
Its four properties, which nothing else has:

1. **Observation/judgment split.** `_build_observations` records *what was seen* at INFO; `_judgment`
   emits *what it might mean* with an explicit severity.
2. **Mandatory confidence.** Every judgment carries `confidence` ∈ [0,1] (0.5–0.85 in practice).
   Nothing claims certainty.
3. **Mandatory `alternatives`.** Every judgment names the benign explanations *in the alert itself*.
4. **Log time, never wall-clock.** Windows are computed from event timestamps, with deltas clamped to
   `[0, window]` so out-of-order entries can't inflate counts.

Plus two disciplines worth copying explicitly: **user-action suppression** (a `userInitiated` stop
excuses a subsequent change) and **signal-quality gating** (fingerprints under 32 hex chars are
discarded as untrustworthy rather than scored).

The contrast is stark. Severity distributions:

| Module | INFO/NONE | LOW | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|---|---|
| `vpn_integrity.py` | 6 | 6 | 3 | 0 | 0 |
| `carrier_detection.py` | 0 | 0 | 2 | 4 | 1 |
| `api_abuse.py` | 0 | 0 | 3 | 2 | 0 |
| `cert_validator.py` | 1 | 0 | 2 | 4 | 1 |
| `device_info.py` | 1 | 2 | 2 | 1 | 3 |

`vpn_integrity` emits **nothing above MEDIUM**. Every other module's *floor* is roughly where
`vpn_integrity`'s ceiling is.

### 3.2 Rule-by-rule table

**Verdicts:** **sound** · **needs corroboration** (real signal, must not fire alone) ·
**needs downgrade** (over-severe) · **delete** (no detection value)

**Tally across all 55 rules:**

| Module | Rules | sound | needs corroboration | needs downgrade | delete |
|---|---|---|---|---|---|
| `vpn_integrity.py` | 17 | **16** | 1 | 0 | 0 |
| `carrier_detection.py` | 19 | 2 | 3 | 10 | **4** |
| `api_abuse.py` | 5 | 0 | 1 | 3 | 1 |
| `cert_validator.py` | 8 | 2 | 2 | 3 | 1 |
| `device_info.py` | 6 | 1 | 1 | 4 | 0 |
| `backup_monitor.py` | 0 | — | — | — | — |
| **Total** | **55** | **21** | **8** | **20** | **6** |

Read the first row against the rest: the module written in August is 94% sound; the five written
before it are 13% sound (5 of 38).

#### `monitors/vpn_integrity.py` — the reference

| # | Rule | Signal it keys on | Severity | Benign conditions that also produce this signal | Verdict |
|---|---|---|---|---|---|
| 1 | `analyze_transport_protocol` (tcp) | `socketType tcp` | INFO | Proton Smart Protocol on UDP-blocked Wi-Fi | **sound** |
| 2 | `analyze_transport_protocol` (udp) | `socketType udp` | NONE | — | **sound** |
| 3 | `validate_vpn_certificate` (refresh) | "seems up to date" | *none emitted* | Routine cert refresh | **sound** |
| 4 | `validate_vpn_certificate` (known) | fp in known-good | NONE | — | **sound** |
| 5 | `validate_vpn_certificate` (short fp) | fp < 32 hex | *discarded* | Truncated log fragment | **sound** |
| 6 | `validate_vpn_certificate` (unknown) | fp not in known-good | LOW | Cert rotation; empty known-good set (§3.3) | **sound** |
| 7 | `detect_api_rate_limiting` | `cooldown(...)` | INFO | Proton rate-limits routine clients | **sound** |
| 8 | `track_server_connection` | ≥4 DNS64 IPs / 10 min log-time | MEDIUM | Load balancing; roaming; manual server switch | **sound** |
| 9 | `_detect_path_monitor_storm` | >60 bumps/hr, or 3/60s while satisfied | LOW (0.8) | `wgBumpSockets` churn; Wi-Fi↔cell handoff | **sound** |
| 10 | `_detect_persistent_tcp` | TCP >15 min, no UDP, no user stop | LOW (0.5) | Hotel/captive network blocking UDP all session | **sound** |
| 11 | `_detect_expensive_flap` | `isExpensive` toggles, path never unsatisfied | LOW (0.7) | iOS cost re-evaluation; hotspot; low-data mode | **sound** |
| 12 | `_detect_sleep_handshake_gap` | Handshake retry ±60s of sleep/wake | INFO (0.85) | Locked iPhone suspends the extension | **sound** |
| 13 | `_detect_dns64_hopping` | ≥4 DNS64 IPs/10 min, no user reconnect | MEDIUM (0.6) | Gateway load-balancing; roaming | **sound** |
| 14 | `_detect_stop_and_peer` → `PEER_SWITCH` | Peer change after user stop+start | INFO (0.8) | User picked another server | **sound** |
| 15 | `_detect_stop_and_peer` → `UNEXPECTED_PEER_SWITCH` | Peer change, no stop/start between | MEDIUM (0.55) | **Silent app-driven reconnect; provider-side migration — both common and both invisible in the log.** Confidence 0.55 is honest, but MEDIUM on a coin-flip is the one over-call in this module. | **needs corroboration** |
| 16 | `_detect_stop_and_peer` → `UNEXPLAINED_STOP` | Stop, no reason, no nearby wake | LOW (0.5) | OS reclaimed the extension; uncaptured crash | **sound** |
| 17 | `_detect_keepalive_asymmetry` | sends > 3× receives / 10 min, no sleep | LOW (0.5) | Radio ramp-up buffering; lossy network | **sound** |

#### `monitors/carrier_detection.py` — never calibrated

| # | Rule | Signal it keys on | Severity | Benign conditions that also produce this signal | Verdict |
|---|---|---|---|---|---|
| 18 | `monitor_esim_profiles` unsigned | `is_signed == False` | **CRITICAL** | `_extract_esim_profiles` reads `data.get("IsSigned", False)` — **absent key ⇒ False**. Any plist lacking the key is CRITICAL. Signature state isn't even in these plists. | **needs downgrade** |
| 19 | `monitor_esim_profiles` issuer | `["localhost","127.0.0.1","test","debug"]` substring in issuer | **CRITICAL** | Any issuer CN containing "test" — `TestFlight`, `Latest`, `Contest`, lab/staging carrier bundles | **needs downgrade** |
| 20 | `monitor_esim_profiles` unknown carrier | Name not in a 14-entry carrier list | HIGH | **Every MVNO on earth** — Mint, Visible, Cricket, Google Fi, Boost, Lyca, Giffgaff; every non-US/UK/CA carrier; every roaming partner | **delete** |
| 21 | `monitor_esim_profiles` persistence | Profile in ≥2 consecutive backups | **CRITICAL** | **A working SIM appears in every backup.** Persistence across backups is the *normal* state of a carrier profile; only survival across a *factory reset* is interesting, and the code computes a 7-day time gap that it logs and then discards. | **delete** |
| 22 | `monitor_esim_profiles` carrier renamed | `carrier_name` changed | HIGH | Carrier rebrand (Sprint→T-Mobile); roaming display change; MVNO host change | **needs corroboration** |
| 23 | `monitor_esim_profiles` signature changed | `is_signed` changed | HIGH | Flips whenever the key's presence changes between backups (see #18) | **needs corroboration** |
| 24 | `detect_localhost_routing` localhost | server ∈ `{127.0.0.1, ::1, localhost}` | **CRITICAL** | Essentially none. **This is the module's one genuinely good rule** — the documented attack, precisely matched, correctly CRITICAL. | **sound** |
| 25 | `detect_localhost_routing` private IP | RFC1918 server address | HIGH | **Nearly every corporate VPN.** The code's own comment concedes "Some corporate VPNs legitimately use these, but still flag for review." | **needs downgrade** |
| 26 | `detect_localhost_routing` no endpoint | server ∈ `{"", "null", "none"}` | **CRITICAL** | Parser defaults missing addresses to `"unknown"` (not in the list), so this mostly misfires on genuinely malformed plists — a parse-quality signal dressed as an attack | **needs downgrade** |
| 27 | `detect_localhost_routing` MDM no org | MDM profile, no `PayloadOrganization` | **CRITICAL** | `PayloadOrganization` is **optional** in Apple's spec. Any MDM profile omitting it — routine — is CRITICAL. | **needs downgrade** |
| 28 | `detect_localhost_routing` unsigned | `is_signed` = `bool(PayloadCertificateUUID)` | HIGH | **Every manually-created VPN config.** A hand-added WireGuard/IKEv2 profile has no `PayloadCertificateUUID`. | **needs downgrade** |
| 29 | `detect_localhost_routing` name keywords | `["test","debug","local","proxy","intercept","mitm","capture"]` substring in display name | HIGH | **"local" matches `Localhost`, `Local Network`, `LocalNet`, and — critically — any profile named for a locale.** "test" matches `TestFlight`, `Latest`. "proxy" matches every legitimate corporate proxy config. Substring, not token, matching. | **needs downgrade** |
| 30 | `detect_localhost_routing` install hour | `install_date.hour >= 23 or < 6` | HIGH | **Any late-night install.** Also fires on timezone-shifted timestamps, and on travel. Attackers are not constrained to office hours; this rule encodes no threat model at all. | **delete** |
| 31 | `is_critical` escalation | `"MDM" in str(localhost_indicators)` | **CRITICAL** | Two compounding defects: (a) **any MDM-managed device is permanently CRITICAL** — every corporate iPhone; (b) it substring-matches a **stringified Python list**, so any indicator text containing "MDM" anywhere escalates. Fragile independent of calibration. | **delete** (rewrite as typed flags) |
| 32 | `_check_tun_tap_config` count | tun/tap count > vpn_count + 2 | MEDIUM | macOS keeps `utun0`–`utun3` up permanently (AWDL, Back to My Mac, iCloud Private Relay). Private Relay alone adds interfaces. | **needs corroboration** |
| 33 | `_check_tun_tap_config` route | Route destination contains localhost | HIGH | Rare benign cause; reasonable signal | **sound** |
| 34 | `analyze_dns_resolution` localhost DNS | DNS server ∈ `{127.0.0.1, ::1}` | HIGH | **Every local DNS proxy**: NextDNS CLI, AdGuard Home, dnscrypt-proxy, Pi-hole-on-device, DoH clients. This is the standard deployment shape for the *privacy tools this project's users run*. | **needs downgrade** |
| 35 | `analyze_dns_resolution` private DNS | DNS server in RFC1918 | HIGH | **Every home router.** `192.168.1.1` is the single most common DNS server on Earth. Also every corporate resolver. | **needs downgrade** |
| 36 | `track_network_interfaces` | tun/tap count > `len(known_vpn_profiles)` + 2 | MEDIUM | `known_vpn_profiles` is populated only by a prior `detect_localhost_routing` run; on a fresh process it is **empty**, so the threshold is a bare `> 2` — which stock macOS exceeds at idle | **needs downgrade** |

#### `monitors/api_abuse.py` — never calibrated

| # | Rule | Signal it keys on | Severity | Benign conditions that also produce this signal | Verdict |
|---|---|---|---|---|---|
| 37 | `check_rate_limit_responses` cooldown | `cooldown(` in log | **HIGH** `API_TRACKING` | **Direct contradiction with rule #7**: `vpn_integrity.detect_api_rate_limiting` scores the *identical* ProtonVPN log line as **INFO**, documented as "Proton rate-limits routine client requests; this is not, by itself, evidence of tracking." Two modules, one log line, four severity levels apart. | **needs downgrade** |
| 38 | `check_rate_limit_responses` generic | `"rate limit"` / `"too many requests"` / `"429"` | MEDIUM | Any 429 from any API. Substring `"429"` also matches timestamps, byte counts, IDs, ports — it is matched against the whole log line. | **needs downgrade** |
| 39 | `detect_location_tracking` | >10 location requests/hour | HIGH | **A VPN app legitimately polls `/api/v1/location`** to display the exit country — that is its job. Also fires on any navigation/weather/transit app. Threshold is unsourced. | **needs downgrade** |
| 40 | `_detect_burst_pattern` | ≥20 requests / 5 min | MEDIUM | App launch; server-list refresh; post-reconnect resync; user pull-to-refresh | **needs corroboration** |
| 41 | `_detect_background_activity` | ≥5 requests between 23:00–06:00 | MEDIUM | **iOS Background App Refresh is designed to run overnight while charging.** Also: push wake-ups, silent notifications, overnight backup, and *any user awake at night*. Same unfounded "night = suspicious" premise as #30. | **delete** |

Additional defect across #39–41: all three use `datetime.now()` (wall-clock) rather than event
timestamps — the exact failure mode `vpn_integrity` deliberately avoids. Replaying a historical log
compares its timestamps against *today*, so every stored request falls outside the window and the
detectors silently return nothing.

#### `crypto/cert_validator.py`

| # | Rule | Signal it keys on | Severity | Benign conditions that also produce this signal | Verdict |
|---|---|---|---|---|---|
| 42 | `SELF_SIGNED` | subject == issuer | **CRITICAL** | **Every root CA is self-signed.** If a chain is passed, the root triggers this. Strong signal for a *leaf*; the code doesn't distinguish leaf from root. | **needs corroboration** |
| 43 | `WEAK_HASH_ALGORITHM` | md5 / sha1 | HIGH | Legacy roots still in some trust stores | **sound** |
| 44 | `CHAIN_MISMATCH` | issuer[i] ≠ subject[i+1] | HIGH | Out-of-order chain; cross-signed intermediates | **sound** |
| 45 | `SHORT_VALIDITY` | validity ≤ 7 days | MEDIUM | **Short-lived certs are now standard practice** (ACME automation, 6-day Let's Encrypt profiles). This rule ages badly and is trending toward pure false positive. | **needs downgrade** |
| 46 | `INCOMPLETE_CHAIN` | `chain is None or len < 2` | MEDIUM | **Fires on the default call path.** `validate_vpn_certificate(cert_bytes)` with no `chain_bytes` — the documented single-argument usage — *always* appends this. **Every certificate validated without an explicit chain is MEDIUM minimum, by construction.** | **delete** (make it a data-quality flag, not a threat) |
| 47 | Unknown fingerprint, no indicators | fall-through `else` | **HIGH** | The `else` branch comment says "Unknown fingerprint but no strong MITM indicators: treat as HIGH." Given #49, **this is the outcome for essentially every real certificate.** Compare rule #6, which scores the same condition **LOW** and says so in the alert text. | **needs downgrade** |
| 48 | `PARSE_ERROR` | Cert bytes won't parse | HIGH | Truncated capture; wrong encoding; a non-certificate blob | **needs downgrade** |
| 49 | `KNOWN_GOOD_FINGERPRINTS` containment | `known.lower() in fp_lower` | (gates all of the above) | See §3.3 | **needs corroboration** |

#### `device_info.py` — a second, better-calibrated profile analyzer

Worth noting: this module already does what `carrier_detection` should — `APPLE_SYSTEM_PATHS` and
`KNOWN_LEGITIMATE_SERVICES` allowlists, an early `return []` for system files, and a graded
`_assess_threat_level`. It is the closer of the two to the target design, and it is *duplicate
functionality*: both modules parse VPN/MDM profiles out of the same backups.

| # | Rule | Signal it keys on | Severity | Benign conditions that also produce this signal | Verdict |
|---|---|---|---|---|---|
| 50 | `_has_localhost_server` | `localhost/127.0.0.1/0.0.0.0/::1` substring in **profile_id or display_name** | **CRITICAL** | **Bug, not just calibration: it never inspects the server address.** A profile literally routing to `127.0.0.1` but named "Work VPN" is **missed**; one named "Localhost Lab" is CRITICAL. The detector keys on the wrong field. | **needs corroboration** |
| 51 | Suspicious VPN name | `["test","debug","local","proxy"]` substring | HIGH | Same substring problems as #29 | **needs downgrade** |
| 52 | Unsigned VPN, unknown org | not signed AND org ∉ `KNOWN_LEGITIMATE_ORGS` | **CRITICAL** | `KNOWN_LEGITIMATE_ORGS` is **`{Apple Inc., Apple, NextDNS Inc, NextDNS}`** — four entries. **ProtonVPN, Mullvad, Tailscale, WireGuard, and every corporate VPN are "unknown orgs."** Combined with unsigned-by-default (#28), this makes the ordinary case CRITICAL. | **needs downgrade** |
| 53 | VPN with no organization | `PayloadOrganization` absent | MEDIUM | Optional field; routinely omitted | **needs downgrade** |
| 54 | Unsigned MDM, no org | not signed AND no org | **CRITICAL** | Same optional-field issue | **needs downgrade** |
| 55 | MDM unknown org (signed) | signed, org not allowlisted | LOW | Correctly graded — the one well-calibrated rule here | **sound** |

**Code defect found while reading:** `_is_apple_system_file` is **truncated mid-comment**
(`# Check for ` followed by the next `def`) and has **no trailing `return False`**. It returns `None`
implicitly. Falsy, so it happens to behave correctly — but it is unfinished code in the allowlist
path, and any future `elif` after that comment would be unreachable.

#### `backup_monitor.py`

**Zero detection rules.** `_analyze_file` is a documented stub:

```python
Note:
    This is a stub implementation. Real implementation would
    perform actual threat analysis.
"""
self.logger.debug(f"Analyzing file: {file_path}")
```

The file watcher, callback plumbing, and `scan_existing_backups` are real. The analysis is a debug
log line. **Nothing this module watches can ever produce an alert.** Its 93% coverage measures the
plumbing around an empty centre — and is a good illustration of why the 73%/100% coverage gap
matters less than *what* is covered.

### 3.3 `KNOWN_GOOD_FINGERPRINTS` — the containment problem

```python
KNOWN_GOOD_FINGERPRINTS = {"6a1e93785520dade"}   # 16 hex chars = 64 bits
```

Matching is `if known.lower() in fp_lower` — **substring containment against a full SHA-256 hex
string (64 chars)**.

**Three distinct problems:**

1. **It never matches.** A SHA-256 fingerprint contains this 16-char sequence only by astronomical
   coincidence. So the known-good fast path is dead, and **every real certificate falls through** —
   to LOW in `vpn_integrity` (rule #6, fine) and to **HIGH** in `cert_validator` (rule #47, not fine).
   The single entry the comment labels "example" is the entire database.
2. **Substring is the wrong operator.** It is unanchored, so a known-good value would match anywhere
   in the hex — position-independent. It also means a *shorter* entry is a *weaker* constraint:
   truncating to 8 chars (32 bits) would start producing collisions against unrelated certificates,
   silently marking hostile certs as known-good. The failure mode is **fail-open**, which is the
   wrong direction for an allowlist.
3. **64 bits is below collision resistance** for an adversarial setting. Grinding a certificate whose
   SHA-256 contains a chosen 16-hex substring is feasible. A partial-fingerprint allowlist is only
   safe if the partial is long enough that forgery is infeasible.

**How it should be populated and matched:**

- **Store full 64-char SHA-256 fingerprints and compare with `==`** after normalising case and
  stripping separators. Never containment. If truncation is ever needed, anchor it as a documented
  prefix and require ≥32 hex chars (128 bits).
- **Pin the issuing CA, not the leaf.** Leaf certificates rotate on the order of days; a leaf
  allowlist guarantees constant churn and trains users to ignore the alert. Pin the ProtonVPN
  intermediate/root SPKI (SPKI hash, not cert hash — it survives reissuance).
- **Populate it as data, not code.** A `known_hosts`-style file (`~/.privasee/known_certs.json`)
  with a TOFU bootstrap: first observation per server is recorded with a timestamp; later *changes*
  are the alert. That converts an unmaintainable static set into a per-user baseline, and turns the
  signal from "is this in my list" (unanswerable) to "did this change under me" (the actual question).
- **Keep the empty-set semantics honest.** While the database is empty or unbootstrapped, unknown
  fingerprints must be **INFO/LOW**, never HIGH — you cannot claim a cert is unrecognised when you
  recognise nothing. Rule #6 already gets this right; rule #47 does not.

---

## 4. Negative-test coverage — proposed design

*(Design only, per brief — no tests written.)*

### 4.1 Current state

**11 benign-input tests out of 287 ≈ 3.8%.** And 9 of the 11 sit in `vpn_integrity`/`api_abuse`:

```
test_real_attack_detection.py::test_no_false_positives_for_normal_operation
test_vpn_integrity_monitor.py::test_udp_normal_operation
test_analyze_aug31_shapes.py::test_scenario1_clean_udp_five_bumps_storm_low_no_high
test_analyze_aug31_shapes.py::test_full_aug31_style_session_exits_clean
test_vpn_integrity_session.py::test_clean_udp_session_with_bumps_is_low_no_high
test_vpn_integrity_session.py::test_cert_up_to_date_emits_no_threat
test_api_abuse.py::{test_no_rate_limit_in_normal_log, test_normal_location_usage_no_alert,
                    test_normal_request_rate_no_burst, test_daytime_activity_no_alert,
                    test_no_threats_for_normal_usage}
```

**`carrier_detection.py` has none. `device_info.py` has none. `cert_validator.py` has none.**
Precisely the three modules with the worst calibration have zero evidence they stay quiet. That is
not a coincidence — it is the mechanism. The suite proves detection *fires*; nothing proves it *doesn't*.

### 4.2 Proposed structure

```
tests/negative/
├── conftest.py                     # shared asserts + fixture loaders
├── corpus/
│   ├── vpn_logs/                   # synthetic WireGuard/Proton sessions
│   ├── backups/                    # synthetic iOS backup trees (plists + Manifest.db)
│   └── network/                    # scutil --dns / ifconfig captures
├── test_benign_vpn_sessions.py
├── test_benign_backups.py
├── test_benign_network_state.py
├── test_benign_certificates.py
└── test_benign_api_patterns.py
```

**The core contract**, one shared assertion used by every case:

```python
def assert_quiet(detections, max_severity=ThreatLevel.INFO):
    """No detection may exceed max_severity. On failure, print every
    offending rule, its severity, and its indicators — so a regression
    names the rule that broke, not just a count."""
```

Three supporting conventions:

- **Corpus as data, not literals.** Fixtures live as files so the same corpus feeds unit tests, a
  future `privasee analyze` regression run, and manual inspection.
- **A `# BENIGN-BECAUSE:` header on every fixture**, citing the real-world behaviour it represents.
  A fixture nobody can justify is a fixture that will be "fixed" by loosening the assert.
- **Frozen clock.** Every case pins `datetime.now()`. Rules #39–41 and #30 are time-dependent;
  without a frozen clock these tests pass or fail based on when CI runs.

### 4.3 Specific cases

**A. `test_benign_vpn_sessions.py`** — must stay ≤ INFO

| Case | Fixture | Guards against |
|---|---|---|
| A1 | Clean UDP session, 2 h, periodic keepalives | baseline |
| A2 | Hotel Wi-Fi: TCP for the whole session, no UDP recovery | #1 must be INFO; #10 LOW at most |
| A3 | Wi-Fi↔cellular handoff: 40 path bumps, always `satisfied` | #9 |
| A4 | Overnight locked phone: sleep/wake pairs, handshake retries at each wake | #12 |
| A5 | `isExpensive` toggles on hotspot connect/disconnect | #11 |
| A6 | User switches server 3× (userInitiated stop → start → new peer) | #14 must be INFO, **not** #15 MEDIUM |
| A7 | **IPv6-only carrier, DNS64/NAT64: 3 distinct DNS64 IPs in 10 min** | #8/#13 threshold is ≥4 — this must stay silent |
| A8 | **iCloud Private Relay active**: extra `utun` interfaces present | #32, #36 |
| A9 | Post-sleep reconnection gap: 40-minute silence, clean resume | #16 |
| A10 | Lossy cellular: keepalive sends 2× receives (below the 3× threshold) | #17 |
| A11 | Provider-side server migration: peer changes with no user stop | **Expected to fail today** — pins #15 as the known over-call |

**B. `test_benign_backups.py`** — the highest-value group

| Case | Fixture | Guards against |
|---|---|---|
| B1 | Backup with a single legitimate carrier eSIM (T-Mobile), signed | baseline |
| B2 | **MVNO profile: "Mint Mobile"** — not in the 14-carrier list | #20 |
| B3 | **Non-US carrier: "Telstra" / "SoftBank"** | #20 |
| B4 | **Same carrier profile present in 4 consecutive backups** | #21 — normal SIM, must be silent |
| B5 | **Carrier plist with no `IsSigned` key** (the common real shape) | #18 |
| B6 | **Corporate MDM profile, signed, `PayloadOrganization` absent** | #27, #31, #54 |
| B7 | **Corporate VPN to RFC1918 `10.x.x.x`, signed** | #25 |
| B8 | **Profile named "Contoso Test Network"** | #29, #51 — substring "test" |
| B9 | **Profile named "Local Office Wi-Fi"** | #29, #51 — substring "local" |
| B10 | **Profile named "Corp Proxy Config"** | #29, #51 — substring "proxy" |
| B11 | **Legit profile installed at 01:30 local** | #30 — the late-night rule |
| B12 | **Hand-added WireGuard profile: unsigned, no org, public server** | #28, #52 — the ordinary case |
| B13 | ProtonVPN profile (`PayloadOrganization: "Proton AG"`) | #52 — not in the 4-entry allowlist |
| B14 | Apple system config profile under `Library/ConfigurationProfiles/` | #50–55 allowlist path |
| B15 | Carrier rebrand across backups (Sprint → T-Mobile) | #22 |
| B16 | **Profile named "Work VPN" whose server *is* `127.0.0.1`** | **Inverse test** — #50 must FIRE. Pins the wrong-field bug. |

**C. `test_benign_network_state.py`**

| Case | Fixture | Guards against |
|---|---|---|
| C1 | `scutil --dns` with **`192.168.1.1`** (home router) | #35 |
| C2 | `scutil --dns` with **`127.0.0.1`** (NextDNS/AdGuard/dnscrypt local proxy) | #34 |
| C3 | DNS changes on network switch: home → office → cellular | #34, #35 baseline churn |
| C4 | Corporate resolver `10.0.0.53` | #35 |
| C5 | **`ifconfig` on stock macOS: `utun0`–`utun3` up, zero VPN profiles known** | #36 — the bare `> 2` threshold |
| C6 | Private Relay + one real VPN: 5 utun interfaces, 1 profile | #32, #36 |
| C7 | DNS64 resolver on an IPv6-only carrier | #34 |

**D. `test_benign_certificates.py`**

| Case | Fixture | Guards against |
|---|---|---|
| D1 | Valid 90-day leaf, full chain supplied | baseline |
| D2 | **Valid leaf, `validate_vpn_certificate(cert_bytes)` with no chain** | #46 — must not be MEDIUM on the default path |
| D3 | **Routine cert rotation: same CA, new leaf, unknown fingerprint** | #47 — the everyday case, must not be HIGH |
| D4 | **6-day ACME/Let's Encrypt leaf** | #45 |
| D5 | Chain including a self-signed **root** | #42 — root self-signature is not MITM |
| D6 | Full 64-char fingerprint present in a properly-populated known-good set | #49 — proves `==` matching works |
| D7 | **Truncated 16-hex fingerprint from a log line** | #5 must discard; must *not* containment-match |
| D8 | Cross-signed intermediate (valid, out of naive order) | #44 |

**E. `test_benign_api_patterns.py`**

| Case | Fixture | Guards against |
|---|---|---|
| E1 | **ProtonVPN `cooldown(...)` line** | #37 vs #7 — **must be INFO in both modules.** The cross-module consistency test. |
| E2 | VPN app polling `/api/v1/location` 12×/hr to show exit country | #39 |
| E3 | App-launch burst: 25 requests in 2 min, then idle | #40 |
| E4 | **Background App Refresh: 8 requests at 03:00 while charging** | #41 |
| E5 | Single 429 during a server-list refresh | #38 |
| E6 | Log line containing `"429"` as a byte count / port / ID | #38 substring matching |
| E7 | **Replay a 6-month-old log through `analyze_request_patterns`** | The wall-clock bug — asserts detectors use event time, not `datetime.now()` |

### 4.4 Expected outcome

Written against today's code, this suite should be **roughly 60–70% red** — concentrated in B, C,
and E. That is the point. Each red case is a named, reproducible false positive with a
justification header, and the §5 work is done when they go green **without weakening `assert_quiet`**.

Two cases (A11, B16) are deliberately written to fail as *pins* on known defects.

---

## 5. Prioritised remediation plan

Ordered by **alert-noise reduction ÷ effort**. Items marked ⚠️ are correctness/integrity issues that
outrank noise.

### P0 — Integrity: stop claiming things that aren't true (~1 day)

⚠️ **These are not calibration issues. They are false statements in a security product.**

1. **Delete `CryptoHandler.encrypt`/`decrypt`, or implement them.** (2 h)
   A function documented "AES-256-GCM" that base64-encodes and discards the key must not exist in a
   security tool. It has no callers — deleting it is safe and immediate. If the API is wanted, it is
   ~15 lines with `cryptography`'s `AESGCM` (already a dependency). **Then remove the "Encryption at
   Rest" / "Encrypted Storage" claims from `SECURITY.md`** — orchestrator state is plaintext JSON
   with `chmod 600`; say that instead.
2. **Make `_send_to_telegram` either work or fail loudly.** (3 h)
   Implement with `python-telegram-bot` (already installed) — `try/except TelegramError`, timeout,
   bounded retry — **or** raise `NotImplementedError`. What it must not do is `return True`.
   A monitoring tool that silently reports successful delivery of alerts it never sent is worse than
   one with no alerting, because the user believes they are covered.
3. **Correct the README's four false numbers.** (30 min)
   9,879→7,363 lines; 196→287 tests; 100%→73% coverage; drop "Production Ready".
4. **Label the dashboard as a mock.** (30 min)
   A banner in `dashboard.html` and a line in `dashboard/README.md`. Until §5-P3, anyone who opens it
   sees fabricated threats attributed to a named device.

### P1 — Port `carrier_detection.py` to the `_judgment` pattern (~3–4 days) ⭐

**This is the discrete piece of work the brief asks to be scoped.** It is the single largest
alert-noise reduction available: 19 rules, of which **2 are sound**.

*Scope — deliberately excludes any new detection capability.*

**1. Adopt the reference data model** (~0.5 day)
   Introduce `CarrierObservation` / `CarrierJudgment` mirroring `vpn_integrity`'s `SessionReport`:
   `_build_observations` records profile facts at INFO; `_judgment(kind, severity, confidence,
   alternatives, summary)` emits conclusions. **Every judgment gets a `confidence` and a non-empty
   `alternatives` list** — enforce with an assertion in `_judgment`, so the pattern can't be
   half-adopted later.

**2. Replace stringly-typed escalation** (~0.5 day)
   Delete `"MDM" in str(localhost_indicators)` and every other `in str(list)` test (rules #18, #19,
   #21, #26, #27, #31, and the same pattern in `device_info._assess_threat_level`). Replace with a
   typed `Indicator` dataclass carrying `kind: IndicatorKind` and let severity derive from enum
   membership. This removes a whole class of accidental-substring escalation and is a prerequisite
   for the rest.

**3. Re-grade the 19 rules** per §3.2 (~1 day)

   | Action | Rules |
   |---|---|
   | **Delete** | #20 (unknown carrier), #21 (backup persistence), #30 (install hour), #31 (MDM→CRITICAL) |
   | **Downgrade to INFO observation** | #18 (unsigned eSIM), #26 (no endpoint), #27 (MDM no org), #28 (unsigned VPN) |
   | **Downgrade to LOW + alternatives** | #19 (issuer substring), #25 (private IP), #29 (name keywords), #34 (localhost DNS), #35 (private DNS), #36 (interface count) |
   | **Keep, add corroboration** | #22, #23 (profile deltas), #32 (tun/tap count) |
   | **Keep as-is** | **#24 (localhost VPN server → CRITICAL)**, #33 (localhost route → HIGH) |

**4. Token-match, don't substring-match** (~0.5 day)
   Split display names on non-alphanumerics and match whole tokens against the keyword set. Fixes
   `Latest`→"test", `Local Office`→"local", `TestFlight`→"test" in one change, and applies equally to
   `device_info` #51.

**5. Add allowlists — reuse, don't rewrite** (~0.5 day)
   `device_info` already has `APPLE_SYSTEM_PATHS` / `KNOWN_LEGITIMATE_SERVICES` /
   `KNOWN_LEGITIMATE_ORGS`. **Promote them to a shared module** and have `carrier_detection` consult
   them before scoring. Expand `KNOWN_LEGITIMATE_ORGS` beyond its four entries (Proton AG, Mullvad,
   Tailscale, Cloudflare, and a user-extensible config key). Drop the carrier allowlist entirely —
   rule #20 is being deleted.

**6. Corroboration gate** (~0.5 day)
   Port `vpn_integrity`'s user-action suppression: a single indicator never exceeds LOW unless it is
   #24 or #33. CRITICAL requires either a localhost server address or ≥2 independent MEDIUM+ indicators.

**7. Land the §4-B and §4-C negative tests green** (~0.5 day)

*Exit criteria:* B1–B15 and C1–C7 pass with `assert_quiet(max_severity=INFO)`; B16 still fires
CRITICAL; existing `test_carrier_detection.py` attack cases still pass.

### P2 — Cross-module calibration (~2 days)

5. **Reconcile #37 with #7.** (2 h) `api_abuse.check_rate_limit_responses` → INFO, matching
   `vpn_integrity`. One log line cannot be INFO in one module and HIGH in another; test E1 pins it.
6. **Fix the wall-clock bug in `api_abuse`.** (4 h) Rules #39–41 use `datetime.now()`; take a
   reference timestamp parameter defaulting to the newest event. Currently, replaying any stored log
   silently detects nothing. Test E7 pins it.
7. **Delete rule #41** (night-time activity) and **downgrade #39** to LOW with alternatives.
8. **`cert_validator`:** make `INCOMPLETE_CHAIN` (#46) a data-quality flag rather than a threat
   contribution; change the unknown-fingerprint fall-through (#47) from HIGH to LOW, matching #6;
   restrict `SELF_SIGNED` (#42) to the leaf. (4 h)
9. **Rebuild `KNOWN_GOOD_FINGERPRINTS`** per §3.3: full-length fingerprints, `==` matching, CA/SPKI
   pinning, TOFU baseline file. (1 day)
10. **Fix `device_info._has_localhost_server` (#50)** to inspect the *server address* field, not the
    name. Currently the detector cannot see the attack it names. (2 h)
11. **Add `ThreatLevel.INFO` to `should_alert`'s `severity_order`.** (15 min) Prerequisite for the
    INFO-heavy world P1 creates.

### P3 — Close the honesty gaps in the plumbing (~1 week)

12. **Wire the orchestrator's VPN and API loops to real input** (2 d), or **remove the tasks** and
    document that `privasee start` is carrier-only. Either is honest; spawning two tasks that sleep
    is not.
13. **Wire `database/` to the orchestrator** (2 d). The schema and repositories exist and are
    unused; threats are lost on exit.
14. **Point the dashboard at real data** (2 d) — or delete `dashboard/` and PR #18's coverage
    template together. Reading from the P3-13 repositories makes it real; anything less should not
    ship as a monitoring UI.
15. **Fix `privasee dashboard`** (2 h): add `jinja2` + `python-multipart` to `requirements.txt`;
    import the app object directly rather than by dotted string; fix the `/` 500.
16. **Fix the launchd plists** (4 h): template the paths (the vpnmonitor plist ships
    `/Users/karkusdog/...`), remove the duplicate `--log-dir`, reconcile `WorkingDirectory` and the
    interpreter with the documented venv install, move logs to `~/Library/Logs/`. Replace the
    string-grep tests with one that actually loads the job on macOS CI.
17. **Implement or delete `backup_monitor._analyze_file`** (1 d). It is a file watcher that watches
    and does nothing.

### P4 — Housekeeping (~1 day)

18. Close PR #18; delete all four stale branches (§1.8).
19. Add upper bounds and a lockfile (`pip-compile` / `uv lock`).
20. Move or delete the six root `test_*.py` scripts; two fail at import.
21. Resolve the Python 3.12 skip or drop the 3.12 classifier.
22. Prune the 25 root markdown files — several (`NEXT_STEPS.md`, `PRE_FLIGHT_CHECKLIST.md`,
    `MVP_ORCHESTRATOR_COMPLETE.md`, `GitHub_Copilot_Implementation_Prompts.md`) describe work that
    is finished, abandoned, or was never started. Documentation volume is what let the drift hide.
23. Add `return False` to the truncated `_is_apple_system_file` (§3.2).
24. Delete the four committed `test-results*.xml` files and the stale scan reports.

---

## 6. Honest verdict

**Refactor — but narrow the project's claims to what it actually does, and do that before anything else.**

Not archive. Three things here are genuinely good, and they'd be expensive to rebuild:

- **`vpn_integrity.py` is real security engineering.** The observation/judgment split, mandatory
  confidence and `alternatives`, log-time windows, user-action suppression, and the refusal to emit
  anything above MEDIUM — that is a correct model of how to reason under uncertainty about noisy
  telemetry. Most detection tooling never gets there.
- **The iOS backup parsing works** and is the hard, unglamorous part. `device_info.py` handles
  encrypted Manifest.db, plist shapes, and profile extraction against real backups.
- **The engineering substrate is sound.** Asyncio orchestration with graceful shutdown, exponential
  backoff, state persistence and dedup; a valid Timescale migration; a green suite that runs in five
  seconds; clean dependency resolution and zero runtime CVEs after six months untouched.

But the honest reading of this repo is that **it is one well-calibrated module and a large amount of
scaffolding that documentation describes as finished.** The gap is not cosmetic:

- A user who configures Telegram gets log lines claiming delivery and **no alerts, ever**.
- A user who opens the dashboard sees threats on "Mark's iPhone" that **were never detected**.
- A user who reads SECURITY.md believes their data is **encrypted at rest**; it is base64 at best and
  plaintext JSON in practice.
- A user who runs `privasee start` — the primary mode — gets **one eSIM check on a loop**, while the
  best detector in the codebase is unreachable outside a manual command.
- And a user who runs it against a **corporate iPhone on an MVNO behind a home router** gets
  CRITICAL for the MDM profile, CRITICAL for the persistent SIM, HIGH for the "unknown" carrier,
  HIGH for the `192.168.1.1` DNS server, and HIGH again if they installed anything after 11pm.

That last point is the one that matters most, and it is the brief's own thesis: **a detector that
cries wolf is worse than no detector.** With **34 of 55 rules mis-calibrated — 33 of them outside
`vpn_integrity.py`** — and 3.8% negative-test coverage, the current tool would train its user to
ignore it within a week — and the one rule that
would genuinely matter (#24, localhost VPN routing — correctly CRITICAL) would be buried in the noise
of the thirty-three around it.

**What I'd actually do, in order:**

1. **P0 this week.** The false crypto and the fake alert delivery are not roadmap items; they are
   claims a security tool must not make. That is one day's work and it is not optional.
2. **P1 next.** The `carrier_detection` port is the highest-leverage change in the repo and it is
   well-bounded (3–4 days) *because* `vpn_integrity` already establishes the target design. This is
   a port, not a design exercise.
3. **Then decide what this project is.** The most valuable thing here is a
   *VPN-log timeline analyser that is honest about uncertainty*. That is a real, differentiated,
   nearly-finished tool — `privasee analyze` already works today. The iOS-backup carrier-compromise
   detector is a second, much less mature product sharing a repo with it, and the dashboard and
   persistence layer are a third.

   **My recommendation: ship the first, fix the second, and cut the third until the first two are
   trustworthy.** Scope is what killed the six dormant months — a `benefit_plans` domain module on a
   branch of an iOS security tool is the clearest possible symptom.

The project is worth reviving. It is not worth reviving *as documented*, and the documentation is
the first thing that should change.

---

## Appendix — how to reproduce

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt && pip install -e .

pytest -q --no-cov                     # 277 passed, 10 skipped
pytest -q --cov=src/privaseeai_security --cov-report=term   # TOTAL 73%
pip install pip-audit && pip-audit     # only setuptools (build tool)
alembic upgrade head --sql             # offline SQL generation
privasee --help && privasee scan       # OK
privasee dashboard                     # ModuleNotFoundError: dashboard
```

**Not verified in this environment** (and not claimed above): `docker build` / `docker-compose`
(no Docker daemon); live Alembic apply against PostgreSQL+TimescaleDB (no database); launchd
installation (macOS only).
