# Cerberus

**Cerberus Guard Bot**: A hardened, multi-agent shield for AI-to-AGI systems.

## Overview

Cerberus is a security framework that uses multiple guardian agents to protect AI systems against:
- Prompt injection attacks
- Jailbreak attempts
- System manipulation
- Bot attacks

## Key Features

- **Multi-Agent Architecture**: Starts with 3 guardians using different detection styles
- **Central Hub Coordination**: All guardians report to a central hub for aggregated decision making
- **Exponential Defense Growth**: Any bypass attempt spawns 3 new random guardians
- **Automatic Shutdown**: Guardian count capped at 27 before triggering total shutdown
- **Defense in Depth**: Multiple detection approaches ensure comprehensive protection

## Guardian Types

1. **PatternGuardian**: Rule-based pattern matching for known attack vectors
2. **HeuristicGuardian**: Behavioral heuristics for suspicious patterns
3. **StatisticalGuardian**: Statistical anomaly detection for unusual inputs

## Installation

```bash
# Clone the repository
git clone https://github.com/IAmSoThirsty/Cerberus.git
cd Cerberus

# Install in development mode
pip install -e ".[dev]"
```

## Quick Start

```python
from cerberus import CerberusHub

# Create the hub (initializes with 3 guardians)
hub = CerberusHub()

# Analyze user input
decision = hub.analyze("Hello, how can I help you?")

if decision.should_block:
    print(f"BLOCKED: {decision.summary}")
else:
    print(f"ALLOWED: {decision.summary}")

# Check hub status
status = hub.get_status()
print(f"Active guardians: {status['active_guardians']}")
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cerberus

# Run specific test file
pytest tests/test_hub.py
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run linting
ruff check src tests

# Run type checking
mypy src
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 CerberusHub                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │ Pattern  │ │Heuristic │ │   Statistical    │ │
│  │ Guardian │ │ Guardian │ │    Guardian      │ │
│  └────┬─────┘ └────┬─────┘ └────────┬─────────┘ │
│       │            │                │           │
│       └────────────┴────────────────┘           │
│                    │                            │
│            [Aggregated Decision]                │
└─────────────────────────────────────────────────┘
```

## License

MIT License
GitHub Copilot Chat Assistant:

I attempted to push the prepared safety changes to IAmSoThirsty/Cerberus but could not access the repository from here. Below are the exact artifacts and step-by-step commands you can run locally (or run via a CI/automation account) to apply everything I prepared: config, safe-spawn logic, structured logging, tests, CI, docs, and cleaned PR text.

Summary
- Target repo: IAmSoThirsty/Cerberus
- Branch to create: cerberus/safety-improvements
- Commit message: chore: add safety/config, structured logging, CI, docs, and adversarial tests
- PR title suggestion: chore(safety): add config, logging, CI, and docs
- Config defaults: spawn_factor=3, max_guardians=27
- Files to add/update: src/cerberus/config.py, src/cerberus/logging_config.py, edits to src/cerberus/hub.py (spawn logic), tests/tests_spawn_behavior.py, .github/workflows/python-ci.yml, .github/workflows/codeql.yml, SECURITY.md, CONTRIBUTING.md, threat-model.md, cleaned PR description file.

Files and snippets (apply/adapt to your codebase as needed)

1) src/cerberus/config.py
Save this file exactly (creates pydantic settings and a singleton settings instance).

from pydantic import BaseSettings, Field, validator
from typing import Optional

class CerberusSettings(BaseSettings):
    spawn_factor: int = Field(3, ge=1, le=10)
    max_guardians: int = Field(27, ge=1, le=1000)
    spawn_cooldown_seconds: float = Field(1.0, ge=0.0)
    spawn_rate_per_minute: int = Field(60, ge=1)
    per_source_rate_limit_per_minute: int = Field(30, ge=1)
    log_json: bool = Field(True)

    class Config:
        env_prefix = "CERBERUS_"
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("max_guardians")
    def max_at_least_spawn(cls, v, values):
        sf = values.get("spawn_factor", 1)
        if v < sf:
            raise ValueError("max_guardians must be >= spawn_factor")
        return v

settings = CerberusSettings()

2) src/cerberus/logging_config.py
Structured JSON logging helper.

import logging
import json
import sys
from .config import settings

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": record.created,
            "name": record.name,
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)

def configure_logging():
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if settings.log_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.handlers = [handler]

Call configure_logging() at your app entrypoint (e.g., in src/cerberus/__init__.py or main).

3) Hub spawn logic (edit src/cerberus/hub.py)
Replace hard-coded spawn logic with safe token-bucket + cooldown. Adapt names to your CerberusHub class and method names.

Add imports:
import time
from threading import Lock
from .config import settings

In CerberusHub.__init__:
self._last_spawn_time = 0.0
self._spawn_lock = Lock()
self._spawn_tokens = float(settings.spawn_rate_per_minute)
self._last_token_refill = time.time()

Add helper methods to the class:

def _refill_spawn_tokens(self):
    now = time.time()
    elapsed = now - self._last_token_refill
    rate_per_sec = settings.spawn_rate_per_minute / 60.0
    to_add = elapsed * rate_per_sec
    with self._spawn_lock:
        self._spawn_tokens = min(settings.spawn_rate_per_minute, self._spawn_tokens + to_add)
        self._last_token_refill = now

def _can_spawn(self, source_id: Optional[str] = None) -> bool:
    self._refill_spawn_tokens()
    now = time.time()
    with self._spawn_lock:
        if now - self._last_spawn_time < settings.spawn_cooldown_seconds:
            return False
        if self._spawn_tokens < 1:
            return False
        # consume one token
        self._spawn_tokens -= 1
        self._last_spawn_time = now
        return True

When handling a bypass event (replace your existing bypass handler logic):

if self._can_spawn(source_id=source_id):
    current_count = len(self.guardians)
    spawn_n = min(settings.spawn_factor, settings.max_guardians - current_count)
    for _ in range(spawn_n):
        self._spawn_guardian()   # adapt to your spawn method
    if len(self.guardians) >= settings.max_guardians:
        self._enter_safe_shutdown()
else:
    self.logger.info("Spawn throttled", extra={"current_guardians": len(self.guardians)})

Notes: adjust method/attribute names to your codebase (e.g., _spawn_guardian, _enter_safe_shutdown, guards list name). If CerberusHub stores guardians differently, adapt accordingly.

4) tests/test_spawn_behavior.py
Add these tests (adapt to your constructors/API names):

import time
from cerberus.config import settings
from cerberus.hub import CerberusHub

def test_spawn_respects_max_and_cooldown():
    settings.spawn_factor = 3
    settings.max_guardians = 27
    settings.spawn_cooldown_seconds = 0.01
    settings.spawn_rate_per_minute = 1000

    hub = CerberusHub(initial_guardians=3)  # adapt constructor
    for _ in range(10):
        hub.handle_bypass(source_id="test")
    assert len(hub.guardians) <= settings.max_guardians

def test_spawn_throttling():
    settings.spawn_factor = 3
    settings.max_guardians = 27
    settings.spawn_cooldown_seconds = 1.0
    settings.spawn_rate_per_minute = 1
    hub = CerberusHub(initial_guardians=3)
    hub.handle_bypass(source_id="test")
    hub.handle_bypass(source_id="test")
    assert len(hub.guardians) <= 3 + settings.spawn_factor

(Adapt to your actual API—these are examples that assert spawn caps and throttling behavior.)

5) .github/workflows/python-ci.yml
CI workflow to run tests, ruff, mypy.

name: CI
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.10, 3.11]
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
      - name: Lint (ruff)
        run: ruff check .
      - name: Type check (mypy)
        run: mypy src
      - name: Run tests
        run: pytest -q

6) .github/workflows/codeql.yml
Add a standard CodeQL analysis workflow (use GitHub's CodeQL template if you want; the CI YAML above plus the standard codeql.yml will enable scans).

7) SECURITY.md
Create a responsible disclosure file with contact info or directions to open a private security issue. Example content:

# Security Policy
If you discover a security vulnerability, please email security@example.com or open a private issue labeled "security". Provide reproduction steps and affected versions. We will respond within 72 hours.

8) CONTRIBUTING.md
Add contributor guidelines: local setup (pip install -e ".[dev]"), testing, linting, commit message style, PR expectations.

9) threat-model.md
Add an initial threat model covering: attacker capabilities (remote user submitting inputs; malicious prompts), trust boundaries (model input/output vs. system), mitigation controls (input validation, rate limits, audit logs), escalation path.

10) Cleaned PR #1 description (PR_description.md)
Replace the Copilot agent footer and add a checklist (example body available; include the checklist items from earlier).

Git commands to run locally (exact sequence)

# create branch
git checkout -b cerberus/safety-improvements

# add files and edit existing files (apply snippets above)
# e.g., create src/cerberus/config.py, src/cerberus/logging_config.py, update hub.py, add tests, add workflows, add docs

git add .
git commit -m "chore: add safety/config, structured logging, CI, docs, and adversarial tests"
git push --set-upstream origin cerberus/safety-improvements

Open PR (using gh CLI or GitHub UI). gh command example:

gh pr create --base main --head cerberus/safety-improvements --title "chore(safety): add config, logging, CI, and docs" --body-file PR_description.md

If you prefer a single combined PR or multiple smaller PRs, adjust steps accordingly:
- Combined: include all changes in one branch (above).
- Split: create separate branches for config/logging, CI, and docs respectively and open separate PRs.

Issue templates / issues to open (you can open these via the GitHub UI)
- Add threat model and security requirements
- Make spawn_factor and max_guardians configurable via pydantic settings
- Add spawn cooldown and rate limiting to CerberusHub
- Add structured audit logging and metrics (Prometheus)
- Add adversarial/integration tests for spawn/shutdown and bypass scenarios
- Add CI: tests, ruff, mypy, and CodeQL
- Pin dependencies and enable Dependabot
- Add CONTRIBUTING.md and SECURITY.md

Notes and adaptations
- The hub edits are conceptual: you must adapt the method and attribute names to your existing CerberusHub implementation.
- For per-source rate limiting beyond a single-process memory store, use Redis or another distributed store for multi-instance deployments.
- Ensure configure_logging() is called exactly once at startup.
- Review all places that may execute or deserialize untrusted input (eval/exec, subprocess calls, pickle, yaml.unsafe_load) and remove or sandbox them; run a repo-wide search for those patterns.

If you want me to produce the exact file contents for each file as downloadable patches here in chat, say: "show patches" — I will print full file contents for each file so you can copy/paste.
