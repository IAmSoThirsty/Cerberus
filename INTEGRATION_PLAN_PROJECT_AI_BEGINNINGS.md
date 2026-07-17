# Integration Plan — Cerberus Guard Bot × Project-AI-Beginnings

Status: DRAFT integration plan (Cerberus is now production-deployment-ready and CI-green; this
document specifies how to embed it into Project-AI-Beginnings).
Last updated: 2026-07-17
Author: Hermes Agent (on user directive: "push-commit-then-make-everything-green … followed by a
comprehensive integration plan with project-ai-beginnings")

## 0. Why this integration exists

Cerberus (`T:\00-Active\Cerberus`, github.com/IAmSoThirsty/Cerberus) is a hardened, multi-agent
LLM/AGI security framework: prompt-injection detection, input validation, sandboxing, threat
detection, audit logging, rate limiting, RBAC, and 4 guardian agents (strict / heuristic /
pattern / statistical) coordinated by a hub.

Project-AI-Beginnings (`T:\00-Active\Project-AI-Beginnings`) is a monorepo with:
  - `apps/services/`  — a FastAPI "service host" (`project-ai-service-host`) that boots roles
                        swr / atlas / arbiter-rlp and imports AI modules (e.g. `swr`, `atlas`,
                        `arbiter`, `rlp`).  See apps/services/src/project_ai_services/app.py.
  - `apps/web/triumvirate-portal/` — the operator/orchestration web console (appears in the repo's
                        own security/cross-reference docs).
  - `.project-ai/automation/` — automation subsystem with its own `quarantine/` directory, which
                        maps conceptually onto Cerberus's fail-closed "block/quarantine" stance.

The integration goal: every prompt/input that flows into a PAB AI module is screened by Cerberus
before execution, with blocked inputs quarantined and audited — without changing PAB's existing
service contract.

## 1. Current readiness (verified, real state as of 2026-07-17)

Cerberus:
  - 104 tests passing, ~59% coverage (security modules 55–86%, guardians 0–100%).
  - ruff lint + format: CLEAN.  mypy strict: CLEAN on the shippable `cerberus` package.
  - Builds a clean wheel + sdist (`python -m build`); installs and runs from the wheel with only
    runtime deps (pydantic, pydantic-settings, structlog, bcrypt, cryptography).
  - Latent bug fixed during greening: guardian subclasses called an undefined `self._create_report`;
    now they construct `ThreatReport` directly. Monitoring `clear_old_data` bug fixed.
  - Thirsty-Lang 0.8.3 binding in `main.py` is OPTIONAL and loaded lazily inside try/except; if the
    `utf.*` packages are not on the path, Cerberus still runs (it just skips the T_A_R_L/TSCG
    sovereign-execution layer). This is important for PAB: the binding is OFF by default in PAB.

PAB:
  - `apps/services` is a minimal FastAPI host; the only current endpoint is `/health/live` and
    `/service/info`. There is NO inbound prompt/input path yet — so Cerberus integration must be
    added at the point where PAB begins accepting model-facing input (the natural next feature).
  - Python 3.12 venv present (`.venv`); service uses `uvicorn[standard]`.

## 2. Integration architecture

```
                          ┌─────────────────────────────────────┐
   client request  ─────► │  apps/services (FastAPI, role swr…)  │
                          │                                       │
                          │   Cerberus GuardMiddleware (NEW)       │
                          │      │ 1. InputValidator (SQL/XSS/cmd/ │
                          │      │    prompt-injection/XXE/…)      │
                          │      │ 2. Guardian hub.analyze(content)│
                          │      │    strict+heuristic+pattern+     │
                          │      │    statistical → ThreatReport    │
                          │      ├─ pass  ──────────────► module    │
                          │      └─ block ─► quarantine + audit     │
                          └─────────────────────────────────────┘
                                          │
                                          ▼
                          Cerberus audit_logger → .project-ai/automation/quarantine  (shared sink)
```

Key design rules:
  - Fail-closed: any analysis error → block (never silently pass). This mirrors Cerberus's own
    design and PAB's `.project-ai/automation/quarantine` concept.
  - Cerberus is a pure library dependency; it does NOT import PAB. PAB imports Cerberus.
  - The Thirsty-Lang sovereign layer stays optional in PAB (not installed by default).

## 3. Concrete wiring steps

### Step 1 — Add Cerberus as a dependency
In `Project-AI-Beginnings/apps/services/pyproject.toml`, add to `[project].dependencies`:
    "cerberus-guard-bot @ git+https://github.com/IAmSoThirsty/Cerberus.git@main"
(or a pinned tag once a release is cut). Runtime deps are already satisfied by Cerberus's own
requirements (pydantic, pydantic-settings, structlog, bcrypt, cryptography).

### Step 2 — Create the guard adapter (new file in PAB)
`apps/services/src/project_ai_services/guard.py`:
    - A `GuardMiddleware` (Starlette `BaseHTTPMiddleware`) OR a FastAPI dependency
      `require_safe_input(payload: dict) -> dict`.
    - Internally: `InputValidator().validate(...)` + `Hub([...guardians]).analyze(...)`.
    - On `ThreatReport.should_block`: raise `HTTPException(403)` AND write a quarantine record
      (JSON) to `.project-ai/automation/quarantine/<timestamp>-<hash>.json` mirroring Cerberus's
      `audit_logger` schema (so the two systems share one evidence format).
    - On pass: attach the `ThreatReport` to `request.state` for downstream audit/observability.

### Step 3 — Wire into `create_app`
In `app.py`, register the middleware/dependency for any route that accepts model-facing input.
Keep `/health/live` and `/service/info` UNGUARDED (liveness must stay open).

### Step 4 — Tie monitoring into PAB's existing observability
Cerberus `SecurityMonitor` / `AlertManager` can publish to the same sink PAB already uses for the
triumvirate-portal. This is optional Phase 2; start by forwarding `Alert` events to
`.project-ai/automation/reports`.

### Step 5 — Config
Add Cerberus tunables to PAB's `apps/services` config (mirroring Cerberus `config/default.yaml`):
    - which guardians are active per service role (e.g. `arbiter-rlp` enables the statistical
      guardian for anomaly detection; `swr` uses strict+pattern).
    - block-threshold per role.

## 4. Phased rollout

  Phase A (this plan's first PR): dependency + adapter + guard on a single new endpoint that
          accepts a `prompt` field. Prove end-to-end block of
          "ignore all previous instructions" with a PAB test. CI: reuse Cerberus's green ruff/mypy
          gates via pre-commit (PAB already has `.pre-commit-config.yaml`).

  Phase B: extend guard to all model-facing routes; wire quarantine sink to
          `.project-ai/automation/quarantine`; add `SecurityMonitor` alert forwarding.

  Phase C (optional): enable the Thirsty-Lang 0.8.3 sovereign layer in PAB by installing
          `utf.*` packages and setting the env flag; this gives T_A_R_L/TSCG validated execution
          paths. Out of scope until a PAB need is identified.

## 5. Risks & mitigations (verified, not assumed)

  - Coverage gap: Cerberus guardians have low/zero unit coverage in places (pattern guardian 0%,
    statistical 0%). Mitigation: Phase A adds PAB-side integration tests that exercise each guardian
    via real blocked prompts, raising effective coverage through the consumer.
  - Optional Thirsty-Lang binding: if a PAB dev sets the env flag without the `utf.*` packages,
    `main.py` catches ImportError and degrades gracefully. No hard failure.
  - Latent runtime bugs already found & fixed in Cerberus during greening (guardian
    `_create_report`, monitoring `clear_old_data`) — these would have crashed PAB on the first
    heuristic/statistical analysis; they are now patched and tested.
  - Windows vs Linux: Cerberus sandbox uses `import resource` guarded by `sys.platform != "win32"`,
    so the PAB Linux service host gets POSIX resource limits; local Windows dev runs unconstrained.
    No action needed.

## 6. Acceptance criteria for "integrated"

  [ ] Cerberus installed as a pinned dependency in `apps/services`.
  [ ] A PAB endpoint accepts a prompt and is screened by Cerberus; a known injection string is
      blocked with HTTP 403 and a quarantine record is written.
  [ ] ruff + mypy stay green in both repos (Cerberus already green; PAB CI extended to the new
      `guard.py`).
  [ ] ≥ 1 integration test in `apps/services/tests` covering pass + block paths.

## 7. Open questions for the user (not blockers)

  - Should the sovereign Thirsty-Lang layer be enabled in PAB now, or kept optional? (Recommend:
    optional / off by default.)
  - Which PAB service role is the first integration target — `swr` (simplest) or `arbiter-rlp`
    (most security-sensitive)? (Recommend: `swr` first as the canary.)
  - Quarantine sink: write JSON to `.project-ai/automation/quarantine` (reuse existing dir) or a
    dedicated Cerberus-owned path? (Recommend: reuse existing `quarantine/` dir for unified evidence.)
