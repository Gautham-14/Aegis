# Aegis

Local Python AI runtime with authenticated accounts, role-based approvals,
purpose-bound coding and media tasks, encrypted retained output, and a local
receipt ledger. Supported Python versions: 3.11–3.14.
Native operator/development platforms: Windows, macOS and Linux. Hardened
production uses the isolated guest backend or native Linux services; see
[Docs/VM_DEPLOYMENT.md](Docs/VM_DEPLOYMENT.md). Device infrastructure acceptance remains unperformed.

The operator interface is the CLI. Start with [Docs/QUICKSTART.md](Docs/QUICKSTART.md).
The API binds to numeric loopback; `/docs` serves local, offline documentation.

The application version comes from `aegis/version.py`. Installed wheels provide
`aegis` (operator CLI), `aegis-server` (API) and `aegis-vm` (VM host);
source launchers remain supported.
For reproducible CLI installation, use `requirements-cli.lock` with
`--require-hashes`, then install the reviewed wheel with `--no-deps`.

Maintenance: [architecture](Docs/ARCHITECTURE.md), [environment settings](Docs/CONFIGURATION.md),
[contributing](Docs/CONTRIBUTING.md), [changelog](Docs/CHANGELOG.md) and
[release gate](Docs/RELEASE.md). The project is proprietary/all rights reserved; see
[LICENSE](LICENSE).

Read-only source-grounded advisory, coding and media workflows can be prepared
without a GPU or model weights. Configuration and preflight never load models;
inference runs only through an explicitly selected local server. See
[Docs/WORKFLOW_READINESS.md](Docs/WORKFLOW_READINESS.md) for contracts, security gates,
model-free verification and later model onboarding.
For prompt-based selection among the owner's local GGUFs, use
[dynamic local model routing](Docs/LOCAL_MODELS.md). PUBLIC auto-chat is opt-in;
protected workflows keep their exact leases and provider approvals.

Historical workstation account and recovery records are described in
[Docs/LOCAL_OPERATIONS.md](Docs/LOCAL_OPERATIONS.md); their private artifacts are not
included in this checkout. Provision and verify your own installation. Use
[Docs/DEPLOYMENT_ACCEPTANCE.md](Docs/DEPLOYMENT_ACCEPTANCE.md) to qualify the later
model/hardware deployment.

The `reference` provider and industrial demos are deterministic fixtures. Live
models require an explicitly configured local server. Internal data additionally
requires a verified offline bundle and an independently approved, short-lived
provider release. See [Docs/PROVIDER_ASSURANCE.md](Docs/PROVIDER_ASSURANCE.md).

Production custody, MFA, independent audit anchoring, hardened Linux services,
signed releases and recovery procedures are documented in
[Docs/SECURITY_IMPLEMENTATION.md](Docs/SECURITY_IMPLEMENTATION.md). Production mode refuses
startup when independent custody or audit prerequisites are missing.

Run tests in the dedicated environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Test storage is disposable and separate from the application's `data` directory.
Windows tests exercise current-user DPAPI and file ACLs; they need a normal
Windows user context. Linux/gVisor execution and real model quality require
separate deployment validation.
