# Contributing

Use Python 3.11+ and an isolated virtual environment. Install `pip install -e '.[dev]'`.
Run `ruff check .`, `ruff format --check .`, `mypy`, and `pytest -q` before opening a PR.
With Nmap installed, run `SECURITYSCANNER_NMAP_TEST=1 pytest -q` on your own loopback host.
Build distributions with `python -m build` and verify templates are present in the wheel.

Keep changes small, include tests for changed behavior and explain evidence and limitations.
Tests must not contact public targets. Use local servers, fixtures and mocks. Do not commit
real audit evidence, credentials, databases or logs. Synthetic examples must say they are
synthetic. Do not change severity without describing confidence and technical evidence.

New scanners must enforce explicit authorization, validated exact-host scope, DNS pinning,
bounded deadlines and cancellation. Redirects must be validated before connecting. No
arbitrary shell arguments, exploit automation, brute force, evasion or denial-of-service
features. Review the threat model and roadmap before expanding the CLI or adding dependencies.

PR descriptions should state the problem, resulting behavior, tests executed and remaining
limitations. Do not claim remote CI, coverage or platform support without evidence.

Contributions are accepted under the project's MIT license. Respect third-party licenses.
