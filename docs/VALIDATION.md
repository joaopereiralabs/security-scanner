# Local validation record

Date: **2026-10-28 (America/Sao_Paulo)**. Version: **0.2.0**.

Environment: Windows, Python 3.12.10, Nmap 7.991. An isolated development virtual environment
was created and dependencies installed successfully. Linux/Kali execution was not available
in this session; the Ubuntu/Python 3.11–3.13 CI workflow is configured but has not been run
on GitHub. Compatibility with Linux is intended, not claimed as verified here.

## Results

| Check | Observed result |
|---|---|
| Full pytest suite with `SECURITYSCANNER_NMAP_TEST=1` | **86 passed in 3.78s**, no skips |
| Ruff check | All checks passed |
| Ruff format check | 31 files already formatted |
| mypy strict | No issues in 18 source files |
| pip dependency check | No broken requirements |
| Build | Source distribution and wheel built successfully |
| Clean wheel installation | Second venv: isolated imports, HTML template, three report formats, CLI version and doctor passed |
| Installed CLI doctor | Python, dependencies, Nmap and writable SQLite verified |
| Report QA | Synthetic HTML rendered and visually inspected in Edge headless |

The exact final pytest stdout is in [validation-tests.txt](validation-tests.txt). Dependency
versions used locally are in [tested-dependencies.txt](tested-dependencies.txt); this is an
environment snapshot, not a cross-platform or hash-locked dependency specification.

The real Nmap test starts a TCP server on **127.0.0.1 and an ephemeral port**. The server
emits an SSH-format test greeting (`OpenSSH_9.6`) and implements no SSH authentication or
shell. Nmap actually connects and identifies that greeting. The test asserts the observed
port, protocol label, product, version and pinned command destination. This validates the
integration and parsing, not the truth of arbitrary remote banners or vulnerability status.

The default offline suite skips that opt-in integration test. All other tests use local
fixtures, mocks and temporary files. No public target was scanned.

## Findings corrected during review

- The first packaging attempt ran before README creation and failed metadata generation;
  installation succeeded once the document existed.
- Initial static checks reported formatting and two Literal type mismatches; corrected.
- `--version` initially required a subcommand; corrected and covered by regression test.
- A first real integration fixture incorrectly expected intensity-0 probes to identify HTTP
  on any random port. The port was found, but identity was unknown. The fixture now uses a
  greeting-based service suited to the configured NULL probe; version assertions remain strict.
- SQLite connection lifecycle now explicitly closes connections. Reports use private file
  modes at creation, not only after writing. Doctor validates Nmap execution with a deadline.

## Limits of this validation

No HTTP/TLS or TUI tests exist because those features are not implemented. Cancellation and
timeout cleanup are exercised with mocked process handles; the real integration covers
successful Nmap execution. Tests do not establish safety on fragile production services or
all Nmap releases. There is no published coverage percentage, independent security review,
release tag or remote CI result established by this local validation. This record was
written before source publication; consult GitHub Actions for subsequent CI results.

See [ROADMAP.md](ROADMAP.md) for milestone reviews and next acceptance gates.
