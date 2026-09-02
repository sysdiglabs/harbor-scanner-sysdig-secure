# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

Harbor Scanner Adapter for Sysdig Secure. Implements Harbor's Pluggable Scanner API so Harbor can use Sysdig Secure as its vulnerability scanning engine. The adapter receives scan requests from Harbor, spawns Kubernetes jobs running `sysdig-cli-scanner`, and translates results back into Harbor's vulnerability report format.

## Build and Development

The project uses **Nix flakes** for reproducible builds and `just` as a task runner. Enter the dev shell with `nix develop` to get all required tools.

```bash
just test          # Run tests (Ginkgo with race detection, randomized)
just lint          # Run golangci-lint
just fmt           # Format code (go fmt + gofumpt)
just check         # Run all checks: lint, vulnerability scan, tests
just check-vulns   # Scan Go dependencies with govulncheck
```

To run a single test or test file, use Ginkgo directly:
```bash
ginkgo --focus "test description" ./pkg/scanner/
ginkgo -r ./pkg/http/api/v1/
```

After changing Go dependencies:
```bash
just update              # Update flake + go deps + rehash
just rehash-package-nix  # Only recalculate vendorHash in package.nix
```

## Architecture

**Adapter pattern** is the core abstraction. All scanning backends implement `scanner.Adapter`:

```
scanner.Adapter (interface)
├── InlineAdapter   – creates K8s batch Jobs running sysdig-cli-scanner
├── AsyncAdapter    – wraps any Adapter with goroutine-based async polling
└── BackendAdapter  – legacy, no longer supported
```

`base_adapter.go` holds shared logic (metadata, vulnerability severity mapping) embedded by concrete adapters.

**HTTP layer** (`pkg/http/api/v1/handler.go`): gorilla/mux router with four endpoints:
- `GET /health` — health check
- `GET /api/v1/metadata` — scanner capabilities
- `POST /api/v1/scan` — trigger scan (returns 202)
- `GET /api/v1/scan/{scan_request_id}/report` — fetch report (302 + Refresh-After if not ready)

Custom `loggingMiddleware` using `log/slog` wraps the router for structured request logging.

**Sysdig Secure client** (`pkg/secure/client.go`): HTTP client with retry and rate-limit handling.

## Testing

Tests use **Ginkgo v2 + Gomega** (BDD-style) with **gomock** for interface mocking. Mocks live in `mocks/` subdirectories and are generated via `go:generate mockgen`.

Test suites configure `gomega.format.MaxLength = 9999` to avoid truncated assertion output.

## Configuration

The adapter is configured via environment variables (auto-bound by viper) or CLI flags:

| Flag / Env Var | Required | Description |
|---|---|---|
| `SECURE_API_TOKEN` | Yes | Sysdig Secure API token |
| `SECURE_URL` | No | Sysdig endpoint (default: `https://secure.sysdig.com`) |
| `CLI_SCANNING` | Yes* | Enable CLI scanning mode (only supported mode) |
| `NAMESPACE_NAME` | When CLI | K8s namespace for scanner jobs |
| `SECRET_NAME` | When CLI | K8s secret with scanner credentials |
| `VERIFY_SSL` | No | SSL verification (default: true) |
| `ASYNC_MODE` | No | Enable async report retrieval |

## CI Workflows

Three GitHub Actions workflows run on PRs to `master`:

**CI (`ci.yaml`)** — three parallel jobs:
- **Lint**: `just lint`
- **Pre-commit**: `prek run -a` (fmt, lint, trivy vulnerability scan)
- **Build and test**: `just test` (requires `SECURE_API_TOKEN` and `SECURE_URL` secrets)

**E2E (`ci-e2e.yaml`)** — full integration test on Minikube, run as a matrix over the newest and oldest supported `sysdig-cli-scanner` versions:
1. Starts Minikube, installs Harbor via Helm
2. Builds the adapter Docker image with `nix build .#harbor-adapter-docker`
3. Deploys the scanner adapter via the `sysdig/harbor-scanner-sysdig-secure` Helm chart, setting `cliScanning.image` to `quay.io/sysdig/sysdig-cli-scanner:<matrix version>`
4. Pushes an Alpine image to Harbor, triggers a scan, and polls the vulnerability report API until completion (30 attempts, 10s intervals)

## Scanner Version Support

The `sysdig-cli-scanner` is supported for **1 year after release**. The e2e matrix (`cli_scanner_version` in `ci-e2e.yaml`) pins the newest default version and the oldest still-supported version for backward-compat coverage. Two `just` recipes keep these current:

```bash
# Print the oldest version still within the support window (probes binary Last-Modified)
just oldest-cli-scanner

# Substitute the oldest supported version wherever the oldest-version-marker is placed
just update-oldest-cli-scanner

# Bump the default version to the latest available (via newest-version-marker)
just update-cli-scanner
```

- **Version markers:** the recipes find/replace via `newest-version-marker` / `oldest-version-marker` sentinels — trailing `#`/`//` comments in YAML/TS, HTML-comment spans in Markdown. Target files are discovered by `grep`, not hardcoded, so a new marker anywhere is picked up. **Do not remove these markers** or the recipes stop updating that spot.
- The version number comes from `https://download.sysdig.com/scanning/sysdig-cli-scanner/latest_version.txt` (same semver as the `quay.io/sysdig/sysdig-cli-scanner` image tags).
- Both recipes run as part of `just update`. The recipes require GNU `date`/`sed` and `curl`, provided by the `nix develop` devshell.

**Release (`release.yaml`)** — triggers on `package.nix` changes pushed to `master`:
- Extracts version from `package.nix`, compares with latest git tag
- Builds and pushes Docker image to DockerHub (`sysdiglabs/harbor-scanner-sysdig-secure`)
- Creates a GitHub release with changelog generated by `git-chglog`

## Conventions

- Logging uses Go stdlib `log/slog` (recently migrated from logrus). No external logging libraries.
- Code formatting enforced by `gofumpt` (stricter than `go fmt`).
- Pre-commit hooks run on `nix develop` entry: trailing whitespace, YAML checks, fmt, lint, trivy scan.
- Nix builds use `buildGoModule` with a pinned `vendorHash` in `package.nix`.
