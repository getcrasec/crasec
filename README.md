# crasec

A CLI application built with Go, Cobra, and Viper.

---

## What's been set up

### CLI foundation — Cobra + Viper

The entry point is `main.go`, which delegates to the `cmd` package. `cmd/root.go` defines the root command using [Cobra](https://github.com/spf13/cobra) and wires in [Viper](https://github.com/spf13/viper) for config file support.

**Config file search order** (when `--config` is not passed):

1. `.crasec.yaml` in the current working directory (project root)
2. `~/.crasec/config.yaml` (user home directory)

Override with an explicit path at runtime:

```sh
crasec --config /path/to/config.yaml
```

Environment variables are also picked up automatically.

---

### Version command with ldflags injection

`cmd/version.go` adds a `version` subcommand that prints build metadata:

```sh
crasec version
# crasec dev (commit: none, built: unknown)
```

The three values (`version`, `commit`, `date`) default to development placeholders and are overridden at build time via `-ldflags`:

```sh
go build -ldflags "\
  -X github.com/getcrasec/crasec/cmd.version=1.0.0 \
  -X github.com/getcrasec/crasec/cmd.commit=$(git rev-parse --short HEAD) \
  -X github.com/getcrasec/crasec/cmd.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o crasec .
```

GoReleaser injects these automatically on every release.

---

### Static analysis — golangci-lint

`.golangci.yml` runs four linters (all others disabled by default):

| Linter | What it catches |
|---|---|
| `errcheck` | Unhandled errors, including `_ = f()` assignments |
| `govet` | All `go vet` analyzers (shadow, loopclosure, etc.) |
| `staticcheck` | Bugs, performance issues, and deprecated API usage |
| `gosec` | Security issues (G104 excluded — covered by errcheck) |

Run locally (requires [golangci-lint](https://golangci-lint.run/)):

```sh
golangci-lint run ./...
```

---

### CI — GitHub Actions

`.github/workflows/ci.yml` runs on every pull request and push to `main`. Three jobs run in parallel:

| Job | Command |
|---|---|
| **Test** | `go test -race ./...` + coverage artifact upload |
| **Lint** | `golangci-lint` via official action |
| **Vulnerability check** | `govulncheck` via official action |

A fourth **Release** job runs only on `v*` tags and only after all three pass. All actions use Node 22 runtimes (`checkout@v5`, `setup-go@v6`, etc.).

---

### Release pipeline — GoReleaser

`.goreleaser.yml` builds static binaries for five targets on every `v*` tag push:

| OS | amd64 | arm64 |
|---|---|---|
| Linux | ✓ | ✓ |
| macOS | ✓ | ✓ |
| Windows | ✓ | — |

Archives are `.tar.gz` on Linux/macOS and `.zip` on Windows. A `checksums.txt` (SHA-256) is attached to every GitHub Release alongside the binaries.

To cut a release:

```sh
git tag v1.0.0
git push origin v1.0.0
```

---

### Community

`CODE_OF_CONDUCT.md` — Contributor Covenant v2.1. Enforcement contact: domenico.lorenti@crasec.io.

---

## Local development

```sh
# Build
go build -o crasec .

# Test
go test -race ./...

# Lint
golangci-lint run ./...

# Snapshot build (all platforms, no publish)
goreleaser build --snapshot --clean
```
