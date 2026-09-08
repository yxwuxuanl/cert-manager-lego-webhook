# Repository Guidelines

## Project Structure & Module Organization

This is a cert-manager DNS-01 webhook backed by lego DNS providers. The executable entry point is `cmd/cert-manager-lego-webhook/main.go`. Webhook implementation lives in `internal/solver/`: `solver.go` handles lifecycle, `acme.go` resolves challenges and keys, `provider.go` adapts lego, and `config.go` parses configuration. Unit tests sit beside their subjects as `*_test.go`; Helm rendering tests live in `tests/chart/`. The Helm chart is under `charts/templates/`, with manifests in its `templates/` subdirectory. Image settings live in `Dockerfile` and `.ko.yaml`; release automation lives in `.github/workflows/`.

## Build, Test, and Development Commands

- `go build ./...` compiles the webhook and catches package-level errors.
- `go test ./...` runs unit and chart rendering tests; Helm must be on `PATH`.
- `go test -race ./...` checks concurrent code paths.
- `go vet ./...` performs standard Go static checks.
- `go fmt ./...` formats Go sources across all packages before committing.
- `GROUP_NAME=lego.dns-solver go run ./cmd/cert-manager-lego-webhook` starts the webhook against the current Kubernetes client configuration.
- `docker build -t cert-manager-lego-webhook:dev .` builds the production-style distroless image.
- `helm lint charts/templates` validates the chart; `helm template dev charts/templates --set certManager.namespace=cert-manager` previews rendered resources.

## Coding Style & Naming Conventions

Target the Go version in `go.mod`. Use `gofmt`, grouped imports, short receiver names, and `%w` for contextual error wrapping. Use PascalCase only for exported identifiers and camelCase otherwise. Indent Kubernetes YAML by two spaces. Name chart values in camelCase and reuse `charts/templates/templates/_helpers.tpl` helpers.

## Testing Guidelines

Use Go's `testing` package and name tests `TestXxx`; prefer table-driven subtests for multiple inputs. Call `t.Parallel()` only when tests do not share mutable process state. There is no enforced coverage threshold, but behavior changes should include focused regression tests. Run `go test -race ./...` before opening a pull request.

## Commit & Pull Request Guidelines

Recent history uses short, imperative subjects such as `charts: add tolerations`, `fix challenge match`, and `chore: update dependencies`. Keep commits focused and use a component prefix when helpful. Pull requests should explain the problem and solution, link issues, list verification commands, and call out configuration, RBAC, image, or chart-version changes.

## Security & Configuration Tips

Never commit DNS credentials or populated Secret manifests. Pass provider credentials through `envFrom.secret`, keep examples redacted, and review RBAC changes for least privilege.
