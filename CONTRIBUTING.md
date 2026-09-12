# Contributing

[← Back to README](README.md)

Bug fixes, provider compatibility reports, and documentation improvements are
welcome. For a larger change, open an issue to discuss the proposed behavior.

## Local development

Use the Go version specified in [go.mod](go.mod). Helm is needed for chart checks.

```text
cmd/cert-manager-lego-webhook/  Executable entry point
internal/solver/               Webhook, ACME and provider logic with unit tests
charts/templates/              Helm chart
tests/chart/                   Helm rendering and schema tests
scripts/                       Chart installation and upgrade checks
docs/                          Configuration and troubleshooting guides
examples/                      Sample Kubernetes manifests
```

Keep the entry point focused on starting the server. Implementation details belong
in `internal/solver/`, with unit tests beside the code they exercise.

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

To build the executable or run it against a configured test cluster:

```sh
go build -o /tmp/cert-manager-lego-webhook ./cmd/cert-manager-lego-webhook
GROUP_NAME=lego.dns-solver go run ./cmd/cert-manager-lego-webhook
```

Both the Dockerfile and the ko image workflow build the command in
`cmd/cert-manager-lego-webhook/`. For a local Docker build:

```sh
docker build -t cert-manager-lego-webhook:dev .
```

For chart changes:

```sh
helm lint charts/templates
helm template dev charts/templates --set certManager.namespace=cert-manager
go test ./tests/chart -count=1
```

Unit tests and chart rendering do not verify live DNS provider access. Validate
provider behavior with a staging certificate in a test cluster when relevant.

Chart CI runs the rendering and schema tests with Helm 3 and Helm 4, verifies
the default image exists, and tests fresh installation and an upgrade from chart
1.5.0 in a disposable kind cluster. The upgrade reuses the old values and enables
Restricted Pod Security before creating the updated Pods. To run the cluster
checks locally, create a disposable kind cluster and run:

```sh
KUBE_CONTEXT=kind-chart-testing bash scripts/test-chart-install.sh
```

The script installs cert-manager and webhook releases in that cluster; it only
accepts an explicitly named `kind-*` context. It verifies serving certificates
and API discovery, without using DNS provider credentials. Discovery requests
retry for up to two minutes after APIService availability to allow routing to
settle during rollouts; a persistent failure still fails the test. Delete the
disposable cluster after testing.

Chart publication on `main` requires all chart checks to pass. For chart-only
changes, bump `Chart.yaml`'s `version` while keeping `appVersion` at the existing
webhook version. For a new application release, publish its `v<appVersion>` image
before publishing a chart that selects it.

To release matching chart and image versions, set both `version` and `appVersion`
to the release number and update the chart tests and installation docs. Commit
the changes, then push only the `v<appVersion>` tag on that commit to trigger the
image workflow. After the image build succeeds and the tag exists in GHCR, push
the same commit to `main` to trigger chart validation and publication. The cluster
checks verify that upgrades and fresh installations select the expected image.

## Pull requests

- Keep changes focused and format changed Go files with `gofmt`.
- Add focused regression tests for behavior changes. Run `go test -race ./...`
  before opening a pull request.
- Describe the problem, resulting behavior, related issues, and checks you ran.
- Call out configuration, RBAC, image, and chart-version changes. Bump the chart
  version when changing the chart or its templates.
- Update examples and documentation when configuration changes. Keep credentials
  and completed Secret manifests out of commits.
