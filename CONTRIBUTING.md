# Contributing

[← Back to README](README.md)

Bug fixes, provider compatibility reports, and documentation improvements are
welcome. For a larger change, open an issue to discuss the proposed behavior.

## Local development

Use the Go version specified in [go.mod](go.mod). Helm is needed for chart checks.
The Go sources and their tests are in the repository root; the Helm chart is in
`charts/templates/`.

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

For chart changes:

```sh
helm lint charts/templates
helm template dev charts/templates --set certManager.namespace=cert-manager
```

Unit tests and chart rendering do not verify live DNS provider access. Validate
provider behavior with a staging certificate in a test cluster when relevant.

## Pull requests

- Keep changes focused and format changed Go files with `gofmt`.
- Add focused regression tests for behavior changes. Run `go test -race ./...`
  before opening a pull request.
- Describe the problem, resulting behavior, related issues, and checks you ran.
- Call out configuration, RBAC, image, and chart-version changes. Bump the chart
  version when changing the chart or its templates.
- Update examples and documentation when configuration changes. Keep credentials
  and completed Secret manifests out of commits.
