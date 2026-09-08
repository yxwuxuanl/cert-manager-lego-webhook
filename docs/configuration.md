# Configuration

[← Back to README](../README.md)

## Provider support

Set `config.provider` to the provider code listed in the
[lego DNS provider directory](https://go-acme.github.io/lego/dns/), such as `alidns`.
Use that provider's documented environment variable names for credentials and options.

The webhook resolves providers through lego's `NewDNSChallengeProviderByName`.
Provider availability and behavior follow the lego version bundled with the
webhook image. Check `go.mod` at the source tag for your installed release;
the [current go.mod](../go.mod) describes the current checkout. Upstream's latest
provider documentation may describe features unavailable in an older release.

Providers that need files, external programs, or interactive input may require
additional deployment support. The chart does not expose arbitrary credential
file mounts or sidecars. A provider appearing in lego's directory does not by
itself establish that it works with the default webhook image and chart.

## Solver configuration

Use this structure under `spec.acme.solvers[].dns01` in an Issuer or ClusterIssuer:

```yaml
webhook:
  groupName: lego.dns-solver
  solverName: lego-solver
  config:
    provider: alidns
    envFrom:
      secret:
        name: alidns-secret
        namespace: cert-manager
```

| Field | Meaning |
| --- | --- |
| `groupName` | Must match the Helm chart's `groupName`; defaults to `lego.dns-solver`. |
| `solverName` | Must be `lego-solver`. |
| `config.provider` | Required lego provider code. |
| `config.envFrom.secret.name` | Required when using a Secret. All Secret data keys become provider environment variables. |
| `config.envFrom.secret.namespace` | Explicit Secret namespace. When omitted, the webhook uses the ChallengeRequest's resource namespace, as described below. |
| `config.envs` | Optional map of environment variable names to string values. Takes precedence over `envFrom`; the two sources are not merged. |

### Secret namespaces

If `config.envFrom.secret.namespace` is omitted:

| Issuer type | Namespace used for the provider Secret |
| --- | --- |
| `Issuer` | The Issuer's namespace. |
| `ClusterIssuer` | cert-manager's cluster resource namespace, normally `cert-manager`, configurable with `--cluster-resource-namespace`. |

This default is independent of the webhook's Helm release namespace and the
`certManager.namespace` chart value. See cert-manager's
[cluster resource namespace documentation](https://cert-manager.io/docs/configuration/#cluster-resource-namespace).

For a namespaced Issuer, set `kind: Issuer`, give it the Certificate's namespace,
and set the Certificate's `spec.issuerRef.kind` to `Issuer`. An explicit provider
Secret namespace can still point elsewhere, subject to the webhook's RBAC.

### Environment settings

Prefer `envFrom.secret` for credentials. Put additional provider settings in the
same Secret when they need to be used together; values must be strings.

Alternatively, `envs` can supply values directly:

```yaml
config:
  provider: alidns
  envs:
    ALICLOUD_REGION_ID: cn-hangzhou
```

This fragment only demonstrates inline options; the provider still needs its
required credentials through a supported mechanism, such as an already configured
workload identity. Inline values are stored in the Issuer resource, so avoid
placing credentials there.

**`envs` and `envFrom` are alternatives.** If `envs` is present, even as an empty
object, `envFrom.secret` is ignored. Neither map is merged with the other.

`webhook.envs` is a separate Helm setting for environment variables on the
webhook container. These are process defaults shared by its providers, rather
than settings scoped to an individual Issuer.

### Credential access

The current chart grants the webhook cluster-wide `get`, `list`, and `watch`
access to Secrets and ConfigMaps, along with access to cert-manager resources.
The webhook reads provider credentials and the ACME account private key used
to reconstruct the challenge authorization. Review the
[RBAC template](../charts/templates/templates/rbac.yaml) for your environment,
and scope DNS credentials to the zones and operations required by your provider.

## Helm values

See [values.yaml](../charts/templates/values.yaml) for the complete set of defaults.

| Value | Default | Purpose |
| --- | --- | --- |
| `groupName` | `lego.dns-solver` | API group used by the webhook and Issuer configuration. |
| `nameOverride` | Empty | Override resource names; otherwise the release name is used. |
| `certManager.namespace` | Release namespace | Namespace of cert-manager's ServiceAccount for the role binding. |
| `certManager.serviceAccountName` | `cert-manager` | cert-manager ServiceAccount allowed to call the webhook. |
| `webhook.image.repository` | `ghcr.io/yxwuxuanl/cert-manager-lego-webhook` | Container image repository. |
| `webhook.image.tag` | `v` + `appVersion` | Image tag; an empty value selects the webhook application version prefixed with `v`. |
| `webhook.imagePullPolicy` | `IfNotPresent` | Image pull policy. |
| `webhook.replicas` | `1` | Number of webhook replicas. |
| `webhook.envs` | `LEGO_DISABLE_CNAME_SUPPORT: 'true'` | Environment variables on the webhook container. |
| `webhook.resources` | `{}` | CPU and memory requests and limits. |
| `webhook.nodeSelector` | `{}` | Node selection. |
| `webhook.tolerations` | `[]` | Pod tolerations. |
| `webhook.affinity` | `{}` | Omitted by default; supply a Kubernetes affinity object to enable it. The legacy empty `[]` is also accepted. |
| `webhook.extraArgs` | `[]` | Additional webhook server arguments. |
| `webhook.dnsConfig` | `{}` | Custom pod DNS configuration; setting it switches `dnsPolicy` to `None`. |

Starting with chart 1.5.1, the deployment uses `webhook.image.tag`, falling back
to `v<appVersion>`. Chart 1.5.1 therefore continues to deploy webhook v1.5.0.
Chart-only fixes no longer require a new application image.

Value types and unknown chart configuration keys are validated before rendering.
Environment variable values must be strings, and a nonempty `webhook.dnsConfig`
must include `nameservers`. See the [chart guide](../charts/templates/README.md)
for upgrade notes and Pod security defaults.

### CNAME delegation

The chart sets `LEGO_DISABLE_CNAME_SUPPORT` to `'true'`. If your challenge records
use CNAME delegation, review both this setting and cert-manager's
[DNS-01 delegation configuration](https://cert-manager.io/docs/configuration/acme/dns01/#delegated-domains-for-dns01).
The webhook passes the original challenge DNS name to lego, so validate delegation
with a staging certificate for your provider before relying on it.

### Upgrade

Review the [release notes](https://github.com/yxwuxuanl/cert-manager-lego-webhook/releases),
then upgrade using your saved Helm values and an explicit chart version:

```sh
helm repo update
helm upgrade cert-manager-lego-webhook \
  cert-manager-lego-webhook/cert-manager-lego-webhook \
  --namespace cert-manager \
  --version CHART_VERSION \
  --values my-values.yaml \
  --wait --timeout 5m
```

Replace `CHART_VERSION` and `my-values.yaml` before running the command. After
upgrading, verify webhook availability and a staging certificate issuance.
