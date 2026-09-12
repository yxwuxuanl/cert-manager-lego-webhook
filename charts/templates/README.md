# cert-manager-lego-webhook Helm chart

A DNS-01 webhook that lets cert-manager use lego DNS providers.

## Requirements

- Kubernetes with cert-manager and its CA injector installed.
- Helm 3 or Helm 4.
- Permission to create the chart's cluster-scoped RBAC and APIService resources.

## Install

```sh
helm repo add cert-manager-lego-webhook https://yxwuxuanl.github.io/cert-manager-lego-webhook/
helm repo update
helm upgrade --install cert-manager-lego-webhook \
  cert-manager-lego-webhook/cert-manager-lego-webhook \
  --version 1.6.0 \
  --namespace cert-manager --create-namespace \
  --set certManager.namespace=cert-manager \
  --set certManager.serviceAccountName=cert-manager \
  --wait --timeout 5m
```

Adjust the namespace and ServiceAccount to match your cert-manager installation.
Use `groupName: lego.dns-solver` and `solverName: lego-solver` in the Issuer's
webhook solver. See the [provider setup guide and examples](https://github.com/yxwuxuanl/cert-manager-lego-webhook#quick-start).

## Values

| Value | Default | Description |
| --- | --- | --- |
| `groupName` | `lego.dns-solver` | API group; must match your Issuer configuration. |
| `nameOverride` | `""` | Resource name override; otherwise the release name is used. |
| `certManager.namespace` | Release namespace | Namespace of cert-manager's caller ServiceAccount. |
| `certManager.serviceAccountName` | `cert-manager` | Caller ServiceAccount; an empty string disables its role binding. |
| `webhook.image.repository` | `ghcr.io/yxwuxuanl/cert-manager-lego-webhook` | Webhook image repository. |
| `webhook.image.tag` | `v<appVersion>` | Explicit image tag; an empty string uses the application version. |
| `webhook.imagePullPolicy` | `IfNotPresent` | Image pull policy. |
| `webhook.replicas` | `1` | Replica count; zero is allowed to suspend the webhook. |
| `webhook.affinity` | `{}` | Kubernetes affinity object; legacy empty `[]` is also accepted. |
| `webhook.resources` | `{}` | Resource requests and limits. |
| `webhook.envs` | `LEGO_DISABLE_CNAME_SUPPORT: 'true'` | Container environment variables, with string values. |
| `webhook.nodeSelector` | `{}` | Node labels used for scheduling. |
| `webhook.tolerations` | `[]` | Pod tolerations. |
| `webhook.extraArgs` | `[]` | Additional webhook arguments, as strings. |
| `webhook.dnsConfig` | `{}` | Custom DNS settings; nonempty settings require `nameservers` and select `dnsPolicy: None`. |

The chart validates value types and rejects unknown top-level, `webhook`, image,
and `certManager` keys. `global` and `tags` are accepted for use in parent charts.
Kubernetes-specific objects still need to satisfy the Kubernetes API schema.

## Upgrading from 1.5.x

Chart **1.6.0** uses webhook image **v1.6.0** by default. Both `version` and
`appVersion` are `1.6.0`. The default image follows `appVersion`, while an explicit
`webhook.image.tag` takes precedence. If your saved values pin an older image,
remove that override or pass `--set webhook.image.tag=` to use the chart default.

Resource names and Deployment selectors are preserved. Existing empty
`webhook.affinity: []` values remain valid, including with `helm upgrade --reuse-values`.
Correct any previously ignored value names or invalid types before upgrading;
for example, use `certManager.serviceAccountName` for the caller ServiceAccount.

The Pod now uses `seccompProfile: RuntimeDefault` and sets
`allowPrivilegeEscalation: false`, retaining the non-root user, dropped capabilities,
and read-only root filesystem. These settings support namespaces enforcing the
Kubernetes Restricted Pod Security Standard. RBAC permissions are unchanged.

## Verify

```sh
kubectl rollout status deployment/cert-manager-lego-webhook --namespace cert-manager
kubectl get apiservice v1alpha1.lego.dns-solver
```

The APIService should report `AVAILABLE=True`. Continue with a staging DNS-01
certificate to verify your provider credentials and DNS permissions.

[Configuration reference](https://github.com/yxwuxuanl/cert-manager-lego-webhook/blob/main/docs/configuration.md)
· [Troubleshooting](https://github.com/yxwuxuanl/cert-manager-lego-webhook/blob/main/docs/troubleshooting.md)
