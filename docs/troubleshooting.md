# Troubleshooting

[← Back to README](../README.md)

These commands use the README's release name and namespaces. Adjust them for
your installation.

## Check the webhook

```sh
helm status cert-manager-lego-webhook --namespace cert-manager
kubectl get pods --namespace cert-manager \
  --selector app=cert-manager-lego-webhook
kubectl get apiservice v1alpha1.lego.dns-solver
kubectl logs deployment/cert-manager-lego-webhook \
  --namespace cert-manager --tail=100
```

The APIService should report `AVAILABLE=True`. If it does not, inspect its
conditions and the webhook's serving certificate:

```sh
kubectl describe apiservice v1alpha1.lego.dns-solver
kubectl describe certificate cert-manager-lego-webhook --namespace cert-manager
kubectl describe deployment cert-manager-lego-webhook --namespace cert-manager
```

Check that cert-manager and its CA injector are running, the webhook's serving
certificate is ready, and the Kubernetes API server can reach the webhook service.

## Check certificate issuance

```sh
kubectl describe clusterissuer alidns-staging
kubectl describe certificate lego-example --namespace default
kubectl get orders,challenges --namespace default
kubectl describe challenges --namespace default
```

Read the events to identify whether the failure occurs during ACME account setup,
credential loading, DNS record creation, or propagation checking.

| Symptom | Check |
| --- | --- |
| Missing credentials despite a configured Secret | Remove `config.envs`, including `envs: {}`, when using `envFrom.secret`. Verify the keys against your provider's lego documentation. |
| Secret not found | Check its name and explicit namespace. If the namespace is omitted, check the [namespace rules](configuration.md#secret-namespaces). |
| cert-manager is forbidden from calling the webhook | Verify `certManager.namespace` and `certManager.serviceAccountName`. The key is not `certManager.serviceAccount.name`. |
| The webhook cannot read a Secret or Issuer | Check the webhook ServiceAccount's ClusterRoleBinding and any local RBAC changes. |
| Unknown provider | Use the exact lego provider code and confirm it exists in the lego version bundled with your image. |
| DNS propagation does not complete | Check Challenge events, authoritative TXT records, DNS API permissions, cluster DNS resolution, and CNAME delegation if used. |
| Browser rejects a certificate that is Ready | The example uses staging. Issue through a production ACME issuer for a trusted certificate. |

See cert-manager's [ACME troubleshooting guide](https://cert-manager.io/docs/troubleshooting/acme/)
for the Order and Challenge lifecycle.

## Report a problem

Include the following in a [GitHub issue](https://github.com/yxwuxuanl/cert-manager-lego-webhook/issues):

- Chart version and webhook image tag.
- Kubernetes and cert-manager versions.
- lego provider code and whether you use an Issuer or ClusterIssuer.
- Relevant Helm values, solver configuration, events, and webhook logs.
- What you expected, what happened, and steps to reproduce it.

Redact credentials, private keys, tokens, and sensitive names before sharing
configuration or logs. Do not attach Secret contents.
