#!/usr/bin/env bash
set -euo pipefail

# Only run against an explicitly selected disposable kind cluster.
: "${KUBE_CONTEXT:?Set KUBE_CONTEXT to a disposable kind cluster context}"
case "$KUBE_CONTEXT" in
  kind-*) ;;
  *) echo "Refusing to install test resources outside a kind-* context." >&2; exit 1 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }
helm() { command helm --kube-context "$KUBE_CONTEXT" "$@"; }

helm upgrade --install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.21.1 --namespace cert-manager --create-namespace \
  --set crds.enabled=true --wait --timeout 5m

release=lego-webhook-test
namespace=lego-webhook-test
baseline=https://github.com/yxwuxuanl/cert-manager-lego-webhook/releases/download/cert-manager-lego-webhook-1.5.0/cert-manager-lego-webhook-1.5.0.tgz

# Install the published baseline before enforcing the new Pod security requirements.
helm install "$release" "$baseline" \
  --namespace "$namespace" --create-namespace \
  --set certManager.namespace=cert-manager \
  --set certManager.serviceAccountName=cert-manager \
  --wait --timeout 5m
kubectl wait --for=condition=Available apiservice/v1alpha1.lego.dns-solver --timeout=2m
deployment_uid=$(kubectl get deployment "$release" -n "$namespace" -o jsonpath='{.metadata.uid}')
ca_certificate=$(kubectl get secret "$release-ca" -n "$namespace" -o jsonpath='{.data.tls\.crt}')

kubectl label namespace "$namespace" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.35 --overwrite
helm upgrade "$release" charts/templates --namespace "$namespace" \
  --reuse-values --wait --timeout 5m
kubectl rollout status deployment/"$release" -n "$namespace" --timeout=2m
kubectl wait --for=condition=Available apiservice/v1alpha1.lego.dns-solver --timeout=2m
kubectl get --raw /apis/lego.dns-solver/v1alpha1

# An upgrade must preserve the Deployment identity and the existing serving CA.
test "$deployment_uid" = "$(kubectl get deployment "$release" -n "$namespace" -o jsonpath='{.metadata.uid}')"
test -n "$ca_certificate"
test "$ca_certificate" = "$(kubectl get secret "$release-ca" -n "$namespace" -o jsonpath='{.data.tls\.crt}')"

# Verify a fresh installation in a namespace that enforces Restricted from the start.
fresh=lego-webhook-fresh
kubectl create namespace "$fresh"
kubectl label namespace "$fresh" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.35
helm install "$fresh" charts/templates --namespace "$fresh" \
  --set groupName=fresh.lego.dns-solver \
  --set certManager.namespace=cert-manager \
  --set certManager.serviceAccountName=cert-manager \
  --wait --timeout 5m
kubectl wait --for=condition=Available apiservice/v1alpha1.fresh.lego.dns-solver --timeout=2m
kubectl get --raw /apis/fresh.lego.dns-solver/v1alpha1
