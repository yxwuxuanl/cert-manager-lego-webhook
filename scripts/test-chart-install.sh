#!/usr/bin/env bash
set -euo pipefail

kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }
helm() { command helm --kube-context "$KUBE_CONTEXT" "$@"; }

wait_for_api() {
  local group="$1"
  local timeout="${2:-120}"
  local endpoint="/apis/$group/v1alpha1"

  kubectl wait --for=condition=Available "apiservice/v1alpha1.$group" --timeout="${timeout}s" || return

  # Available can still be true while the aggregation layer switches endpoints
  # during a rollout. Verify discovery itself, allowing time for that transition.
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if kubectl get --raw "$endpoint" --request-timeout=5s; then
      return 0
    fi
    sleep 2
  done

  echo "Timed out waiting for discovery endpoint $endpoint after ${timeout}s." >&2
  return 1
}

main() {
  # Only run against an explicitly selected disposable kind cluster.
  : "${KUBE_CONTEXT:?Set KUBE_CONTEXT to a disposable kind cluster context}"
  case "$KUBE_CONTEXT" in
    kind-*) ;;
    *) echo "Refusing to install test resources outside a kind-* context." >&2; exit 1 ;;
  esac

  cd "$(dirname "${BASH_SOURCE[0]}")/.."

  helm upgrade --install cert-manager oci://quay.io/jetstack/charts/cert-manager \
    --version v1.21.1 --namespace cert-manager --create-namespace \
    --set crds.enabled=true --wait --timeout 5m

  local release=lego-webhook-test
  local namespace=lego-webhook-test
  local baseline=https://github.com/yxwuxuanl/cert-manager-lego-webhook/releases/download/cert-manager-lego-webhook-1.5.0/cert-manager-lego-webhook-1.5.0.tgz

  # Install the published baseline before enforcing the new Pod security requirements.
  helm install "$release" "$baseline" \
    --namespace "$namespace" --create-namespace \
    --set certManager.namespace=cert-manager \
    --set certManager.serviceAccountName=cert-manager \
    --wait --timeout 5m
  wait_for_api lego.dns-solver
  local deployment_uid ca_certificate
  deployment_uid=$(kubectl get deployment "$release" -n "$namespace" -o jsonpath='{.metadata.uid}')
  ca_certificate=$(kubectl get secret "$release-ca" -n "$namespace" -o jsonpath='{.data.tls\.crt}')

  kubectl label namespace "$namespace" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=v1.35 --overwrite
  helm upgrade "$release" charts/templates --namespace "$namespace" \
    --reuse-values --wait --timeout 5m
  kubectl rollout status deployment/"$release" -n "$namespace" --timeout=2m
  wait_for_api lego.dns-solver

  # An upgrade must preserve the Deployment identity and the existing serving CA.
  test "$deployment_uid" = "$(kubectl get deployment "$release" -n "$namespace" -o jsonpath='{.metadata.uid}')"
  test -n "$ca_certificate"
  test "$ca_certificate" = "$(kubectl get secret "$release-ca" -n "$namespace" -o jsonpath='{.data.tls\.crt}')"

  # Verify a fresh installation in a namespace that enforces Restricted from the start.
  local fresh=lego-webhook-fresh
  kubectl create namespace "$fresh"
  kubectl label namespace "$fresh" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=v1.35
  helm install "$fresh" charts/templates --namespace "$fresh" \
    --set groupName=fresh.lego.dns-solver \
    --set certManager.namespace=cert-manager \
    --set certManager.serviceAccountName=cert-manager \
    --wait --timeout 5m
  wait_for_api fresh.lego.dns-solver
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
