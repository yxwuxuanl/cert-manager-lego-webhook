# cert-manager-lego-webhook

[All in one](https://go-acme.github.io/lego/dns/#dns-providers) cert-manager dns solver webhook, based on lego.

## Install

```sh
helm repo add cert-manager-lego-webhook https://yxwuxuanl.github.io/cert-manager-lego-webhook/

helm install cert-manager-lego-webhook cert-manager-lego-webhook/cert-manager-lego-webhook \
    --set=certManager.namespace=cert-manager \ # replace with your cert-manager namespace
    --set=certManager.serviceAccount.name=cert-manager # replace with your cert-manager service account
```

## Usage

```yaml
# step 1: create secret for dns provider
kind: Secret
apiVersion: v1
metadata:
  name: alidns-secret
stringData:
  # The key will be passed to Lego DNS Provider as an credentials
  # for example: https://go-acme.github.io/lego/dns/alidns/#credentials
  ALICLOUD_ACCESS_KEY: ''
  ALICLOUD_SECRET_KEY: ''

---
# step 2: create ClusterIssuer or Issuer
kind: ClusterIssuer
apiVersion: cert-manager.io/v1
metadata:
  name: alidns
spec:
  acme:
    privateKeySecretRef:
      name: alidns-alidns-issuer
    server: https://acme-v02.api.letsencrypt.org/directory
    email: '' # your email
    solvers:
      - dns01:
          webhook:
            groupName: lego.dns-solver
            solverName: lego-solver
            config:
              # available provider refer to https://go-acme.github.io/lego/dns/#dns-providers
              provider: alidns
              envFrom: # use env from secret
                secret:
                  name: alidns-secret
                  namespace: '' # if not set, use cert-manager namespace
              envs: { } # or use envs

---
# step 3: create Certificate
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: lego.example.com
spec:
  issuerRef:
    name: alidns
    kind: ClusterIssuer
  secretName: lego.example.com-tls
  commonName: lego.example.com
  dnsNames:
    - lego.example.com
    - '*.lego.example.com'
```