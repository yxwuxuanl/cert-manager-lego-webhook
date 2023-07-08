# cert-manager-lego-webhook

[All in one](https://go-acme.github.io/lego/dns/#dns-providers) cert-manager dns solver webhook, based on lego.

## Install

```sh
helm repo add cert-manager-lego-webhook https://yxwuxuanl.github.io/cert-manager-lego-webhook/

helm install cert-manager-lego-webhook cert-manager-lego-webhook/cert-manager-lego-webhook \
    --set=groupName=acme.lego.example.com \
    --set=webhook.image.tag=main
```

## Usage

```yaml
# DNS Provider Secret
kind: Secret
apiVersion: v1
metadata:
    name: lego-alidns-secret
stringData:
    # The key will be passed to Lego DNS Provider as an credentials
    # for example, https://go-acme.github.io/lego/dns/alidns/#credentials
    ALICLOUD_ACCESS_KEY: ''
    ALICLOUD_SECRET_KEY: ''

---
kind: ClusterIssuer
apiVersion: cert-manager.io/v1
metadata:
  name: lego-alidns
spec:
  acme:
    privateKeySecretRef:
      name: lego-alidns-alidns-issuer
    server: ''
    email: ''
    solvers:
      - dns01:
          webhook:
            groupName: acme.lego.example.com
            solverName: lego-solver
            config:
              # Available `provider` refer to https://go-acme.github.io/lego/dns/#dns-providers
              provider: alidns
              envFrom:
                secret:
                  name: lego-alidns-secret
```