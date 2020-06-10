# Installing Harbor Scanner Adapter for Sysdig Secure

This guide explains how to install Harbor Scanner Adapter for Sysdig Secure.

## Prerequisites

* Kubernetes >= 1.14
* Harbor >= 1.10
* Helm >= 3
* A Sysdig Secure API Token

### Obtaining the Sysdig Secure API Token

## Deploying on Kubernetes using the Helm Chart

1. Deploy the scanner adapter using the Helm Chart:

```
$ helm repo add sysdiglabs https://sysdiglabs.github.io/charts
"sysdiglabs" has been added to your repositories

$ kubectl create namespace harbor-scanner-sysdig-secure
namespace/harbor-scanner-sysdig-secure created

$ helm -n harbor-scanner-sysdig-secure install harbor-scanner-sysdig-secure sysdig.secure.apiToken=XXX sysdiglabs/harbor-scanner-sysdig-secure
NAME: harbor-scanner-sysdig-secure
LAST DEPLOYED: Tue Jun  9 13:38:12 2020
NAMESPACE: harbor-scanner-sysdig-secure
STATUS: deployed
REVISION: 1
NOTES:
1. Get the application URL by running these commands:

export POD_NAME=$(kubectl get pods --namespace harbor-scanner-sysdig-secure -l "app.kubernetes.io/name=harbor-scanner-sysdig-secure,app.kubernetes.io/instance=harbor-scanner-sysdig-secure" -o jsonpath="{.items[0].metadata.name}")
echo "Visit http://127.0.0.1:8080 to use your application"
kubectl --namespace harbor-scanner-sysdig-secure port-forward $POD_NAME 8080:80
```

2. Configure the scanner adapter in the Harbor interface using the default
service that Helm Chart creates as Endpoint URL:

```
http://harbor-scanner-sysdig-secure.harbor-scanner-sysdig-secure:5000/
```

You can test the connection to see if everything is fine.

3. Select Sysdig Secure scanner and set it as default. You can check the
**Default** label appears next to the scanner's name.

![Set Secure as default scanner](docs/images/secure_as_default_harbor_ui.png)

### Using Inline Scanning instead of Backend Scanning
