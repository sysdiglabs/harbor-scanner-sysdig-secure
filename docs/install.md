# Installing Harbor Scanner Adapter for Sysdig Secure

This guide explains how to install Harbor Scanner Adapter for Sysdig Secure.

## Prerequisites

* Kubernetes >= 1.14
* Harbor >= 1.10
* Helm >= 3
* A valid Sysdig Secure API Token
* A valid Sysdig URL

### Obtaining the Sysdig Secure API Token

Once you have your Sysdig Secure account, you need to login and go to your
settings. Is just below the Get Started sidebar item.

![Getting Secure API Token](images/getting_secure_api_token.png)

### Obtaining the Sysdig Secure API Token
Your URL is listed in the address bar of your browser.  If you login to `https://secure.sysdig.com` then that is your URL.
If you login to `https://app.au1.sysdig.com` for the AP region, then this is the URL you use.

### Example values.yaml configuration.

```yaml
# Default values for harbor-scanner-sysdig-secure.
# This is a YAML-formatted file.
# Declare variables to be passed into your templates.

replicaCount: 1

image:
  repository: miles3719/harbor-scanner-sysdig-secure
  pullPolicy: IfNotPresent

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

podAnnotations: {}

serviceAccount:
  # Specifies whether a service account should be created
  create: true
  # Annotations to add to the service account
  annotations: {}
  # The name of the service account to use.
  # If not set and create is true, a name is generated using the fullname template
  name:

rbac:
  create: true

podSecurityContext: {}
# fsGroup: 2000

securityContext: {}
  # capabilities:
  #   drop:
  #   - ALL
  # readOnlyRootFilesystem: true
  # runAsNonRoot: true
# runAsUser: 1000

service:
  type: ClusterIP
  port: 5000

resources: {}
  # We usually recommend not to specify default resources and to leave this as a conscious
  # choice for the user. This also increases chances charts run on environments with little
  # resources, such as Minikube. If you do want to specify resources, uncomment the following
  # lines, adjust them as necessary, and remove the curly braces after 'resources:'.
  # limits:
  #   cpu: 100m
  #   memory: 128Mi
  # requests:
  #   cpu: 100m
#   memory: 128Mi

nodeSelector: {}

tolerations: []

affinity: {}

# Custom entrypoint for the harbor plugin
customEntryPoint: []

sysdig:
  secure:

    # **required**
    # API Token to access Sysdig Secure.
    # If neither this value nor `sysdig.secure.existingSecureAPITokenSecret` are configured, the
    # user will be required to provide the deployment the `SECURE_API_TOKEN` environment variables.
    apiToken: bs456348-45a6-4b5f-c57d-35572b981a3b

    # Alternatively, specify the name of a Kubernetes secret containing an 'sysdig_secure_api_token' entry
    existingSecureAPITokenSecret: ""

    # Sysdig backend URL (SaaS Regions API endpoints are listed here: https://docs.sysdig.com/en/docs/administration/saas-regions-and-ip-ranges/)
    url: https://app.au1.sysdig.com
    verifySSL: true

proxy:
  httpProxy:
  httpsProxy:
  # Comma-separated list of domain extensions proxy should not be used for.
  # Include in noProxy the internal IP of the kubeapi server,
  # and you probably need to add your registry if it is inside the cluster
  noProxy:

CliScanning:
  enabled: true

asyncMode:
  enabled: true
```

## Deploying on Kubernetes using the Helm Chart

The fastest way to deploy the scanner adapter is using the Helm Chart we
provide. Be aware that you need to provide the Sysdig Secure API token when
you type the `helm install` command.

```
$ helm repo add aaronm-sysdig https://aaronm-sysdig.github.io/charts
"aaronm-sysdig" has been added to your repositories

$ kubectl create namespace harbor-scanner-sysdig-secure
namespace/harbor-scanner-sysdig-secure created

$ helm -n harbor-scanner-sysdig-secure install harbor-scanner-sysdig-secure --set sysdig.secure.apiToken=XXX aaronm-sysdig/harbor-scanner-sysdig-secure
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

And that's it. The new scanner adapter is deployed. Now is time to tell Harbor
to use it, and you can find [how to configure Harbor to use Sysdig Secure Scanner Adapter](#configuring-harbor-to-use-sysdig-secure-scanner-adapter) a few lines below.

You already know [how to get the Sysdig Secure API Token](#obtaining-the-sysdig-secure-api-token) and the Secure URL

## Configuring Harbor to use Sysdig Secure Scanner Adapter

Once the Helm Chart is deployed, is time to configure Harbor to use the scanner
adapter. You need to add it under Interrogation Services. Click on New Scanner
button and fill the details:

Use the service that Helm Chart creates as endpoint, and to make sure it can be
reached click on Test Connection button.

![Adding Sysdig Secure to Harbor Interrogation Services](images/add_secure_to_harbor.png)

Final step is to select Sysdig Secure scanner and set it as default. You can
check the **Default** label appears next to the scanner's name.

![Set Secure as default scanner](images/secure_as_default_harbor_ui.png)
