# Installing Harbor Scanner Adapter for Sysdig Secure

This guide explains how to install Harbor Scanner Adapter for Sysdig Secure.

## Prerequisites

* Kubernetes >= 1.14
* Harbor >= 1.10
* Helm >= 3
* A Sysdig Secure API Token

### Obtaining the Sysdig Secure API Token

Once you have your Sysdig Secure account, you need to login and go to your
settings. Is just below the Get Started sidebar item.

![Getting Secure API Token](images/getting_secure_api_token.png)

## Deploying on Kubernetes using the Helm Chart

The fastest way to deploy the scanner adapter is using the Helm Chart we
provide. Be aware that you need to provide the Sysdig Secure API token when
you type the `helm install` command.

```
$ helm repo add sysdiglabs https://sysdiglabs.github.io/charts
"sysdiglabs" has been added to your repositories

$ kubectl create namespace harbor-scanner-sysdig-secure
namespace/harbor-scanner-sysdig-secure created

$ helm -n harbor-scanner-sysdig-secure install harbor-scanner-sysdig-secure --set sysdig.secure.apiToken=XXX sysdiglabs/harbor-scanner-sysdig-secure
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

Once the Helm Chart is deployed, is time to configure Harbor to use the scanner
adapter. You need to add it under Interrogation Services. Click on New Scanner
button and fill the details:

Use the service that Helm Chart creates as endpoint, and to make sure it can be
reached click on Test Connection button.

![Adding Sysdig Secure to Harbor Interrogation Services](images/add_secure_to_harbor.png)

Final step is to select Sysdig Secure scanner and set it as default. You can
check the **Default** label appears next to the scanner's name.

![Set Secure as default scanner](images/secure_as_default_harbor_ui.png)

### Using Inline Scanning instead of Backend Scanning

The Inline Scanning requires a bit more of configuration. We will use a file
to keep these settings:

```yaml
sysdig:
  secure:
    apiToken: XXX

inlineScanning:
  enabled: true
  harbor:
    robotAccount:
      name: robotAccount
      password: XXX
    CA: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

You already know [how to get the Sysdig Secure API Token](#obtaining-the-sysdig-secure-api-token)
so that we can go to next steps.

Next step is about the robot account. As long as this mode uses `docker` command
under the hoods to perform the scanning, we need to authenticate against
the registry using `docker`, and we will do it using a robot acount. Harbor
folks did a pretty good job documenting [how to create a robot account]
(https://goharbor.io/docs/1.10/working-with-projects/project-configuration/create-robot-accounts/).
Once you created the account, be sure you fill the values under
`inlineScanning.harbor.robotAccount` key.

Next step is to get and configure the CA certificate that Harbor uses. Again,
Harbor folks did a great job documenting [how to download the CA certificate]
(https://goharbor.io/docs/1.10/working-with-projects/working-with-images/pulling-pushing-images/#download-the-harbor-certificate).
Once you have the certificate, ensure is under the `inlineScanning.harbor.CA` key.
Pay attention to the `|` pipe symbol because we need to keep it raw.

Finally, next step is to deploy the scanner adapter:

```
$ helm repo add sysdiglabs https://sysdiglabs.github.io/charts
"sysdiglabs" has been added to your repositories

$ kubectl create namespace harbor-scanner-sysdig-secure
namespace/harbor-scanner-sysdig-secure created

$ helm -n harbor-scanner-sysdig-secure install harbor-scanner-sysdig-secure -f value.yaml sysdiglabs/harbor-scanner-sysdig-secure
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
to use it, and you can find these instructions a few lines above.
