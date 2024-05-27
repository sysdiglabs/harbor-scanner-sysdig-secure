# Harbor Scanner Adapter for Sysdig Secure

![CI](https://github.com/sysdiglabs/harbor-scanner-sysdig-secure/workflows/CI/badge.svg) ![last commit](https://flat.badgen.net/github/last-commit/sysdiglabs/harbor-scanner-sysdig-secure?icon=github) ![license](https://flat.badgen.net/github/license/sysdiglabs/harbor-scanner-sysdig-secure) ![docker pulls](https://flat.badgen.net/docker/pulls/sysdiglabs/harbor-scanner-sysdig-secure?icon=docker)

The Sysdig Secure Harbor Scanner Adapter enables Harbor to use Sysdig Secure scanning engine to analyze the container images managed by the platform.

> See [Pluggable Scanner API Spec](https://github.com/goharbor/pluggable-scanner-spec) for more details.

This adapter also provides a service that translates the Harbor scanning API requests into Sysdig Secure API calls, allowing Harbor to retrieve vulnerability reports and additional information from the scanning adapter. This information will be presented in the Harbor UI, transparently for the user.

## Getting Started
You can follow a [detailed guide to deploy the Scanner Adapter](docs/install.md).

### CLI Scanning
Using CLI scanning, the scanning operation itself will be triggered and performed on your own infrastructure. It spawns a Kubernetes job when a new image is pushed, this job will communicate **only** the container metadata to the Sysdig Secure Backend, which will perform the evaluation based on the configured image [scanning policies](https://docs.sysdig.com/en/manage-scanning-policies.html).

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name              | Default                     | Description                                                               |
|-------------------|-----------------------------| ---                                                                       |
| `SECURE_URL`      | `https://secure.sysdig.com` | Sysdig Secure URL                                                         |
| `SECURE_API_TOKEN` | ` `                         | Sysdig Secure API Token                                                   |
| `CLI_SCANNING`    | ` `                         | Enable CLI Scanning instead of Backend                                 |
| `NAMESPACE_NAME`  | ` `                         | Namespace where CLI Scanning will spawn jobs                           |
| `CONFIGMAP_NAME`  | ` `                         | ConfigMap name where Harbor Certificate is available                      |
| `SECRET_NAME`     | ` `                         | Secret name where Sysdig Secure API Token and Robot Account are available |
