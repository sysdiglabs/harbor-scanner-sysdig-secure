# Harbor Scanner Adapter for Sysdig Secure

![CI](https://github.com/sysdiglabs/harbor-scanner-sysdig-secure/workflows/CI/badge.svg) ![last commit](https://flat.badgen.net/github/last-commit/sysdiglabs/harbor-scanner-sysdig-secure?icon=github) ![license](https://flat.badgen.net/github/license/sysdiglabs/harbor-scanner-sysdig-secure) ![docker pulls](https://flat.badgen.net/docker/pulls/sysdiglabs/harbor-scanner-sysdig-secure?icon=docker)

The Sysdig Secure Harbor Scanner Adapter enables Harbor to use Sysdig Secure scanning engine to analyze the container images managed by the platform.

> See [Pluggable Scanner API Spec](https://github.com/goharbor/pluggable-scanner-spec) for more details.

This adapter also provides a service that translates the Harbor scanning API requests into Sysdig Secure API calls, allowing Harbor to retrieve vulnerability reports and additional information from the scanning adapter. This information will be presented in the Harbor UI, transparently for the user.

## Getting Started

You can follow a [detailed guide to deploy the Scanner Adapter](docs/install.md).

## Inline and Backend Scanning

This scanning adapter has two operation modes: 
* Backend Scanning: Image scanning happens in the Sysdig Secure Backend
* Inline Scanning: Image scanning happens in the host executing Harbor

### Backend Scanning

This is the default mode. The Sysdig Harbor adapter will forward the container image path to the Sysdig Secure backend (either SaaS or Onprem), for example `docker.io/alpine:latest`. The backend will use this path to retrieve and scan the container image, providing the results back to the Sysdig Harbor adapter. 

PRO:
* Easier to install

CON:
* Sysdig Secure Backend needs to have network visibility in order to fetch images from Harbor

### Inline Scanning

Using inline scanning, the scanning operation itself will be triggered and performed on your own infrastructure. It spawns a Kubernetes job when a new image is pushed, this job will communicate **only** the container metadata to the Sysdig Secure Backend, which will perform the evaluation based on the configured image [scanning policies](https://docs.sysdig.com/en/manage-scanning-policies.html).

PRO:
* No need to configure registry credentials in the Sysdig Secure Backend
* No need to expose your registry externally, so it can be reached by Sysdig Secure (see CON in the section above)
* Image contents are never transmitted outside the pipeline, just the image metadata

CON:
* The job performing the inline scanning needs to have access to the host-local Docker daemon

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name               | Default | Description                                                               |
| ---                | ---     | ---                                                                       |
| `SECURE_URL`       | ` `     | Sysdig Secure URL                                                         |
| `SECURE_API_TOKEN` | ` `     | Sysdig Secure API Token                                                   |
| `INLINE_SCANNING`  | ` `     | Enable Inline Scanning instead of Backend                                 |
| `NAMESPACE_NAME`   | ` `     | Namespace where Inline Scanning will spawn jobs                           |
| `CONFIGMAP_NAME`   | ` `     | ConfigMap name where Harbor Certificate is available                      |
| `SECRET_NAME`      | ` `     | Secret name where Sysdig Secure API Token and Robot Account are available |
