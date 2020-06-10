# Harbor Scanner Adapter for Sysdig Secure

![CI](https://github.com/sysdiglabs/harbor-scanner-sysdig-secure/workflows/CI/badge.svg) ![last commit](https://flat.badgen.net/github/last-commit/sysdiglabs/harbor-scanner-sysdig-secure?icon=github) ![license](https://flat.badgen.net/github/license/sysdiglabs/harbor-scanner-sysdig-secure) ![docker pulls](https://flat.badgen.net/docker/pulls/sysdiglabs/harbor-scanner-sysdig-secure?icon=docker)

The Harbor Scanner Adapter for Sysdig Secure is a service that translates the
Harbor scanning API into Sysdig Secure API calls and allows Harbor to use Sysdig
Secure for providing vulnerability reports on images stored on Harbor registry
as part of its vulnerability scan feature.

> See [Pluggable Scanner API Spec](https://github.com/goharbor/pluggable-scanner-spec) for more details.

## Getting Started

You can follow a [detailed guide to deploy the Scanner Adapter](docs/install.md).

## Inline and Backend Scanning

This scanner has two ways of working, inline and backend.

### Backend Scanning

This is the default and well known mode. It allows to Sysdig Secure to pull the
image and performs the image scanning the backend infrastructure.

### Inline Scanning

This is another way of scanning which triggers the scanning in your own
infrastructure. It spawns Kubernetes jobs when a new image is pushed and sends
only the results back to Sysdig Secure.

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
