# Harbor Scanner Adapter for Sysdig Secure

![CI status](https://flat.badgen.net/circleci/github/sysdiglabs/harbor-scanner-sysdig-secure?icon=circleci) ![last commit](https://flat.badgen.net/github/last-commit/sysdiglabs/harbor-scanner-sysdig-secure?icon=github) ![license](https://flat.badgen.net/github/license/sysdiglabs/harbor-scanner-sysdig-secure) ![docker pulls](https://flat.badgen.net/docker/pulls/sysdiglabs/harbor-scanner-sysdig-secure?icon=docker)

The Harbor Scanner Adapter for Sysdig Secure is a service that translates the
Harbor scanning API into Sysdig Secure API calls and allows Harbor to use Sysdig
Secure for providing vulnerability reports on images stored on Harbor registry
as part of its vulnerability scan feature.

> See [Pluggable Scanner API Spec](https://github.com/goharbor/pluggable-scanner-spec) for more details.

## Getting Started

### Prerequisites

### Deployment

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name               | Default | Description             |
| ------------------ | ------- | ----------------------- |
| `SECURE_URL`       | ` `     | Sysdig Secure URL       |
| `SECURE_API_TOKEN` | ` `     | Sysdig Secure API Token |

## Inline and Backend Scanning
