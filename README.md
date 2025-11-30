[![GitHub release](https://img.shields.io/github/release/UnitVectorY-Labs/authzgcpk8stokeninjector.svg)](https://github.com/UnitVectorY-Labs/authzgcpk8stokeninjector/releases/latest) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active) [![Go Report Card](https://goreportcard.com/badge/github.com/UnitVectorY-Labs/authzgcpk8stokeninjector)](https://goreportcard.com/report/github.com/UnitVectorY-Labs/authzgcpk8stokeninjector)

# authzgcpk8stokeninjector

A gRPC-based [ExtAuthz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) service for [Envoy Proxy](https://www.envoyproxy.io/) for injecting GCP identity tokens into requests in Kubernetes environments.

## Overview

The purpose of this service is to request JWT identity tokens from GCP using the service account configured in Kubernetes using [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) and set the authoriztion bearer token to the request to backend services through the use of an Envoy Proxy ExtAuthz service.

This service is implemented in Go and is intended to run as a sidecar to the Envoy Proxy. It is configured to listen on a specific port, 50051 by default, for gRPC requests from the Envoy Proxy and then make requests to the OAuth 2.0 server to get the JWT token to inject into the request to the backend service.

## Usage

The latest `authzgcpk8stokeninjector` Docker image is available for deployment from GitHub Packages at [ghcr.io/unitvectory-labs/authzgcpk8stokeninjector](https://github.com/UnitVectorY-Labs/authzjwtbearerinjector/pkgs/container/authzgcpk8stokeninjector). This service is designed to run as a sidecar to Envoy Proxy. You can deploy this container alongside Envoy and configure Envoy to point to the `authzgcpk8stokeninjector` using the ExtAuthz filter, as described in the configuration section.

## Configuration

This service is configured using environment variables.

| Variable                | Description                                            | Required |
|-------------------------|--------------------------------------------------------|----------|
| `K8S_TOKEN_PATH`        | Path to the Kubernetes service account token           | Yes      |
| `PROJECT_NUMBER`        | GCP Project Number                                     | Yes      |
| `WORKLOAD_IDENTITY_POOL`| Workload Identity Pool name                            | Yes      |
| `WORKLOAD_PROVIDER`     | Workload Identity Provider name                        | Yes      |
| `SERVICE_ACCOUNT_EMAIL` | Email of the GCP service account                       | Yes      |
| `PORT`                  | Port on which the service will listen (default: 50051) | No       |
| `DEBUG`                 | Enable debug logging (`true` or `false`)               | No       |

For compatibility with multiple backends the audience is set as part of the Envoy Proxy metadata.

```yaml
metadata:
  filter_metadata:
    com.unitvectory.authzgcpk8stokeninjector:
      audience: "https://app.example.com"
```

## Token Caching

To reduce the number of requests to the GCP OAuth 2.0 server, the service caches the JWT tokens and will reuse them. The token cache is stored in memory inside of this service.

## Envoy Proxy Configuration

The Envoy Proxy configuration uses ExtAuthz to call this service. The context extensions are passed to the service in the request and can be used to convey additional information.

```yaml
- name: envoy.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    failure_mode_allow: false
    allowed_headers:
    patterns:
        - exact: ''
    route_metadata_context_namespaces:
    - com.unitvectory.authzgcpk8stokeninjector
    grpc_service:
    google_grpc:
        target_uri: "127.0.0.1:50051"
        stat_prefix: ext_authz
    timeout: 5s
```

Then on each route the variables can be set in the metadata:

```yaml
routes:
- match:
    prefix: "/"
route:
    cluster: example_cluster
metadata:
    filter_metadata:
    com.unitvectory.authzgcpk8stokeninjector:
      target_audience: https://app.example.com
```

## Configure Workload Identity Federation

This service is designed to work with GCP Workload Identity Federation and therefore is compatible with Kubernetes running on GCP in the form of GKE in addition to other Kubernetes running elsewhere.
