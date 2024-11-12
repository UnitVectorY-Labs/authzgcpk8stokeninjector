# authzgcpk8stokeninjector

A gRPC-based Envoy ExtAuthz service for injecting GCP access and identity tokens into requests in Kubernetes environments.

## Configuration

The service requires the following environment variables:

| Variable                | Description                                           | Required |
|-------------------------|-------------------------------------------------------|----------|
| `K8S_TOKEN_PATH`        | Path to the Kubernetes service account token           | Yes      |
| `PROJECT_NUMBER`        | GCP Project Number                                    | Yes      |
| `WORKLOAD_IDENTITY_POOL`| Workload Identity Pool name                           | Yes      |
| `WORKLOAD_PROVIDER`     | Workload Identity Provider name                       | Yes      |
| `SERVICE_ACCOUNT_EMAIL` | Email of the GCP service account                      | Yes      |
| `PORT`                  | Port on which the service will listen (default: 50051)| No       |
| `DEBUG`                 | Enable debug logging (`true` or `false`)              | No       |