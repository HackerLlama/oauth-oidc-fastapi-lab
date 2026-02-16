# Documentation

## API specifications (OpenAPI 3.0)

Each service has an OpenAPI YAML spec in this folder:

| Service              | Spec file                         | Base URL              |
|----------------------|-----------------------------------|------------------------|
| Authorization Server | [openapi-auth-server.yaml](openapi-auth-server.yaml) | http://127.0.0.1:9000 |
| Client Web           | [openapi-client-web.yaml](openapi-client-web.yaml)   | http://127.0.0.1:8000 |
| Resource Server      | [openapi-resource-server.yaml](openapi-resource-server.yaml) | http://127.0.0.1:7000 |

You can view or validate these with any OpenAPI tool (e.g. [Swagger Editor](https://editor.swagger.io/), `redoc-cli`, or IDE plugins).

## Other docs

- [ENV.md](ENV.md) — Environment variables for all three servers
- [KEY_ROTATION.md](KEY_ROTATION.md) — Signing key rotation (auth server, M11)
