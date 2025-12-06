# Runner

A generic OCI-based container runner for serverless platforms. Pulls container images from registries and runs them without requiring a Docker daemon.

## Overview

Runner is a bootstrap container that pulls and executes container images at runtime. This is useful for environments like Hugging Face Spaces where you cannot run arbitrary Docker images directly.

## Quick Start

```bash
docker run \
  -e IMAGE=ghcr.io/your-org/your-app:latest \
  -e PORT=7860 \
  -e REGISTRY_USER=username \
  -e REGISTRY_PASSWORD=token \
  -p 7860:7860 \
  ghcr.io/drengskapur/runner:latest
```

For public images, omit `REGISTRY_USER` and `REGISTRY_PASSWORD`.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `IMAGE` | Yes | Full OCI image reference to pull and run |
| `PORT` | No | Port for the application (default: `7860`) |
| `REGISTRY_USER` | No | Username for private registry authentication |
| `REGISTRY_PASSWORD` | No | Password/token for private registry authentication |
| `LOG_LEVEL` | No | Logging level: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | No | Log format: `text` or `json` |
| `APP_ENV_*` | No | Passthrough variables (prefix stripped before passing to app) |

### Environment Passthrough

Variables prefixed with `APP_ENV_` are passed to the application with the prefix stripped:

```bash
-e APP_ENV_API_KEY=secret123    # Becomes API_KEY=secret123 in the app
-e APP_ENV_DATABASE_URL=...     # Becomes DATABASE_URL=... in the app
```

## How It Works

1. Validates required environment variables
2. Authenticates to registry (if credentials provided), then clears credentials
3. Fetches image configuration to determine entrypoint and environment
4. Extracts application directories (`/app`, `/data`, `/home`, `/opt`, site-packages)
5. Drops privileges to non-root user (UID 1000)
6. Executes the image's configured entrypoint/command

## Hugging Face Spaces

To use on Hugging Face Spaces, create a Space with Docker SDK and set the required secrets:

```yaml
# README.md in your HF Space
---
title: My App
sdk: docker
app_port: 7860
---
```

Then set these secrets in the Space settings:
- `IMAGE`: Your container image reference
- `REGISTRY_USER`: (optional) Registry username
- `REGISTRY_PASSWORD`: (optional) Registry password/token
- `APP_ENV_*`: Any environment variables your app needs

## Security

- Credentials cleared immediately after authentication
- Application runs as non-root user (UID 1000)
- System directories excluded from extraction (only application paths copied)
- Base image: [Chainguard wolfi-base](https://images.chainguard.dev/directory/image/wolfi-base/overview)

## Requirements

The target image must have:

- A valid entrypoint or command that starts the application
- Application code in extractable paths (`/app`, `/opt`, `/home`, or site-packages)
- The application should bind to `0.0.0.0` and read port from `PORT` environment variable

## License

Apache 2.0
