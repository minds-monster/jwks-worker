# jwks-worker [DEPRECATED]

> **Status**: Deprecated and no longer used in the minds.MONSTER project.

This is a serverless Cloudflare Worker designed to serve JSON Web Key Sets (JWKS). It was formerly used to distribute public signing keys and verify JWT/token signatures for credential validation.

## Original Purpose
In the early architecture, this worker served the public keys needed to verify Moca credentials and signature payloads at the edge.
