# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

This is an OpenBSD process mitigation visibility tool. If you discover a security vulnerability, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Security Features

PMV self-hardens using OpenBSD's pledge(2) and unveil(2) system calls at runtime. These restrict the process to the minimum necessary capabilities after setup.

## Known Limitations

- **TOCTOU in snapshot file**: The save operation uses mkstemp()+rename() for atomicity, but the load operation reads the file directly. The snapshot inherently reflects a point-in-time view.
