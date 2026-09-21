---
name: Bug Report
about: Report a defect, incorrect behavior, or security regression
title: "bug: <concise description>"
labels: ["bug", "triage"]
assignees: []
---

## Describe the Bug
A clear and concise description of what the bug is.

## Steps to Reproduce
1. Start the stack: `docker compose --profile oss up -d`
2. Send request: `...`
3. Observe: `...`

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened. Include error messages, logs, or stack traces.

## Environment
- OS: [e.g. Ubuntu 22.04, macOS Sonoma, Windows 11]
- Docker version: [e.g. Docker 25.0]
- Python version: [e.g. 3.12.10]
- Kong Gateway version: [e.g. 3.14 OSS]
- Profile used: [ ] oss  [ ] enterprise

## Affected Component
- [ ] Kong Lua Plugin (`bcb-pii-sanitizer`)
- [ ] Kong Lua Plugin (`bcb-otel-scrubber`)
- [ ] Python PII Sanitizer microservice (`pii-sanitizer/`)
- [ ] Docker Compose / Configuration
- [ ] CI/CD (`ci-cd.yml`)
- [ ] Documentation / ADRs

## Additional Context
Any other context, configuration, logs, or screenshots that may help diagnose the issue.

## Security Note
> [!CAUTION]
> If this bug relates to a **security vulnerability** or potential PII data leakage, please do **NOT** file a public GitHub issue. Follow the [Security Policy](../../SECURITY.md) and disclose privately to the maintainers.
