## Summary
<!-- Provide a concise description of the changes in this pull request. -->

## Motivation & Context
<!-- Why is this change needed? Link to the related GitHub Issue if applicable. -->

Closes #<!-- issue number -->

## Type of Change
- [ ] `fix` — Bug fix (non-breaking change that resolves an issue)
- [ ] `feat` — New feature (non-breaking change that adds functionality)
- [ ] `feat!` — Breaking change (fix or feature that changes existing behavior)
- [ ] `docs` — Documentation only change
- [ ] `test` — Adding or updating tests
- [ ] `chore` — Maintenance (CI, deps, tooling)
- [ ] `refactor` — Code refactoring without behavior change

## Changes Made
<!-- List the key files modified and a concise description of each change. -->

- `file1.py`: ...
- `handler.lua`: ...

## Testing
Describe the tests you ran to validate your changes.

- [ ] Python pytest suite passes locally (`pytest pii-sanitizer/tests/ -v` → all 42+ tests green)
- [ ] Docker Compose OSS profile validates (`docker compose --profile oss config`)
- [ ] Lua Busted specs pass (`pongo run spec/`)
- [ ] New tests added for all new behavior

## Regulatory Impact
<!-- If this change impacts regulatory compliance controls, specify the impact. -->

- [ ] No regulatory impact — purely technical improvement
- [ ] Impacts PII detection / sanitization (requires test coverage for CPF/CNPJ/phone/bank-account)
- [ ] Impacts telemetry / OTel pipeline
- [ ] Impacts compliance documentation or ADRs
- [ ] Impacts Kong configuration (`config/kong.yaml`, `config/kong.oss.yaml`, or `config/kong.enterprise.yaml`)

## Documentation
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] ADR created or updated (if architectural decision made)
- [ ] `README.md` updated (if user-facing behavior changed)

## Checklist
- [ ] Code follows the style guidelines in [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] Self-review performed
- [ ] No secrets, credentials, or real PII included in this PR
- [ ] Comments added for non-obvious logic
