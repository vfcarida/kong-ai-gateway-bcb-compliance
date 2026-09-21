---
name: Feature Request
about: Propose a new feature, enhancement, or architectural improvement
title: "feat: <concise description>"
labels: ["enhancement", "triage"]
assignees: []
---

## Summary
A clear, concise description of the proposed feature or improvement.

## Motivation & Use Case
Explain why this feature is needed. What problem does it solve? Who benefits?

Example:
> As a compliance engineer at a Brazilian payment institution, I need [capability] so that [regulatory/technical objective].

## Proposed Solution
Describe your proposed approach. Include:
- Architectural design decisions
- Relevant code files that would change (`handler.lua`, `pii_engine.py`, etc.)
- Any new dependencies or infrastructure requirements

## Regulatory Context (if applicable)
If this feature supports compliance with BCB/CMN regulations, specify the relevant regulation and article:
- [ ] Resolução CMN nº 4.893/2021 (as amended by CMN nº 5.274/2025)
- [ ] Resolução BCB nº 85/2021
- [ ] OWASP Top 10 for LLM Applications 2025 — LLM0X: `...`
- [ ] Other: `...`

## Alternatives Considered
Describe any alternative solutions or features you've considered, and why you chose your proposed approach instead.

## Definition of Done
- [ ] Feature implemented with appropriate unit and/or integration tests
- [ ] All existing 42+ pytest tests remain green
- [ ] Documentation and ADRs updated (if architectural change)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
