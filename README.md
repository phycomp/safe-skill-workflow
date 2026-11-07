# safe-skill-workflow

A security-first workflow skill for developing or installing agent skills.

Before any skill is created or installed, it summarizes its content and scans for malicious intent, then produces an `APPROVE` / `CAUTION` / `REJECT` verdict.

## What it does

- Summarizes a skill's content and stated purpose
- Runs static + semantic scans (NVIDIA SkillSpector when available, otherwise manual review)
- Triages vendored noise and records a sha256 manifest
- Produces a final `APPROVE` / `CAUTION` / `REJECT` verdict with guardrails

## Install

```bash
npx skills add phycomp/safe-skill-workflow@safe-skill-workflow -g -y
```

## Usage

Trigger phrases: "develop a new skill", "find/install a skill", "vet an existing skill for safety".

## Contents

- `SKILL.md` — skill instructions and review workflow
- `scripts/audit_skill.py` — static scanner helper

## License

MIT
EOF