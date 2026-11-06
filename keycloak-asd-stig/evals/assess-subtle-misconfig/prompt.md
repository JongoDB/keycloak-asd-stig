---
tags: [skill-creator]
max_turns: 40
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

we already hardened our keycloak realm for the app security & development STIG last month (CAC login, MFA fallback, lockout, timeouts, the works) but the ISSO wants a second look before the assessor shows up. attached is the realm export from prod. tell me what we still got wrong - only real findings please, the last review padded the list with stuff that was actually fine and it wasted everyones time. for each one give the vuln ID, CAT and the exact keycloak setting to change. put it in ./outputs/findings.md

Input files: realm-export.json
