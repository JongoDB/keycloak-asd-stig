---
tags: [skill-creator]
max_turns: 40
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Our assessor shows up next week to run the Application Security and Development STIG against our login service. Attached is the export of our Keycloak realm (it's what we run in prod today). Tell me exactly which ASD STIG findings they're going to write up from this config - vuln IDs and CAT level - and what the precise Keycloak setting change is for each. Write the findings to ./outputs/findings.md.

Input files: realm-export.json
