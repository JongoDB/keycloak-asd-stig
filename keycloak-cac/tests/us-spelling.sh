#!/usr/bin/env bash
# User-facing text is US English: every login message bundle and template of the extension, the dod-stig theme and the
# example theme. Fails on a UK spelling ("enrol", "organisation", "authorise", ...), and pins the admin second-factor
# message. "licence" is not checked: as a noun it is right in legal text.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
FILES=$(find keycloak-asd-stig/assets/extension/src/main/resources keycloak-asd-stig/assets/theme keycloak-cac/deploy/vm/theme-example \
  -type f \( -name 'messages*.properties' -o -name '*.ftl' -o -name '*.html' \) | sort)
UK='\b(enrol|enrols|enrolment|enrolments)\b|organis(e|ed|es|ing|ation|ations)\b|authoris(e|ed|es|ing|ation|ations)\b|recognis|behaviour|colour|cancell(ed|ing)\b|\bcentre|favour|catalogue|labell(ed|ing)\b|analys(e|ed|es|ing)\b|sanitis|minimis|customis|initialis|utilis|summaris|optimis|categoris|\bdefence\b|\bwhilst\b|acknowledgement|judgement'
fail=0
if hits=$(grep -n -i -E -H "$UK" $FILES); then echo "FAIL UK spelling in user-facing text:"; echo "$hits"; fail=1
else echo "PASS no UK spelling in $(echo "$FILES" | wc -l | tr -d ' ') message bundles and templates"; fi
M=keycloak-asd-stig/assets/extension/src/main/resources/theme-resources/messages/messages_en.properties
grep -qx 'stigAdminSecondFactor=Administrators must sign in with their CAC, or enroll an authenticator app first.' "$M" \
  && echo "PASS admin second-factor message: \"enroll an authenticator app\"" || { echo "FAIL admin second-factor message: $(grep '^stigAdminSecondFactor=' "$M")"; fail=1; }
exit $fail
