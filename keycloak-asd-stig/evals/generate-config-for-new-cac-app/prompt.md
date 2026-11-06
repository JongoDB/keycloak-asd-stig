---
tags: [skill-creator]
max_turns: 40
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

we're standing up a new logistics tracking app called LogTrack for an army unit and need the login side done right for the ATO. users are mostly CAC holders but there are ~20 contractors without CACs who still need to get in with MFA. admins should use their alt tokens. the app is a server-side OIDC app at https://logtrack.army.mil (callback https://logtrack.army.mil/oauth2/callback, backchannel logout https://logtrack.army.mil/oauth2/bc-logout, post logout goes to https://logtrack.army.mil/signed-out) and there's an old reporting tool that only speaks SAML (entity id https://reports.logtrack.army.mil/saml, ACS https://reports.logtrack.army.mil/saml/acs). we use keycloak 26. dont deploy anything, I'll apply it myself next week - just generate the keycloak configuration I need and put it in ./outputs, plus a short doc in ./outputs that tells the LogTrack dev team which app security & development STIG items they still own vs what the IdP covers.
