{{- define "kcs.name" -}}{{ default .Release.Name .Values.fullnameOverride | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- define "kcs.labels" -}}
app.kubernetes.io/name: keycloak-stig
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "kcs.podSecurity" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 0
fsGroup: 0
seccompProfile: {type: RuntimeDefault}
{{- end -}}
{{- define "kcs.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end -}}
{{- define "kcs.toolsEnv" -}}
- {name: KC_CACERT, value: /run/secrets/tls/ca.crt}
- {name: KC_CLIENT_ID, value: {{ .Values.automation.clientId | quote }}}
- {name: KC_CLIENT_SECRET_FILE, value: /run/secrets/automation/secret}
- {name: STIG_PROFILE, value: /etc/kcstig/profile.json}
- {name: STIG_CLIENTS_DIR, value: /etc/kcstig/clients.d}
{{- end -}}
{{- define "kcs.toolsVolumes" -}}
- name: profile
  configMap: {name: {{ include "kcs.name" . }}-profile, items: [{key: profile.json, path: profile.json}]}
- name: clients
  projected:
    sources:
    - configMap: {name: {{ include "kcs.name" . }}-clients}
    {{- range .Values.stig.clientConfigMaps }}
    - configMap: {name: {{ . }}}
    {{- end }}
- name: tls
  secret: {secretName: {{ .Values.tls.secretName }}, items: [{key: ca.crt, path: ca.crt}]}
- name: automation
  secret: {secretName: {{ .Values.automation.secret.name }}, items: [{key: {{ .Values.automation.secret.key }}, path: secret}]}
- {name: tmp, emptyDir: {}}
{{- end -}}
{{- define "kcs.toolsMounts" -}}
- {name: profile, mountPath: /etc/kcstig/profile.json, subPath: profile.json, readOnly: true}
- {name: clients, mountPath: /etc/kcstig/clients.d, readOnly: true}
- {name: tls, mountPath: /run/secrets/tls, readOnly: true}
- {name: automation, mountPath: /run/secrets/automation, readOnly: true}
- {name: tmp, mountPath: /tmp}
{{- end -}}
