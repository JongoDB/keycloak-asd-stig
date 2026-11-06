{{- define "kcc.name" -}}{{ .Release.Name }}-keycloak-cac{{- end -}}
{{- define "kcc.labels" -}}
app.kubernetes.io/name: keycloak-cac
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "kcc.selector" -}}
app.kubernetes.io/name: keycloak-cac
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
