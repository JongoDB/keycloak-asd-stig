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

{{- define "kcc.guards" -}}
{{- if .Values.edge.enabled }}
{{- if not .Values.networkPolicy.enabled }}{{ fail "edge.enabled=true needs networkPolicy.enabled=true: Keycloak trusts the certificate header, so only the proxy may reach it" }}{{ end }}
{{- if ne .Values.service.type "ClusterIP" }}{{ fail "edge.enabled=true needs service.type=ClusterIP: a LoadBalancer/NodePort would let clients bypass the verifying proxy and forge the certificate header" }}{{ end }}
{{- $ca := and .Values.edge.proxyCA .Values.edge.proxyCA.secretName .Values.edge.proxyCA.key }}
{{- $pin := and .Values.edge.proxyCert .Values.edge.proxyCert.secretName .Values.edge.proxyCert.key }}
{{- if not (or $ca $pin) }}{{ fail "edge.enabled=true needs edge.proxyCA (dedicated CA) or edge.proxyCert (pinned certificate), each with secretName and key: Keycloak must require the verifying proxy's TLS client certificate, or anything that reaches port 8443 could forge the certificate header" }}{{ end }}
{{- if not .Values.edge.proxyFrom }}{{ fail "edge.enabled=true needs edge.proxyFrom: the proxy pods allowed to reach port 8443" }}{{ end }}
{{- range $i, $p := .Values.edge.proxyFrom }}
{{- if or (not $p.namespaceSelector) (not $p.namespaceSelector.matchLabels) (not $p.podSelector) (not $p.podSelector.matchLabels) }}{{ fail (printf "edge.proxyFrom[%d] must give namespaceSelector.matchLabels AND podSelector.matchLabels (an empty selector admits every namespace or every pod)" $i) }}{{ end }}
{{- end }}
{{- end }}
{{- end -}}
