#!/usr/bin/env bash
# Render guards of the keycloak-cac chart: edge mode must refuse every unsafe combination, and render the mTLS +
# NetworkPolicy controls when it is configured properly. Needs helm. Run from anywhere.
set -euo pipefail
C="$(cd "$(dirname "$0")/../deploy/helm/keycloak-cac" && pwd)"
fail=0
ok_edge=(--set edge.enabled=true --set service.type=ClusterIP --set edge.proxyCA.secretName=edge-proxy-ca
         --set 'edge.proxyFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=iam-edge'
         --set 'edge.proxyFrom[0].podSelector.matchLabels.app=keycloak-edge-proxy')
refuses() { local why="$1"; shift
  if out=$(helm template t "$C" "$@" 2>&1); then echo "FAIL rendered although $why"; fail=1
  else echo "PASS refuses: $why ($(echo "$out" | grep -o 'edge[^:]*needs[^:]*\|must give[^(]*' | head -1))"; fi; }
refuses "no proxy CA"                    "${ok_edge[@]}" --set edge.proxyCA.secretName=
refuses "no proxyFrom"                   "${ok_edge[@]}" --set 'edge.proxyFrom=null'
refuses "proxyFrom without a namespace"  "${ok_edge[@]}" --set 'edge.proxyFrom[0].namespaceSelector=null'
refuses "proxyFrom without a pod"        "${ok_edge[@]}" --set 'edge.proxyFrom[0].podSelector=null'
refuses "a LoadBalancer Service"         "${ok_edge[@]}" --set service.type=LoadBalancer
refuses "NetworkPolicy off"              "${ok_edge[@]}" --set networkPolicy.enabled=false
out=$(helm template t "$C" "${ok_edge[@]}")
check() { if echo "$out" | grep -q -- "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
check "edge: listener requires the proxy CA"     'CAC_EDGE_PROXY_CA_FILE, value: /run/secrets/edge-proxy-ca/ca.crt'
check "edge: proxy CA mounted alone, 0440"       'secretName: edge-proxy-ca, defaultMode: 0440, items: \[{key: ca.crt, path: ca.crt}\]'
check "edge: 8443 admits the proxy pods only"    'app: keycloak-edge-proxy'
def=$(helm template t "$C")
if echo "$def" | grep -q CAC_EDGE_PROXY_CA_FILE; then echo "FAIL default render sets edge env"; fail=1; else echo "PASS default render: no edge settings"; fi
if echo "$def" | grep -q 'runAsGroup: 0\|fsGroup: 0'; then echo "FAIL default render uses the root group"; fail=1; else echo "PASS default render: no root group"; fi
if echo "$def" | grep -E 'secret: \{secretName' | grep -vq 'items:'; then echo "FAIL a Secret is mounted whole"; fail=1; else echo "PASS every Secret mounts named keys only"; fi
exit $fail
