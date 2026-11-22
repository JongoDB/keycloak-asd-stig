#!/bin/sh
# Container egress policy for the shared IdP host: Keycloak may reach the PUBLIC internet (DoD CRL/OCSP, Entra, the
# ACS mail relay, the relying applications' JWKS and back-channel URLs - see README "Egress firewall"), and nothing
# internal. This is the control behind add-client's add-time DNS check of jwks_url / backchannel_logout_url: DNS can
# change or rebind after the check, and Keycloak may follow an HTTP redirect, so the network itself refuses internal
# destinations whatever name led there. Fails closed:
#  - idp-egress.service runs BEFORE docker.service and docker.service REQUIRES it, so no container starts before these
#    rules exist, and dockerd does not start at all if they cannot be applied. Because of that Requires=, NEVER
#    `systemctl restart` or `stop` idp-egress: it restarts or stops dockerd and every container. To re-apply, run
#    /usr/local/sbin/idp-egress (idempotent, no gap); `--check` to verify.
#  - raw PREROUTING rule 1 -> IDP-RAW drops every packet NOT from the host itself (! -i lo) to 169.254.169.254 (IMDS:
#    the VM's managed identity writes backups to Blob Storage) and 168.63.129.16 (Azure WireServer), from ANY bridge;
#    only DNS to 168.63.129.16 from the Keycloak egress subnet is let through first (see below). The host's own
#    requests go through OUTPUT and are unaffected. raw is evaluated before every filter chain. Docker 29 also writes
#    raw PREROUTING itself - one rule per published container address (`-d <container> ! -i <its bridge> -j DROP`),
#    added and removed as containers start and stop - but never flushes the chain or touches a rule it did not add.
#    A container start can therefore place its rule above ours; that is harmless (it only drops): --check tolerates
#    exactly those Docker drops ahead of the jump and fails on anything else there; an idp-egress run puts the jump
#    back at position 1 anyway.
#  - FORWARD (DOCKER-USER rule 1 -> IDP-FWD): a NEW connection from the Keycloak egress subnet (compose network
#    `egress`, 172.31.250.0/24, fixed in compose.yaml) to loopback, link-local (IMDS included), RFC1918, CGNAT
#    (100.64/10), 0/8, multicast or reserved (240/4) space, or to 168.63.129.16 other than DNS, is logged and dropped.
#    Inside the subnet itself is allowed. Everything else (the public internet) passes on to Docker's own chains.
#    PostgreSQL is on the separate internal `backend` network, whose traffic never carries an egress-subnet source.
#    docker0 (unused here) is denied outright. Replies pass.
#  - FORWARD, backend: the `backend` network (172.31.251.0/24, bridge br-idp-backend, Keycloak <-> PostgreSQL) may
#    only talk within itself; anything else NEW from it is logged and dropped (Docker's `internal: true` already
#    gives it no route out; this does not depend on that).
#  - INPUT (rule 1 -> IDP-IN): NO Docker bridge - br-idp-egress, br-idp-backend, docker0, any br-* - and neither
#    subnet can open a connection to a host listener (sshd, docker-proxy on 443, ...); Keycloak sits on both
#    networks, so either would otherwise reach the host. Replies to connections the host made pass. Keycloak <->
#    PostgreSQL stays inside br-idp-backend and never reaches INPUT.
#  DNS: measured 2026-11-16 (Docker 29.1.3), Keycloak's lookups go to Docker's embedded resolver (127.0.0.11 inside the
#  container) and dockerd forwards them from the HOST (<private ip> -> 168.63.129.16:53, OUTPUT), so nothing from the
#  container needs port 53. The 168.63.129.16:53 exception exists only so a Docker change to forward from the
#  container's namespace cannot take every sign-in down; nothing else on 168.63.129.16 is reachable.
#  Each chain is built under a temporary name and swapped in, so a re-run never leaves a gap.
#  RESIDUAL RISK (README): IPv4 only - the egress network has no IPv6, so the container has no IPv6 route. Anything
#  holding the Docker socket is root and can attach a container elsewhere; these rules see the egress subnet only.
#   idp-egress            apply (systemd: idp-egress.service)
#   idp-egress --check    exit 0 only if the live rules are EXACTLY the expected set: both chains compared rule for
#                         rule (IDP-RAW, IDP-FWD, IDP-IN), and raw PREROUTING -> IDP-RAW, FORWARD -> DOCKER-USER ->
#                         IDP-FWD and INPUT -> IDP-IN each at position 1
#   EGRESS_SUBNET=172.31.250.0/24 BACKEND_SUBNET=172.31.251.0/24   (from /etc/default/idp-egress; must equal the
#   subnets in compose.yaml)
set -eu
# The file is PARSED as data, never sourced, so a value cannot run a command; the validation below sees it whole.
CFG=/etc/default/idp-egress
cfg() { sed -n "s/^$1=//p" "$CFG" | tail -1 | sed "s/^[\"']//; s/[\"']\$//"; }
if [ -r "$CFG" ]; then
  v=$(cfg EGRESS_SUBNET); [ -n "$v" ] && EGRESS_SUBNET=$v
  v=$(cfg BACKEND_SUBNET); [ -n "$v" ] && BACKEND_SUBNET=$v
fi
NET="${EGRESS_SUBNET:-172.31.250.0/24}"; BK="${BACKEND_SUBNET:-172.31.251.0/24}"
WIRESERVER=168.63.129.16
METADATA="169.254.169.254 $WIRESERVER"
# loopback, link-local (IMDS), RFC1918, CGNAT, "this network", multicast, reserved, and the WireServer (DNS excepted)
DENY="127.0.0.0/8 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 $WIRESERVER/32"
OCT='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
valid() { [ "$(printf '%s' "$2" | wc -l)" -eq 0 ] && printf '%s\n' "$2" | grep -Eqx "$1"; }
valid "$OCT\.$OCT\.$OCT\.$OCT/(1[6-9]|2[0-9]|30)" "$NET" || { echo "idp-egress: EGRESS_SUBNET is not an IPv4 /16-/30 network"; exit 1; }
valid "$OCT\.$OCT\.$OCT\.$OCT/(1[6-9]|2[0-9]|30)" "$BK" || { echo "idp-egress: BACKEND_SUBNET is not an IPv4 /16-/30 network"; exit 1; }
[ "$NET" != "$BK" ] || { echo "idp-egress: EGRESS_SUBNET and BACKEND_SUBNET must differ"; exit 1; }

fill_fwd() {  # fill_fwd <chain>
  iptables -A "$1" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A "$1" -s "$NET" -d "$NET" -j RETURN                          # within the egress network itself
  iptables -A "$1" -s "$NET" -d $WIRESERVER -p udp --dport 53 -j RETURN    # DNS (see header; not used today)
  iptables -A "$1" -s "$NET" -d $WIRESERVER -p tcp --dport 53 -j RETURN
  for d in $DENY; do
    iptables -A "$1" -s "$NET" -d "$d" -m limit --limit 6/min -j LOG --log-prefix "idp-egress-drop: "
    iptables -A "$1" -s "$NET" -d "$d" -j DROP
  done
  iptables -A "$1" -s "$BK" -d "$BK" -j RETURN                            # Keycloak <-> PostgreSQL
  iptables -A "$1" -s "$BK" -m limit --limit 6/min -j LOG --log-prefix "idp-backend-drop: "
  iptables -A "$1" -s "$BK" -j DROP
  iptables -A "$1" -i docker0 -m limit --limit 6/min -j LOG --log-prefix "idp-docker0-drop: "
  iptables -A "$1" -i docker0 -j DROP
}
fill_in() {   # fill_in <chain>: by interface (every Docker bridge) AND by subnet (both networks)
  for ifc in br-idp-egress br-idp-backend docker0 br-+; do
    iptables -A "$1" -i "$ifc" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -A "$1" -i "$ifc" -m limit --limit 6/min -j LOG --log-prefix "idp-host-drop: "
    iptables -A "$1" -i "$ifc" -j DROP
  done
  for n in "$NET" "$BK"; do
    iptables -A "$1" -s "$n" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -A "$1" -s "$n" -j DROP
  done
}
fresh() { iptables -N "$1" 2>/dev/null || iptables -F "$1"; }
first_rule() { iptables -S "$1" | grep '^-A ' | head -1; }
fill_raw() {  # fill_raw <raw chain>: the raw rules this script owns, in order (DNS exceptions first)
  for p in udp tcp; do iptables -t raw -A "$1" -s "$NET" -d $WIRESERVER -p $p --dport 53 -j ACCEPT; done
  for ip in $METADATA; do iptables -t raw -A "$1" ! -i lo -d "$ip" -j DROP; done
}

if [ "${1:-}" = --check ]; then
  trap 'iptables -F IDP-CHK 2>/dev/null; iptables -X IDP-CHK 2>/dev/null; iptables -t raw -F IDP-CHK 2>/dev/null; iptables -t raw -X IDP-CHK 2>/dev/null || true' EXIT
  fail() { echo "idp-egress: $1"; exit 1; }
  # Docker 29 inserts its own raw rules on every container start, possibly above ours: one DROP per published
  # container address (`-d <ip>/32 ! -i <bridge> -j DROP`). Those only drop, so they are tolerated ahead of the jump;
  # anything else ahead of it (an ACCEPT, another jump) fails the check.
  first=$(iptables -t raw -S PREROUTING | grep '^-A ' | grep -v -E '^-A PREROUTING -d ([0-9]{1,3}\.){3}[0-9]{1,3}/32 ! -i [A-Za-z0-9_.-]+ -j DROP$' | head -1)
  [ "$first" = "-A PREROUTING -j IDP-RAW" ] || fail "raw PREROUTING: the first rule that is not one of Docker's own per-container drops is not the jump to IDP-RAW ($first)"
  [ "$(iptables -t raw -S PREROUTING | grep -c -x -e '-A PREROUTING -j IDP-RAW')" -eq 1 ] || fail "raw PREROUTING jumps to IDP-RAW more than once"
  iptables -t raw -N IDP-CHK 2>/dev/null || iptables -t raw -F IDP-CHK; fill_raw IDP-CHK
  [ "$(iptables -t raw -S IDP-CHK | sed "s/IDP-CHK/IDP-RAW/g")" = "$(iptables -t raw -S IDP-RAW 2>/dev/null)" ] || fail "IDP-RAW differs from the expected rule set"
  [ "$(first_rule FORWARD)" = "-A FORWARD -j DOCKER-USER" ] || fail "FORWARD rule 1 is not the jump to DOCKER-USER"
  [ "$(first_rule DOCKER-USER)" = "-A DOCKER-USER -j IDP-FWD" ] || fail "DOCKER-USER rule 1 is not the jump to IDP-FWD"
  [ "$(first_rule INPUT)" = "-A INPUT -j IDP-IN" ] || fail "INPUT rule 1 is not the jump to IDP-IN"
  for pair in IDP-FWD:fill_fwd IDP-IN:fill_in; do
    ch=${pair%%:*}; fresh IDP-CHK; ${pair#*:} IDP-CHK
    [ "$(iptables -S IDP-CHK | sed "s/IDP-CHK/$ch/g")" = "$(iptables -S "$ch" 2>/dev/null)" ] || fail "$ch differs from the expected rule set"
  done
  echo "idp-egress: in place (exact)"; exit 0
fi

swap() {  # swap <table> <parent chain> <chain>: <chain>-NEW is filled; make it live at position 1, retire the old one, rename
  iptables -t "$1" -I "$2" 1 -j "$3-NEW"
  while iptables -t "$1" -D "$2" -j "$3" 2>/dev/null; do :; done
  iptables -t "$1" -F "$3" 2>/dev/null && iptables -t "$1" -X "$3" 2>/dev/null || true
  iptables -t "$1" -E "$3-NEW" "$3"
}

# ---- raw: metadata endpoints unreachable from anything but the host itself (DNS from the egress subnet excepted)
iptables -t raw -N IDP-RAW-NEW 2>/dev/null || iptables -t raw -F IDP-RAW-NEW; fill_raw IDP-RAW-NEW; swap raw PREROUTING IDP-RAW

iptables -N DOCKER-USER 2>/dev/null || true             # pre-created: Docker adopts it and never flushes it
fresh IDP-FWD-NEW; fill_fwd IDP-FWD-NEW; swap filter DOCKER-USER IDP-FWD
fresh IDP-IN-NEW; fill_in IDP-IN-NEW; swap filter INPUT IDP-IN

echo "idp-egress: backend $BK -> itself only; egress $NET -> public internet only (loopback, link-local/IMDS, RFC1918, CGNAT, multicast, reserved and the WireServer denied; DNS to $WIRESERVER allowed); docker0 denied; host listeners closed to containers"
