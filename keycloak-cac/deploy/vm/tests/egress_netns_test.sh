#!/bin/sh
# Functional test of host/egress.sh in throwaway network namespaces - it never touches the host's own rules.
#   zzh  "the host": Linux bridges br-idp-egress (172.31.250.1/24) and br-idp-backend (172.31.251.1/24), as compose
#        names them, uplink 198.51.100.1/24; egress.sh runs HERE
#   zzc  "the Keycloak container": on BOTH bridges - 172.31.250.2 (egress, default route) and 172.31.251.3 (backend)
#   zzd  "PostgreSQL": 172.31.251.2 on br-idp-backend only (default route via the host, as a worst case)
#   zzx  "the world": one listener per destination class (public, RFC1918, CGNAT, IMDS, WireServer, ...)
# Checks: the public address is reachable; every denied class is not; WireServer:53 is (the DNS exception) and
# WireServer:80 is not; Keycloak -> PostgreSQL works across br-idp-backend; NO host listener is reachable from
# either container through either bridge; PostgreSQL cannot leave its network; --check passes on the applied rules,
# passes again after a re-run, and fails after a rule is removed, a chain is reordered or a raw drop is gone.
#   sudo sh egress_netns_test.sh <path to egress.sh>
set -u
E=${1:?usage: egress_netns_test.sh <egress.sh>}
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "PASS  $1"; }
no() { FAIL=$((FAIL+1)); echo "FAIL  $1"; }
cleanup() { for n in zzc zzd zzh zzx; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT
cleanup
for n in zzc zzd zzh zzx; do ip netns add $n; ip -n $n link set lo up; done
ip -n zzh link add br-idp-egress type bridge; ip -n zzh link add br-idp-backend type bridge
ip -n zzh addr add 172.31.250.1/24 dev br-idp-egress; ip -n zzh addr add 172.31.251.1/24 dev br-idp-backend
ip -n zzh link set br-idp-egress up; ip -n zzh link set br-idp-backend up
# bridge netfilter: as on the production host (Docker 29 does not load br_netfilter there), traffic WITHIN a bridge is not
# seen by iptables; if the module is loaded, it is turned on here so the intra-backend RETURN rule is exercised too
[ -d /sys/module/br_netfilter ] && ip netns exec zzh sysctl -qw net.bridge.bridge-nf-call-iptables=1
ip link add zzce netns zzc type veth peer name ve-c netns zzh      # Keycloak, egress leg
ip link add zzcb netns zzc type veth peer name vb-c netns zzh      # Keycloak, backend leg
ip link add zzdb netns zzd type veth peer name vb-d netns zzh      # PostgreSQL, backend
ip -n zzh link set ve-c master br-idp-egress; ip -n zzh link set vb-c master br-idp-backend; ip -n zzh link set vb-d master br-idp-backend
for i in ve-c vb-c vb-d; do ip -n zzh link set $i up; done
ip -n zzc addr add 172.31.250.2/24 dev zzce; ip -n zzc addr add 172.31.251.3/24 dev zzcb
ip -n zzc link set zzce up; ip -n zzc link set zzcb up; ip -n zzc route add default via 172.31.250.1
ip -n zzd addr add 172.31.251.2/24 dev zzdb; ip -n zzd link set zzdb up; ip -n zzd route add default via 172.31.251.1
ip link add zzh1 netns zzh type veth peer name zzx0 netns zzx
ip -n zzh addr add 198.51.100.1/24 dev zzh1; ip -n zzh link set zzh1 up
ip netns exec zzh sysctl -qw net.ipv4.ip_forward=1
ip -n zzx link set zzx0 up; ip -n zzx addr add 198.51.100.2/24 dev zzx0
# destinations: public (TEST-NET-3 stands in for the internet), and one per denied class
DESTS="203.0.113.5 10.9.9.9 172.20.0.9 192.168.7.7 100.64.1.1 169.254.169.254 168.63.129.16 127.9.9.9 240.0.0.9"
for d in $DESTS; do ip -n zzx addr add $d/32 dev zzx0 2>/dev/null || ip -n zzx addr add $d/32 dev lo; ip -n zzh route add $d/32 via 198.51.100.2; done
ip -n zzx route add 172.31.250.0/24 via 198.51.100.1; ip -n zzx route add 172.31.251.0/24 via 198.51.100.1
LISTEN='import socket,sys,threading
def srv(a,p,t):
    s=socket.socket(socket.AF_INET,t); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((a,p))
    if t==socket.SOCK_STREAM:
        s.listen(16)
        while True:
            c,_=s.accept(); c.sendall(b"hi"); c.close()
    while True:
        d,x=s.recvfrom(512); s.sendto(b"hi",x)
for a in sys.argv[1:]:
    for p,t in ((80,socket.SOCK_STREAM),(53,socket.SOCK_DGRAM),(53,socket.SOCK_STREAM)):
        threading.Thread(target=srv,args=(a,p,t),daemon=True).start()
threading.Event().wait()'
ip netns exec zzx python3 -c "$LISTEN" $DESTS &
ip netns exec zzh python3 -c "$LISTEN" 172.31.250.1 172.31.251.1 198.51.100.1 &
ip netns exec zzd python3 -c "$LISTEN" 172.31.251.2 &
sleep 1
reach() { from zzc "$@"; }
from() {  # from <ns> <addr> <port> <tcp|udp> -> 0 if a reply came back within 2 s
  ns=$1; shift
  ip netns exec $ns python3 -c '
import socket,sys
a,p,t=sys.argv[1],int(sys.argv[2]),sys.argv[3]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if t=="tcp" else socket.SOCK_DGRAM); s.settimeout(2)
try:
    if t=="tcp": s.connect((a,p)); r=s.recv(2)
    else: s.sendto(b"q",(a,p)); r=s.recv(2)
    sys.exit(0 if r==b"hi" else 1)
except Exception: sys.exit(1)' "$1" "$2" "$3"
}
# before: everything is reachable (the test network itself works)
reach 10.9.9.9 80 tcp && ok "before the rules: RFC1918 reachable (the test network works)" || no "test network broken"
reach 172.31.251.1 80 tcp && ok "before the rules: the host is reachable over the backend bridge (the gap)" || no "test network broken (backend)"
ip netns exec zzh iptables -N DOCKER-USER; ip netns exec zzh iptables -A FORWARD -j DOCKER-USER    # what dockerd sets up
ip netns exec zzh sh "$E" >/dev/null && ok "apply" || no "apply"
ip netns exec zzh sh "$E" --check >/dev/null && ok "--check passes on the applied rules" || no "--check after apply"
reach 203.0.113.5 80 tcp && ok "public address: reachable" || no "public address blocked"
for d in 10.9.9.9 172.20.0.9 192.168.7.7 100.64.1.1 169.254.169.254 127.9.9.9 240.0.0.9; do
  reach $d 80 tcp && no "$d:80 reachable" || ok "$d:80 refused"
done
reach 168.63.129.16 80 tcp && no "WireServer :80 reachable" || ok "WireServer 168.63.129.16:80 refused"
reach 168.63.129.16 53 udp && ok "WireServer DNS udp/53 allowed" || no "WireServer DNS udp/53 blocked"
reach 168.63.129.16 53 tcp && ok "WireServer DNS tcp/53 allowed" || no "WireServer DNS tcp/53 blocked"
reach 10.9.9.9 53 udp && no "RFC1918 udp/53 reachable" || ok "DNS anywhere else (10.9.9.9:53) refused"
reach 172.31.250.1 80 tcp && no "host listener reachable over the egress bridge" || ok "host listener over the egress bridge (172.31.250.1:80) refused"
reach 172.31.251.1 80 tcp && no "host listener reachable over the backend bridge" || ok "host listener over the backend bridge (172.31.251.1:80) refused"
reach 198.51.100.1 80 tcp && no "host's other address reachable from the container" || ok "host's uplink address (198.51.100.1:80) refused"
reach 172.31.251.2 80 tcp && ok "Keycloak -> PostgreSQL across br-idp-backend works" || no "Keycloak -> PostgreSQL blocked"
from zzd 172.31.251.1 80 tcp && no "PostgreSQL reaches the host" || ok "PostgreSQL -> host listener refused"
from zzd 203.0.113.5 80 tcp && no "PostgreSQL reaches the internet" || ok "PostgreSQL -> public address refused (backend stays inside)"
ip netns exec zzh sh "$E" >/dev/null && ip netns exec zzh sh "$E" --check >/dev/null && ok "re-run is idempotent (--check still exact)" || no "re-run"
[ "$(ip netns exec zzh iptables -t raw -S PREROUTING | grep -c -e '-j IDP-RAW')" -eq 1 ] && [ "$(ip netns exec zzh iptables -t raw -S IDP-RAW | grep -c '^-A')" -eq 4 ] && ok "re-run adds no duplicate raw jump or rule" || no "duplicate raw rules"
ip netns exec zzh iptables -t raw -I PREROUTING 1 -d 172.31.250.2 ! -i br-idp-egress -j DROP      # what dockerd adds on a container start
ip netns exec zzh sh "$E" --check >/dev/null && ok "--check tolerates Docker's own per-container raw drop above the IDP-RAW jump (a container start)" || no "--check went red after a container start"
ip netns exec zzh iptables -t raw -I PREROUTING 1 -s 10.0.0.0/8 -j ACCEPT                    # not Docker's: an ACCEPT above our drops
ip netns exec zzh sh "$E" --check >/dev/null && no "--check missed an ACCEPT above the IDP-RAW jump" || ok "--check fails when anything else (an ACCEPT) sits above the IDP-RAW jump"
ip netns exec zzh iptables -t raw -D PREROUTING -s 10.0.0.0/8 -j ACCEPT
ip netns exec zzh sh "$E" >/dev/null && ip netns exec zzh sh "$E" --check >/dev/null \
  && [ "$(ip netns exec zzh iptables -t raw -S PREROUTING | grep '^-A ' | head -1)" = "-A PREROUTING -j IDP-RAW" ] \
  && ok "a re-run puts the IDP-RAW jump back at rule 1 (Docker's rule kept below)" || no "re-run after a Docker raw rule"
ip netns exec zzh iptables -t raw -S PREROUTING | grep -q -e '-d 172.31.250.2/32 ! -i br-idp-egress -j DROP' && ok "Docker's own raw rule is left in place" || no "Docker's raw rule removed"
ip netns exec zzh iptables -D IDP-IN -i br-idp-backend -j DROP
ip netns exec zzh sh "$E" --check >/dev/null && no "--check missed the backend-bridge host rule" || ok "--check fails when the backend-bridge INPUT drop is removed"
ip netns exec zzh sh "$E" >/dev/null
ip netns exec zzh iptables -D IDP-FWD -s 172.31.251.0/24 -j DROP
ip netns exec zzh sh "$E" --check >/dev/null && no "--check missed the backend FORWARD drop" || ok "--check fails when the backend FORWARD drop is removed"
ip netns exec zzh sh "$E" >/dev/null
ip netns exec zzh iptables -D IDP-FWD -s 172.31.250.0/24 -d 10.0.0.0/8 -j DROP
ip netns exec zzh sh "$E" --check >/dev/null && no "--check missed a removed rule" || ok "--check fails when a rule is removed"
ip netns exec zzh sh "$E" >/dev/null
ip netns exec zzh iptables -I DOCKER-USER 1 -j ACCEPT
ip netns exec zzh sh "$E" --check >/dev/null && no "--check missed an ACCEPT ahead of IDP-FWD" || ok "--check fails when IDP-FWD is not rule 1"
ip netns exec zzh iptables -D DOCKER-USER 1
ip netns exec zzh iptables -t raw -D IDP-RAW ! -i lo -d 169.254.169.254 -j DROP
ip netns exec zzh sh "$E" --check >/dev/null && no "--check missed a removed raw drop" || ok "--check fails when the IMDS raw drop is gone"
echo; echo "$PASS passed, $FAIL failed"; [ $FAIL -eq 0 ]
