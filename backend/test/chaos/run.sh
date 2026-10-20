#!/bin/sh
# Chaos suite (ARCHITECTURE §16).
# Phase 1: two real marmot processes joined by two TLS routes. While a
# stream of data is verified byte for byte, iptables blackholes one route,
# then the other; the stream must survive. Then the node is reloaded with
# SIGHUP (a good and a bad config) and stopped with SIGTERM.
# Phase 2: three processes, iran -> kharej over tls (IPv4 and IPv6), ws and
# grpc, and a relay node. Direct routes are blackholed one by one until only
# the relay is left, then restored; the stream must survive throughout and
# the session must return to a direct path.
# Runs inside a Linux container with NET_ADMIN; use docker.sh.
set -u
fail() {
  echo "FAIL: $*"
  for f in iran2.log relay.log kharej2.log; do
    [ -f "$f" ] && { echo "--- $f (last 80 lines)"; tail -n 80 "$f"; }
  done
  exit 1
}
W=$(mktemp -d); cd "$W"
if ! command -v iptables >/dev/null; then
  apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables procps >/dev/null 2>&1
fi
command -v iptables >/dev/null || fail "iptables is not available (the suite needs it to blackhole routes)"
iptables -L OUTPUT >/dev/null 2>&1 || fail "iptables does not work here; run the container with --cap-add NET_ADMIN"
(cd /src && go build -o "$W/marmot" ./cmd/marmot && go build -o "$W/chaos" ./test/chaos/client) || fail build

IK=$(./marmot keygen -out iran.key); KK=$(./marmot keygen -out kharej.key)
cat > kharej.toml <<CFG
[node]
id = "kharej-01"
identity_key_file = "kharej.key"
[[transport_listen]]
transport = "tls"
port = 9443
[[transport_listen]]
transport = "tls"
port = 9444
[[peers]]
id = "iran-01"
public_key = "$IK"
[api]
listen = "127.0.0.1:27443"
data_dir = "data-k"
CFG
cat > iran.toml <<CFG
[node]
id = "iran-01"
identity_key_file = "iran.key"
[steering]
tunneled_ports = [22052]
[steering.port_map]
22052 = 23000
[session]
probe_interval = "250ms"
standby_paths = 1
[[peers]]
id = "kharej-01"
public_key = "$KK"
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [9443, 9444]
  options = { sni = "www.example.com" }
[api]
listen = "127.0.0.1:27444"
data_dir = "data-i"
CFG

./marmot run -config kharej.toml 2> kharej.log & KP=$!
./marmot run -config iran.toml 2> iran.log & IP=$!
sleep 3

blackhole() { iptables -A OUTPUT -o lo -p tcp --dport "$1" -j DROP; iptables -A OUTPUT -o lo -p tcp --sport "$1" -j DROP; }
restore()   { iptables -D OUTPUT -o lo -p tcp --dport "$1" -j DROP; iptables -D OUTPUT -o lo -p tcp --sport "$1" -j DROP; }

echo "== 30 s verified stream; blackhole 9443 at 6 s, then 9444 at 16 s"
./chaos -for 30s -rate 8388608 & CP=$!
sleep 6;  blackhole 9443
sleep 10; restore 9443; blackhole 9444
wait $CP || fail "stream did not survive the blackholes"
restore 9444
FO=$(grep -c '"msg":"failover"' iran.log)
echo "   failovers: $FO"
[ "$FO" -ge 1 ] || fail "no failover happened"

echo "== SIGHUP with a new port"
sed -i 's/tunneled_ports = \[22052\]/tunneled_ports = [22052, 22053]/; s/^22052 = 23000$/22052 = 23000\n22053 = 23000/' iran.toml
kill -HUP $IP; sleep 1
out=$(./chaos -via 127.0.0.1:22053 -echo 127.0.0.1:23000 -for 2s) || fail "new port does not carry traffic after reload: $out"
echo "   via 22053: $out"
grep -q '"msg":"config reloaded"' iran.log || fail "reload not logged"

echo "== SIGHUP with a broken file keeps the running config"
echo "garbage = [" >> iran.toml
kill -HUP $IP; sleep 1
grep -q 'reload rejected' iran.log || fail "broken config not rejected"
kill -0 $IP || fail "node died on a broken config"

echo "== SIGTERM"
kill -TERM $IP $KP; wait $IP; IE=$?; wait $KP; KE=$?
[ $IE -eq 0 ] && [ $KE -eq 0 ] || fail "exit codes iran=$IE kharej=$KE"
if grep -h '"level":"ERROR"' iran.log kharej.log | grep -v 'reload rejected'; then fail "errors in logs"; fi

# ---------------------------------------------------------------- Phase 2
command -v ip6tables >/dev/null || fail "ip6tables is not available"
grep -q ' lo$' /proc/net/if_inet6 || fail "no IPv6 loopback; run the container with IPv6 enabled (docker.sh does)"
I2=$(./marmot keygen -out iran2.key); K2=$(./marmot keygen -out kharej2.key); RK=$(./marmot keygen -out relay.key)
cat > kharej2.toml <<CFG
[node]
id = "kharej-02"
identity_key_file = "kharej2.key"
[[transport_listen]]
transport = "tls"
port = 9543
[[transport_listen]]
transport = "ws"
port = 9544
options = { path = "/edge" }
[[transport_listen]]
transport = "grpc"
port = 9545
[[transport_listen]]
transport = "tcp"
port = 9547
[[peers]]
id = "iran-02"
public_key = "$I2"
[[peers]]
id = "relay-01"
public_key = "$RK"
[api]
listen = "127.0.0.1:27453"
data_dir = "data-k2"
CFG
cat > relay.toml <<CFG
[node]
id = "relay-01"
identity_key_file = "relay.key"
[[transport_listen]]
transport = "tls"
port = 9546
[relay]
allow_transit = true
[session]
probe_interval = "250ms"
[[peers]]
id = "iran-02"
public_key = "$I2"
[[peers]]
id = "kharej-02"
public_key = "$K2"
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tcp"
  ports = [9547]
[api]
listen = "127.0.0.1:27454"
data_dir = "data-r"
CFG
cat > iran2.toml <<CFG
[node]
id = "iran-02"
identity_key_file = "iran2.key"
[steering]
tunneled_ports = [22062]
[steering.port_map]
22062 = 23010
[steering.port_peers]
"22062" = ["kharej-02"]
[session]
probe_interval = "250ms"
standby_paths = 1
[telemetry]
metrics_listen = "127.0.0.1:29090"
log_level = "debug"
[[peers]]
id = "kharej-02"
public_key = "$K2"
ipv4_pool = ["127.0.0.1"]
ipv6_pool = ["::1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [9543]
  options = { sni = "www.example.com" }
  [[peers.endpoints]]
  transport = "ws"
  ports = [9544]
  options = { path = "/edge", sni = "www.example.com" }
  [[peers.endpoints]]
  transport = "grpc"
  ports = [9545]
  options = { sni = "www.example.com" }
[[peers]]
id = "relay-01"
public_key = "$RK"
ipv4_pool = ["127.0.0.1"]
  [[peers.endpoints]]
  transport = "tls"
  ports = [9546]
[api]
listen = "127.0.0.1:27455"
data_dir = "data-i2"
CFG

./marmot run -config kharej2.toml 2> kharej2.log & K2P=$!
./marmot run -config relay.toml 2> relay.log & RP=$!
./marmot run -config iran2.toml 2> iran2.log & I2P=$!
sleep 3

blackhole6() { ip6tables -A OUTPUT -o lo -p tcp --dport "$1" -j DROP; ip6tables -A OUTPUT -o lo -p tcp --sport "$1" -j DROP; }
restore6()   { ip6tables -D OUTPUT -o lo -p tcp --dport "$1" -j DROP; ip6tables -D OUTPUT -o lo -p tcp --sport "$1" -j DROP; }
relayed() { curl -s 127.0.0.1:29090/metrics | grep -q '^marmot_peer_relayed{peer="kharej-02"} 1'; }

echo "== 60 s verified stream; blackhole tls/IPv4, tls/IPv6, ws, grpc, then restore all"
./chaos -via 127.0.0.1:22062 -echo 127.0.0.1:23010 -for 60s -rate 4194304 & CP=$!
sleep 5;  blackhole 9543;  echo "   t=5   tls over IPv4 blocked"
sleep 5;  blackhole6 9543; echo "   t=10  tls over IPv6 blocked"
sleep 5;  blackhole 9544; blackhole6 9544; echo "   t=15  ws blocked (both families)"
sleep 5;  blackhole 9545; blackhole6 9545; echo "   t=20  grpc blocked (both families): only the relay is left"
R=0; for _ in $(seq 1 20); do if relayed; then R=1; break; fi; sleep 1; done
[ $R -eq 1 ] || fail "kharej-02 never became reachable through the relay"
echo "   relayed"
sleep 3
for p in 9543 9544 9545; do restore $p; restore6 $p; done; echo "   direct routes restored"
wait $CP || fail "stream did not survive losing every direct route"
D=0; for _ in $(seq 1 60); do if grep -q 'session back on a direct path' iran2.log; then D=1; break; fi; sleep 1; done
[ $D -eq 1 ] || fail "session never left the relay after the direct routes came back"
relayed && fail "metrics still say relayed"
grep -q '"msg":"failover"' iran2.log || fail "no failover logged"
echo "   back on a direct path. Path events of iran-02 -> kharej-02:"
grep '"peer":"kharej-02"' iran2.log | grep -E '"msg":"(path added|path down|failover|session back on a direct path|standby join failed|dial failed|handshake failed)"' |
  sed -E 's/.*"time":"[^T]*T([0-9:]{8})[^"]*".*"msg":"([^"]*)".*"via":(.*)/   \1 \2 \3/' | cut -c 1-150 | tail -n 40

echo "== SIGTERM (phase 2 nodes)"
kill -TERM $I2P $RP $K2P; wait $I2P; A=$?; wait $RP; B=$?; wait $K2P; C=$?
[ $A -eq 0 ] && [ $B -eq 0 ] && [ $C -eq 0 ] || fail "exit codes iran2=$A relay=$B kharej2=$C"
if grep -h '"level":"ERROR"' iran2.log relay.log kharej2.log; then fail "errors in phase 2 logs"; fi
echo "CHAOS SUITE PASSED"
