#!/bin/sh
# Chaos suite (ARCHITECTURE §16): two real marmot processes joined by two
# TLS routes. While a stream of data is verified byte for byte, iptables
# blackholes one route, then the other; the stream must survive. Then the
# node is reloaded with SIGHUP (a good and a bad config) and stopped with
# SIGTERM. Runs inside a Linux container with NET_ADMIN; use docker.sh.
set -u
fail() { echo "FAIL: $*"; exit 1; }
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
echo "CHAOS SUITE PASSED"
