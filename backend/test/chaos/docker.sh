#!/bin/sh
# Runs the chaos suite in a Linux container (needs Docker; NET_ADMIN lets
# iptables blackhole routes inside the container only; IPv6 is enabled for
# the dual-stack scenario). From backend/:
#   sh test/chaos/docker.sh
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker image inspect marmot-chaos >/dev/null 2>&1 || docker build -q -t marmot-chaos "$here/test/chaos"
exec docker run --rm --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 -v "$here:/src:ro" -v marmot-gomod:/go/pkg/mod -e GOFLAGS=-buildvcs=false \
  marmot-chaos sh /src/test/chaos/run.sh
