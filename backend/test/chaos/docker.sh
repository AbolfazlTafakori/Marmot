#!/bin/sh
# Runs the chaos suite in a Linux container (needs Docker; NET_ADMIN lets
# iptables blackhole routes inside the container only). From backend/:
#   sh test/chaos/docker.sh
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker image inspect marmot-chaos >/dev/null 2>&1 || docker build -q -t marmot-chaos "$here/test/chaos"
exec docker run --rm --cap-add NET_ADMIN -v "$here:/src:ro" -v marmot-gomod:/go/pkg/mod -e GOFLAGS=-buildvcs=false \
  marmot-chaos sh /src/test/chaos/run.sh
