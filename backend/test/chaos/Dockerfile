# Image for the chaos suite: the Go toolchain plus iptables.
FROM golang:1.27
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends iptables procps >/dev/null \
 && rm -rf /var/lib/apt/lists/*
