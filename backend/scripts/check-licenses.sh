#!/bin/sh
# Fails if any Go dependency compiled into marmot has a licence ADR-0008
# forbids or puts under review: GPL/AGPL/LGPL (restricted), SSPL and similar
# (forbidden), MPL (reciprocal; needs review). Marmot's own packages are
# skipped: they are proprietary. Needs: go install github.com/google/go-licenses/v2@latest
set -e
cd "$(dirname "$0")/.."
go-licenses check ./... --ignore marmot --disallowed_types=forbidden,restricted,reciprocal,unknown
echo "all Go dependency licences allowed (ADR-0008)"
