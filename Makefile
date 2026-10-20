# Common tasks. The merge gate (CONTRIBUTING) is `make check`.
.PHONY: check backend-check frontend-check test race lint licenses chaos image fmt

check: backend-check frontend-check

backend-check: lint test licenses

test:
	cd backend && go vet ./... && go test -count=1 ./...

race:
	cd backend && go test -race -count=3 ./...

lint:
	cd backend && test -z "$$(gofmt -l .)" && golangci-lint run ./...

licenses:
	sh backend/scripts/check-licenses.sh
	cd frontend && npm run licenses

frontend-check:
	cd frontend && npm ci --no-audit --no-fund && npm run build && npm run lint && npm run format:check && npm test

chaos:
	sh backend/test/chaos/docker.sh

image:
	docker build -f backend/Dockerfile --build-arg VERSION=$$(git describe --tags --always 2>/dev/null || echo dev) -t marmot:latest .

fmt:
	cd backend && gofmt -w .
	cd frontend && npm run format
