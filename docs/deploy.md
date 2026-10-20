# Deploying a Marmot node

One node per server. The image contains the `marmot` binary and the web
panel; configuration and keys stay on the host.

## With Docker Compose

From the repository's `deploy/` directory:

```sh
# 1. Build the image (or load a released one as marmot:latest)
docker compose build

# 2. Create the config and data directories, owned by the image's user
#    (uid 65532), so the panel can save marmot.toml and its database.
mkdir -p etc data
cp etc/marmot.toml.example etc/marmot.toml     # then edit it
sudo chown -R 65532:65532 etc data

# 3. Create this node's identity; the command prints its public key,
#    which the other nodes put in their [[peers]] public_key.
docker compose run --rm marmot keygen -out /etc/marmot/identity.key

# 4. Create the first panel owner (password from stdin, at least 12 chars)
docker compose run --rm -T marmot admin create -config /etc/marmot/marmot.toml -username admin

# 5. Start
docker compose up -d
docker compose ps        # "healthy" once the node is ready
```

The panel is at `http://<server>:7443/` (or `https://` with `api.tls_cert`).

### Why these settings

| Setting | Reason |
|---|---|
| `network_mode: host` | User ports and inter-node ports are bound on the host itself, with no Docker NAT on the data path. |
| `cap_add: NET_BIND_SERVICE` | Tunneled ports such as 443 are below 1024; the binary carries the file capability, the container must allow it. |
| `cap_add: NET_ADMIN` | Socket options for paths from several local addresses. |
| `cap_drop: ALL`, `read_only`, `no-new-privileges`, non-root user | Nothing else is needed. |
| `./etc` is a directory mount | The panel replaces `marmot.toml` atomically (write + rename); that needs the directory, not a single-file mount. |
| `memory` limit | `GOMEMLIMIT` is set to 90 % of it automatically. `GOGC` can be set in `environment:`. |

## Without Docker (systemd)

```sh
sudo install -m 0755 marmot /usr/local/bin/marmot
sudo setcap cap_net_bind_service=+ep /usr/local/bin/marmot
sudo useradd --system --home /var/lib/marmot marmot
sudo install -d -o marmot -g marmot -m 0750 /etc/marmot /var/lib/marmot
sudo -u marmot marmot keygen -out /etc/marmot/identity.key
```

`/etc/systemd/system/marmot.service`:

```ini
[Unit]
Description=Marmot tunnel node
After=network-online.target
Wants=network-online.target

[Service]
User=marmot
ExecStart=/usr/local/bin/marmot run -config /etc/marmot/marmot.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/marmot /var/lib/marmot
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

To serve the panel, copy `frontend/dist` to `/usr/share/marmot/web` and set
`api.web_root` to it.

## Operating

| Task | Command |
|---|---|
| Check a config before applying it | `marmot check -config /etc/marmot/marmot.toml` |
| Apply an edited file without a restart | `systemctl reload marmot` (SIGHUP), or the panel's *Re-read the file* |
| Health (exit code) | `marmot health -config /etc/marmot/marmot.toml` |
| Locked out of the panel | `marmot admin passwd -username admin` or `marmot admin reset-totp -username admin` |
| Metrics | `telemetry.metrics_listen`, Prometheus format at `/metrics` |

A config that fails validation is never applied: the running one stays.
Ports that cannot be bound (held by another process) are reported with the
owning process, and everything else is applied.
