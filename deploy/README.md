# Sendit! deployment

**One container image:** the API only. **Host nginx** terminates TLS, serves
`public/`, and proxies `/api/` (and favicon) to the container on `127.0.0.1:8080`.

| File | Role |
|------|------|
| `Dockerfile` | API image (self-contained Alpine musl + `fontconfig` for themed logo PNG) |
| `docker-compose.yml` | Sample compose (API + data volume); builds for the host arch |
| `nginx/sendit.conf` | Host nginx site (TLS + static + reverse proxy) |
| `cloudflare-worker-check-ip/` | Optional client-IP canary Worker |

The runtime image installs **fontconfig** so SkiaSharp can load (`libSkiaSharp.so`
needs `libfontconfig.so.1`). That is required for dynamic `SENDIT_HIGHLIGHT` email
logos (MIME-inline PNG) and `GET /api/v1/branding/logo.png`. Without it, mail still
sends but the logo is omitted and logs show `DllNotFoundException` / fontconfig.

There is **no** in-container nginx, acme.sh, or embedded UI image. Manage
certificates on the host (certbot, etc.).

## Production layout

```text
Internet → host nginx (TLS + public/) → 127.0.0.1:8080 → sendit container (API)
```

```bash
# Frontend (build host or CI)
python3 scripts/build-frontend.py
rsync -a --delete public/ user@server:/var/www/sendit/public/

# On the target machine (native arch only)
cd /path/to/sendit
# Edit environment in deploy/docker-compose.yml
docker compose -f deploy/docker-compose.yml up -d --build

# Host nginx: copy deploy/nginx/sendit.conf, set server_name + SSL certs
sudo nginx -t && sudo systemctl reload nginx
```

Build is **local via Compose** for the architecture of the machine you run it on
(`docker compose … --build` / `docker compose build`). There is no multi-arch
registry push script in this repo.

- API listen: `127.0.0.1:8080` (do not publish 8080 publicly)
- Data volume: `/data` (SQLite, ticket key, optional log file)
- TLS and static files: **host nginx** (`nginx/sendit.conf`)

Complete env tables: [`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md).

## Client-IP canary (Cloudflare Worker)

Deploy [`cloudflare-worker-check-ip/`](cloudflare-worker-check-ip/) (or use the public default).

```bash
SENDIT_PUBLIC_BASE_URL=https://your.domain
# default Worker: https://sendit-check-ip.domains-8c1.workers.dev
# SENDIT_IP_CHECK_WORKER_URL=...   # optional override or off/false to disable
# SENDIT_IP_CHECK_WORKER_CALLER_SECRET=...  # default matches public Worker; off to omit
```

**Once at API startup** (not a loop), Sendit! POSTs the base URL to the Worker, waits for
the reply, and logs if the client IP is not public. Built-in default probe
secret is shared with the Worker unless you override `SENDIT_IP_PROBE_SECRET` /
Worker `PROBE_SECRET`. Guide: [`cloudflare-worker-check-ip/README.md`](cloudflare-worker-check-ip/README.md).

## Security notes

- Bind the API to loopback only (`127.0.0.1:8080`); terminate TLS on host nginx.
- Set long `SENDIT_TICKET_KEY` / `SENDIT_DATA_KEY` and a tight email allow-list in production.
- Forward real client IPs (`X-Forwarded-For` / `X-Real-IP`) only from trusted nginx.
- See `docs/CONFIGURATION.md` and `docs/SECURITY.md`.
