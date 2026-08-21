# Cloudflare Worker: client-IP canary

External check that **Sendit! sees a public client IP** when a request hits your
public origin (through nginx / TLS). Cloudflare’s edge calls your site; your
API must not see loopback or RFC1918 addresses.

This replaces any in-process “self-probe” against `SENDIT_PUBLIC_BASE_URL`
(which often false-positive’d under split-horizon / Docker hairpin).

```
API startup (one-shot) ──►  Cloudflare Worker  ──►  {PUBLIC_BASE_URL}/api/v1/diagnostics/client-ip
  or you / CI curl                 │                         │
                                   │                         ▼
                                   │              nginx X-Forwarded-For + Kestrel
                                   │              ForwardedHeaders → client IP
                                   │                         │
                     ◄── JSON ok:true / ok:false ────────────┘
```

**Sendit! boot:** default `SENDIT_IP_CHECK_WORKER_URL` is
`https://sendit-check-ip.domains-8c1.workers.dev` (this public Worker). Override or set
`off` to disable (disables IP restrictions). Default `SENDIT_IP_CHECK_WORKER_CALLER_SECRET`
matches this Worker’s `CALLER_SECRET`
(`18c471779a90d164c6e47df4e67770114cdd32c6b425f718dbcdb31f9a5c97dd`); set `off` to omit
the Bearer header. After listen, the API POSTs **once** (no schedule):

- public IP → Info, restrictions stay on  
- non-public IP → Warning, restrictions off (collect allow-list may force process exit)  
- cannot reach Worker → Warning + attempted URL, restrictions stay on  

## 1. API side (Sendit!)

By default Sendit! and this Worker share a **built-in public probe secret**
(`70fded0f66a1c64e08f16f253ce41d6adfb13701ca1dcedf62995ef6cea252a3`). No env
vars are required for the canary to work.

Optional private override (≥16 characters):

```bash
openssl rand -hex 32
# API:
SENDIT_IP_PROBE_SECRET=<that value>
# Worker secret PROBE_SECRET: same value
```

Restart the API after changing the override. Logs say either
`built-in default probe secret` or `SENDIT_IP_PROBE_SECRET override`.

Ensure nginx still does:

   ```nginx
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-Proto $scheme;
   ```

   and that Kestrel is only reachable via that proxy (not publicly).

`GET /api/v1/diagnostics/client-ip` is **not** a public oracle:

| Condition | HTTP |
|-----------|------|
| Missing / wrong secret | **404** |
| Secret OK, client IP private/loopback | **503** + `{ "ok": false, "isPrivateOrLocal": true, "clientIp": "…" }` |
| Secret OK, client IP public | **200** + `{ "ok": true, "isPrivateOrLocal": false, "clientIp": "…" }` |

## 2. Deploy the Worker

### Option A — Wrangler (recommended)

```bash
cd deploy/cloudflare-worker-check-ip
npm install
npx wrangler login
# Optional — only if you overrode SENDIT_IP_PROBE_SECRET on the API:
# npx wrangler secret put PROBE_SECRET
npx wrangler secret put CALLER_SECRET  # optional but recommended (who may call the Worker)
npx wrangler deploy
```

If you omit `PROBE_SECRET`, the Worker uses the same built-in default as the API.

Note the URL, e.g. `https://sendit-check-ip.<account>.workers.dev`.

### Option B — Cloudflare dashboard

1. Workers & Pages → Create → “Create Worker”.
2. Paste the contents of [`src/index.js`](src/index.js) (module Worker).
3. Settings → Variables → optional secrets:
   - `PROBE_SECRET` — only if you set a custom `SENDIT_IP_PROBE_SECRET` (else built-in default)
   - `CALLER_SECRET` — recommended gate for who may invoke the Worker
4. Deploy.

## 3. Run the canary

Replace the Worker URL and base URL with yours.

**GET:**

```bash
curl -sS "https://sendit-check-ip.<account>.workers.dev/?baseUrl=https://your.domain" \
  -H "Authorization: Bearer YOUR_CALLER_SECRET"
```

**POST:**

```bash
curl -sS -X POST "https://sendit-check-ip.<account>.workers.dev/" \
  -H "Authorization: Bearer YOUR_CALLER_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"baseUrl":"https://your.domain"}'
```

Omit `Authorization` if you did not set `CALLER_SECRET`.

### Success

HTTP **200** from the Worker and something like:

```json
{
  "ok": true,
  "worker": { "called": "https://your.domain/api/v1/diagnostics/client-ip", "upstreamStatus": 200 },
  "check": {
    "ok": true,
    "clientIp": "104.21.x.x",
    "isPrivateOrLocal": false,
    ...
  },
  "hint": "Sendit! saw a public client IP ..."
}
```

`clientIp` will be a **Cloudflare egress** address (or your edge’s view of the Worker). That is fine — the point is it is **public**, not `127.0.0.1` / `10.x` / docker bridge.

### Failure modes

| Symptom | Likely cause |
|---------|----------------|
| Worker `upstreamStatus` **404** | `PROBE_SECRET` ≠ `SENDIT_IP_PROBE_SECRET`, or secret not set / API not restarted |
| Worker `upstreamStatus` **503**, `isPrivateOrLocal: true` | nginx not appending real peer, API not behind proxy, or `UseForwardedHeaders` / KnownProxies mismatch |
| Worker 502 “Failed to reach” | DNS, firewall, or baseUrl wrong / not public |
| Worker 401 | `CALLER_SECRET` set but caller header missing/wrong |

## 4. CI / one-liner after deploy

```bash
#!/usr/bin/env bash
set -euo pipefail
WORKER_URL="${WORKER_URL:?}"
BASE_URL="${BASE_URL:?}"          # e.g. https://sendit.example.com
CALLER_SECRET="${CALLER_SECRET:-}"

args=(-sS -f -X POST "$WORKER_URL" -H "Content-Type: application/json" -d "{\"baseUrl\":\"$BASE_URL\"}")
if [[ -n "$CALLER_SECRET" ]]; then
  args+=(-H "Authorization: Bearer $CALLER_SECRET")
fi

curl "${args[@]}" | tee /tmp/sendit-ip-check.json
# -f fails on non-2xx; Worker returns 502 when check fails
jq -e '.ok == true' /tmp/sendit-ip-check.json >/dev/null
echo "client-IP canary OK"
```

## Security notes

- Do **not** leave `/api/v1/diagnostics/client-ip` unauthenticated. Wrong secret → 404.
- Prefer setting **`CALLER_SECRET`** so strangers cannot use your Worker as a free HTTP client against arbitrary `baseUrl`s.
- The Worker only allows `http(s)` origins and rejects localhost / `.local` hosts; it does not replace a full SSRF policy if you expose the Worker publicly without `CALLER_SECRET`.
- Behind Cloudflare in front of origin: the API may see a Cloudflare IP as `clientIp` for *all* visitors depending on nginx/`real_ip` setup. This canary still proves “not loopback/LAN from this path.”
