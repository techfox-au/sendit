/**
 * Sendit! client-IP canary (Cloudflare Worker).
 *
 * Called at API startup (and manually via curl): receives baseUrl, GETs
 * {baseUrl}/api/v1/diagnostics/client-ip with the shared probe secret, returns whether
 * Sendit! saw a public client IP (Worker egress after nginx + ASP.NET ForwardedHeaders).
 *
 * Response contract used by ClientIpWorkerProbeService:
 *   ok: true  + check.isPrivateOrLocal false → public path OK
 *   ok: false + check.isPrivateOrLocal true  → definitive non-public (restrictions off)
 *   other (401, 404, network) → inconclusive on the API (restrictions stay on)
 *
 * Env (Workers secrets / vars):
 *   PROBE_SECRET   — optional; defaults to ClientIpProbeAuth.DefaultSecret / SENDIT_IP_PROBE_SECRET
 *   CALLER_SECRET  — optional; Authorization: Bearer or X-Worker-Auth to invoke this Worker
 */

const CHECK_PATH = "/api/v1/diagnostics/client-ip";
const PROBE_HEADER = "X-Sendit-Ip-Probe";
// Must match Sendit.Api ClientIpProbeAuth.DefaultSecret
const DEFAULT_PROBE_SECRET =
  "70fded0f66a1c64e08f16f253ce41d6adfb13701ca1dcedf62995ef6cea252a3";

export default {
  async fetch(request, env) {
    try {
      if (request.method === "OPTIONS") {
        return cors(new Response(null, { status: 204 }));
      }

      if (request.method !== "GET" && request.method !== "POST") {
        return cors(json({ ok: false, error: "Use GET or POST" }, 405));
      }

      const authErr = requireCallerAuth(request, env);
      if (authErr) return cors(authErr);

      const probeSecret = (env.PROBE_SECRET || DEFAULT_PROBE_SECRET).trim();
      if (probeSecret.length < 16) {
        return cors(
          json(
            {
              ok: false,
              error:
                "Worker misconfigured: PROBE_SECRET must be ≥16 chars (or omit for built-in default)",
            },
            500
          )
        );
      }

      const baseUrl = await readBaseUrl(request);
      if (!baseUrl) {
        return cors(
          json(
            {
              ok: false,
              error:
                'Missing baseUrl. GET ?baseUrl=https://your.domain or POST {"baseUrl":"https://your.domain"}',
            },
            400
          )
        );
      }

      const target = resolveCheckUrl(baseUrl);
      if (!target.ok) {
        return cors(json({ ok: false, error: target.error }, 400));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15_000);
      let upstream;
      try {
        upstream = await fetch(target.url, {
          method: "GET",
          headers: {
            [PROBE_HEADER]: probeSecret,
            Accept: "application/json",
            "User-Agent": "Sendit-IpCheck-Worker/1.0",
          },
          redirect: "manual",
          signal: controller.signal,
        });
      } catch (err) {
        const aborted = err?.name === "AbortError";
        return cors(
          json(
            {
              ok: false,
              error: aborted
                ? "Timeout calling diagnostics/client-ip (15s)"
                : `Failed to reach diagnostics/client-ip: ${err?.message || String(err)}`,
              target: target.url,
            },
            502
          )
        );
      } finally {
        clearTimeout(timer);
      }

      const text = await upstream.text();
      let body = null;
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = { raw: text.slice(0, 500) };
      }

      // API: 200 = public client IP, 503 = private/loopback, 404 = bad/missing secret.
      const pass =
        upstream.status === 200 && body && body.ok === true && body.isPrivateOrLocal === false;

      return cors(
        json(
          {
            ok: pass,
            worker: {
              called: target.url,
              upstreamStatus: upstream.status,
            },
            check: body,
            hint: pass
              ? "Sendit! saw a public client IP for this Worker request — proxy forwarding looks good."
              : upstream.status === 404
                ? "diagnostics/client-ip returned 404: wrong PROBE_SECRET / SENDIT_IP_PROBE_SECRET, or secret unset on API."
                : upstream.status === 503
                  ? "diagnostics/client-ip returned 503: client IP is private/loopback — nginx is not giving the API the real peer (or you are not hitting the public edge)."
                  : "Unexpected response from diagnostics/client-ip; inspect check and worker.upstreamStatus.",
          },
          pass ? 200 : 502
        )
      );
    } catch (err) {
      return cors(
        json({ ok: false, error: err?.message || String(err) }, 500)
      );
    }
  },
};

function requireCallerAuth(request, env) {
  const needed = (env.CALLER_SECRET || "").trim();
  if (!needed) return null;

  const auth = request.headers.get("Authorization") || "";
  let presented = "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    presented = auth.slice(7).trim();
  } else {
    presented = (request.headers.get("X-Worker-Auth") || "").trim();
  }

  if (!presented || presented !== needed) {
    return json(
      {
        ok: false,
        error:
          "Unauthorized: set Authorization: Bearer <CALLER_SECRET> or X-Worker-Auth (Worker has CALLER_SECRET configured)",
      },
      401
    );
  }
  return null;
}

async function readBaseUrl(request) {
  const url = new URL(request.url);
  const q = (url.searchParams.get("baseUrl") || url.searchParams.get("base_url") || "").trim();
  if (q) return q;

  if (request.method === "POST") {
    const ct = (request.headers.get("Content-Type") || "").toLowerCase();
    if (ct.includes("application/json")) {
      const data = await request.json().catch(() => null);
      if (data && typeof data.baseUrl === "string") return data.baseUrl.trim();
      if (data && typeof data.base_url === "string") return data.base_url.trim();
    } else {
      const text = (await request.text()).trim();
      if (text.startsWith("http://") || text.startsWith("https://")) return text;
    }
  }
  return "";
}

function resolveCheckUrl(baseUrlRaw) {
  let s = baseUrlRaw.trim().replace(/\/+$/, "");
  // Allow bare origin or origin already ending with the diagnostics path
  if (/\/api\/v1\/diagnostics\/client-ip\/?$/i.test(s)) {
    s = s.replace(/\/api\/v1\/diagnostics\/client-ip\/?$/i, "");
  }

  let u;
  try {
    u = new URL(s);
  } catch {
    return { ok: false, error: "baseUrl is not a valid absolute URL" };
  }

  if (u.protocol !== "https:" && u.protocol !== "http:") {
    return { ok: false, error: "baseUrl must be http(s)" };
  }

  // Block obvious SSRF targets (Worker still reaches the public Internet only).
  const host = u.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return {
      ok: false,
      error: "baseUrl host looks local; use the public origin clients hit (through nginx)",
    };
  }

  return { ok: true, url: `${u.origin}${CHECK_PATH}` };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function cors(res) {
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Worker-Auth"
  );
  return new Response(res.body, { status: res.status, headers });
}
