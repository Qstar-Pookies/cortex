"use strict";

/*
 * Cortex server
 * ---------------------------------------------------------------
 * Serves index.html + assets and proxies chat requests to NVIDIA
 * NIM. The API key stays on the server as NVIDIA_API_KEY, never in
 * the browser bundle.
 *
 *   NVIDIA_API_KEY=... node server.js
 *
 * Models can be overridden without editing this file:
 *   NVIDIA_MODELS="nvidia/model-a,deepseek-ai/model-b"
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 8080);
const ROOT = __dirname;

/* Secrets are easy to paste wrong: quotes, a trailing newline, a truncated
   value, or the literal "nvapi-..." placeholder from the README. Normalise
   what we can and expose a harmless fingerprint so the health check can
   tell you whether the server is holding the exact same key you tested. */
const RAW_KEY = process.env.NVIDIA_API_KEY || "";
const KEY = RAW_KEY.trim().replace(/^["']+|["']+$/g, "").trim();

const UPSTREAM = (process.env.NVIDIA_BASE_URL || "https://integrate.api.nvidia.com/v1").replace(/\/+$/, "");

/* The allow-list MUST match the model ids the browser (index.html) sends.
   Override with NVIDIA_MODELS if your NVIDIA account exposes different ids. */
const DEFAULT_MODELS = [
  "nvidia/nemotron-3-ultra-550b-a55b",
   "moonshotai/kimi-k3"
   
];
const MODELS = new Set(
  (process.env.NVIDIA_MODELS
    ? process.env.NVIDIA_MODELS.split(",").map(s => s.trim()).filter(Boolean)
    : DEFAULT_MODELS)
);

/* Once we learn an endpoint rejects stream_options, stop sending it so every
   later request streams cleanly instead of failing then retrying. */
let dropStreamOptions = false;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2"
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-Frame-Options": "DENY"
};

const CSP = [
  "default-src 'self'",
  "img-src 'self' data: blob:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline'",
  "connect-src 'self' https://api.github.com https://data.jsdelivr.com https://raw.githubusercontent.com",
  "font-src 'self' data:",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join("; ");

const BODY_LIMIT = 30 * 1024 * 1024;
const RATE_WINDOW = 60 * 1000;
const RATE_MAX = 60;
const rateHits = new Map();

function keyReport() {
  return {
    present: Boolean(KEY),
    length: KEY.length,
    prefixOk: KEY.startsWith("nvapi-"),
    placeholder: KEY === "nvapi-..." || KEY === "nvapi-",
    hadWhitespace: RAW_KEY !== RAW_KEY.trim(),
    hadQuotes: RAW_KEY.trim() !== RAW_KEY.trim().replace(/^["']+|["']+$/g, ""),
    fingerprint: KEY
      ? crypto.createHash("sha256").update(KEY).digest("hex").slice(0, 8)
      : null
  };
}

function json(res, status, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extra
  });
  res.end(body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on("data", chunk => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error("request too large"), { status: 413 }));
        req.removeAllListeners("data");
        req.resume();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function clientIp(req) {
  return String(
    req.headers["fly-client-ip"] ||
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function isLimited(ip) {
  const now = Date.now();
  let hit = rateHits.get(ip);
  if (!hit || now > hit.reset) {
    hit = { count: 0, reset: now + RATE_WINDOW };
    rateHits.set(ip, hit);

    if (rateHits.size > 5000) {
      for (const [k, v] of rateHits) if (now > v.reset) rateHits.delete(k);
    }
  }
  hit.count += 1;
  return hit.count > RATE_MAX;
}

function clamp(value, lo, hi, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, n));
}

/* NVIDIA NIM is strict about message shape and will answer a malformed
   request with a generic "Error in input stream". Normalise before sending:
   valid roles only, string or multimodal content, no empty turns, and no two
   turns of the same role in a row (which some models reject). */
function sanitizeMessages(list) {
  const out = [];

  for (const m of list) {
    if (!m || typeof m !== "object") continue;

    const role = m.role === "assistant" ? "assistant"
      : m.role === "system" ? "system"
      : "user";

    let content = m.content;

    if (Array.isArray(content)) {
      const parts = content.filter(p =>
        p && (
          (p.type === "text" && typeof p.text === "string") ||
          (p.type === "image_url" && p.image_url && typeof p.image_url.url === "string")
        ));
      if (!parts.length) continue;
      content = parts;
    } else {
      content = typeof content === "string" ? content : content == null ? "" : String(content);
      if (!content.trim() && role !== "system") continue;
    }

    const prev = out[out.length - 1];
    if (prev && prev.role === role && typeof prev.content === "string" && typeof content === "string") {
      prev.content = `${prev.content}\n\n${content}`;       /* merge same-role turns */
    } else {
      out.push({ role, content });
    }
  }

  /* the first non-system message must be from the user */
  let i = 0;
  while (i < out.length && out[i].role === "system") i++;
  while (i < out.length && out[i].role === "assistant") out.splice(i, 1);

  return out;
}

function normalizeErr(text, status) {
  const t = String(text || "").trim();
  if (!t) return `NVIDIA returned HTTP ${status}.`;
  try {
    const j = JSON.parse(t);
    const e = j.error;
    const msg = (typeof e === "string" ? e : (e && (e.message || e.detail || e.msg))) ||
      j.detail || j.message || j.title || j.msg;
    if (msg) return String(msg).slice(0, 600);
  } catch {}
  return t.slice(0, 600);
}

function callUpstream(body, signal) {
  return fetch(`${UPSTREAM}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": body.stream ? "text/event-stream" : "application/json",
      "Authorization": `Bearer ${KEY}`
    },
    body: JSON.stringify(body),
    signal
  });
}

/* Try the request, and if the endpoint rejects it, escalate automatically:
   1) as sent (streaming, with usage reporting)
   2) streaming, without stream_options
   3) non-streaming, without stream_options
   The browser handles either a stream or a plain JSON reply, so the user gets
   an answer instead of "Error in input stream". */
async function requestUpstream(baseBody, signal) {
  const attempts = [{ ...baseBody }];
  if (baseBody.stream && baseBody.stream_options) {
    const b = { ...baseBody };
    delete b.stream_options;
    attempts.push(b);
  }
  if (baseBody.stream) {
    const b = { ...baseBody, stream: false };
    delete b.stream_options;
    attempts.push(b);
  }

  let resp = null, lastErr = "", status = 502;

  for (let i = 0; i < attempts.length; i++) {
    const r = await callUpstream(attempts[i], signal);     /* network errors bubble up */
    if (r.ok) {
      if (i >= 1) dropStreamOptions = true;                /* stream_options was the problem */
      return { resp: r, body: attempts[i], ok: true };
    }
    status = r.status;
    lastErr = await r.text().catch(() => "");
    resp = r;
  }

  return { resp, body: attempts[attempts.length - 1], ok: false, lastErr, status };
}

async function chat(req, res) {
  if (!KEY) {
    return json(res, 503, {
      error: {
        message: "NVIDIA_API_KEY is not set on the server. Run: fly secrets set NVIDIA_API_KEY=..."
      }
    });
  }

  if (isLimited(clientIp(req))) {
    return json(res, 429, {
      error: { message: "Too many messages in a short time. Wait a minute and try again." }
    }, { "Retry-After": "60" });
  }

  let payload;
  try {
    const raw = await readBody(req, BODY_LIMIT);
    payload = JSON.parse(raw);
  } catch (err) {
    return json(res, err && err.status ? err.status : 400, {
      error: { message: err && err.status === 413 ? "Attachment is too large." : "Invalid JSON body." }
    });
  }

  if (!payload || !MODELS.has(payload.model)) {
    return json(res, 400, {
      error: {
        message: `Unknown or unsupported model${payload && payload.model ? ` "${payload.model}"` : ""}. ` +
          `Allowed: ${[...MODELS].join(", ")}.`
      }
    });
  }

  const messages = sanitizeMessages(Array.isArray(payload.messages) ? payload.messages : []);
  if (!messages.length || messages.length > 64) {
    return json(res, 400, { error: { message: "messages must be a non-empty, well-formed array." } });
  }

  const body = {
    model: payload.model,
    messages,
    max_tokens: clamp(payload.max_tokens, 16, 8192, 2048),
    temperature: clamp(payload.temperature, 0, 2, 0.65),
    top_p: clamp(payload.top_p, 0, 1, 0.95),
    stream: payload.stream !== false
  };

  /* Ask NVIDIA to send a final usage chunk while streaming, so the browser
     can show real token counts. Skipped once we learn it isn't supported. */
  if (body.stream && !dropStreamOptions) body.stream_options = { include_usage: true };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 180000);

  let result;
  try {
    result = await requestUpstream(body, controller.signal);
  } catch (err) {
    clearTimeout(timer);
    const timedOut = err && err.name === "AbortError";
    return json(res, timedOut ? 504 : 502, {
      error: { message: timedOut ? "NVIDIA took too long to respond." : "Could not reach NVIDIA NIM." }
    });
  }

  if (!result.ok) {
    clearTimeout(timer);
    return json(res, result.status || 502, {
      error: { message: normalizeErr(result.lastErr, result.status || 502) }
    });
  }

  const upstream = result.resp;

  res.writeHead(upstream.status, {
    ...SECURITY_HEADERS,
    "Content-Type": upstream.headers.get("content-type") || "application/json",
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no"
  });

  if (!upstream.body) {
    clearTimeout(timer);
    res.end();
    return;
  }

  const onClose = () => {
    if (!res.writableEnded) controller.abort();
  };
  res.on("close", onClose);

  try {
    for await (const chunk of upstream.body) {
      if (!res.write(chunk)) {
        await new Promise(resolve => res.once("drain", resolve));
      }
    }
    res.end();
  } catch (err) {
    if (!res.writableEnded) res.end();
  } finally {
    clearTimeout(timer);
    res.removeListener("close", onClose);
  }
}

async function serveStatic(req, res, pathname) {
  let rel;
  try {
    rel = decodeURIComponent(pathname);
  } catch {
    res.writeHead(400, { ...SECURITY_HEADERS, "Content-Type": "text/plain" });
    return res.end("bad path");
  }

  if (rel.endsWith("/")) rel += "index.html";
  if (rel === "/") rel = "/index.html";

  const file = path.normalize(path.join(ROOT, rel));
  const rootPrefix = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;
  const dataRoot = path.join(ROOT, "data");
  const dataPrefix = dataRoot + path.sep;

  if (!file.startsWith(rootPrefix)) {
    res.writeHead(403, { ...SECURITY_HEADERS, "Content-Type": "text/plain" });
    return res.end("forbidden");
  }

  if (file === dataRoot || file.startsWith(dataPrefix)) {
    res.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" });
    return res.end("not found");
  }

  let stat;
  try {
    stat = await fs.promises.stat(file);
  } catch {
    res.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" });
    return res.end("not found");
  }

  if (!stat.isFile()) {
    res.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" });
    return res.end("not found");
  }

  const ext = path.extname(file).toLowerCase();
  const isHtml = ext === ".html";
  const headers = {
    ...SECURITY_HEADERS,
    "Content-Type": MIME[ext] || "application/octet-stream",
    "Content-Length": stat.size,
    "Cache-Control": isHtml ? "no-store" : "public, max-age=3600"
  };

  if (isHtml) headers["Content-Security-Policy"] = CSP;

  res.writeHead(200, headers);
  if (req.method === "HEAD") return res.end();

  const stream = fs.createReadStream(file);
  stream.on("error", () => res.end());
  stream.pipe(res);
}

const server = http.createServer(async (req, res) => {
  const started = Date.now();
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;

  try {
    if (req.method === "GET" && pathname === "/healthz") {
      return json(res, 200, { ok: true });
    }

    if (req.method === "GET" && pathname === "/api/health") {
      return json(res, 200, {
        ok: Boolean(KEY),
        configured: Boolean(KEY),
        key: keyReport(),
        models: [...MODELS]
      });
    }

    if (pathname === "/api/chat") {
      if (req.method !== "POST") return json(res, 405, { error: { message: "POST only." } });
      return await chat(req, res);
    }

    if (req.method === "GET" || req.method === "HEAD") {
      return await serveStatic(req, res, pathname);
    }

    json(res, 405, { error: { message: "Method not allowed." } });
  } catch (err) {
    if (!res.headersSent) {
      json(res, 500, { error: { message: "Server error." } });
    } else {
      try { res.end(); } catch {}
    }
  } finally {
    if (pathname === "/api/chat") {
      const ms = Date.now() - started;
      console.log(`POST /api/chat ${res.statusCode} ${ms}ms`);
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Cortex on http://0.0.0.0:${PORT}`);
  console.log(`Models: ${[...MODELS].join(", ")}`);
  if (!KEY) console.warn("NVIDIA_API_KEY is not set - the AI tab will return 503.");
});
