"use strict";

/*
 * Cortex server
 * ---------------------------------------------------------------
 * Serves index.html + assets and proxies chat requests to NVIDIA
 * NIM. The API key stays on the server as NVIDIA_API_KEY, never in
 * the browser bundle.
 *
 *   NVIDIA_API_KEY=... node server.js
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

const MODELS = new Set([
  "meta/llama-3.2-90b-vision-instruct",
  "google/gemma-4-31b-it",
  "nvidia/nemotron-3.5-lightning-30b-a3b",
  "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning",
  "nvidia/nemotron-3.5-super-vl-120b-a12b",
  "mistralai/mistral-large-4-1t-a52b"
]);

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
    return json(res, 400, { error: { message: "Unknown or unsupported model." } });
  }

  if (!Array.isArray(payload.messages) || payload.messages.length === 0 || payload.messages.length > 64) {
    return json(res, 400, { error: { message: "messages must be a non-empty array." } });
  }

  const body = {
    model: payload.model,
    messages: payload.messages,
    max_tokens: clamp(payload.max_tokens, 16, 8192, 2048),
    temperature: clamp(payload.temperature, 0, 2, 0.65),
    top_p: clamp(payload.top_p, 0, 1, 0.95),
    stream: payload.stream !== false
  };

  /* Ask NVIDIA to send a final usage chunk while streaming, so the browser
     can show real prompt/completion token counts instead of guessing. */
  if (body.stream) body.stream_options = { include_usage: true };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 180000);

  let upstream;
  try {
    upstream = await fetch(`${UPSTREAM}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": body.stream ? "text/event-stream" : "application/json",
        "Authorization": `Bearer ${KEY}`
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
  } catch (err) {
    clearTimeout(timer);
    const timedOut = err && err.name === "AbortError";
    return json(res, timedOut ? 504 : 502, {
      error: { message: timedOut ? "NVIDIA took too long to respond." : "Could not reach NVIDIA NIM." }
    });
  }

  res.writeHead(upstream.status, {
    ...SECURITY_HEADERS,
    "Content-Type": upstream.headers.get("content-type") || "application/json",
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no"
  });

  if (!upstream.ok || !upstream.body) {
    const text = await upstream.text().catch(() => "");
    clearTimeout(timer);
    res.end(text || JSON.stringify({ error: { message: `NVIDIA returned HTTP ${upstream.status}` } }));
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

  if (!file.startsWith(rootPrefix)) {
    res.writeHead(403, { ...SECURITY_HEADERS, "Content-Type": "text/plain" });
    return res.end("forbidden");
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
  if (!KEY) console.warn("NVIDIA_API_KEY is not set - the AI tab will return 503.");
});
