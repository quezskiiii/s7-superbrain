// ============================================================================
// S7 Superbrain — Kalshi READ-ONLY Relay (Cloudflare Worker)
// ============================================================================
// What this is:
//   A tiny relay that lives in YOUR Cloudflare account. It holds your Kalshi
//   API credentials as Cloudflare secrets (never in this code, never in the
//   app, never in chat) and exposes exactly two read endpoints so the S7
//   Superbrain app can show your real Kalshi balance and your real record.
//
// What this can NEVER do:
//   There is no order code in this file at all — no POST/PUT/DELETE to
//   Kalshi, no order endpoint, nothing that can place, amend, or cancel a
//   trade. Every upstream call is a GET against a portfolio read endpoint.
//   Even a stolen relay token can only read balance / settlements / fills.
//
// Secrets (set in Cloudflare → Worker → Settings → Variables and Secrets):
//   KALSHI_KEY_ID      — your Kalshi API Key ID (the UUID, not the key itself)
//   KALSHI_PRIVATE_KEY — the full private-key PEM text you downloaded from
//                        Kalshi (RSA PKCS#8 or PKCS#1, or Ed25519 PKCS#8)
//   RELAY_TOKEN        — a long random string YOU invent (30+ chars). The app
//                        must send it as "Authorization: Bearer <RELAY_TOKEN>".
//
// Endpoints:
//   GET /health   → { ok: true }                                  (no auth)
//   GET /balance  → real cash balance + portfolio value           (auth)
//   GET /record   → win/loss record from settlements + last fills (auth)
//   GET /board/*  → PUBLIC Kalshi market data, proxied unchanged  (auth)
//                   e.g. /board/trade-api/v2/markets?... reads
//                   https://api.elections.kalshi.com/trade-api/v2/markets?...
//                   Token-gated like the rest, but NO Kalshi key is used or
//                   needed on this route — it works with only RELAY_TOKEN
//                   set, so the board bridge can be deployed before the
//                   read-only key exists. Allowlisted public paths only
//                   (markets / events / series); GET only.
//
// Signing follows docs.kalshi.com ("API Keys" / "Quick Start: Authenticated
// Requests"): message = timestamp_ms + METHOD + full path from /trade-api/v2
// (query string NOT signed); RSA keys sign with RSA-PSS / SHA-256 / MGF1
// SHA-256 / salt length = digest length (32); Ed25519 keys sign directly.
// ============================================================================

const KALSHI_BASE = "https://api.elections.kalshi.com";
const API_PREFIX = "/trade-api/v2";
const ALLOWED_ORIGIN = "https://quezskiiii.github.io";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function centsToDollars(cents) {
  return round2(Number(cents) / 100);
}

function bytesToBase64(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// Relay token check (constant-time over SHA-256 digests, so the compare does
// not leak the token through timing and never compares raw strings directly)
// ---------------------------------------------------------------------------

async function tokenOk(request, env) {
  const expected = env.RELAY_TOKEN;
  if (!expected) return false;
  const auth = request.headers.get("Authorization") || "";
  const provided = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  if (!provided) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(provided)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  const av = new Uint8Array(a);
  const bv = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < av.length; i++) diff |= av[i] ^ bv[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Kalshi private key handling
//
// Kalshi hands out two key types (docs.kalshi.com → API Keys):
//   - Ed25519 (the default in the Kalshi UI): PKCS#8 PEM, signs directly.
//   - RSA 2048-bit: Kalshi's download is PKCS#1 ("BEGIN RSA PRIVATE KEY");
//     RSA keys made elsewhere may be PKCS#8 ("BEGIN PRIVATE KEY").
// WebCrypto only imports PKCS#8, so a PKCS#1 RSA key is re-wrapped into a
// PKCS#8 envelope here. The PEM is accepted with real newlines or with
// literal "\n" escapes (which is how it often survives being pasted).
// ---------------------------------------------------------------------------

function normalizePem(pem) {
  return String(pem).replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\r\n/g, "\n").trim();
}

function pemToDer(pem) {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function derEncodeLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function derWrap(tag, content) {
  const len = derEncodeLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

// PKCS#1 RSAPrivateKey → PKCS#8 PrivateKeyInfo (rsaEncryption OID + NULL params)
function pkcs1ToPkcs8(pkcs1Der) {
  const version = new Uint8Array([0x02, 0x01, 0x00]); // INTEGER 0
  const algId = new Uint8Array([
    0x30, 0x0d, // SEQUENCE (13 bytes)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID 1.2.840.113549.1.1.1
    0x05, 0x00, // NULL
  ]);
  const privateKeyOctets = derWrap(0x04, pkcs1Der); // OCTET STRING
  return derWrap(0x30, concatBytes(version, algId, privateKeyOctets)); // SEQUENCE
}

let keyCache = null; // { source, key, type: "rsa" | "ed25519" }

async function importKalshiKey(env) {
  const raw = env.KALSHI_PRIVATE_KEY;
  if (!raw) throw new Error("missing_private_key");
  if (keyCache && keyCache.source === raw) return keyCache;

  const pem = normalizePem(raw);
  let der = pemToDer(pem);
  if (pem.indexOf("BEGIN RSA PRIVATE KEY") !== -1) {
    der = pkcs1ToPkcs8(der);
  }

  let imported = null;
  try {
    const key = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "RSASSA-PSS", hash: "SHA-256" },
      false,
      ["sign"]
    );
    imported = { source: raw, key, type: "rsa" };
  } catch (rsaErr) {
    // Not an RSA key — try Ed25519 (Kalshi's current default key type).
    const key = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
    imported = { source: raw, key, type: "ed25519" };
  }
  keyCache = imported;
  return imported;
}

async function signMessage(env, message) {
  const { key, type } = await importKalshiKey(env);
  const data = new TextEncoder().encode(message);
  let signature;
  if (type === "rsa") {
    signature = await crypto.subtle.sign({ name: "RSASSA-PSS", saltLength: 32 }, key, data);
  } else {
    signature = await crypto.subtle.sign({ name: "Ed25519" }, key, data);
  }
  return bytesToBase64(new Uint8Array(signature));
}

// ---------------------------------------------------------------------------
// Signed GET against Kalshi. The signature covers the path WITHOUT the query
// string; the query string is still sent on the URL. GET only — this relay
// has no code path that can send any other method upstream.
// ---------------------------------------------------------------------------

async function kalshiGet(env, pathWithQuery) {
  const signedPath = pathWithQuery.split("?")[0];
  const timestamp = Date.now().toString();
  const signature = await signMessage(env, timestamp + "GET" + signedPath);
  const res = await fetch(KALSHI_BASE + pathWithQuery, {
    method: "GET",
    headers: {
      "KALSHI-ACCESS-KEY": env.KALSHI_KEY_ID,
      "KALSHI-ACCESS-TIMESTAMP": timestamp,
      "KALSHI-ACCESS-SIGNATURE": signature,
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) throw new Error("upstream_status_" + res.status);
  return res.json();
}

// ---------------------------------------------------------------------------
// Response shaping
// ---------------------------------------------------------------------------

function shapeFill(f) {
  // Current docs: count_fp ("10.00") + yes/no_price_dollars ("0.5600").
  // Older responses used count (number) + yes/no_price (integer cents);
  // both shapes are handled so a schema drift cannot silently zero the data.
  let price = null;
  if (f.side === "no") {
    if (f.no_price_dollars != null) price = parseFloat(f.no_price_dollars);
    else if (f.no_price != null) price = Number(f.no_price) / 100;
  }
  if (price == null) {
    if (f.yes_price_dollars != null) price = parseFloat(f.yes_price_dollars);
    else if (f.yes_price != null) price = Number(f.yes_price) / 100;
  }
  let count = null;
  if (f.count_fp != null) count = parseFloat(f.count_fp);
  else if (f.count != null) count = Number(f.count);
  return {
    ticker: f.ticker,
    side: f.side,
    action: f.action,
    price_dollars: price == null || isNaN(price) ? null : round2(price),
    count: count == null || isNaN(count) ? null : count,
    created_time: f.created_time,
  };
}

async function handleBalance(env) {
  const data = await kalshiGet(env, API_PREFIX + "/portfolio/balance");
  const updatedIso =
    data.updated_ts != null
      ? new Date(Number(data.updated_ts) * 1000).toISOString()
      : new Date().toISOString();
  return json({
    ok: true,
    balance_dollars: centsToDollars(data.balance),
    portfolio_value_dollars: centsToDollars(data.portfolio_value),
    updated_iso: updatedIso,
  });
}

async function handleRecord(env) {
  const [settlementsData, fillsData] = await Promise.all([
    kalshiGet(env, API_PREFIX + "/portfolio/settlements?limit=100"),
    kalshiGet(env, API_PREFIX + "/portfolio/fills?limit=20"),
  ]);

  const settlementsRaw = Array.isArray(settlementsData.settlements) ? settlementsData.settlements : [];
  let wins = 0;
  let losses = 0;
  let pushes = 0;
  let netCents = 0;
  const settlements = settlementsRaw.map((s) => {
    const revenue = Number(s.revenue) || 0;
    netCents += revenue;
    if (revenue > 0) wins++;
    else if (revenue < 0) losses++;
    else pushes++;
    return {
      ticker: s.ticker,
      result: s.market_result,
      revenue_dollars: centsToDollars(revenue),
      settled_time: s.settled_time,
    };
  });

  const fillsRaw = Array.isArray(fillsData.fills) ? fillsData.fills : [];
  const fills = fillsRaw.map(shapeFill);

  return json({
    ok: true,
    wins,
    losses,
    pushes,
    net_dollars: centsToDollars(netCents),
    settlements,
    fills,
  });
}

// ---------------------------------------------------------------------------
// Board bridge — PUBLIC Kalshi market data, proxied unchanged.
//
// The app's browser is blocked by Kalshi's public API (Origin/CORS), so the
// board asks this Worker instead. This route NEVER signs anything and never
// touches the Kalshi key: it forwards a GET to a public market-data path
// and returns the upstream body byte-for-byte. Only the relay token gates
// it, so it works when RELAY_TOKEN is the only secret set.
// ---------------------------------------------------------------------------

const BOARD_PREFIX = "/board";
const BOARD_ALLOWLIST = ["/trade-api/v2/markets", "/trade-api/v2/events", "/trade-api/v2/series"];

async function handleBoard(request, env, url, path) {
  if (request.method !== "GET") {
    return json({ ok: false, error: "method_not_allowed" }, 405);
  }
  if (!env.RELAY_TOKEN) {
    return json({ ok: false, error: "relay_not_configured" }, 500);
  }
  const authed = await tokenOk(request, env).catch(() => false);
  if (!authed) {
    return json({ ok: false, error: "unauthorized" }, 401);
  }
  const subPath = path.slice(BOARD_PREFIX.length);
  const allowed = BOARD_ALLOWLIST.some(
    (p) => subPath === p || subPath.startsWith(p + "/") || subPath.startsWith(p + "?")
  );
  if (!allowed) {
    return json({ ok: false, error: "not_found" }, 404);
  }
  let upstream;
  try {
    upstream = await fetch(KALSHI_BASE + subPath + url.search, { method: "GET" });
  } catch (err) {
    return json({ ok: false, error: "upstream_error" }, 502);
  }
  const body = await upstream.text();
  const headers = {
    "Content-Type": upstream.headers.get("Content-Type") || "application/json",
    ...corsHeaders(),
  };
  return new Response(body, { status: upstream.status, headers });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (path === "/health") {
      return json({ ok: true });
    }

    if (path === BOARD_PREFIX || path.startsWith(BOARD_PREFIX + "/")) {
      return handleBoard(request, env, url, path);
    }

    if (path !== "/balance" && path !== "/record") {
      return json({ ok: false, error: "not_found" }, 404);
    }
    if (request.method !== "GET") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }

    if (!env.KALSHI_KEY_ID || !env.KALSHI_PRIVATE_KEY || !env.RELAY_TOKEN) {
      return json({ ok: false, error: "relay_not_configured" }, 500);
    }

    const authed = await tokenOk(request, env).catch(() => false);
    if (!authed) {
      return json({ ok: false, error: "unauthorized" }, 401);
    }

    try {
      if (path === "/balance") return await handleBalance(env);
      return await handleRecord(env);
    } catch (err) {
      // Generic on purpose: never leak upstream bodies, headers, or secrets.
      return json({ ok: false, error: "upstream_error" }, 502);
    }
  },
};
