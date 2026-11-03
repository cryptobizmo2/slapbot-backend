/**
 * BIG MOUF SLAPBOT — Personal Backend
 * ─────────────────────────────────────────────────────────────────────────
 * Purpose: lock the bot to ONE wallet (yours) by checking your SLAP GOLD
 * token balance directly on Solana. No login, no password — just your
 * connected wallet and your token.
 *
 * Security model:
 *   - This server NEVER holds private keys or funds.
 *   - It only reads public blockchain data (anyone could look this up
 *     manually on Solscan — this just automates the check).
 *   - Real trades are signed by YOUR wallet (Phantom) on the frontend,
 *     never by this server.
 *
 * Deploy: Railway, Render, or any Node host. See DEPLOY.md.
 */

/**
 * PROXY MODE (Railway only). When the variable PROXY_TO is set, this whole file turns into a tiny
 * forwarder: every request is passed straight to the real server (AWS) and the answer comes back
 * unchanged. Old links and the scanner keep working on the Railway address, and Railway stops
 * doing any background work of its own. AWS never sets PROXY_TO, so it runs the full bot below.
 * The forwarder proves itself to AWS with a key derived from CG_API_KEY (both servers have it),
 * so AWS can rate-limit each real visitor separately instead of lumping everyone together.
 */
if (process.env.PROXY_TO) {
  const http = require("http"), cryptoP = require("crypto");
  const target = String(process.env.PROXY_TO).replace(/\/+$/, "");
  const proof = cryptoP.createHash("sha256").update("slapbot-proxy:" + String(process.env.CG_API_KEY || "")).digest("hex");
  const DROP = new Set(["host", "connection", "content-length", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection", "te", "trailer"]);
  http.createServer((req, res) => {
    const chunks = []; let size = 0;
    req.on("data", (c) => { size += c.length; if (size > 64 * 1024) { res.writeHead(413).end(); req.destroy(); } else chunks.push(c); });
    req.on("end", async () => {
      try {
        const headers = {};
        for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k.toLowerCase()) && !k.toLowerCase().startsWith("x-slapbot")) headers[k] = v;
        const xff = String(req.headers["x-forwarded-for"] || "").split(",").map((x) => x.trim()).filter(Boolean);
        headers["x-slapbot-proxy"] = proof;
        headers["x-slapbot-client"] = xff[xff.length - 1] || req.socket.remoteAddress || "";
        const r = await fetch(target + req.url, { method: req.method, headers, redirect: "manual",
          body: ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.concat(chunks), signal: AbortSignal.timeout(30000) });
        const out = {};
        r.headers.forEach((v, k) => { if (!["content-encoding", "content-length", "transfer-encoding", "connection"].includes(k)) out[k] = v; });
        const body = Buffer.from(await r.arrayBuffer());
        res.writeHead(r.status, out); res.end(body);
      } catch (e) {
        res.writeHead(502, { "content-type": "application/json", "access-control-allow-origin": "*" });
        res.end(JSON.stringify({ error: "The main server didn't answer. Try again in a moment." }));
      }
    });
  }).listen(process.env.PORT || 3000, () => console.log(`[proxy] forwarding everything to ${target}`));
  return;   // stop here: nothing below runs in proxy mode
}

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { Connection, PublicKey } = require("@solana/web3.js");
const crypto = require("crypto");
const zlib = require("zlib");

const app = express();
const PORT = process.env.PORT || 3000;

// Railway terminates TLS at a single reverse proxy and forwards the real
// client IP in X-Forwarded-For. Without this, req.ip is the PROXY's IP, so
// every user on earth shares one rate-limit bucket — the limiter becomes
// global and blocks everyone once it fills. Trust exactly ONE hop (not
// 'true'), so a client can't forge its own IP to dodge the limit.
app.set("trust proxy", 1);
// Requests forwarded by our own Railway proxy carry a proof key: use the real visitor's address for them.
const PROXY_PROOF = process.env.CG_API_KEY ? crypto.createHash("sha256").update("slapbot-proxy:" + process.env.CG_API_KEY).digest("hex") : null;
app.use((req, res, next) => {
  const p = req.headers["x-slapbot-proxy"];
  if (PROXY_PROOF && typeof p === "string" && p.length === PROXY_PROOF.length &&
      crypto.timingSafeEqual(Buffer.from(p), Buffer.from(PROXY_PROOF))) {
    const c = String(req.headers["x-slapbot-client"] || "").slice(0, 64);
    if (c) Object.defineProperty(req, "ip", { value: c, configurable: true });
  }
  next();
});

// ── config from environment (set these in Railway/Render dashboard) ───────
// Connections you set from the dashboard (a faster RPC such as Helius, the Telegram bot) live in one private file on the server's disk.
const CONN_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || "";
const CONN_FILE = CONN_DIR ? require("path").join(CONN_DIR, "connections.json") : "";
let CONN = {};
try { if (CONN_FILE && require("fs").existsSync(CONN_FILE)) CONN = JSON.parse(require("fs").readFileSync(CONN_FILE, "utf8")) || {}; } catch {}
function saveConn() { if (!CONN_FILE) return false; try { const fs = require("fs"), t = CONN_FILE + ".tmp"; fs.writeFileSync(t, JSON.stringify(CONN), { mode: 0o600 }); fs.renameSync(t, CONN_FILE); return true; } catch { return false; } }
const SOLANA_RPC_URL = CONN.rpcUrl || process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const SLAPGOLD_MINT = process.env.SLAPGOLD_MINT; // e.g. 4R7Hbdhh3YeVqZaESRA3qPJ8Z3xh3Qedsw88RDjxL1Q9
// The owner wallet. Set here (it's a public address, not a secret) so it can be changed with a normal upload,
// without touching the server's settings file. It wins over the MY_WALLET setting.
const BUILD_ID = "2026-11-03 · FUFLOPBOT · V1.2 · Analyst: a birth record for every launch, top-20 tracking, /analyst /top20 /birth · Winner Lab counts finished launches only";            // shown on the dashboard and the health page: it tells you which version is running
const OWNER_WALLET = "4t3F4TvCsRCohYJ3EZ4B2ahaN2nN5kBE3A8WUVy2K1CF";
const MY_WALLET = OWNER_WALLET || process.env.MY_WALLET;   // YOUR wallet address — the only one allowed in
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*"; // lock to your GitHub Pages URL once live
const MIN_HOLD_AMOUNT = parseFloat(process.env.MIN_HOLD_AMOUNT || "1"); // min SLAP GOLD to unlock

// ── Exclusive-page gate: which token opens it, and how much you must hold ──
// Defaults to your main token. Change either one in Railway → Variables,
// no code upload needed. Pump.fun tokens have ~1B supply, so hold "1" would
// cost a fraction of a cent — set GATE_MIN_HOLD to a meaningful amount.
const MAIN_TOKEN = "9pn9N3S3QQUfkWpDzw98Jags6eWeSyti42DvHAsmpump";
let GATE_MINT = (process.env.GATE_MINT || MAIN_TOKEN).trim();
try { new PublicKey(GATE_MINT); }
catch { console.error(`[WARN] GATE_MINT "${GATE_MINT}" is not a valid address — using main token`); GATE_MINT = MAIN_TOKEN; }
// Holder Key fallback: used ONLY when the live price can't be read
const GATE_MIN_HOLD = parseFloat(process.env.GATE_MIN_HOLD || "1000000");

// ── Two keys to Exclusive — either one opens it ──
//  🥇 Gold Key   hold GOLD_MIN_HOLD of the scarce $SLAPGOLD (10,000 exist → 2,000 keys at 5 each)
//  🔑 Holder Key hold GATE_MIN_USD dollars of the main token. Pegged to dollars because a meme
//                coin's price swings — a fixed count would cost $250 one month and pennies the next.
let GOLD_MINT = (process.env.GOLD_MINT || SLAPGOLD_MINT).trim();
try { new PublicKey(GOLD_MINT); } catch { console.error(`[WARN] GOLD_MINT invalid — using SLAPGOLD_MINT`); GOLD_MINT = SLAPGOLD_MINT; }
const GOLD_MIN_HOLD = parseFloat(process.env.GOLD_MIN_HOLD || "5");
const GATE_MIN_USD = parseFloat(process.env.GATE_MIN_USD || "25");
if (GATE_MINT === GOLD_MINT) console.error("[WARN] GATE_MINT equals GOLD_MINT — both keys use one token; remove GATE_MINT to use the main token");

if (!SLAPGOLD_MINT) {
  console.error("[FATAL] SLAPGOLD_MINT env var not set. Server cannot start.");
  process.exit(1);
}

/** Every request to the chain is counted, so you can see (and cap) how much of a metered plan you use. */
const RPC = { day: "", n: 0, month: "", monthN: 0, by: {} };
function rpcCount(init) {
  const d = new Date().toISOString().slice(0, 10), m = d.slice(0, 7);
  if (RPC.day !== d) { RPC.day = d; RPC.n = 0; RPC.by = {}; } if (RPC.month !== m) { RPC.month = m; RPC.monthN = 0; }
  RPC.n++; RPC.monthN++;
  try { const j = JSON.parse(init && init.body); const k = Array.isArray(j) ? "batch" : j.method; RPC.by[k] = (RPC.by[k] || 0) + 1; } catch {}
}
/** Background research slows down (never trading) once the daily cap you set is used up. */
const rpcBudgetOk = () => !(CONN.rpcDailyCap > 0) || RPC.n < CONN.rpcDailyCap;
const connection = new Connection(SOLANA_RPC_URL, { commitment: "confirmed", fetchMiddleware: (info, init, go) => { rpcCount(init); go(info, init); } });

// ── middleware ──────────────────────────────────────────────────────────
// ── Security hardening ──────────────────────────────────────────────────
app.disable("x-powered-by");                      // don't advertise the framework

/** This server only ever returns JSON, so lock browsers down accordingly. */
function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  if (req.path.startsWith("/api/auth") || req.path.startsWith("/api/exclusive") || req.path.startsWith("/api/smart")) res.setHeader("Cache-Control", "no-store");
  next();
}
app.use(securityHeaders);

// CORS allowlist — comma-separated, e.g. "https://cryptobizmo2.github.io,https://bigmoufslapbot.com"
const ALLOWED_ORIGINS = String(ALLOWED_ORIGIN).split(",").map((o) => o.trim()).filter(Boolean);
app.use(cors({
  origin: ALLOWED_ORIGINS.includes("*") ? "*" : ALLOWED_ORIGINS,
  // let the security self-scan read these from the browser
  exposedHeaders: ["X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy",
                   "Strict-Transport-Security", "RateLimit-Limit", "RateLimit-Remaining"],
}));
// Only one route takes a body ({wallet, signature}); 8 KB is generous. Objects/arrays only.
app.use(express.json({ limit: "8kb", strict: true }));

// Per-user now (thanks to trust proxy). A live dashboard + armed Micro Bot
// + scans legitimately runs ~10-20 req/min, so 30 left no headroom.
// The risk engine asks this same server for token data. Those internal calls come from
// the machine itself, never through Railway's proxy, so outsiders can't fake them.
const isLoopback = (req) => ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket?.remoteAddress) && !req.headers["x-forwarded-for"];
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/api/health" || isLoopback(req),
  message: { error: "Rate limit exceeded. Slow down." },
});
app.use(limiter);
app.use("/api/auth", rateLimit({ windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Wait a minute." } }));
app.use("/api/claim", rateLimit({ windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many attempts. Wait a minute." } }));
app.use("/api/lowsupply", rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many requests. Slow down." } }));
app.use(["/api/token", "/api/mint-check"], rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true,
  legacyHeaders: false, skip: isLoopback, message: { error: "Too many lookups. Slow down." } }));
app.use("/api/risk", rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many scans. Wait a minute." } }));

function log(type, msg) {
  console.log(`[${new Date().toISOString()}] [${type.toUpperCase()}] ${msg}`);
}

/**
 * Core on-chain check, shared by /api/mint-check and /api/scan.
 * Reads the SPL token mint account directly from Solana.
 *   mintAuthority present   = dev can print unlimited new supply (red flag)
 *   freezeAuthority present = dev can freeze YOUR wallet's tokens (red flag)
 * Also pulls top-10 holder concentration via getTokenLargestAccounts
 * (built into Solana RPC — no third-party API key required).
 */
// Public Solana RPC can hang for 30s+ on getTokenLargestAccounts for tokens
// with huge holder counts (e.g. BONK). Never let one slow call stall a scan.
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label + " timed out after " + ms + "ms")), ms)),
  ]);
}

/**
 * Market-data gate. The free market-data service allows roughly 30 calls a minute per server.
 * Every call goes through here: what users are looking at goes first, background learning only
 * uses what's left (it keeps 8 slots free for users), and if the service says "slow down" (429)
 * the background backs off for a minute instead of making things worse.
 */
// With a free CoinGecko Demo key (Railway variable CG_API_KEY) the same data comes through CoinGecko's
// /onchain doorway with ~30 calls a minute that belong to YOU. Without a key, every app on Railway's shared
// address competes for ~10 calls a minute, which is why pools went to "fallback".
const CG_API_KEY = String(process.env.CG_API_KEY || "").trim();
const CG_PRO = /^pro$/i.test(String(process.env.CG_PLAN || ""));
const CG_BASE = CG_PRO ? "https://pro-api.coingecko.com/api/v3/onchain" : "https://api.coingecko.com/api/v3/onchain";
// On a server with its own address (AWS) the free doorway gives ~30 calls a minute that are ours alone.
// The free CoinGecko Demo key also caps at about 10,000 calls a MONTH, which a busy bot burns in hours,
// so the key is now the backup: used only when the free doorway says "slow down", and capped per day.
const OWN_IP = !process.env.RAILWAY_ENVIRONMENT && !process.env.RAILWAY_PROJECT_ID;
const GT_PER_MIN = Math.max(5, parseInt(process.env.GT_PER_MIN || (CG_PRO ? "450" : OWN_IP ? "26" : CG_API_KEY ? "28" : "9"), 10));
const KEY_PER_DAY = Math.max(0, parseInt(process.env.CG_KEY_PER_DAY || (CG_PRO ? "100000" : "300"), 10));
let keyDay = { day: "", n: 0 };
function keyAllowed() {
  const d = new Date().toISOString().slice(0, 10);
  if (keyDay.day !== d) keyDay = { day: d, n: 0 };
  return CG_API_KEY && keyDay.n < KEY_PER_DAY;
}
let gtTimes = [], gtBackoffUntil = 0;
const gtStats = { ok: 0, limited: 0, failed: 0, skipped: 0, last429: null };
async function gtFetch(url, prio = "user") {
  const reserve = prio === "user" ? 0 : Math.ceil(GT_PER_MIN * 0.35), start = Date.now();   // ~35% always kept for people
  for (;;) {
    const now = Date.now();
    gtTimes = gtTimes.filter((t) => now - t < 60000);
    if (prio !== "user" && now < gtBackoffUntil) { gtStats.skipped++; throw new Error("market data cooling down"); }
    if (gtTimes.length < GT_PER_MIN - reserve) break;
    if (prio !== "user") { gtStats.skipped++; throw new Error("market data budget in use"); }
    if (now - start > 6000) break;                    // a user never waits more than ~6 s
    await new Promise((r) => setTimeout(r, 300));
  }
  gtTimes.push(Date.now());
  let r;
  const keyed = () => { keyDay.n++; gtStats.keyCalls = (gtStats.keyCalls || 0) + 1;
    return fetch(url.replace("https://api.geckoterminal.com/api/v2", CG_BASE), { headers: { accept: "application/json", [CG_PRO ? "x-cg-pro-api-key" : "x-cg-demo-api-key"]: CG_API_KEY } }); };
  if (CG_PRO || (!OWN_IP && keyAllowed())) {
    r = await keyed();                                              // paid plan, or no address of our own: key first
    if ([401, 403, 404, 429].includes(r.status)) r = await fetch(url, { headers: { accept: "application/json" } });
  } else {
    r = await fetch(url, { headers: { accept: "application/json" } });   // our own address: free doorway first
    if (r.status === 429 && keyAllowed()) { const k = await keyed(); if (k.ok) r = k; }   // key only as backup
  }
  if (r.status === 429) { gtStats.limited++; gtStats.last429 = Date.now(); gtBackoffUntil = Date.now() + 60000; throw new Error("GeckoTerminal 429"); }
  if (!r.ok) { gtStats.failed++; throw new Error("GeckoTerminal " + r.status); }
  gtStats.ok++;
  return r;
}

// Authority + holder data changes slowly — cache it so repeat scans are instant.
const mintCache = new Map();
const MINT_TTL = 5 * 60 * 1000;

/** An RPC error message, safe to show anywhere: RPC addresses (which can carry an API key) are removed. */
function rpcErrSafe(e) { return String((e && e.message) || e || "").replace(/https?:\/\/[^\s"'<>)]+/gi, "[rpc address hidden]").replace(/(api[-_]?key|token|secret)=([^\s&"']+)/gi, "$1=[hidden]").slice(0, 160); }
async function getMintCheck(address, opts = {}) {
  const cached = mintCache.get(address);
  if (cached && Date.now() - cached.ts < MINT_TTL && (opts.holders === false || cached.data.holdersTried)) return cached.data;
  try {
    const mintPubkey = new PublicKey(address);
    const info = await withTimeout(connection.getParsedAccountInfo(mintPubkey), 6000, "getParsedAccountInfo");

    if (!info.value || info.value.data.parsed?.type !== "mint") {
      return { error: "Not a valid SPL token mint", found: false };
    }

    const parsed = info.value.data.parsed.info;
    const mintAuthority = parsed.mintAuthority || null;
    const freezeAuthority = parsed.freezeAuthority || null;
    const supply = Number(parsed.supply) / Math.pow(10, parsed.decimals);

    // Two concentration figures:
    //   top10Pct       — every account, including pools and bonding curves
    //   top10WalletPct — only accounts owned by real wallets
    // A pump.fun bonding curve (or an AMM pool) is usually the single largest
    // "holder", but it's a program, not a whale. Counting it would flag nearly
    // every pre-graduation token as 90%+ concentrated. Wallets are points on
    // the Ed25519 curve; program-derived addresses are deliberately off it —
    // that is exactly how Solana tells the two apart.
    let top10Pct = null, top10WalletPct = null, top1WalletPct = null; const topOwners = [];
    if (opts.holders !== false) try {                       // skipped when the live feed already counted the holders exactly
      const largest = await withTimeout(connection.getTokenLargestAccounts(mintPubkey), 5000, "getTokenLargestAccounts");
      const top = largest.value.slice(0, 20);
      const top10Sum = top.slice(0, 10).reduce((s, acc) => s + (acc.uiAmount || 0), 0);
      top10Pct = supply > 0 ? (top10Sum / supply) * 100 : null;
      try {
        const infos = await withTimeout(connection.getMultipleParsedAccounts(top.map((a) => a.address)), 5000, "holder owners");
        let walletSum = 0, counted = 0;
        top.forEach((a, i) => {
          const owner = infos.value[i]?.data?.parsed?.info?.owner;
          if (!owner || counted >= 10) return;
          if (PublicKey.isOnCurve(new PublicKey(owner).toBytes())) {
            if (!counted && supply > 0) top1WalletPct = ((a.uiAmount || 0) / supply) * 100;   // largest real wallet
            if (supply > 0) topOwners.push({ owner, pct: +(((a.uiAmount || 0) / supply) * 100).toFixed(2) });
            walletSum += a.uiAmount || 0; counted++; }
        });
        top10WalletPct = supply > 0 ? (walletSum / supply) * 100 : null;
      } catch (e) {
        log("error", `holder owner lookup failed for ${address}: ${e.message}`);
      }
    } catch (e) {
      log("error", `getTokenLargestAccounts failed for ${address}: ${e.message}`);
      if (typeof HOLDDIAG !== "undefined") { HOLDDIAG.rpcFails++; HOLDDIAG.rpcErr = rpcErrSafe(e); HOLDDIAG.rpcErrAt = Date.now(); }
    }

    const result = {
      found: true,
      mintAuthority,
      mintAuthorityRenounced: !mintAuthority,
      freezeAuthority,
      freezeAuthorityRenounced: !freezeAuthority,
      supply,
      decimals: parsed.decimals,
      top10HolderPct: top10Pct !== null ? parseFloat(top10Pct.toFixed(2)) : null,
      top10WalletPct: top10WalletPct !== null ? parseFloat(top10WalletPct.toFixed(2)) : null,
      top1WalletPct: top1WalletPct !== null ? parseFloat(top1WalletPct.toFixed(2)) : null, topOwners, holdersTried: opts.holders !== false,
      criticalHoneypot: !!freezeAuthority,
    };

    if (result.criticalHoneypot) {
      log("flagged_rug", `${address.slice(0, 8)}... → FREEZE AUTHORITY ENABLED — honeypot risk`);
    } else {
      log("audit", `${address.slice(0, 8)}... → mint:${result.mintAuthorityRenounced ? "renounced" : "ACTIVE"} top10:${result.top10HolderPct}%`);
    }
    mintCache.set(address, { data: result, ts: Date.now() });
    if (mintCache.size > 2000) mintCache.delete(mintCache.keys().next().value);
    return result;
  } catch (err) {
    log("error", `mint-check failed for ${address}: ${err.message}`);
    return { error: "Invalid mint address or RPC error", found: false };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ③ TOKEN SCANNER — market data + real on-chain rug checks
// ═══════════════════════════════════════════════════════════════════════

/**
 * GET /api/mint-check/:address
 * Reads the SPL token mint account directly from Solana.
 * mintAuthority present  = dev can print unlimited new supply (red flag)
 * freezeAuthority present = dev can freeze YOUR wallet's tokens (red flag)
 * Also pulls top-10 holder concentration from the largest token accounts.
 */
app.get("/api/mint-check/:address", async (req, res) => {
  try { if (b58decode(String(req.params.address)).length !== 32) throw 0; }
  catch { return res.status(400).json({ error: "Invalid token address" }); }
  const result = await getMintCheck(req.params.address);
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

// ═══════════════════════════════════════════════════════════════════════
// ⑦ HOLDER-GATED EXCLUSIVE — proof of ownership + live balance check
// ═══════════════════════════════════════════════════════════════════════
/**
 * Why a signature: checking the balance of an address someone *types in*
 * proves nothing — anyone could paste a whale's address. Signing a message
 * proves they control the wallet. Signing is free, sends no transaction and
 * cannot move funds.
 *
 * Why the data lives here: the site is a public GitHub repo, so anything
 * "hidden" in the page can be read by anyone. Exclusive data is only ever
 * handed to a valid, signed session.
 *
 * Uses only Node's built-in crypto (Ed25519 + HMAC) — no extra npm packages.
 */

// Base58 (the alphabet Solana uses for addresses)
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(str) {
  if (typeof str !== "string" || !str.length) throw new Error("empty");
  if (str.length > 64) throw new Error("too long");   // addresses are ≤44 chars; refuse giant inputs cheaply
  let n = 0n;
  for (const ch of str) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error("invalid base58");
    n = n * 58n + BigInt(v);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let lead = 0;
  for (const ch of str) { if (ch === "1") lead++; else break; }
  return Buffer.concat([Buffer.alloc(lead), body]);
}

// A Solana address IS an Ed25519 public key. Wrap its 32 raw bytes in the
// standard SPKI header so Node's crypto can verify signatures against it.
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
function verifySolanaSignature(walletB58, message, signatureB64) {
  try {
    const raw = b58decode(walletB58);
    if (raw.length !== 32) return false;
    const sig = Buffer.from(String(signatureB64 || ""), "base64");
    if (sig.length !== 64) return false;
    const key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, raw]), format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch { return false; }
}

// Signed session passes (HMAC). Set SESSION_SECRET in Railway so passes
// survive restarts; without it they reset and holders simply sign again.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.SESSION_SECRET) log("warn", "SESSION_SECRET not set — holder sessions reset on each restart");
const SESSION_MS = 12 * 60 * 60 * 1000;

const REMEMBER_MS = 30 * 24 * 3600e3;          // "remember this device" for the owner: 30 days
function issuePass(wallet, ms = SESSION_MS) {
  const body = Buffer.from(JSON.stringify({ w: wallet, exp: Date.now() + ms })).toString("base64url");
  const mac = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return body + "." + mac;
}
function readPass(pass) {
  if (typeof pass !== "string" || pass.split(".").length !== 2) return null;
  const [body, mac] = pass.split(".");
  const want = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;   // tamper-proof
  try {
    const data = JSON.parse(Buffer.from(body, "base64url").toString());
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}

// One-time sign-in challenges, 5-minute lifetime
const challenges = new Map();
const CHALLENGE_MS = 5 * 60 * 1000;
function challengeText(wallet, nonce) {
  return "Sign in to SLAPBOT Exclusive\n\n" +
         "Wallet: " + wallet + "\n" +
         "Nonce: " + nonce + "\n\n" +
         "This proves you own this wallet. It is free, sends no transaction, and cannot move your funds.";
}

// Live gate-token balance, cached 5 min per wallet
const holderCache = new Map();
const HOLDER_TTL = 5 * 60 * 1000;
/** Pure: who gets in, and how close everyone else is. */
function decideAccess({ goldBal, mainBal, price, isOwner }) {
  const gold = { balance: goldBal, need: GOLD_MIN_HOLD, ok: goldBal != null && goldBal >= GOLD_MIN_HOLD };
  const key = price
    ? { balance: mainBal, valueUsd: mainBal != null ? +(mainBal * price).toFixed(2) : null, needUsd: GATE_MIN_USD,
        need: Math.ceil(GATE_MIN_USD / price), ok: mainBal != null && mainBal * price >= GATE_MIN_USD }
    : { balance: mainBal, valueUsd: null, needUsd: GATE_MIN_USD, need: GATE_MIN_HOLD, priceUnavailable: true,
        ok: mainBal != null && mainBal >= GATE_MIN_HOLD };
  return { isOwner: !!isOwner, gold, key, authorized: !!isOwner || gold.ok || key.ok,
           balance: mainBal ?? 0, minRequired: key.need };          // older pages read these two
}
async function balanceOf(wallet, mint) {
  const accts = await withTimeout(
    connection.getParsedTokenAccountsByOwner(new PublicKey(wallet), { mint: new PublicKey(mint) }), 8000, "holder balance");
  return accts.value.reduce((s, a) => s + (a.account.data.parsed.info.tokenAmount.uiAmount || 0), 0);
}
async function getHolderStatus(wallet) {
  const hit = holderCache.get(wallet);
  if (hit && Date.now() - hit.ts < HOLDER_TTL) return hit.data;
  const isOwner = !!MY_WALLET && wallet === MY_WALLET;   // base58 is case-sensitive: exact match only
  const [g, m, p] = await Promise.allSettled([balanceOf(wallet, GOLD_MINT), balanceOf(wallet, GATE_MINT), tokenPriceUsd(GATE_MINT)]);
  const goldBal = g.status === "fulfilled" ? g.value : null, mainBal = m.status === "fulfilled" ? m.value : null;
  const data = decideAccess({ goldBal, mainBal, price: p.status === "fulfilled" ? p.value.v : null, isOwner });
  // Never tell a real holder they don't hold just because a lookup failed
  if (!data.authorized && (goldBal == null || mainBal == null)) throw new Error("balance lookup failed");
  holderCache.set(wallet, { data, ts: Date.now() });
  if (holderCache.size > 5000) holderCache.delete(holderCache.keys().next().value);
  return data;
}


/**
 * Trusted USD price for a Solana token. Same rules as the scanner: the token must be
 * the BASE side, the reference price comes from pools against real assets (by address),
 * outliers are dropped, THEN the deepest pool wins. Not on a DEX yet → read the
 * pump.fun bonding curve on-chain. Cached 60 s.
 */
const REAL_QUOTES = new Set(["So11111111111111111111111111111111111111112",
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"]);
function trustedDexPair(pairs, mint) {
  const base = (pairs || []).filter((p) => p.chainId === "solana" && p.baseToken?.address === mint && +p.priceUsd > 0);
  if (!base.length) return null;
  const liquid = base.filter((p) => (+p.liquidity?.usd || 0) >= 1000), pool = liquid.length ? liquid : base;
  const real = (p) => REAL_QUOTES.has(p.quoteToken?.address);
  const ref = (pool.some(real) ? pool.filter(real) : pool).map((p) => +p.priceUsd).sort((x, y) => x - y);
  const med = ref[Math.floor((ref.length - 1) / 2)];
  const sane = pool.filter((p) => { const r = +p.priceUsd / med; return r >= 0.67 && r <= 1.5; });
  const cands = sane.some(real) ? sane.filter(real) : (sane.length ? sane : pool);
  return cands.reduce((best, p) => ((+p.liquidity?.usd || 0) > (+best.liquidity?.usd || 0) ? p : best), cands[0]);
}
const usdCache = new Map();
async function tokenPriceUsd(mint) {
  const hit = usdCache.get(mint);
  if (hit && Date.now() - hit.ts < 60000) return hit;
  let v = null, info = {};
  try {
    const d = await (await withTimeout(fetch(`https://api.dexscreener.com/latest/dex/tokens/${mint}`), 8000, "price")).json();
    const top = trustedDexPair(d.pairs, mint);
    if (top) { v = +top.priceUsd; info = { symbol: top.baseToken?.symbol || null, name: top.baseToken?.name || null, logo: top.info?.imageUrl || null }; }
  } catch {}
  if (!v) { try { const c = await readBondingCurve(mint); if (c && !c.complete) v = curveMarket(c, await getSolUsd(), 6).price; } catch {} }
  if (!info.symbol) { try { const md = await readMetadata(mint); if (md) info = { ...info, symbol: md.symbol, name: md.name }; } catch {} }
  const out = { v: v > 0 ? v : null, info, ts: Date.now() };
  usdCache.set(mint, out);
  return out;
}

/**
 * GET /api/gate — public: the two keys, what each costs right now, and how many
 * Gold Keys can ever exist (from real on-chain supply — burns lower it honestly).
 */
let gateInfoCache = { data: null, ts: 0 };
app.get("/api/gate", async (req, res) => {
  if (gateInfoCache.data && Date.now() - gateInfoCache.ts < 60000) return res.json(gateInfoCache.data);
  const [gold, main, goldChain] = await Promise.all([
    tokenPriceUsd(GOLD_MINT), tokenPriceUsd(GATE_MINT), getMintCheck(GOLD_MINT).catch(() => null)]);
  const supply = goldChain && goldChain.found ? goldChain.supply : null;
  const keyNeed = main.v ? Math.ceil(GATE_MIN_USD / main.v) : GATE_MIN_HOLD;
  const out = {
    gold: { mint: GOLD_MINT, symbol: gold.info.symbol || "SLAPGOLD", need: GOLD_MIN_HOLD, price: gold.v,
            needUsd: gold.v ? +(gold.v * GOLD_MIN_HOLD).toFixed(2) : null, supply,
            maxKeys: supply ? Math.floor(supply / GOLD_MIN_HOLD) : null },
    key: { mint: GATE_MINT, symbol: main.info.symbol || null, name: main.info.name || null, needUsd: GATE_MIN_USD,
           price: main.v, need: keyNeed, priceUnavailable: !main.v },
    // older pages read these
    mint: GATE_MINT, symbol: main.info.symbol || null, name: main.info.name || null, logo: main.info.logo || null,
    price: main.v, minRequired: keyNeed, minUsd: main.v ? GATE_MIN_USD : null,
  };
  gateInfoCache = { data: out, ts: Date.now() };
  res.json(out);
});

/** Step 1 — get a one-time message to sign */
app.get("/api/auth/challenge", (req, res) => {
  const wallet = String(req.query.wallet || "");
  try { if (b58decode(wallet).length !== 32) throw 0; }
  catch { return res.status(400).json({ error: "That isn't a valid Solana wallet address." }); }
  const nonce = crypto.randomBytes(16).toString("hex");
  challenges.set(wallet, { nonce, exp: Date.now() + CHALLENGE_MS });
  if (challenges.size > 5000) challenges.delete(challenges.keys().next().value);
  res.json({ message: challengeText(wallet, nonce) });
});

/** Step 2 — prove ownership, check balance, receive a pass */
app.post("/api/auth/verify", async (req, res) => {
  const { wallet, signature } = req.body || {};   // optional: remember (owner only)
  // Types and sizes first — never let an object, array or huge string reach the crypto
  if (typeof wallet !== "string" || typeof signature !== "string" || wallet.length > 64 || signature.length > 200)
    return res.status(400).json({ error: "Malformed sign-in request." });
  const ch = challenges.get(wallet);
  if (!ch || ch.exp < Date.now()) return res.status(400).json({ error: "Sign-in expired — please try again." });
  challenges.delete(wallet);   // single use: blocks replay and brute-force
  if (!verifySolanaSignature(wallet, challengeText(wallet, ch.nonce), signature)) {
    log("access", `rejected signature for ${String(wallet).slice(0, 4)}…`);
    return res.status(401).json({ error: "That signature doesn't match this wallet." });
  }
  let status;
  try { status = await getHolderStatus(wallet); }
  catch (err) {
    log("error", `holder check failed: ${err.message}`);
    // Never tell a real holder they're not one just because Solana was slow
    return res.status(503).json({ error: "Couldn't reach Solana to check your balance. Please try again.", retry: true });
  }
  log("access", `${wallet.slice(0, 4)}…${wallet.slice(-4)} balance=${status.balance} authorized=${status.authorized}`);
  // basicPass: proves the wallet, opens nothing on its own. Smart Wallets uses it to let
  // non-holders pay; every Exclusive route still re-checks the balance on each visit.
  if (!status.authorized) return res.status(403).json({ error: "Not enough tokens", ...status, basicPass: issuePass(wallet) });
  const remember = (req.body || {}).remember === true && status.isOwner;    // only the owner gets a 30-day pass
  res.json({ pass: issuePass(wallet, remember ? REMEMBER_MS : SESSION_MS), remembered: remember, ...status });
});

/**
 * Owner sign-in with a secret code — no wallet needed.
 * The code lives ONLY in Railway → Variables → OWNER_CODE (never in GitHub, never in a page).
 * It must be 12+ characters or this door stays shut. Wrong guesses are capped hard:
 * 5 per 15 minutes per person, and after 25 wrong guesses from anyone in an hour
 * the door locks for everyone for an hour. Compared in constant time.
 */
const OWNER_CODE = String(process.env.OWNER_CODE || "");
const OWNER_CODE_HASH = OWNER_CODE.length >= 12 ? crypto.createHash("sha256").update(OWNER_CODE).digest() : null;
let ownerFails = [], ownerLockedUntil = 0;
// The owner can pick a new code from the dashboard (after signing in with the wallet). Only its fingerprint is saved, on the server's disk.
let ownerStored = null, ownerStoredLoaded = false;
function ownerHashNow() {
  if (!ownerStoredLoaded) {
    ownerStoredLoaded = true;
    try {
      const f = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "owner-code.json") : "";
      if (f && nodeFs.existsSync(f)) { const h = Buffer.from(String(JSON.parse(nodeFs.readFileSync(f, "utf8")).hash || ""), "hex"); if (h.length === 32) ownerStored = h; }
    } catch {}
  }
  return ownerStored || OWNER_CODE_HASH;
}
app.post("/api/auth/owner", rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many tries. Wait 15 minutes." } }), (req, res) => {
  if (!ownerHashNow() || !MY_WALLET) return res.status(404).json({ error: "Owner sign-in isn't set up." });
  const now = Date.now();
  if (now < ownerLockedUntil) return res.status(429).json({ error: "Owner sign-in is locked for a while. Try later." });
  const code = (req.body || {}).code;
  if (typeof code !== "string" || code.length > 200) return res.status(400).json({ error: "Wrong code." });
  const ok = crypto.timingSafeEqual(crypto.createHash("sha256").update(code).digest(), ownerHashNow());
  if (!ok) {
    ownerFails = ownerFails.filter((t) => now - t < 3600e3); ownerFails.push(now);
    if (ownerFails.length >= 25) { ownerLockedUntil = now + 3600e3; ownerFails = []; log("warn", "owner sign-in locked for 1 hour after repeated wrong codes"); }
    log("access", `wrong owner code from ${String(req.ip).slice(0, 24)}`);
    return res.status(401).json({ error: "Wrong code." });
  }
  log("access", "owner signed in with code");
  const remember = (req.body || {}).remember === true;
  res.json({ pass: issuePass(MY_WALLET, remember ? REMEMBER_MS : SESSION_MS), wallet: MY_WALLET, owner: true, remembered: remember });
});

/** Guard for every exclusive endpoint — re-checks the balance on each visit */
async function requireHolder(req, res, next) {
  const h = req.headers.authorization || "";
  const data = readPass(h.startsWith("Bearer ") ? h.slice(7) : "");
  if (!data || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(data.w))) return res.status(401).json({ error: "Please sign in." });
  try {
    const status = await getHolderStatus(data.w);
    if (!status.authorized) return res.status(403).json({ error: "You no longer hold enough to access Exclusive.", ...status });
    req.holder = { wallet: data.w, ...status };
  } catch {
    // Solana unreachable: they already proved holding at sign-in, so let them in
    req.holder = { wallet: data.w, degraded: true };
  }
  next();
}

/** Who am I — lets the page show the holder badge */
app.get("/api/exclusive/me", requireHolder, (req, res) => res.json(req.holder));

// Shared GeckoTerminal pool mapper for the exclusive feed
const NOISE = new Set(["SOL","WSOL","USDC","USDT","USD1","USDE","PYUSD","USDS","STSOL","MSOL","JITOSOL","JUPSOL","BSOL","INF","HSOL","JSOL","LST"]);
function mapGecko(raw) {
  const inc = raw.included || [];
  const n = (v) => (Number.isFinite(+v) ? +v : 0);
  return (raw.data || []).map((p) => {
    const a = p.attributes || {};
    const btId = p.relationships?.base_token?.data?.id || "";
    const bt = inc.find((x) => x.id === btId);
    const tx = a.transactions?.h24 || {};
    const buys = n(tx.buys), sells = n(tx.sells);
    return {
      addr: btId.split("_")[1] || "", pairAddress: a.address || "",
      sym: bt?.attributes?.symbol || (a.name || "").split("/")[0].trim() || "?",
      name: bt?.attributes?.name || "", logo: bt?.attributes?.image_url || null,
      price: n(a.base_token_price_usd), ch1: n(a.price_change_percentage?.h1), ch24: n(a.price_change_percentage?.h24),
      vol: n(a.volume_usd?.h24), liq: n(a.reserve_in_usd), fdv: n(a.fdv_usd),
      buys, sells, txns: buys + sells,
      createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
      dex: p.relationships?.dex?.data?.id || "",
    };
  }).filter((x) => x.addr && x.price > 0 && !NOISE.has(String(x.sym).toUpperCase()) && !String(x.sym).includes("-"));
}
async function geckoFeed(kind, prio = "user") {
  const r = await withTimeout(gtFetch(`https://api.geckoterminal.com/api/v2/networks/solana/${kind}?include=base_token`, prio), 10000, kind);
  return mapGecko(await r.json());
}

/**
 * The picks are built once a minute and shared by everyone, then filtered per viewer:
 *   daily       🖐 The Daily Slap — passed EVERY on-chain safety check
 *   noSeatbelt  🚨 No Seatbelt — real momentum, but each has at least one named red flag
 *   First Slap  🥇 Gold Key holders see a pick the moment it appears; Holder Key
 *               holders see it FIRST_SLAP_HOURS later (default 2).
 */
const FIRST_SLAP_MS = Math.max(0, parseFloat(process.env.FIRST_SLAP_HOURS || "2")) * 3600 * 1000;
const firstSeen = new Map();   // token → when the bot first picked it
let picksWarm = false;         // first build after a restart: treat current picks as already seen

/** Pure: contract dangers, in plain words. Any one of these keeps a token out of the Daily Slap. */
function redFlags(c) {
  const f = [];
  if (!c.mintAuthorityRenounced) f.push("Creator can still print more");
  if (!c.freezeAuthorityRenounced) f.push("Creator can still freeze wallets");
  const w = c.top10WalletPct ?? c.top10HolderPct;
  if (w != null && w >= 60) f.push(`Top 10 wallets hold ${Math.round(w)}%`);
  return f;
}
/** Pure: market cautions — not contract dangers, but worth knowing. */
function cautions(p, now = Date.now()) {
  const n = [];
  if (p.liq < 10000) n.push(`Thin liquidity ($${Math.round(p.liq).toLocaleString("en-US")})`);
  if (p.createdAt && now - p.createdAt < 24 * 3600e3) n.push("Under a day old");
  return n;
}
const slapScore = (p) => Math.log10(p.vol + 1) + (p.buyPct - 50) / 10 + Math.max(-20, Math.min(20, p.ch1)) / 10;

async function buildPicks() {
  const [fresh, trending] = await Promise.all([
    geckoFeed("new_pools").catch(() => []), geckoFeed("trending_pools").catch(() => [])]);
  const seen = new Set();
  const candidates = [...fresh, ...trending]
    .filter((p) => p.liq >= 3000 && p.txns >= 20 && !seen.has(p.addr) && seen.add(p.addr))
    .sort((x, y) => y.vol - x.vol).slice(0, 18);
  const checks = await Promise.allSettled(candidates.map((p) => getMintCheck(p.addr)));
  let checked = 0;
  const daily = [], noSeatbelt = [];
  candidates.forEach((p, i) => {
    const c = checks[i].status === "fulfilled" ? checks[i].value : null;
    if (!c || !c.found) return;            // couldn't verify: never vouch for it, never accuse it
    checked++;
    const t = { ...p, buyPct: p.txns ? Math.round((p.buys / p.txns) * 100) : 50, top10: c.top10WalletPct ?? c.top10HolderPct ?? null };
    const flags = redFlags(c);
    if (!flags.length) daily.push({ ...t, cautions: cautions(t), score: slapScore(t) });
    else if (t.ch1 > 0 && t.buyPct >= 55 && t.txns >= 100) noSeatbelt.push({ ...t, flags, cautions: cautions(t) });
  });
  daily.sort((x, y) => y.score - x.score);
  noSeatbelt.sort((x, y) => y.ch1 - x.ch1);
  const momentum = trending       // unchanged list, kept for pages that haven't updated yet
    .filter((p) => p.liq >= 10000 && p.txns >= 100 && p.ch1 > 0 && p.buys / p.txns >= 0.55)
    .map((p) => ({ ...p, buyPct: Math.round((p.buys / p.txns) * 100) }))
    .sort((x, y) => y.ch1 - x.ch1).slice(0, 12);
  const now = Date.now(), D = daily.slice(0, 12), N = noSeatbelt.slice(0, 10);
  for (const t of [...D, ...N, ...momentum])
    if (!firstSeen.has(t.addr)) firstSeen.set(t.addr, picksWarm ? now : now - FIRST_SLAP_MS);
  picksWarm = true;
  for (const [k, v] of firstSeen) if (now - v > 48 * 3600e3) firstSeen.delete(k);
  const stamp = (t) => ({ ...t, seenAt: firstSeen.get(t.addr) });
  return { updated: now, checked, candidates: candidates.length, daily: D.map(stamp), noSeatbelt: N.map(stamp), momentum: momentum.map(stamp) };
}

/** Pure: Gold Key (or owner) sees everything now; Holder Key waits out the First Slap window. */
function forViewer(data, holder, now = Date.now()) {
  const early = !!(holder && (holder.isOwner || holder.degraded || (holder.gold && holder.gold.ok)));
  const fresh = (t) => now - (t.seenAt || 0) < FIRST_SLAP_MS;
  const view = (list) => (list || []).filter((t) => early || !fresh(t)).map((t) => ({ ...t, firstSlap: fresh(t) }));
  const daily = view(data.daily), noSeatbelt = view(data.noSeatbelt);
  const heldBack = early ? 0 : [...(data.daily || []), ...(data.noSeatbelt || [])].filter(fresh).length;
  return { ...data, daily, noSeatbelt, verified: daily, momentum: view(data.momentum),
           firstSlap: { early, hours: FIRST_SLAP_MS / 3600e3, heldBack } };
}

let picksCache = { data: null, ts: 0 }, picksBuilding = null;
const PICKS_TTL = 60 * 1000;
app.get("/api/exclusive/picks", requireHolder, async (req, res) => {
  try {
    if (!picksCache.data || Date.now() - picksCache.ts >= PICKS_TTL) {
      picksBuilding = picksBuilding || buildPicks().finally(() => { picksBuilding = null; });
      const data = await picksBuilding;
      if (picksCache.data !== data) {
        picksCache = { data, ts: Date.now() };
        log("exclusive", `picks: ${data.daily.length} Daily Slap, ${data.noSeatbelt.length} No Seatbelt (${data.checked} checked)`);
      }
    }
    res.json(forViewer(picksCache.data, req.holder));
  } catch (err) {
    log("error", `picks failed: ${err.message}`);
    if (picksCache.data) return res.json(forViewer(picksCache.data, req.holder));
    res.status(502).json({ error: "Couldn't build picks right now. Try again shortly." });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ⑧ TOKEN PROFILE, CHART & TRADES — works before AND after graduation
// ═══════════════════════════════════════════════════════════════════════
/**
 * Pre-graduation pump.fun tokens have no DEX pool, so price indexers skip
 * them. But the bonding curve is a Solana account whose reserves set the
 * price exactly, so we read it straight from the chain.
 */
const PUMP_PROGRAM = new PublicKey("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");
// Anchor account ID = first 8 bytes of sha256("account:BondingCurve").
// Every read is checked against it, so no other account can be misread as a price.
const BONDING_CURVE_ID = crypto.createHash("sha256").update("account:BondingCurve").digest().subarray(0, 8);
const INITIAL_REAL_TOKEN_RESERVES = 793100000000000n;   // 793.1M tokens × 10^6, pump.fun's curve size
const METADATA_PROGRAM = new PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

/** Decode a bonding-curve account buffer. Pure — no network. */
function decodeBondingCurve(data) {
  if (!data || data.length < 49 || !data.subarray(0, 8).equals(BONDING_CURVE_ID)) return null;
  return {
    vTok: data.readBigUInt64LE(8),  vSol: data.readBigUInt64LE(16),
    rTok: data.readBigUInt64LE(24), rSol: data.readBigUInt64LE(32),
    supply: data.readBigUInt64LE(40), complete: data[48] === 1,
    creator: data.length >= 81 ? new PublicKey(data.subarray(49, 81)).toBase58() : null,
  };
}
/** Turn curve reserves into USD figures. Pure — no network. */
function curveMarket(c, solUsd, decimals = 6) {
  const priceSol = (Number(c.vSol) / 1e9) / (Number(c.vTok) / 10 ** decimals);
  const supplyTokens = Number(c.supply) / 10 ** decimals;
  const progress = c.rTok >= INITIAL_REAL_TOKEN_RESERVES ? 0
    : 1 - Number((c.rTok * 10000n) / INITIAL_REAL_TOKEN_RESERVES) / 10000;
  const vs = Number(c.vSol), rs = Number(c.rSol), floorRatio = vs > 0 ? Math.pow(Math.max(0, vs - rs) / vs, 2) : null;   // price can never fall below this fraction of today's price while the token is on its curve
  return {
    priceSol, price: priceSol * solUsd, floorRatio,
    mcap: priceSol * solUsd * supplyTokens,
    liq: (Number(c.rSol) / 1e9) * solUsd,          // real SOL locked in the curve
    progress: Math.round(Math.min(1, Math.max(0, progress)) * 10000) / 100,
    complete: c.complete,
  };
}
/** Read a Metaplex metadata account → name / symbol / uri. Pure — no network. */
function decodeMetadata(data) {
  try {
    let o = 1 + 32 + 32;                                   // key, update authority, mint
    const str = () => { const n = data.readUInt32LE(o); o += 4;
      const v = data.subarray(o, o + n).toString("utf8").replace(/\0/g, "").trim(); o += n; return v; };
    const name = str(), symbol = str(), uri = str();
    return { name: name || null, symbol: symbol || null, uri: uri || null };
  } catch { return null; }
}

let solUsd = { v: null, ts: 0 };
async function getSolUsd() {
  if (solUsd.v && Date.now() - solUsd.ts < 60000) return solUsd.v;
  const r = await withTimeout(fetch("https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd"), 6000, "SOL price");
  const v = +(await r.json())?.solana?.usd;
  if (!(v > 0)) throw new Error("no SOL price");
  solUsd = { v, ts: Date.now() };
  return v;
}
async function readBondingCurve(mint) {
  const [curve] = PublicKey.findProgramAddressSync([Buffer.from("bonding-curve"), new PublicKey(mint).toBuffer()], PUMP_PROGRAM);
  const acct = await withTimeout(connection.getAccountInfo(curve), 7000, "bonding curve");
  if (!acct || !acct.owner.equals(PUMP_PROGRAM)) return null;   // not a pump.fun token
  const c = decodeBondingCurve(acct.data);
  return c ? { ...c, curve: curve.toBase58() } : null;
}
async function readMetadata(mint) {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("metadata"), METADATA_PROGRAM.toBuffer(), new PublicKey(mint).toBuffer()], METADATA_PROGRAM);
  const acct = await withTimeout(connection.getAccountInfo(pda), 6000, "metadata");
  return acct ? decodeMetadata(acct.data) : null;
}

async function gecko(path, ms = 9000, prio = "user") {
  const r = await withTimeout(gtFetch("https://api.geckoterminal.com/api/v2/networks/solana" + path, prio), ms, "gecko " + path.split("?")[0]);
  return r.json();
}

/**
 * GET /api/token/:mint — one profile for any token:
 *   source "pool"  → graduated, priced from its most liquid pool
 *   source "curve" → still on pump.fun, priced from the bonding curve on-chain
 *   source "none"  → no market found yet
 */
const profileCache = new Map();
app.get("/api/token/:mint", async (req, res) => {
  const mint = String(req.params.mint || "");
  try { if (b58decode(mint).length !== 32) throw 0; } catch { return res.status(400).json({ error: "Invalid token address" }); }
  const hit = profileCache.get(mint);
  if (hit && Date.now() - hit.ts < 30000) return res.json(hit.data);

  const [poolsR, curveR, metaR, chainR] = await Promise.allSettled([
    gecko(`/tokens/${mint}/pools?include=base_token,quote_token&page=1`),
    readBondingCurve(mint),
    readMetadata(mint),
    getMintCheck(mint),
  ]);
  const n = (v) => (Number.isFinite(+v) ? +v : 0);
  const chain = chainR.status === "fulfilled" ? chainR.value : null;
  const meta = metaR.status === "fulfilled" ? metaR.value : null;
  const curve = curveR.status === "fulfilled" ? curveR.value : null;
  const p = {
    mint, symbol: meta?.symbol || null, name: meta?.name || null, logo: null,
    source: "none", price: null, ch1: 0, ch24: 0, vol24: 0, liq: 0, mcap: null,
    buys24: 0, sells24: 0, txns24: 0, poolAddress: null, dex: null, createdAt: null, curve: null,
    supply: chain?.found ? chain.supply : null, decimals: chain?.decimals ?? null,
    mintAuthority: chain?.mintAuthority ?? null, freezeAuthority: chain?.freezeAuthority ?? null,
    top10Pct: chain?.top10HolderPct ?? null, top10WalletPct: chain?.top10WalletPct ?? null,
    onchainOk: !!chain?.found,
    marketLookupFailed: poolsR.status === "rejected", curveLookupFailed: curveR.status === "rejected",
  };

  // Graduated / indexed. "Biggest pool wins" is exploitable: junk pools pair a real
  // token against a self-priced coin to fake liquidity and a garbage price. So the
  // token must be on the BASE side, the reference price comes from pools against real
  // assets (SOL / USDC / USDT, by address), outliers are dropped, THEN deepest wins.
  if (poolsR.status === "fulfilled") {
    const raw = poolsR.value, inc = raw.included || [], me = "solana_" + mint;
    const REAL = new Set(["solana_So11111111111111111111111111111111111111112",
      "solana_EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "solana_Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"]);
    const rel = (x, k) => x.relationships?.[k]?.data?.id;
    const pick = (list, priceOf, otherKey) => {
      if (!list.length) return null;
      const liquid = list.filter((x) => n(x.attributes?.reserve_in_usd) >= 1000), pool = liquid.length ? liquid : list;
      const real = (x) => REAL.has(rel(x, otherKey));
      const ref = pool.filter(real).length ? pool.filter(real) : pool;
      const sorted = ref.map(priceOf).sort((q, w) => q - w), med = sorted[Math.floor((sorted.length - 1) / 2)];
      const sane = pool.filter((x) => { const r = priceOf(x) / med; return r >= 0.67 && r <= 1.5; });
      const cands = sane.some(real) ? sane.filter(real) : (sane.length ? sane : pool);
      return cands.reduce((best, x) => n(x.attributes?.reserve_in_usd) > n(best.attributes?.reserve_in_usd) ? x : best, cands[0]);
    };
    const all = raw.data || [];
    let side = "base";
    let top = pick(all.filter((x) => rel(x, "base_token") === me && n(x.attributes?.base_token_price_usd) > 0),
                   (x) => n(x.attributes.base_token_price_usd), "quote_token");
    if (!top) {
      side = "quote";       // only trades as the quote coin
      top = pick(all.filter((x) => rel(x, "quote_token") === me && n(x.attributes?.quote_token_price_usd) > 0),
                 (x) => n(x.attributes.quote_token_price_usd), "base_token");
    }
    if (top) {
      const a = top.attributes || {}, tx = a.transactions?.h24 || {}, buys = n(tx.buys), sells = n(tx.sells);
      const tok = inc.find((x) => x.id === me);
      Object.assign(p, {
        source: "pool", side, poolAddress: a.address || null, dex: rel(top, "dex") || null,
        price: side === "base" ? n(a.base_token_price_usd) : n(a.quote_token_price_usd),
        // the pool's % change and market cap describe its BASE coin — only valid when that's us
        ch1: side === "base" ? n(a.price_change_percentage?.h1) : null,
        ch24: side === "base" ? n(a.price_change_percentage?.h24) : null,
        mcap: side === "base" ? (n(a.market_cap_usd) || n(a.fdv_usd) || null) : null,
        vol24: n(a.volume_usd?.h24), liq: n(a.reserve_in_usd),
        buys24: side === "base" ? buys : sells, sells24: side === "base" ? sells : buys, txns24: buys + sells,
        createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
      });
      if (tok?.attributes) {
        p.symbol = p.symbol || tok.attributes.symbol || null;
        p.name = p.name || tok.attributes.name || null;
        p.logo = tok.attributes.image_url || null;
      }
    }
  }

  // Still on the curve: price it from the chain itself
  if (curve && !curve.complete) {
    try {
      const m = curveMarket(curve, await getSolUsd(), p.decimals ?? 6);
      p.curve = { progress: m.progress, complete: false, address: curve.curve };
      if (p.source === "none") Object.assign(p, { source: "curve", price: m.price, mcap: m.mcap, liq: m.liq, dex: "pump.fun curve" });
    } catch (err) { log("error", `curve pricing failed for ${mint}: ${err.message}`); }
  }

  if (p.price > 0 && p.supply > 0) {
    const ceiling = p.price * p.supply;
    if (p.mcap == null || p.mcap > ceiling * 1.02) p.mcap = ceiling;
  }

  // Logo from the token's own metadata file, if nobody indexed one
  if (!p.logo && meta?.uri && /^https:\/\//.test(meta.uri)) {
    try { const j = await (await withTimeout(fetch(meta.uri), 4000, "token uri")).json();
      if (typeof j?.image === "string" && /^https:\/\//.test(j.image)) p.logo = j.image; } catch {}
  }

  profileCache.set(mint, { data: p, ts: Date.now() });
  if (profileCache.size > 2000) profileCache.delete(profileCache.keys().next().value);
  res.json(p);
});

/** GET /api/chart/:pool?tf=1m|5m|15m|1h — candles, oldest first */
const TF = { "1m": ["minute", 1], "5m": ["minute", 5], "15m": ["minute", 15], "1h": ["hour", 1] };
const chartCache = new Map();
app.get("/api/chart/:pool", async (req, res) => {
  const pool = String(req.params.pool || ""), tf = TF[req.query.tf] ? req.query.tf : "5m";
  const chain = String(req.query.chain || "solana").toLowerCase();
  if (!DEX_CHAINS.includes(chain)) return res.status(400).json({ error: "Unknown chain" });
  if (!POOL_ADDR.test(pool)) return res.status(400).json({ error: "Invalid pool" });
  const side = req.query.side === "quote" ? "quote" : "base";
  const key = chain + pool + tf + side, hit = chartCache.get(key);
  if (hit && Date.now() - hit.ts < 20000) return res.json(hit.data);
  try {
    const [unit, agg] = TF[tf];
    const gid = await resolveGecko(chain);
    if (!gid) return res.status(404).json({ error: "Charts aren't available for this chain yet." });
    const d = await geckoAny(`/networks/${gid}/pools/${pool}/ohlcv/${unit}?aggregate=${agg}&limit=120&currency=usd&token=${side}`);
    const candles = (d?.data?.attributes?.ohlcv_list || [])
      .map(([t, o, h, l, c, v]) => ({ t: +t, o: +o, h: +h, l: +l, c: +c, v: +v }))
      .filter((k) => k.t > 0 && k.c > 0).sort((a, b) => a.t - b.t);
    const out = { tf, candles };
    chartCache.set(key, { data: out, ts: Date.now() });
    if (chartCache.size > 1000) chartCache.delete(chartCache.keys().next().value);
    res.json(out);
  } catch (err) {
    if (hit) return res.json(hit.data);
    res.status(502).json({ error: "Chart data unavailable right now." });
  }
});

/** GET /api/trades/:pool — latest trades, newest first */
const tradesCache = new Map();
app.get("/api/trades/:pool", async (req, res) => {
  const pool = String(req.params.pool || "");
  const chain = String(req.query.chain || "solana").toLowerCase();
  if (!DEX_CHAINS.includes(chain)) return res.status(400).json({ error: "Unknown chain" });
  if (!POOL_ADDR.test(pool)) return res.status(400).json({ error: "Invalid pool" });
  const tkey = chain + pool, hit = tradesCache.get(tkey);
  if (hit && Date.now() - hit.ts < 15000) return res.json(hit.data);
  try {
    const gid = await resolveGecko(chain);
    if (!gid) return res.status(404).json({ error: "Trades aren't available for this chain yet." });
    const d = await geckoAny(`/networks/${gid}/pools/${pool}/trades`);
    const trades = (d?.data || []).slice(0, 40).map((t) => {
      const a = t.attributes || {};
      // Only address-shaped strings get through, so nothing from the data source can inject into a page
      const okAddr = /^(?:[1-9A-HJ-NP-Za-km-z]{32,44}|0x[0-9a-fA-F]{40})$/, okTx = /^(?:[1-9A-HJ-NP-Za-km-z]{64,90}|0x[0-9a-fA-F]{64})$/;
      return { kind: a.kind === "sell" ? "sell" : "buy", usd: Number.isFinite(+a.volume_in_usd) ? +a.volume_in_usd : 0,
        wallet: okAddr.test(String(a.tx_from_address)) ? a.tx_from_address : null, tx: okTx.test(String(a.tx_hash)) ? a.tx_hash : null,
        at: a.block_timestamp ? new Date(a.block_timestamp).getTime() : null };
    });
    const out = { trades };
    tradesCache.set(tkey, { data: out, ts: Date.now() });
    if (tradesCache.size > 1000) tradesCache.delete(tradesCache.keys().next().value);
    res.json(out);
  } catch (err) {
    if (hit) return res.json(hit.data);
    res.status(502).json({ error: "Trades unavailable right now." });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ⑨ MULTI-CHAIN — every chain DexScreener lists; graded ONLY where verifiable
// ═══════════════════════════════════════════════════════════════════════
/** Every chain in DexScreener's top bar (their own ids). */
const DEX_CHAINS = ["solana","robinhood","bsc","base","ethereum","arc","polygon","pulsechain","hyperevm","ton",
  "sui","near","avalanche","arbitrum","ink","cronos","xrpl","sonic","hyperliquid","monad","hedera","tron",
  "worldchain","starknet","abstract","stable","optimism","mantle","seiv2","linea","icp","berachain","megaeth",
  "injective","aptos","flare","algorand","plasma","zksync","metis","fantom","apechain","cardano","unichain",
  "blast","stacks","celo","opbnb","flowevm","soneium","manta","conflux","merlinchain","scroll","beam","katana",
  "story","kava","fuse","multiversx","telos","movement","polkadot","stepnetwork"];

/** GoPlus chain ids — ONLY these have verified contract-safety coverage. */
const GOPLUS = { ethereum:1, bsc:56, polygon:137, arbitrum:42161, base:8453, avalanche:43114,
  optimism:10, fantom:250, cronos:25, linea:59144, scroll:534352, mantle:5000, zksync:324 };

/** DexScreener→GeckoTerminal ids that differ. Each is confirmed against the
 *  live network list before use — a wrong guess can never be trusted. */
const GECKO_ALIAS = { ethereum:"eth", polygon:"polygon_pos", avalanche:"avax", cronos:"cro",
  fantom:"ftm", sui:"sui-network", seiv2:"sei-evm" };

const normName = (s) => String(s || "").toLowerCase().replace(/\b(chain|network|mainnet)\b/g, "").replace(/[^a-z0-9]/g, "");
/** Pure: pick the GeckoTerminal id for a DexScreener chain, given the live list. */
function pickGecko(dexChain, nets) {
  dexChain = String(dexChain || "").toLowerCase();
  if (!nets || !nets.length) return null;
  const ids = new Set(nets.map((n) => n.id));
  if (ids.has(dexChain)) return dexChain;
  const alias = GECKO_ALIAS[dexChain];
  if (alias && ids.has(alias)) return alias;
  const m = nets.find((n) => normName(n.name) === normName(dexChain));
  return m ? m.id : null;
}

let geckoNets = { list: null, ts: 0 };
async function getGeckoNetworks() {
  if (geckoNets.list && Date.now() - geckoNets.ts < 24 * 3600e3) return geckoNets.list;
  const all = [], seen = new Set();
  for (let page = 1; page <= 15; page++) {
    let rows = [];
    try {
      const r = await withTimeout(gtFetch(`https://api.geckoterminal.com/api/v2/networks?page=${page}`, "user"), 9000, "networks");
      rows = (await r.json()).data || [];
    } catch { break; }
    let fresh = 0;
    for (const n of rows) { if (!seen.has(n.id)) { seen.add(n.id); fresh++; all.push({ id: n.id, name: n.attributes?.name || n.id }); } }
    if (!rows.length || !fresh) break;             // empty or repeating page → done
  }
  if (all.length) geckoNets = { list: all, ts: Date.now() };
  return geckoNets.list || [];
}
const resolvedNets = new Map();
async function resolveGecko(dexChain) {
  dexChain = String(dexChain || "solana").toLowerCase();
  if (dexChain === "solana") return "solana";
  if (resolvedNets.has(dexChain)) return resolvedNets.get(dexChain);
  const nets = await getGeckoNetworks();
  if (!nets.length) return GECKO_ALIAS[dexChain] || dexChain;   // list down: best effort, not cached
  const gid = pickGecko(dexChain, nets);
  resolvedNets.set(dexChain, gid);
  return gid;
}
async function geckoAny(fullPath, ms = 9000, prio = "user") {
  const r = await withTimeout(gtFetch("https://api.geckoterminal.com/api/v2" + fullPath, prio), ms, "gecko " + fullPath.split("?")[0]);
  return r.json();
}

// Pool/pair addresses differ by chain (base58, 0x…40, v4 0x…64). Allow only
// characters that can't break out of a URL or a quoted string.
const SAFE_ADDR = /^[A-Za-z0-9:._-]{3,200}$/;
// Pool IDs must be a REAL format — Solana base58, EVM 0x…40 (v2/v3) or 0x…64 (v4 / Sui), or TON —
// so junk like "__proto__" is refused before it costs an outbound call.
const POOL_ADDR = /^(?:[1-9A-HJ-NP-Za-km-z]{32,44}|0x[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?|[EU]Q[A-Za-z0-9_-]{46})$/;
const WRAPPED_NOISE = new Set([...NOISE, "WETH","ETH","WBNB","BNB","WAVAX","AVAX","WMATIC","MATIC","WPOL","POL",
  "DAI","WBTC","CBBTC","FDUSD","TUSD","USDBC","USDB","EURC","WS","WHYPE","WBERA","WTRX","WTON"]);

/**
 * GET /api/feed/:type?chain=all|<dexChainId>   (type = trending | new)
 * "all" mirrors DexScreener's homepage: one mixed list across every network.
 */
const feedCache = new Map();
app.get("/api/feed/:type", async (req, res) => {
  const type = req.params.type === "new" ? "new_pools" : "trending_pools";
  const chain = String(req.query.chain || "all").toLowerCase();
  if (chain !== "all" && !DEX_CHAINS.includes(chain)) return res.status(400).json({ error: "Unknown chain" });
  const key = type + ":" + chain, hit = feedCache.get(key);
  if (hit && Date.now() - hit.ts < 45000) return res.json(hit.data);
  try {
    let path;
    if (chain === "all") path = `/networks/${type}?include=base_token,network`;
    else {
      const gid = await resolveGecko(chain);
      if (!gid) return res.json({ chain, pools: [], unavailable: true });
      path = `/networks/${gid}/${type}?include=base_token,network`;
    }
    const raw = await geckoAny(path);
    const inc = raw.included || [];
    const netName = (id) => inc.find((x) => x.type === "network" && x.id === id)?.attributes?.name || id;
    // map GeckoTerminal ids back to DexScreener ids for the frontend
    const nets = await getGeckoNetworks();
    const back = {}; for (const d of DEX_CHAINS) { const g = pickGecko(d, nets); if (g) back[g] = d; }
    back.solana = "solana";
    const n = (v) => (Number.isFinite(+v) ? +v : 0);
    const pools = (raw.data || []).map((p) => {
      const a = p.attributes || {}, tx = a.transactions?.h24 || {};
      const btId = p.relationships?.base_token?.data?.id || "";
      const bt = inc.find((x) => x.id === btId);
      const gid = p.relationships?.network?.data?.id || btId.split("_")[0] || "";
      return {
        addr: btId.slice(btId.indexOf("_") + 1) || "", pairAddress: a.address || "",
        sym: bt?.attributes?.symbol || (a.name || "").split("/")[0].trim() || "?",
        name: bt?.attributes?.name || "", logo: bt?.attributes?.image_url || null,
        price: n(a.base_token_price_usd), ch1: n(a.price_change_percentage?.h1), ch24: n(a.price_change_percentage?.h24),
        vol: n(a.volume_usd?.h24), liq: n(a.reserve_in_usd), fdv: n(a.fdv_usd),
        buys: n(tx.buys), sells: n(tx.sells), txns: n(tx.buys) + n(tx.sells),
        createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
        dex: p.relationships?.dex?.data?.id || "",
        net: { gid, name: netName(gid), chain: back[gid] || null },
      };
    }).filter((x) => x.addr && SAFE_ADDR.test(x.addr) && x.price > 0 && !WRAPPED_NOISE.has(String(x.sym).toUpperCase()));
    const out = { chain, count: pools.length, pools };
    feedCache.set(key, { data: out, ts: Date.now() });
    log("discovery", `${chain} ${type}: ${pools.length} pools`);
    res.json(out);
  } catch (err) {
    log("error", `feed ${chain} ${type}: ${err.message}`);
    if (hit) return res.json(hit.data);
    res.status(502).json({ error: "Market data unavailable right now.", pools: [] });
  }
});

/** Pure: GoPlus raw record → normalized flags. Unknown stays null — never "safe". */
function normalizeGoPlus(e, chain) {
  if (!e || typeof e !== "object" || !Object.keys(e).length)
    return { covered: true, ok: false, chain, error: "No security data for this token yet" };
  const flag = (v) => (String(v) === "1" ? true : String(v) === "0" ? false : null);
  const frac = (v) => (v === "" || v == null || !Number.isFinite(+v) ? null : +v);
  const owner = String(e.owner_address || "");
  const renounced = owner === "" || /^0x0{40}$/i.test(owner) || /^0x0{36}dead$/i.test(owner);
  const holders = Array.isArray(e.holders) ? e.holders : [];
  // Real wallets only — skip contracts and locked positions (pools, lockers)
  const wallets = holders.filter((h) => String(h.is_contract) !== "1" && String(h.is_locked) !== "1").slice(0, 10);
  const top10 = wallets.length ? wallets.reduce((s, h) => s + (+h.percent || 0), 0) * 100 : null;
  return {
    covered: true, ok: true, chain, name: e.token_name || null, symbol: e.token_symbol || null,
    honeypot: flag(e.is_honeypot), cannotBuy: flag(e.cannot_buy), cannotSellAll: flag(e.cannot_sell_all),
    buyTax: frac(e.buy_tax), sellTax: frac(e.sell_tax),
    mintable: flag(e.is_mintable), openSource: flag(e.is_open_source), proxy: flag(e.is_proxy),
    hiddenOwner: flag(e.hidden_owner), takeBackOwnership: flag(e.can_take_back_ownership),
    ownerChangeBalance: flag(e.owner_change_balance), blacklist: flag(e.is_blacklisted),
    pausable: flag(e.transfer_pausable), taxModifiable: flag(e.slippage_modifiable), selfdestruct: flag(e.selfdestruct),
    ownerRenounced: renounced, holderCount: Number.isFinite(+e.holder_count) && e.holder_count !== "" ? +e.holder_count : null,
    top10WalletPct: top10 != null ? +top10.toFixed(2) : null,
  };
}

/** GET /api/security/:chain/:address — contract safety, only on chains GoPlus covers */
const secCache = new Map();
app.get("/api/security/:chain/:address", async (req, res) => {
  const chain = String(req.params.chain || "").toLowerCase();
  const addr = String(req.params.address || "").toLowerCase();
  const cid = GOPLUS[chain];
  if (!cid) return res.json({ covered: false, chain });
  if (!/^0x[0-9a-f]{40}$/.test(addr)) return res.status(400).json({ error: "Invalid contract address" });
  const key = chain + ":" + addr, hit = secCache.get(key);
  if (hit && Date.now() - hit.ts < 10 * 60e3) return res.json(hit.data);
  try {
    const r = await withTimeout(fetch(`https://api.gopluslabs.io/api/v1/token_security/${cid}?contract_addresses=${addr}`,
      { headers: { accept: "application/json" } }), 10000, "goplus");
    const d = await r.json();
    const res0 = d?.result || {};
    const entry = res0[addr] || Object.entries(res0).find(([k]) => k.toLowerCase() === addr)?.[1];
    const out = normalizeGoPlus(entry, chain);
    secCache.set(key, { data: out, ts: Date.now() });
    if (secCache.size > 3000) secCache.delete(secCache.keys().next().value);
    res.json(out);
  } catch (err) {
    log("error", `security ${chain} ${addr}: ${err.message}`);
    res.json({ covered: true, ok: false, chain, error: "Security data unavailable right now" });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ⑩ BIG MOUF ALLOCATION LIST — hold SLAP IT N YA MOUF, earn a $SLAPGOLD share
// ═══════════════════════════════════════════════════════════════════════
/**
 * Holders of the main token sign once (free, no transaction) to join the list.
 * At the reveal, the owner takes a snapshot: every wallet's holding is re-read
 * LIVE, anyone who sold below the bar drops off, and the $SLAPGOLD pool is split
 * in proportion to what each wallet holds right then.
 *
 *  - Proportional, not per-wallet: one bag split across ten wallets earns exactly
 *    what it earns in one, so the list can't be farmed.
 *  - Snapshot at export, not at sign-up: buy, join, sell = nothing.
 *  - Stored on a Railway Volume so restarts and new uploads never wipe it.
 *    Without one it still works in memory, and /api/health says so plainly.
 */
const nodeFs = require("fs"), nodePath = require("path");
const VOLUME_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || "";
const CLAIMS_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "allocation-list.json") : "";
const claims = new Map();
let claimsPersistent = false;
if (CLAIMS_FILE) {
  try {
    nodeFs.mkdirSync(VOLUME_DIR, { recursive: true });
    if (nodeFs.existsSync(CLAIMS_FILE))
      for (const c of JSON.parse(nodeFs.readFileSync(CLAIMS_FILE, "utf8")))
        if (c && typeof c.wallet === "string") claims.set(c.wallet, c);
    nodeFs.accessSync(VOLUME_DIR, nodeFs.constants.W_OK);
    claimsPersistent = true;
    log("init", `Allocation list: ${claims.size} wallets loaded from the volume`);
  } catch (e) { log("error", `Allocation list storage unavailable (${e.message}) — memory only`); }
} else log("warn", "No Railway Volume attached — the allocation list is wiped on every restart");

function saveClaims() {
  if (!claimsPersistent) return;
  try {
    const tmp = CLAIMS_FILE + ".tmp";
    nodeFs.writeFileSync(tmp, JSON.stringify([...claims.values()]));
    nodeFs.renameSync(tmp, CLAIMS_FILE);        // atomic: a crash mid-write can't corrupt the list
  } catch (e) { log("error", `Saving the allocation list failed: ${e.message}`); }
}

function claimChallengeText(wallet, nonce) {
  return "Join the BIG MOUF allocation list\n\nWallet: " + wallet + "\nNonce: " + nonce +
         "\n\nThis proves you own this wallet. It is free, sends no transaction, and cannot move your funds.";
}
const claimChallenges = new Map();

/** Live holding check — used at sign-up and again for every wallet at the snapshot. */
async function holdingNow(wallet) {
  const [bal, price] = await Promise.all([balanceOf(wallet, GATE_MINT), tokenPriceUsd(GATE_MINT)]);
  const valueUsd = price.v ? +(bal * price.v).toFixed(2) : null;
  return { balance: bal, valueUsd, eligible: price.v ? valueUsd >= GATE_MIN_USD : bal >= GATE_MIN_HOLD };
}

/** Pure: split `pool` across eligible rows in proportion to holdings. Rounds down, never over-allocates. */
function allocate(rows, pool) {
  const total = rows.reduce((s, r) => s + (r.eligible ? r.balance : 0), 0);
  return rows.map((r) => {
    const share = r.eligible && total > 0 ? r.balance / total : 0;
    return { ...r, sharePct: +(share * 100).toFixed(4), amount: Math.floor(pool * share * 1e4) / 1e4 };
  });
}

app.get("/api/claim/challenge", (req, res) => {
  const wallet = String(req.query.wallet || "");
  try { if (b58decode(wallet).length !== 32) throw 0; }
  catch { return res.status(400).json({ error: "That isn't a valid Solana wallet address." }); }
  const nonce = crypto.randomBytes(16).toString("hex");
  claimChallenges.set(wallet, { nonce, exp: Date.now() + CHALLENGE_MS });
  if (claimChallenges.size > 5000) claimChallenges.delete(claimChallenges.keys().next().value);
  res.json({ message: claimChallengeText(wallet, nonce) });
});

app.post("/api/claim/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body || {};
    if (typeof wallet !== "string" || typeof signature !== "string" || wallet.length > 64 || signature.length > 200)
      return res.status(400).json({ error: "Malformed request." });
    const ch = claimChallenges.get(wallet);
    if (!ch || ch.exp < Date.now()) return res.status(400).json({ error: "Expired — please try again." });
    claimChallenges.delete(wallet);
    if (!verifySolanaSignature(wallet, claimChallengeText(wallet, ch.nonce), signature))
      return res.status(401).json({ error: "That signature doesn't match this wallet." });

    // The owner gets the snapshot tools — and is never on the list they're distributing.
    if (MY_WALLET && wallet === MY_WALLET)
      return res.json({ owner: true, ownerPass: issuePass(wallet), listedCount: claims.size, persistent: claimsPersistent });

    let h;
    try { h = await holdingNow(wallet); }
    catch (err) {
      log("error", `claim balance check failed: ${err.message}`);
      return res.status(503).json({ error: "Couldn't reach Solana to check your balance. Please try again.", retry: true });
    }
    if (!h.eligible)
      return res.status(403).json({ listed: claims.has(wallet), balance: h.balance, valueUsd: h.valueUsd, needUsd: GATE_MIN_USD, need: GATE_MIN_HOLD });
    const prev = claims.get(wallet);
    claims.set(wallet, { wallet, balance: h.balance, valueUsd: h.valueUsd, joined: prev ? prev.joined : Date.now(), checked: Date.now() });
    saveClaims();
    log("claim", `${wallet.slice(0, 4)}… ${prev ? "re-checked" : "joined"} — ${claims.size} on the list`);
    res.json({ listed: true, first: !prev, balance: h.balance, valueUsd: h.valueUsd, needUsd: GATE_MIN_USD, listedCount: claims.size });
  } catch (err) {
    log("error", `claim/verify crashed: ${err.message}`);
    res.status(500).json({ error: "Something went wrong." });
  }
});

app.get("/api/claim/stats", (req, res) => res.json({ listedCount: claims.size, needUsd: GATE_MIN_USD }));

/** Owner-only: take the snapshot and split the pool. */
app.post("/api/claim/export", async (req, res) => {
  try {
    const p = readPass(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
    if (!p) return res.status(401).json({ error: "Sign in with your owner wallet first." });
    if (!MY_WALLET || p.w !== MY_WALLET) return res.status(403).json({ error: "Owner only." });
    const pool = Number((req.body || {}).pool);
    if (!Number.isFinite(pool) || pool <= 0 || pool > 10000)
      return res.status(400).json({ error: "The pool must be between 0 and 10,000 $SLAPGOLD." });

    const list = [...claims.values()], rows = [];
    for (let i = 0; i < list.length; i += 5) {               // 5 at a time — gentle on the RPC
      const batch = await Promise.allSettled(list.slice(i, i + 5).map((c) => holdingNow(c.wallet)));
      batch.forEach((r, j) => {
        const c = list[i + j];
        if (r.status === "fulfilled") {
          rows.push({ wallet: c.wallet, balance: r.value.balance, valueUsd: r.value.valueUsd, eligible: r.value.eligible,
                      status: r.value.eligible ? "ok" : "below the bar at snapshot" });
          claims.set(c.wallet, { ...c, balance: r.value.balance, valueUsd: r.value.valueUsd, checked: Date.now() });
        } else rows.push({ wallet: c.wallet, balance: c.balance, valueUsd: c.valueUsd, eligible: false, status: "couldn't check — snapshot again" });
      });
    }
    saveClaims();
    const out = allocate(rows, pool);
    const csv = "wallet,slapit_held,value_usd,status,share_pct,slapgold_amount\n" +
      out.map((r) => [r.wallet, r.balance, r.valueUsd ?? "", r.status, r.sharePct, r.amount].join(",")).join("\n");
    const unchecked = out.filter((r) => r.status.startsWith("couldn")).length;
    log("claim", `snapshot: ${out.filter((r) => r.amount > 0).length} of ${out.length} wallets share ${pool} $SLAPGOLD`);
    res.json({ snapshotAt: new Date().toISOString(), pool, rows: out, csv, unchecked });
  } catch (err) {
    log("error", `claim/export crashed: ${err.message}`);
    res.status(500).json({ error: "Something went wrong." });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ⑪ SMART WALLETS — find wallets that keep winning, watch what they buy
// ═══════════════════════════════════════════════════════════════════════
/**
 * How it learns: every ~20 seconds the bot reads the latest trades from one of
 * the busiest Solana pools (trending + new, refreshed every 10 minutes), and
 * keeps a ledger of what each wallet bought and sold, per token.
 *
 * How it scores: a wallet's result on a token = what it got back from sells
 * + what it still holds at today's price − what it spent. Only positions the
 * bot saw being BOUGHT count, so nobody is credited for a bag we never saw them
 * pay for. A wallet makes the board once it has 3+ real positions ($50+ each),
 * wins at least half of them, and is up overall.
 *
 * Who gets filtered: trading bots and MEV (40+ trades on one token, or 300+
 * overall), and wallets that only ever sell. Rankings sharpen the longer it runs.
 *
 * Access: free for the owner and Gold Key holders (5 $SLAPGOLD). Everyone else
 * pays SMART_PRICE_USD in SOL to the owner wallet for SMART_HOURS of access.
 * The server builds the payment, the user's own wallet signs and sends it, the
 * server reads it back from the chain. No card processor, no ID, no custody.
 */
const { Transaction, SystemProgram, Keypair } = require("@solana/web3.js");
const SMART_PRICE_USD = Math.max(1, parseFloat(process.env.SMART_PRICE_USD || "30"));
const SMART_MS = Math.max(1, parseFloat(process.env.SMART_HOURS || "24")) * 3600e3;
const SMART_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "smart-wallets.json") : "";

const SOL_ADDR = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/, SOL_SIG = /^[1-9A-HJ-NP-Za-km-z]{64,90}$/;
const smartPaid = new Map();     // wallet → { until, sigs: [] }
const smartQuotes = new Map();   // payment reference → { wallet, lamports, exp }
const ledger = new Map();        // wallet → Map(token → { b, bt, s, st, n, f, l })
const tokenInfo = new Map();     // token → { sym, price, pool, ts }
const poolSeen = new Map();      // pool → Set(tx hashes already counted)
let recentBuys = [];             // { w, t, usd, at, tx }
let recentSells = [];            // same shape, for exits
let watchList = [], watchIdx = 0, smartSince = Date.now(), smartPersistent = false;

function b58encode(buf) {
  let n = BigInt("0x" + (Buffer.from(buf).toString("hex") || "0")), s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = "1" + s; else break; }
  return s;
}

// ── storage: survives restarts only with a Railway Volume ──
if (SMART_FILE) {
  try {
    if (nodeFs.existsSync(SMART_FILE)) {
      const d = JSON.parse(nodeFs.readFileSync(SMART_FILE, "utf8"));
      smartSince = d.since || smartSince;
      for (const [w, p] of d.paid || []) smartPaid.set(w, p);
      for (const [t, i] of d.tokens || []) tokenInfo.set(t, i);
      for (const [w, ps] of d.wallets || []) ledger.set(w, new Map(ps));
      recentBuys = d.buys || []; recentSells = d.sells || [];
    }
    smartPersistent = true;
    log("init", `Smart Wallets: ${ledger.size} wallets loaded from the volume`);
  } catch (e) { log("error", `Smart Wallets storage unavailable (${e.message}) — memory only`); }
}
function saveSmart() {
  if (!smartPersistent) return;
  try {
    const tmp = SMART_FILE + ".tmp";
    nodeFs.writeFileSync(tmp, JSON.stringify({
      since: smartSince, paid: [...smartPaid], tokens: [...tokenInfo],
      wallets: [...ledger].map(([w, m]) => [w, [...m]]), buys: recentBuys, sells: recentSells,
    }));
    nodeFs.renameSync(tmp, SMART_FILE);
  } catch (e) { log("error", `Saving Smart Wallets failed: ${e.message}`); }
}

// ── learning ──
async function refreshWatchList() {
  // Wider net = more variety: trending + new, two pages each, plus pump.fun's busiest pools
  const page = (path) => gecko(path, 9000, "bg").then(mapGecko).catch(() => []);
  const sets = await Promise.all([
    geckoFeed("trending_pools", "bg").catch(() => []), page("/trending_pools?include=base_token&page=2"),
    geckoFeed("new_pools", "bg").catch(() => []), page("/new_pools?include=base_token&page=2"),
    page("/dexes/pump-fun/pools?include=base_token&page=1"), page("/dexes/pumpswap/pools?include=base_token&page=1")]);
  for (const p of [...sets[0], ...sets[1]]) LAB.trended.set(p.addr, Date.now());     // trending lists, pages 1–2: the Winner Lab's "made the list" signal
  // interleave the sources so no single list crowds out the rest
  const merged = [];
  for (let i = 0; i < 20; i++) for (const s of sets) if (s[i]) merged.push(s[i]);
  const seen = new Set(), list = [];
  for (const p of merged) {
    if (!p.pairAddress || seen.has(p.addr) || p.liq < 3000 || p.txns < 40) continue;
    seen.add(p.addr);
    if (!SOL_ADDR.test(p.addr) || !SOL_ADDR.test(p.pairAddress)) continue;
    const sym = String(p.sym || "?").replace(/[^\w$.\- ]/g, "").slice(0, 16) || "?";
    p.sym = sym;
    list.push({ addr: p.addr, pair: p.pairAddress, sym });
    tokenInfo.set(p.addr, { sym: p.sym, price: p.price, pool: p.pairAddress, ts: Date.now(),
      mcap: p.fdv || null, vol: p.vol, liq: p.liq, createdAt: p.createdAt, buys: p.buys, sells: p.sells });
  }
  // Early lane: brand-new, still-tiny pools, kept in their own slots so big movers can't crowd them out
  const early = [];
  for (const p of [...sets[2], ...sets[3], ...sets[4]]) {
    if (!p.pairAddress || seen.has(p.addr) || !SOL_ADDR.test(p.addr) || !SOL_ADDR.test(p.pairAddress)) continue;
    const young = p.createdAt && Date.now() - p.createdAt < 12 * 3600e3;
    if (!young || p.liq < 1000 || p.txns < 10 || p.vol > 150000) continue;
    seen.add(p.addr);
    const sym = String(p.sym || "?").replace(/[^\w$.\- ]/g, "").slice(0, 16) || "?";
    early.push({ addr: p.addr, pair: p.pairAddress, sym, early: true });
    tokenInfo.set(p.addr, { sym, price: p.price, pool: p.pairAddress, ts: Date.now(),
      mcap: p.fdv || null, vol: p.vol, liq: p.liq, createdAt: p.createdAt, buys: p.buys, sells: p.sells, early: true });
  }
  if (list.length || early.length) watchList = list.slice(0, 55).concat(early.slice(0, 25));
}

async function ingestPool(pool) {
  const d = await gecko(`/pools/${pool.pair}/trades`, 9000, "bg");
  let seen = poolSeen.get(pool.pair);
  if (!seen) { seen = new Set(); poolSeen.set(pool.pair, seen); }
  let added = 0;
  for (const t of d?.data || []) {
    const a = t.attributes || {};
    if (!a.tx_hash || seen.has(a.tx_hash)) continue;
    if (typeof alertBuySigs !== "undefined" && alertBuySigs.has(a.tx_hash)) { seen.add(a.tx_hash); continue; }   // already counted live
    seen.add(a.tx_hash);
    const w = a.tx_from_address, usd = +a.volume_in_usd || 0, buy = a.kind === "buy";
    if (!SOL_ADDR.test(String(w || "")) || !(usd > 0) || usd > 1e9) continue;   // real wallets, sane sizes only
    if (!SOL_SIG.test(String(a.tx_hash))) continue;
    if (buy && a.to_token_address && a.to_token_address !== pool.addr) continue;
    if (!buy && a.from_token_address && a.from_token_address !== pool.addr) continue;
    const tok = buy ? +a.to_token_amount : +a.from_token_amount;
    if (!(tok > 0)) continue;
    const at = a.block_timestamp ? Date.parse(a.block_timestamp) : Date.now();
    let m = ledger.get(w);
    if (!m) { m = new Map(); ledger.set(w, m); }
    const p = m.get(pool.addr) || { b: 0, bt: 0, s: 0, st: 0, n: 0, f: at, l: at };
    if (buy) { p.b += usd; p.bt += tok; p.lb = Math.max(p.lb || 0, at); } else { p.s += usd; p.st += tok; p.ls = Math.max(p.ls || 0, at); }
    p.n++; p.f = Math.min(p.f, at); p.l = Math.max(p.l, at);
    m.set(pool.addr, p);
    const px = buy ? +a.price_to_in_usd : +a.price_from_in_usd;
    if (px > 0) { const i = tokenInfo.get(pool.addr) || { sym: pool.sym, pool: pool.pair }; tokenInfo.set(pool.addr, { ...i, price: px, ts: Date.now() }); }
    (buy ? recentBuys : recentSells).push({ w, t: pool.addr, usd: +usd.toFixed(2), at, tx: a.tx_hash });
    added++;
  }
  if (seen.size > 3000) poolSeen.set(pool.pair, new Set([...seen].slice(-1500)));
  return added;
}

function pruneSmart() {
  const now = Date.now();
  recentBuys = recentBuys.filter((b) => now - b.at < 24 * 3600e3).slice(-5000);
  recentSells = recentSells.filter((b) => now - b.at < 24 * 3600e3).slice(-5000);
  for (const [w, m] of ledger) {
    for (const [t, p] of m) if (now - p.l > 30 * 24 * 3600e3) m.delete(t);
    if (!m.size) ledger.delete(w);
  }
  if (ledger.size > 40000) {            // drop one-token, oldest wallets first
    const thin = [...ledger].filter(([, m]) => m.size === 1)
      .sort((a, b) => [...a[1].values()][0].l - [...b[1].values()][0].l);
    for (const [w] of thin.slice(0, ledger.size - 40000)) ledger.delete(w);
  }
  for (const [pair] of poolSeen) if (!watchList.some((p) => p.pair === pair)) poolSeen.delete(pair);
  for (const [ref, q] of smartQuotes) if (q.exp < now) smartQuotes.delete(ref);
  if (tokenInfo.size > 3000) {                // keep prices only for tokens someone still holds or we watch
    const live = new Set(watchList.map((p) => p.addr));
    for (const m of ledger.values()) for (const t of m.keys()) live.add(t);
    for (const t of tokenInfo.keys()) if (!live.has(t)) tokenInfo.delete(t);
  }
  for (const [w, p] of smartPaid) if (p.until < now - 7 * 24 * 3600e3) smartPaid.delete(w);
}

/** Pure: one wallet's record from its ledger. */
function walletStats(m) {
  let cost = 0, value = 0, wins = 0, counted = 0, trades = 0, last = 0, realizedPnl = 0, openValue = 0, holding = 0;
  const positions = [];
  for (const [t, p] of m) {
    trades += p.n; last = Math.max(last, p.l);
    if (p.bt <= 0 || p.b < 50) continue;                     // only positions we saw them pay for
    const price = tokenInfo.get(t)?.price || 0;
    const realized = p.st <= p.bt ? p.s : p.s * (p.bt / p.st);
    const held = Math.max(0, p.bt - p.st) * price;
    const pnl = realized + held - p.b;
    cost += p.b; value += realized + held; counted++; if (pnl > 0) wins++;
    const soldPct = Math.min(100, Math.round((p.st / p.bt) * 100));
    const soldCost = p.b * Math.min(1, p.st / p.bt);
    realizedPnl += realized - soldCost; openValue += held; if (soldPct < 95) holding++;
    positions.push({ token: t, sym: tokenInfo.get(t)?.sym || "?", spent: +p.b.toFixed(2), gotBack: +realized.toFixed(2), stillWorth: +held.toFixed(2),
      pnl: +pnl.toFixed(2), roi: +((pnl / p.b) * 100).toFixed(1), soldPct,
      status: soldPct >= 95 ? "sold all" : soldPct > 5 ? "sold part" : "holding", stillHolding: soldPct < 95,
      lastBuy: p.lb || p.f, lastSell: p.ls || null, last: p.l });
  }
  const bot = trades > 300 || [...m.values()].some((p) => p.n > 40);
  positions.sort((a, b) => b.pnl - a.pnl);
  return { pnl: +(value - cost).toFixed(2), spent: +cost.toFixed(2), roi: cost ? +(((value - cost) / cost) * 100).toFixed(1) : 0,
           winRate: counted ? Math.round((wins / counted) * 100) : 0, wins, positions: counted, trades, last, bot, list: positions,
           realized: +realizedPnl.toFixed(2), openValue: +openValue.toFixed(2), holding };
}

let boardCache = { data: null, ts: 0 };
function leaderboard() {
  if (boardCache.data && Date.now() - boardCache.ts < (boardCache.data.length < 25 ? 30000 : 120000)) return boardCache.data;
  const rows = [];
  for (const [w, m] of ledger) {
    if (m.size < 3) continue;
    const s = walletStats(m);
    if (s.bot || s.positions < 3 || s.winRate < 50 || s.pnl <= 0) continue;
    rows.push({ wallet: w, pnl: s.pnl, roi: s.roi, winRate: s.winRate, wins: s.wins, positions: s.positions, last: s.last,
                realized: s.realized, openValue: s.openValue, holding: s.holding,
                best: s.list.slice(0, 3).map((p) => ({ sym: p.sym, token: p.token, roi: p.roi, status: p.status })) });
  }
  rows.sort((a, b) => b.pnl - a.pnl);
  // Early read: while the proven list is short (right after a restart), also show
  // wallets with at least one strong, real win. Clearly labeled, ranked after proven ones.
  if (rows.length < 25) {
    const early = [];
    for (const [w, m] of ledger) {
      const s = walletStats(m);
      if (s.bot || s.positions < 1 || s.pnl < 100 || s.roi < 25 || rows.some((r) => r.wallet === w)) continue;
      early.push({ wallet: w, pnl: s.pnl, roi: s.roi, winRate: s.winRate, wins: s.wins, positions: s.positions, last: s.last,
                   realized: s.realized, openValue: s.openValue, holding: s.holding,
                   best: s.list.slice(0, 3).map((p) => ({ sym: p.sym, token: p.token, roi: p.roi, status: p.status })), tier: "early" });
    }
    early.sort((a, b) => b.pnl - a.pnl);
    const perToken = new Map(), varied = [];
    for (const e of early) {
      const k = e.best[0]?.token || e.wallet, n = perToken.get(k) || 0;
      if (n >= 3) continue;
      perToken.set(k, n + 1); varied.push(e);
    }
    rows.push(...varied.slice(0, 60 - rows.length));
  }
  const data = rows.slice(0, 100).map((r, i) => ({ rank: i + 1, tier: r.tier || "proven", ...r }));
  boardCache = { data, ts: Date.now() };
  return data;
}

// The learning loop: one pool every 20 s (3 calls a minute — gentle on the data source)
let smartTick = 0;
// Warm-up burst: read every watched pool once, right after start, ~2.5 s apart
setTimeout(async () => {
  try { await refreshWatchList(); } catch {}
  for (const pool of watchList.slice()) {
    try { await ingestPool(pool); } catch {}
    await new Promise((r) => setTimeout(r, 2500));
  }
  boardCache = { data: null, ts: 0 };
  log("smart", `warm-up done: ${ledger.size} wallets from ${watchList.length} pools`);
}, 5000);
setInterval(async () => {
  smartTick++;
  try {
    if (smartTick % 50 === 0 || !watchList.length) await refreshWatchList();
    if (!watchList.length) return;
    const pool = watchList[watchIdx++ % watchList.length];
    await ingestPool(pool);
  } catch (e) { if (smartTick % 15 === 0) log("error", `smart wallets: ${e.message}`); }
  if (smartTick % 50 === 0) { try { pruneSmart(); saveSmart(); } catch (e) { log("error", `smart upkeep: ${e.message}`); } }
}, GT_PER_MIN >= 25 ? 9000 : 30000);   // keyed: every 9 s · keyless: every 30 s so users keep the budget

// ── access ──
async function smartAccess(wallet) {
  if (MY_WALLET && wallet === MY_WALLET) return { ok: true, via: "owner" };
  const paid = smartPaid.get(wallet);
  if (paid && paid.until > Date.now()) return { ok: true, via: "paid", until: paid.until };
  try {
    const s = await getHolderStatus(wallet);
    if (s.gold && s.gold.ok) return { ok: true, via: "gold" };
  } catch {}
  return { ok: false };
}
function smartPass(req, res) {
  const p = readPass(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
  if (!p) { res.status(401).json({ error: "Please sign in." }); return null; }
  return p.w;
}
async function requireSmart(req, res, next) {
  const w = smartPass(req, res); if (!w) return;
  const a = await smartAccess(w);
  if (!a.ok) return res.status(402).json({ error: "Smart Wallets is locked.", priceUsd: SMART_PRICE_USD, hours: SMART_MS / 3600e3 });
  req.smart = { wallet: w, ...a };
  next();
}

app.use("/api/smart", rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many requests. Slow down." } }));

/** Who am I, and am I in? */
app.get("/api/smart/status", async (req, res) => {
  const w = smartPass(req, res); if (!w) return;
  const a = await smartAccess(w);
  res.json({ wallet: w, access: a.ok, via: a.via || null, until: a.until || null, priceUsd: SMART_PRICE_USD,
             hours: SMART_MS / 3600e3, payable: !!MY_WALLET, learningSince: smartSince, tracked: ledger.size });
});

/** Build the payment for the user's wallet to sign. The server never signs or holds anything. */
app.post("/api/smart/quote", async (req, res) => {
  const w = smartPass(req, res); if (!w) return;
  if (!MY_WALLET) return res.status(503).json({ error: "Payments aren't set up yet." });
  try {
    const sol = await getSolUsd();
    const lamports = Math.ceil((SMART_PRICE_USD / sol) * 1e9);
    const reference = Keypair.generate().publicKey;
    const ix = SystemProgram.transfer({ fromPubkey: new PublicKey(w), toPubkey: new PublicKey(MY_WALLET), lamports });
    ix.keys.push({ pubkey: reference, isSigner: false, isWritable: false });   // tags this payment
    const { blockhash } = await withTimeout(connection.getLatestBlockhash("finalized"), 8000, "blockhash");
    const tx = new Transaction({ feePayer: new PublicKey(w), recentBlockhash: blockhash }).add(ix);
    smartQuotes.set(reference.toBase58(), { wallet: w, lamports, exp: Date.now() + 15 * 60e3 });
    if (smartQuotes.size > 5000) smartQuotes.delete(smartQuotes.keys().next().value);
    res.json({ message: b58encode(tx.serializeMessage()),
               transaction: tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString("base64"),
               lamports, sol: +(lamports / 1e9).toFixed(4), usd: SMART_PRICE_USD, hours: SMART_MS / 3600e3 });
  } catch (err) {
    log("error", `smart quote failed: ${err.message}`);
    res.status(502).json({ error: "Couldn't prepare the payment. Try again." });
  }
});

/**
 * Read the payment back from the chain. Access runs SMART_HOURS from the moment
 * the payment landed, so re-sending the same signature (say, after a restart)
 * only restores the same window; it can never stack.
 */
app.post("/api/smart/verify", async (req, res) => {
  const w = smartPass(req, res); if (!w) return;
  const sig = String((req.body || {}).signature || "");
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(sig)) return res.status(400).json({ error: "That isn't a valid transaction signature." });
  if (!MY_WALLET) return res.status(503).json({ error: "Payments aren't set up yet." });
  try {
    const tx = await withTimeout(connection.getParsedTransaction(sig, { maxSupportedTransactionVersion: 0, commitment: "confirmed" }), 10000, "payment");
    if (!tx) return res.status(404).json({ error: "Payment not confirmed yet. Give it a few seconds.", retry: true });
    if (tx.meta?.err) return res.status(400).json({ error: "That payment failed on-chain, so nothing was charged." });
    let lamports = 0;
    for (const ix of tx.transaction.message.instructions || [])
      if (ix.program === "system" && ix.parsed?.type === "transfer" && ix.parsed.info?.source === w && ix.parsed.info?.destination === MY_WALLET)
        lamports += Number(ix.parsed.info.lamports) || 0;
    if (!lamports) return res.status(400).json({ error: "That transaction isn't a payment from your wallet to SLAPBOT." });
    const at = (tx.blockTime || Math.floor(Date.now() / 1000)) * 1000;
    if (Date.now() - at > SMART_MS) return res.status(400).json({ error: "That payment's access window has already ended." });
    const keys = (tx.transaction.message.accountKeys || []).map((k) => (k.pubkey ? k.pubkey.toBase58() : String(k)));
    const quote = keys.map((k) => smartQuotes.get(k)).find((q) => q && q.wallet === w);
    let enough = quote ? lamports >= quote.lamports : false;
    if (!enough) enough = (lamports / 1e9) * (await getSolUsd()) >= SMART_PRICE_USD * 0.85;   // price drift allowance
    if (!enough) return res.status(400).json({ error: `That payment is less than $${SMART_PRICE_USD}.` });
    const prev = smartPaid.get(w) || { until: 0, sigs: [] };
    if (!prev.sigs.includes(sig)) {
      prev.until = Math.max(prev.until, at) + SMART_MS;
      prev.sigs = [...prev.sigs, sig].slice(-10);
      smartPaid.set(w, prev);
      saveSmart();
      log("smart", `${w.slice(0, 4)}…${w.slice(-4)} paid ${(lamports / 1e9).toFixed(4)} SOL — access until ${new Date(prev.until).toISOString()}`);
    }
    res.json({ access: prev.until > Date.now(), until: prev.until });
  } catch (err) {
    log("error", `smart verify failed: ${err.message}`);
    res.status(502).json({ error: "Couldn't reach Solana to check the payment. Try again.", retry: true });
  }
});

/** The leaderboard */
/**
 * GET /api/smart/early — tiny, young tokens smart wallets are buying, smallest first.
 * Falls back to the freshest low-volume launches with real buy pressure when no smart wallet is in yet.
 * Each one gets the on-chain basics checked (can the creator print or freeze?).
 */
app.get("/api/smart/early", requireSmart, async (req, res) => {
  const follow = new Set(String(req.query.follow || "").split(",").map((x) => x.trim()).filter((x) => SOL_ADDR.test(x)).slice(0, 50));
  const ranks = new Map(leaderboard().map((r) => [r.wallet, r.rank]));
  const smart = (w) => ranks.has(w) || follow.has(w);
  const now = Date.now(), since = now - 6 * 3600e3;
  const isEarly = (i) => i && i.createdAt && now - i.createdAt < 24 * 3600e3 && ((i.mcap && i.mcap < 150000) || (i.vol != null && i.vol < 75000));
  const by = new Map();
  for (const b of recentBuys) {
    if (b.at < since || !smart(b.w)) continue;
    const i = tokenInfo.get(b.t); if (!isEarly(i)) continue;
    const k = by.get(b.t) || { token: b.t, buyers: new Set(), usd: 0, last: 0, first: b.at }; k.buyers.add(b.w); k.usd += b.usd; k.last = Math.max(k.last, b.at); k.first = Math.min(k.first, b.at); by.set(b.t, k);
  }
  const sold = new Set(recentSells.filter((x) => x.at >= since && smart(x.w)).map((x) => x.t));
  let rows = [...by.values()].map((k) => ({ ...k, smartBuyers: k.buyers.size, backed: true }));
  if (rows.length < 10) {                       // nobody smart in yet: show the freshest launches with real buying
    for (const [t, i] of tokenInfo) {
      if (by.has(t) || !i.early || !isEarly(i)) continue;
      const tx = (i.buys || 0) + (i.sells || 0);
      if (tx < 15 || (i.buys || 0) / Math.max(1, tx) < 0.55) continue;
      rows.push({ token: t, buyers: new Set(), usd: 0, last: i.ts, first: i.createdAt, smartBuyers: 0, backed: false });
    }
  }
  rows = rows.map((r) => { const i = tokenInfo.get(r.token) || {};
    return { token: r.token, sym: i.sym || "?", mcap: i.mcap || null, vol: i.vol ?? null, liq: i.liq ?? null, price: i.price || null,
      createdAt: i.createdAt || null, buys: i.buys || 0, sells: i.sells || 0, smartBuyers: r.smartBuyers, smartUsd: +r.usd.toFixed(2),
      firstSmartBuy: r.backed ? r.first : null, smartSelling: sold.has(r.token), backed: r.backed }; })
    .sort((a, b) => (b.smartBuyers - a.smartBuyers) || ((a.mcap || 9e9) - (b.mcap || 9e9))).slice(0, 25);
  // on-chain basics for each (cached 5 min per token, so this stays quick)
  const checks = await Promise.allSettled(rows.map((r) => withTimeout(getMintCheck(r.token), 6000, "early check")));
  rows.forEach((r, i) => { const c = checks[i].status === "fulfilled" ? checks[i].value : null;
    r.safety = c && c.found ? { canPrint: !c.mintAuthorityRenounced, canFreeze: !c.freezeAuthorityRenounced, top10: c.top10WalletPct ?? c.top10HolderPct ?? null } : null; });
  res.json({ updated: now, tokens: rows });
});

app.get("/api/smart/top", requireSmart, (req, res) => {
  res.json({ updated: Date.now(), learningSince: smartSince, tracked: ledger.size, watching: watchList.length, wallets: leaderboard() });
});

/** Live buys from top wallets, plus any wallets the user follows (?follow=a,b,c) */
/** What happened after a buy: has this wallet sold this token since? */
function exitOf(w, t, after) {
  const p = ledger.get(w)?.get(t);
  if (!p || !p.ls || p.ls < after || !(p.bt > 0)) return null;
  return { soldPct: Math.min(100, Math.round((p.st / p.bt) * 100)), at: p.ls };
}
/** Tokens smart wallets are dumping right now: the "don't chase it" list. */
function dontChase(ranks, follow, hours) {
  const since = Date.now() - hours * 3600e3, by = new Map();
  const smart = (w) => ranks.has(w) || follow.has(w);
  for (const x of recentSells) if (x.at >= since && smart(x.w)) {
    const k = by.get(x.t) || { token: x.t, sym: tokenInfo.get(x.t)?.sym || "?", sellers: new Set(), soldUsd: 0, buyers: new Set(), boughtUsd: 0, last: 0 };
    k.sellers.add(x.w); k.soldUsd += x.usd; k.last = Math.max(k.last, x.at); by.set(x.t, k);
  }
  for (const x of recentBuys) if (x.at >= since && smart(x.w) && by.has(x.t)) { const k = by.get(x.t); k.buyers.add(x.w); k.boughtUsd += x.usd; }
  return [...by.values()].filter((k) => k.soldUsd > k.boughtUsd * 0.6 || k.sellers.size >= 2)
    .map((k) => ({ token: k.token, sym: k.sym, sellers: k.sellers.size, soldUsd: +k.soldUsd.toFixed(2), buyers: k.buyers.size,
                   boughtUsd: +k.boughtUsd.toFixed(2), last: k.last, price: tokenInfo.get(k.token)?.price || null }))
    .sort((a, b) => b.soldUsd - a.soldUsd).slice(0, 30);
}

/** Live feed: buys AND sells from top + followed wallets, each buy marked if they've since exited */
app.get("/api/smart/feed", requireSmart, (req, res) => {
  const follow = new Set(String(req.query.follow || "").split(",").map((s) => s.trim())
    .filter((s) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s)).slice(0, 50));
  const ranks = new Map(leaderboard().map((r) => [r.wallet, r.rank]));
  const since = Date.now() - 6 * 3600e3;
  const smart = (w) => ranks.has(w) || follow.has(w);
  const row = (b, kind, extra) => ({ kind, wallet: b.w, rank: ranks.get(b.w) || null, followed: follow.has(b.w), token: b.t,
    sym: tokenInfo.get(b.t)?.sym || "?", usd: b.usd, at: b.at, tx: b.tx, price: tokenInfo.get(b.t)?.price || null,
    exit: kind === "buy" ? exitOf(b.w, b.t, b.at) : null, ...(extra || {}) });
  const items = recentBuys.filter((b) => b.at >= since && smart(b.w)).map((b) => row(b, "buy"))
    .concat(recentSells.filter((b) => b.at >= since && smart(b.w)).map((b) => row(b, "sell")));
  if (items.length < 15) {                     // big trades fill in while smart money is still being learned
    const have = new Set(items.map((b) => b.tx)), cut = Date.now() - 2 * 3600e3;
    recentBuys.filter((b) => b.at >= cut && b.usd >= 500 && !have.has(b.tx)).forEach((b) => items.push(row(b, "buy", { big: true })));
    recentSells.filter((b) => b.at >= cut && b.usd >= 500 && !have.has(b.tx)).forEach((b) => items.push(row(b, "sell", { big: true })));
  }
  items.sort((a, b) => b.at - a.at);
  const list = items.slice(0, 100);
  res.json({ updated: Date.now(), buys: list.filter((x) => x.kind === "buy"), trades: list, dontChase: dontChase(ranks, follow, 3) });
});

/** One wallet's full record */
app.get("/api/smart/wallet/:addr", requireSmart, (req, res) => {
  const w = String(req.params.addr || "");
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(w)) return res.status(400).json({ error: "Invalid wallet" });
  const m = ledger.get(w);
  if (!m) return res.json({ wallet: w, known: false });
  const s = walletStats(m);
  res.json({ wallet: w, known: true, rank: leaderboard().find((r) => r.wallet === w)?.rank || null, ...s,
             recentBuys: recentBuys.filter((b) => b.w === w).slice(-20).reverse()
               .map((b) => ({ token: b.t, sym: tokenInfo.get(b.t)?.sym || "?", usd: b.usd, at: b.at, tx: b.tx, exit: exitOf(w, b.t, b.at) })),
             recentSells: recentSells.filter((b) => b.w === w).slice(-20).reverse()
               .map((b) => ({ token: b.t, sym: tokenInfo.get(b.t)?.sym || "?", usd: b.usd, at: b.at, tx: b.tx })) });
});

// ═══════════════════════════════════════════════════════════════════════
// ⑫ LIVE WALLET ALERTS — a buy by a top or followed wallet, within seconds
// ═══════════════════════════════════════════════════════════════════════
/**
 * The leaderboard learns from pool trades, which can lag by minutes. Alerts don't:
 * the bot opens a live line to Solana for each watched wallet (top wallets +
 * wallets people follow) and hears every transaction the moment it confirms.
 * It reads the transaction, and if the wallet's balance of some token went UP
 * while its SOL or stablecoins went DOWN, that's a buy. It fires an alert.
 *
 * Stacking: when 2+ smart wallets buy the same token within 30 minutes, the alert
 * says so. That's the closest thing to "before": it's usually early in a move.
 */
const ALERT_MAX_WALLETS = Math.max(5, parseInt(process.env.ALERT_MAX_WALLETS || "80", 10));
const ALERT_TOP_N = Math.max(0, parseInt(process.env.ALERT_TOP_N || "25", 10));
const NOT_A_BUY = new Set(["So11111111111111111111111111111111111111112",
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"]);
const STABLES = new Set(["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"]);

const liveSubs = new Map();      // wallet → subscription id
const followDemand = new Map();  // wallet → last time someone asked to follow it
const alertSeen = new Set();     // tx signatures already handled
const alertBuySigs = new Set();  // buys recorded live, so pool reads don't count them twice
const walletRate = new Map();    // wallet → { n, ts } — caps tx reads per wallet per minute
let alerts = [];                 // { w, t, sym, usd, at, seen, tx, stack }
let alertQueue = [], alertBusy = 0;
const metaCache = new Map();

async function symbolFor(mint) {
  const i = tokenInfo.get(mint);
  if (i && i.sym && i.sym !== "?") return i.sym;
  if (metaCache.has(mint)) return metaCache.get(mint);
  let sym = "?";
  try { const md = await readMetadata(mint); if (md?.symbol) sym = String(md.symbol).replace(/[^\w$.\- ]/g, "").slice(0, 16) || "?"; } catch {}
  metaCache.set(mint, sym);
  if (metaCache.size > 3000) metaCache.delete(metaCache.keys().next().value);
  return sym;
}

/** Pure: did this wallet buy or sell a token in this parsed transaction? */
function readTrade(tx, w, solPrice) {
  if (!tx || tx.meta?.err) return null;
  const keys = (tx.transaction?.message?.accountKeys || []).map((k) => (k.pubkey ? k.pubkey.toBase58() : String(k)));
  const i = keys.indexOf(w);
  if (i < 0) return null;
  const delta = new Map();
  for (const b of tx.meta.preTokenBalances || []) if (b.owner === w) delta.set(b.mint, (delta.get(b.mint) || 0) - (+b.uiTokenAmount?.uiAmount || 0));
  for (const b of tx.meta.postTokenBalances || []) if (b.owner === w) delta.set(b.mint, (delta.get(b.mint) || 0) + (+b.uiTokenAmount?.uiAmount || 0));
  let up = null, down = null;
  for (const [mint, d] of delta) {
    if (NOT_A_BUY.has(mint)) continue;
    if (d > 0 && (!up || d > up.amount)) up = { mint, amount: d };
    if (d < 0 && (!down || -d > down.amount)) down = { mint, amount: -d };
  }
  const fee = i === 0 ? (tx.meta.fee || 0) : 0;
  const lam = (tx.meta.postBalances?.[i] ?? 0) - (tx.meta.preBalances?.[i] ?? 0) + fee;   // SOL moved, fee excluded
  const wsol = delta.get("So11111111111111111111111111111111111111112") || 0;
  let spent = (lam < 0 ? -lam / 1e9 : 0) * solPrice + (wsol < 0 ? -wsol * solPrice : 0);
  let got = (lam > 0 ? lam / 1e9 : 0) * solPrice + (wsol > 0 ? wsol * solPrice : 0);
  for (const s of STABLES) { const d = delta.get(s) || 0; if (d < 0) spent += -d; else got += d; }
  const at = (tx.blockTime || Math.floor(Date.now() / 1000)) * 1000;
  if (up && spent >= 20) return { side: "buy", mint: up.mint, amount: up.amount, usd: +spent.toFixed(2), at };
  if (down && got >= 20) return { side: "sell", mint: down.mint, amount: down.amount, usd: +got.toFixed(2), at };
  return null;                              // dust, airdrops and plain transfers aren't trades
}
const readBuy = (tx, w, solPrice) => { const t = readTrade(tx, w, solPrice); return t && t.side === "buy" ? t : null; };

async function handleWalletTx(w, sig) {
  try {
    const read = () => withTimeout(connection.getParsedTransaction(sig, { maxSupportedTransactionVersion: 0, commitment: "confirmed" }), 9000, "alert tx");
    let tx = await read();
    if (!tx) { await new Promise((r) => setTimeout(r, 1500)); tx = await read(); }   // just-confirmed txs can take a moment to index
    let sol = 0; try { sol = await getSolUsd(); } catch {}
    const buy = readTrade(tx, w, sol || 150);
    if (!buy) return;
    const sym = await symbolFor(buy.mint);
    const now = Date.now();
    if (buy.side === "sell") {               // an exit: record it and raise a "don't chase" alert
      let m = ledger.get(w); if (!m) { m = new Map(); ledger.set(w, m); }
      const p = m.get(buy.mint) || { b: 0, bt: 0, s: 0, st: 0, n: 0, f: buy.at, l: buy.at };
      p.s += buy.usd; p.st += buy.amount; p.n++; p.ls = Math.max(p.ls || 0, buy.at); p.l = Math.max(p.l, buy.at); m.set(buy.mint, p);
      recentSells.push({ w, t: buy.mint, usd: buy.usd, at: buy.at, tx: sig });
      if (typeof mpCopySell === "function") mpCopySell(w, buy.mint);
      alerts.push({ kind: "sell", w, t: buy.mint, sym, usd: buy.usd, at: buy.at, seen: now, tx: sig, stack: 0,
                    soldPct: p.bt > 0 ? Math.min(100, Math.round((p.st / p.bt) * 100)) : null });
      alertBuySigs.add(sig);
      log("alert", `${w.slice(0, 4)}… SOLD ${sym} $${buy.usd}`);
      return;
    }
    const stack = new Set(alerts.filter((a) => a.kind !== "sell" && a.t === buy.mint && now - a.seen < 30 * 60e3).map((a) => a.w).concat(w)).size;
    alerts.push({ kind: "buy", w, t: buy.mint, sym, usd: buy.usd, at: buy.at, seen: now, tx: sig, stack });
    try { const board = leaderboard(), idx = board.findIndex((r) => r.wallet === w);
      if (idx >= 0 && board[idx].tier !== "early" && typeof mpCopyBuy === "function") mpCopyBuy(w, buy.mint, sym, buy.usd, idx + 1, stack).catch(() => {}); } catch {}
    alertBuySigs.add(sig); if (alertBuySigs.size > 20000) for (const x of [...alertBuySigs].slice(0, 10000)) alertBuySigs.delete(x);
    if (alerts.length > 600) alerts = alerts.slice(-500);
    // feed the learning ledger too, so live buys count toward the leaderboard
    let m = ledger.get(w); if (!m) { m = new Map(); ledger.set(w, m); }
    const p = m.get(buy.mint) || { b: 0, bt: 0, s: 0, st: 0, n: 0, f: buy.at, l: buy.at };
    p.b += buy.usd; p.bt += buy.amount; p.n++; p.lb = Math.max(p.lb || 0, buy.at); p.l = Math.max(p.l, buy.at); m.set(buy.mint, p);
    if (!tokenInfo.has(buy.mint)) tokenInfo.set(buy.mint, { sym, price: buy.usd / buy.amount, pool: null, ts: now });
    recentBuys.push({ w, t: buy.mint, usd: buy.usd, at: buy.at, tx: sig });
    log("alert", `${w.slice(0, 4)}… bought ${sym} $${buy.usd}${stack > 1 ? ` — ${stack} smart wallets in` : ""} (${((now - buy.at) / 1000).toFixed(0)}s after the block)`);
  } catch (e) { /* one unreadable tx never matters */ }
}

function pumpAlertQueue() {
  while (alertBusy < 3 && alertQueue.length) {
    const job = alertQueue.shift();
    alertBusy++;
    handleWalletTx(job.w, job.sig).finally(() => { alertBusy--; pumpAlertQueue(); });
  }
}

function onWalletLogs(w, logs) {
  const sig = logs?.signature;
  if (!sig || logs.err || alertSeen.has(sig)) return;
  alertSeen.add(sig);
  if (alertSeen.size > 20000) for (const s of [...alertSeen].slice(0, 10000)) alertSeen.delete(s);
  const r = walletRate.get(w) || { n: 0, ts: Date.now() };
  if (Date.now() - r.ts > 60e3) { r.n = 0; r.ts = Date.now(); }
  if (++r.n > 20) return;                     // a wallet spamming 20+ txs a minute is a bot, skip the rest
  walletRate.set(w, r);
  if (alertQueue.length < 300) { alertQueue.push({ w, sig }); pumpAlertQueue(); }
}

/** Keep live lines open to exactly the wallets that matter right now. */
async function syncLiveWallets() {
  const now = Date.now();
  for (const [w, t] of followDemand) if (now - t > 6 * 3600e3) followDemand.delete(w);
  const want = new Set();
  for (const r of leaderboard().slice(0, ALERT_TOP_N)) { if (want.size >= ALERT_MAX_WALLETS) break; want.add(r.wallet); }
  for (const w of [...followDemand.keys()].sort((a, b) => followDemand.get(b) - followDemand.get(a))) { if (want.size >= ALERT_MAX_WALLETS) break; want.add(w); }
  for (const [w, id] of liveSubs) if (!want.has(w)) { liveSubs.delete(w); try { await connection.removeOnLogsListener(id); } catch {} }
  for (const w of want) {
    if (liveSubs.has(w)) continue;
    try { liveSubs.set(w, connection.onLogs(new PublicKey(w), (l) => onWalletLogs(w, l), "confirmed")); }
    catch (e) { log("error", `live line to ${w.slice(0, 4)}… failed: ${e.message}`); }
  }
}
setTimeout(() => syncLiveWallets().catch(() => {}), 15000);
setInterval(() => syncLiveWallets().catch((e) => log("error", `live wallets: ${e.message}`)), 60000);
setInterval(() => { const cut = Date.now() - 24 * 3600e3; alerts = alerts.filter((a) => a.seen > cut); }, 10 * 60e3);

/**
 * GET /api/smart/alerts?since=<ms>&follow=a,b,c
 * New buys by top wallets and the caller's followed wallets. Asking also tells
 * the bot to keep a live line open to those followed wallets.
 */
app.get("/api/smart/alerts", requireSmart, (req, res) => {
  const follow = String(req.query.follow || "").split(",").map((s) => s.trim()).filter((s) => SOL_ADDR.test(s)).slice(0, 25);
  const now = Date.now();
  let added = false;
  for (const w of follow) { if (!followDemand.has(w)) added = true; followDemand.set(w, now); }
  if (followDemand.size > 2000) for (const k of [...followDemand.keys()].slice(0, 1000)) followDemand.delete(k);
  if (added) syncLiveWallets().catch(() => {});
  const since = Math.max(now - 6 * 3600e3, +req.query.since || 0);
  const ranks = new Map(leaderboard().map((r) => [r.wallet, r.rank]));
  const mine = new Set(follow);
  const out = alerts.filter((a) => a.seen > since && (ranks.has(a.w) || mine.has(a.w) || liveSubs.has(a.w)))
    .slice(-60).reverse()
    .map((a) => ({ kind: a.kind || "buy", wallet: a.w, rank: ranks.get(a.w) || null, followed: mine.has(a.w), token: a.t, sym: a.sym,
                   usd: a.usd, at: a.at, seen: a.seen, tx: a.tx, stack: a.stack, soldPct: a.soldPct ?? null,
                   exit: (a.kind || "buy") === "buy" ? exitOf(a.w, a.t, a.at) : null }));
  res.json({ now, live: liveSubs.size, alerts: out });
});

// ═══════════════════════════════════════════════════════════════════════
// ⑬ LOW SUPPLY FINDER — small-supply tokens on every chain, like $SLAPGOLD
// ═══════════════════════════════════════════════════════════════════════
/**
 * Nobody can list "every token on every chain" (there are millions, most dead).
 * What the bot CAN do: keep sweeping the newest and trending pools across all
 * networks, read each token's real total supply, and keep the ones at or under
 * LOW_SUPPLY_MAX (default 1,000,000) that have real liquidity. One chain gets a
 * deep look every round, so over time every network is covered.
 *
 * Zcash: ZEC is its own network, but it has no tokens or DEX pools to scan yet.
 * Zcash Shielded Assets (custom tokens) are scheduled with Network Upgrade 7.
 * The bot shows ZEC's price now and is ready to add Zcash tokens once they exist
 * and are indexed.
 */
const LOW_SUPPLY_MAX = Math.max(1, parseFloat(process.env.LOW_SUPPLY_MAX || "1000000"));
const LOW_MIN_LIQ = Math.max(0, parseFloat(process.env.LOW_MIN_LIQ || "1000"));
const lowSupply = new Map();        // gid:addr → token record
const supplyKnown = new Map();      // gid:addr → { supply, ts } (big ones too, so we don't re-ask)
let lowRound = 0, lowChainIdx = 0, lowLastRun = 0;

function poolRows(raw) {
  const inc = raw.included || [], n = (v) => (Number.isFinite(+v) ? +v : 0);
  return (raw.data || []).map((p) => {
    const a = p.attributes || {}, btId = p.relationships?.base_token?.data?.id || "";
    const bt = inc.find((x) => x.id === btId);
    const gid = p.relationships?.network?.data?.id || btId.slice(0, btId.indexOf("_"));
    return { gid, addr: btId.slice(btId.indexOf("_") + 1), pool: a.address || "",
      sym: String(bt?.attributes?.symbol || (a.name || "").split("/")[0].trim() || "?").replace(/[^\w$.\- ]/g, "").slice(0, 16) || "?",
      name: String(bt?.attributes?.name || "").replace(/[<>"'&]/g, "").slice(0, 40),
      price: n(a.base_token_price_usd), mcap: n(a.market_cap_usd) || n(a.fdv_usd), liq: n(a.reserve_in_usd),
      vol: n(a.volume_usd?.h24), ch24: n(a.price_change_percentage?.h24),
      createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null };
  }).filter((r) => r.gid && r.addr && SAFE_ADDR.test(r.addr) && SAFE_ADDR.test(r.pool) && r.price > 0 && !WRAPPED_NOISE.has(r.sym.toUpperCase()));
}

async function sweepLowSupply() {
  lowRound++; lowLastRun = Date.now();
  const nets = await getGeckoNetworks();
  const back = {}; for (const d of DEX_CHAINS) { const g = pickGecko(d, nets); if (g) back[g] = d; }
  back.solana = "solana";
  // global new + trending every round, plus one chain's new pools in depth (rotates through all)
  const paths = ["/networks/new_pools?include=base_token,network&page=1", "/networks/trending_pools?include=base_token,network&page=1"];
  if (lowRound % 2 === 0) paths.push("/networks/new_pools?include=base_token,network&page=2");
  const chain = DEX_CHAINS[lowChainIdx++ % DEX_CHAINS.length], cg = await resolveGecko(chain).catch(() => null);
  if (cg) paths.push(`/networks/${cg}/new_pools?include=base_token,network&page=1`);
  const rows = [];
  for (const p of paths) { try { rows.push(...poolRows(await geckoAny(p, 9000, "bg"))); } catch {} }

  // read supply for tokens we haven't seen, 30 per call, grouped by network
  const need = new Map();
  for (const r of rows) {
    const k = r.gid + ":" + r.addr;
    if (supplyKnown.has(k) || r.liq < LOW_MIN_LIQ) continue;
    (need.get(r.gid) || need.set(r.gid, []).get(r.gid)).push(r.addr);
  }
  let calls = 0;
  for (const [gid, addrs] of need) {
    for (let i = 0; i < addrs.length && calls < 6; i += 30, calls++) {
      try {
        const d = await geckoAny(`/networks/${gid}/tokens/multi/${[...new Set(addrs.slice(i, i + 30))].join(",")}`, 9000, "bg");
        for (const t of d.data || []) {
          const a = t.attributes || {}, addr = String(a.address || t.id.slice(t.id.indexOf("_") + 1));
          let sup = +a.normalized_total_supply;
          if (!(sup > 0)) { const raw = +a.total_supply, dec = +a.decimals; sup = raw > 0 && dec >= 0 && dec < 40 ? raw / 10 ** dec : 0; }
          if (sup > 0) supplyKnown.set(gid + ":" + addr, { supply: sup, ts: Date.now() });
        }
      } catch {}
    }
  }
  if (supplyKnown.size > 50000) for (const k of [...supplyKnown.keys()].slice(0, 20000)) supplyKnown.delete(k);

  // keep the small ones, best pool per token
  let added = 0;
  for (const r of rows) {
    const k = r.gid + ":" + r.addr, s = supplyKnown.get(k);
    if (!s || s.supply > LOW_SUPPLY_MAX || r.liq < LOW_MIN_LIQ) continue;
    const prev = lowSupply.get(k);
    if (prev && prev.liq > r.liq) { prev.lastSeen = Date.now(); continue; }
    if (!prev) added++;
    lowSupply.set(k, { ...r, chain: back[r.gid] || r.gid, supply: s.supply, mcap: r.mcap || +(r.price * s.supply).toFixed(2),
      firstSeen: prev ? prev.firstSeen : Date.now(), lastSeen: Date.now(),
      graded: r.gid === "solana" || !!GOPLUS[back[r.gid]] });
  }
  const cut = Date.now() - 7 * 24 * 3600e3;
  for (const [k, t] of lowSupply) if (t.lastSeen < cut) lowSupply.delete(k);
  if (lowSupply.size > 1500) [...lowSupply].sort((a, b) => a[1].lastSeen - b[1].lastSeen).slice(0, lowSupply.size - 1500).forEach(([k]) => lowSupply.delete(k));
  if (added) log("lowsupply", `+${added} low-supply tokens (${lowSupply.size} total, deep look: ${chain})`);
}
setTimeout(() => sweepLowSupply().catch(() => {}), 20000);
setInterval(() => sweepLowSupply().catch((e) => log("error", `low supply: ${e.message}`)), 120000);

/** Zcash: price and network status. Cached 2 minutes. */
let zecCache = { data: null, ts: 0 };
async function zcashStatus() {
  if (zecCache.data && Date.now() - zecCache.ts < 120000) return zecCache.data;
  let price = null, ch24 = null;
  try {
    const r = await withTimeout(fetch("https://api.coingecko.com/api/v3/simple/price?ids=zcash&vs_currencies=usd&include_24hr_change=true"), 6000, "ZEC");
    const z = (await r.json())?.zcash; price = +z?.usd || null; ch24 = Number.isFinite(+z?.usd_24h_change) ? +z.usd_24h_change : null;
  } catch {}
  const data = { symbol: "ZEC", network: "Zcash", price, ch24, tokens: 0,
    note: "Zcash is its own network, but it has no tokens or DEX pools yet. Custom tokens (Zcash Shielded Assets) are scheduled with Network Upgrade 7. SLAPBOT adds them once they exist and are indexed." };
  zecCache = { data, ts: Date.now() };
  return data;
}

/**
 * GET /api/lowsupply?max=1000000&chain=all&sort=new|vol|mcap|supply
 * Public. Every low-supply token the bot has found, newest first by default.
 */
app.get("/api/lowsupply", async (req, res) => {
  const max = Math.min(LOW_SUPPLY_MAX, Math.max(1, +req.query.max || LOW_SUPPLY_MAX));
  const chain = String(req.query.chain || "all").toLowerCase();
  const sort = ["new", "vol", "mcap", "supply", "liq"].includes(req.query.sort) ? req.query.sort : "new";
  let list = [...lowSupply.values()].filter((t) => t.supply <= max && (chain === "all" || t.chain === chain));
  const by = { new: (a, b) => (b.createdAt || b.firstSeen) - (a.createdAt || a.firstSeen), vol: (a, b) => b.vol - a.vol,
               mcap: (a, b) => b.mcap - a.mcap, supply: (a, b) => a.supply - b.supply, liq: (a, b) => b.liq - a.liq }[sort];
  list.sort(by);
  const chains = {}; for (const t of lowSupply.values()) chains[t.chain] = (chains[t.chain] || 0) + 1;
  res.json({ updated: lowLastRun, max, total: lowSupply.size, chains, zcash: await zcashStatus(),
             tokens: list.slice(0, 200).map(({ gid, ...t }) => t) });
});

// ═══════════════════════════════════════════════════════════════════════
// ⑭ RISK ENGINE — every scam check SLAPBOT can verify, one clear verdict
// ═══════════════════════════════════════════════════════════════════════
/**
 * GET /api/risk/:chain/:address
 *   verdict: "DANGER" (do not touch) | "RISKY" | "CAUTION" | "PASSED" | "UNVERIFIED"
 *   flags:   [{ level: "danger"|"risk"|"caution", text }] in plain words
 *
 * Solana (read straight from the chain):
 *   freeze authority · mint authority · Token-2022 traps (permanent delegate that can
 *   take your tokens, transfer hooks, transfer fees, non-transferable, frozen-by-default)
 *   · creator can rewrite name/logo · copycat of a famous coin · top-10 concentration
 * EVM chains (13, contract scan): honeypot · can't sell · hidden owner · owner can take
 *   back control or change balances · blacklist · pause · taxes and changeable taxes ·
 *   self-destruct · proxy · unverified code · concentration
 * Every chain with a market: liquidity pulled · thin liquidity · buys with zero sells
 *   (can't-sell pattern) · fake volume · price crash in progress · brand new
 *
 * No scanner can promise a token is safe. PASSED means none of these checks fired.
 */
const REAL_SOLANA = { SOL: "So11111111111111111111111111111111111111112", WSOL: "So11111111111111111111111111111111111111112",
  USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", USDT: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  JUP: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", BONK: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
  WIF: "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm", TRUMP: "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN",
  PYTH: "HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3", RAY: "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
  POPCAT: "7GCihgDB8fe6KNjn2MYtkzZcRjQy3t9GHdC8uHYmW2hr",
  SLAPGOLD: "4R7Hbdhh3YeVqZaESRA3qPJ8Z3xh3Qedsw88RDjxL1Q9" };
const FAMOUS = new Set(["USDC", "USDT", "ETH", "WETH", "BTC", "WBTC", "BNB", "SOL", "DAI", "PEPE", "SHIB"]);
const TOKEN_2022 = "TokenzQdBNbLqP7VKhdWAWwN6r4LnNWTJ6cB5wT3wP";

/** Pure: read update authority + "can it still be changed" from a Metaplex metadata account. */
function decodeMetaMutability(data) {
  try {
    const updateAuthority = new PublicKey(data.subarray(1, 33)).toBase58();
    let o = 65;
    for (let i = 0; i < 3; i++) { const n = data.readUInt32LE(o); o += 4 + n; }   // name, symbol, uri
    o += 2;                                                                       // seller fee
    if (data[o++] === 1) { const n = data.readUInt32LE(o); o += 4 + n * 34; }    // creators
    o += 1;                                                                       // primary sale
    return { updateAuthority, isMutable: data[o] === 1 };
  } catch { return null; }
}

/** Pure: turn raw findings into flags and a verdict. */
function verdictOf(flags, verified, complete = true) {
  if (flags.some((f) => f.level === "danger")) return "DANGER";
  if (flags.some((f) => f.level === "risk")) return "RISKY";
  if (!verified) return "UNVERIFIED";
  if (!complete) return "UNVERIFIED";            // a check didn't run: never call that clean
  if (flags.some((f) => f.level === "caution")) return "CAUTION";
  return "PASSED";
}
function marketFlags(m, flags) {
  if (!m) return;
  if (!m.onCurve && !(m.liq > 0) && !(m.mcap > 0)) {
    flags.push({ level: "danger", text: "No working market: the liquidity is gone or was never there. You likely can't sell. (This is what a rugged token looks like.)" });
    return;
  }
  if (!m.onCurve && m.liq > 0 && m.liq < 500) {
    flags.push({ level: "danger", text: `Liquidity is basically gone ($${Math.round(m.liq)}): it was pulled or drained. Rugged.` });
    return;
  }
  if (m.mcap > 0 && m.vol24 > m.mcap * 15)
    flags.push({ level: "risk", text: `24h volume is ${Math.round(m.vol24 / m.mcap)}x the whole market cap: that much trading on a coin this size is usually fake` });
  else if (m.mcap > 0 && m.vol24 > m.mcap * 6)
    flags.push({ level: "caution", text: `24h volume is ${Math.round(m.vol24 / m.mcap)}x the market cap: very heavy trading for its size, check the trade tape` });
  if (m.onCurve) {
    // Pre-graduation pump.fun: you sell back to the bonding curve, not a pool, so
    // "pool liquidity" numbers don't apply. The honest risk is how early it is.
    flags.push({ level: "caution", text: `Still on its launch curve (${m.progress != null ? m.progress.toFixed(1) + "% to graduation" : "not graduated"}): early and small, so prices swing hard` });
    if (m.ch24 != null && m.ch24 <= -70) flags.push({ level: "risk", text: `Down ${Math.round(-m.ch24)}% in 24 hours` });
    if (m.createdAt && Date.now() - m.createdAt < 6 * 3600e3) flags.push({ level: "caution", text: "Under 6 hours old" });
    return;
  }
  const liq = +m.liq || 0, mcap = +m.mcap || 0, vol = +m.vol24 || 0, buys = +m.buys24 || 0, sells = +m.sells24 || 0;
  if (mcap > 5000 && liq > 0 && liq < mcap * 0.01 && liq < 50000) flags.push({ level: "danger", text: `Liquidity looks pulled ($${Math.round(liq).toLocaleString("en-US")} behind a $${Math.round(mcap).toLocaleString("en-US")} market cap)` });
  else if (liq > 0 && liq < 1000) flags.push({ level: "risk", text: `Very thin liquidity ($${Math.round(liq).toLocaleString("en-US")}), so selling can crash the price` });
  else if (liq > 0 && liq < 5000) flags.push({ level: "caution", text: `Thin liquidity ($${Math.round(liq).toLocaleString("en-US")}): big sells will move the price a lot` });
  if (buys >= 40 && sells === 0) flags.push({ level: "danger", text: `${buys} buys and zero sells today: classic can't-sell trap` });
  else if (buys >= 60 && sells > 0 && sells / buys < 0.05) flags.push({ level: "risk", text: `Almost nobody is selling (${sells} sells vs ${buys} buys): selling may be blocked` });
  if (liq > 0 && vol / liq > 60) flags.push({ level: "risk", text: `Volume is ${Math.round(vol / liq)}x the liquidity: likely fake (wash) trading` });
  if (m.ch24 != null && m.ch24 <= -70) flags.push({ level: "risk", text: `Down ${Math.round(-m.ch24)}% in 24 hours: possible rug in progress` });
  if (m.createdAt && Date.now() - m.createdAt < 6 * 3600e3) flags.push({ level: "caution", text: "Under 6 hours old" });
  else if (m.createdAt && Date.now() - m.createdAt < 24 * 3600e3) flags.push({ level: "caution", text: "Under a day old" });
}

/**
 * RUG REGISTRY — SLAPBOT's own record of wallets tied to rugs. It never forgets (once the
 * server has a disk), and it grows from three places:
 *   1. its own scans: a token whose liquidity was pulled marks its creator; bundle wallets
 *      on a token that's being dumped get marked too
 *   2. ALKAID's launch watcher: a creator whose token got dumped while they sold out
 *   3. the second opinion: when it calls a token a rug, the creator is noted
 */
const RUG_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "rug-registry.json") : "";
const rugReg = new Map();          // wallet → { role, rugs: [{ mint, sym, at, how }], first }
if (RUG_FILE) { try { if (nodeFs.existsSync(RUG_FILE)) for (const [w, v] of JSON.parse(nodeFs.readFileSync(RUG_FILE, "utf8"))) rugReg.set(w, v); } catch {} }
let rugDirty = false;
function markRug(wallet, info) {
  if (!wallet || !SOL_ADDR_RX.test(wallet)) return;
  const e = rugReg.get(wallet) || { role: info.role, rugs: [], first: Date.now() };
  if (info.role === "creator") e.role = "creator";                       // creator outranks bundler
  if (!e.rugs.some((r) => r.mint === info.mint)) e.rugs.push({ mint: info.mint, sym: String(info.sym || "?").slice(0, 16), at: Date.now(), how: String(info.how || "").slice(0, 120) });
  e.rugs = e.rugs.slice(-20);
  rugReg.set(wallet, e); rugDirty = true;
  if (rugReg.size > 100000) rugReg.delete(rugReg.keys().next().value);
}
const SOL_ADDR_RX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
setInterval(() => {
  if (!rugDirty || !RUG_FILE) return;
  try { const tmp = RUG_FILE + ".tmp"; nodeFs.writeFileSync(tmp, JSON.stringify([...rugReg])); nodeFs.renameSync(tmp, RUG_FILE); rugDirty = false; }
  catch (e) { log("error", `saving rug registry: ${e.message}`); }
}, 5 * 60000);
function rugLine(e) {
  const last = e.rugs[e.rugs.length - 1], days = Math.max(0, Math.round((Date.now() - last.at) / 864e5));
  return `${e.rugs.length} rug${e.rugs.length === 1 ? "" : "s"} on record, last one ${last.sym} ${days ? days + " day" + (days === 1 ? "" : "s") + " ago" : "today"} (${last.how})`;
}

/**
 * Pure: read the recent trade tape for the patterns that come before rugs.
 *   wash trading  — the same few wallets trading back and forth, robot-identical sizes
 *   bundled launch — many different wallets buying in the very same block (usually one person)
 *   dump underway — big sells in the last 15 minutes versus the pool's liquidity
 * trades: [{ kind, usd, wallet, block, at }]
 */
function tapeFlags(trades, liq, createdAt, now = Date.now()) {
  const f = [], stats = {};
  const tr = (trades || []).filter((t) => t && t.usd > 0 && t.wallet);
  const n = tr.length;
  if (n >= 40) {
    const wallets = new Map();
    for (const t of tr) { const w = wallets.get(t.wallet) || { b: 0, s: 0, usd: 0 }; t.kind === "sell" ? w.s++ : w.b++; w.usd += t.usd; wallets.set(t.wallet, w); }
    const uniq = wallets.size, ratio = uniq / n, total = tr.reduce((a, t) => a + t.usd, 0);
    stats.trades = n; stats.wallets = uniq;
    if (ratio < 0.1) f.push({ level: "danger", text: `Only ${uniq} wallets made the last ${n} trades: fake volume (wash trading)` });
    else if (ratio < 0.2) f.push({ level: "risk", text: `Only ${uniq} wallets made the last ${n} trades: likely wash trading` });
    let loopUsd = 0, loopers = 0;
    for (const w of wallets.values()) if (w.b >= 2 && w.s >= 2) { loopUsd += w.usd; loopers++; }
    const loopShare = total > 0 ? loopUsd / total : 0; stats.loopShare = Math.round(loopShare * 100);
    if (loopers >= 2 && loopShare >= 0.5) f.push({ level: "risk", text: `${loopers} wallets keep buying and selling to each other: ${Math.round(loopShare * 100)}% of the volume is them (wash trading)` });
    const sizes = new Map(); for (const t of tr) { if (t.usd < 5) continue; const k = Math.round(t.usd * 2) / 2; sizes.set(k, (sizes.get(k) || 0) + 1); }
    const top = sizes.size ? Math.max(...sizes.values()) : 0;      // tiny trades naturally cluster, so only $5+ sizes count
    if (top >= 8 && top / n >= 0.25) f.push({ level: "risk", text: `${top} of the last ${n} trades are the exact same size: bot-made volume` });

    // flips: a wallet buys then sells (or the reverse) about the same amount within 2 minutes.
    // Volume bots rotate through hundreds of fresh wallets, so this catches them even when "unique wallets" looks healthy.
    const byW = new Map(); for (const t of tr) { if (!byW.has(t.wallet)) byW.set(t.wallet, []); byW.get(t.wallet).push(t); }
    let flipTrades = 0, flippers = 0, sameBlock = 0;
    for (const list of byW.values()) {
      if (list.length < 2) continue;
      list.sort((a, b) => (a.at || 0) - (b.at || 0));
      let flipped = false, blocks = new Map();
      for (let i = 1; i < list.length; i++) {
        const a = list[i - 1], b = list[i];
        if (a.kind !== b.kind && a.at && b.at && Math.abs(b.at - a.at) <= 120000 && Math.abs(a.usd - b.usd) / Math.max(a.usd, b.usd) <= 0.2) { flipTrades += 2; flipped = true; i++; }
      }
      for (const t of list) if (t.block) { const k = blocks.get(t.block) || new Set(); k.add(t.kind); blocks.set(t.block, k); }
      for (const k of blocks.values()) if (k.size === 2) { sameBlock++; break; }
      if (flipped) flippers++;
    }
    const flipShare = flipTrades / n; stats.flipShare = Math.round(flipShare * 100); stats.flippers = flippers;
    if (flipShare >= 0.65) f.push({ level: "danger", text: `${Math.round(flipShare * 100)}% of trades are wallets buying and instantly selling the same amount: a volume bot is faking the activity` });
    else if (flipShare >= 0.4) f.push({ level: "risk", text: `${Math.round(flipShare * 100)}% of trades are quick buy-then-sell flips of the same amount: likely a volume bot` });
    if (sameBlock >= 3) f.push({ level: "risk", text: `${sameBlock} wallets bought and sold in the same block: self-trading for fake volume` });

    // micro-trade spam: lots of tiny trades to pump the trade count
    const tiny = tr.filter((t) => t.usd < 3).length; stats.tinyShare = Math.round((tiny / n) * 100);
    // two-thirds tiny on a busy tape is the volume-bot fingerprint even when the bot splits buys and sells across different wallets
    if (n >= 150 && tiny / n >= 0.6) f.push({ level: "risk", text: `${Math.round((tiny / n) * 100)}% of the last ${n} trades are under $3: a volume bot is padding the activity (wash trading)` });
    else if (n >= 60 && tiny / n >= 0.6) f.push({ level: flipShare >= 0.3 ? "risk" : "caution", text: `${Math.round((tiny / n) * 100)}% of trades are under $3${flipShare >= 0.3 ? ": a bot is spamming tiny trades to fake activity" : ": lots of tiny trades, possibly a volume bot"}` });

    // churn: heavy two-way trading but the price barely moves
    const prices = tr.map((t) => t.price).filter((p) => p > 0);
    const buys = tr.filter((t) => t.kind === "buy").length, balance = Math.abs(buys - (n - buys)) / n;
    if (n >= 80 && prices.length >= 40 && balance <= 0.08) {
      const lo = Math.min(...prices), hi = Math.max(...prices);
      if (lo > 0 && (hi - lo) / lo < 0.03) f.push({ level: "risk", text: `${n} trades split almost exactly 50/50 and the price hasn't moved: churned, fake volume` });
    }
  }
  // bundled launch: only visible while the launch is still on the tape
  if (createdAt && now - createdAt < 3 * 3600e3) {
    const blocks = new Map();
    for (const t of tr) if (t.kind === "buy" && t.block) { const s = blocks.get(t.block) || new Set(); s.add(t.wallet); blocks.set(t.block, s); }
    let maxB = 0; for (const s of blocks.values()) maxB = Math.max(maxB, s.size);
    stats.maxSameBlock = maxB;
    if (maxB >= 4) for (const s of blocks.values()) if (s.size === maxB) { stats.bundleWallets = [...s].slice(0, 20); break; }
    if (maxB >= 8) f.push({ level: "danger", text: `${maxB} wallets bought in the very same block: bundled launch, usually one person holding many wallets` });
    else if (maxB >= 4) f.push({ level: "risk", text: `${maxB} wallets bought in the same block: possible bundled launch` });
  }
  // dump in progress
  const recentSells = tr.filter((t) => t.kind === "sell" && t.at && now - t.at < 15 * 60e3).reduce((a, t) => a + t.usd, 0);
  stats.sells15m = Math.round(recentSells);
  if (liq > 0 && recentSells >= liq * 0.25) f.push({ level: "danger", text: `$${Math.round(recentSells).toLocaleString("en-US")} sold in the last 15 minutes (${Math.round(recentSells / liq * 100)}% of the liquidity): a dump is happening` });
  else if (liq > 0 && recentSells >= liq * 0.1) f.push({ level: "risk", text: `Heavy selling in the last 15 minutes ($${Math.round(recentSells).toLocaleString("en-US")})` });
  return { flags: f, stats };
}

/** Independent second opinion from RugCheck's public report (LP lock, creator holdings, insider networks). */
const secondCache = new Map();
async function secondOpinion(mint) {
  const hit = secondCache.get(mint);
  if (hit && Date.now() - hit.ts < 5 * 60e3) return hit.data;
  const r = await withTimeout(fetch(`https://api.rugcheck.xyz/v1/tokens/${mint}/report/summary`, { headers: { accept: "application/json" } }), 8000, "second opinion");
  if (!r.ok) throw new Error("second opinion " + r.status);
  const d = await r.json();
  const risks = (Array.isArray(d?.risks) ? d.risks : []).slice(0, 12).map((x) => ({
    name: String(x?.name || "").replace(/[<>]/g, "").slice(0, 80), text: String(x?.description || "").replace(/[<>]/g, "").slice(0, 160),
    level: String(x?.level || "").toLowerCase() }));
  const data = { risks, lpLockedPct: Number.isFinite(+d?.lpLockedPct) ? +d.lpLockedPct : null, score: Number.isFinite(+d?.score_normalised) ? +d.score_normalised : null };
  secondCache.set(mint, { data, ts: Date.now() });
  if (secondCache.size > 3000) secondCache.delete(secondCache.keys().next().value);
  return data;
}

async function solanaRisk(mint) {
  const flags = [];
  const [acctR, metaR, chainR, profR] = await Promise.allSettled([
    withTimeout(connection.getParsedAccountInfo(new PublicKey(mint)), 7000, "mint"),
    withTimeout(connection.getAccountInfo(PublicKey.findProgramAddressSync(
      [Buffer.from("metadata"), METADATA_PROGRAM.toBuffer(), new PublicKey(mint).toBuffer()], METADATA_PROGRAM)[0]), 6000, "meta"),
    getMintCheck(mint),
    fetch(`http://127.0.0.1:${PORT}/api/token/${mint}`).then((r) => r.json()),
  ]);
  const secondP = secondOpinion(mint).catch(() => null);   // runs alongside everything else
  const acct = acctR.status === "fulfilled" ? acctR.value?.value : null;
  const chain = chainR.status === "fulfilled" ? chainR.value : null;
  const prof = profR.status === "fulfilled" ? profR.value : null;
  if (!acct || acct.data?.parsed?.type !== "mint" || !chain?.found)
    return { verified: false, flags: [{ level: "risk", text: "Couldn't read this token from Solana. It may not exist, or the network is slow. Try again." }] };

  if (!chain.freezeAuthorityRenounced) flags.push({ level: "danger", text: "Creator can freeze your tokens so you can't sell" });
  if (!chain.mintAuthorityRenounced) flags.push({ level: "risk", text: "Creator can print more tokens and dump them on you" });

  // Token-2022 traps
  if (String(acct.owner?.toBase58?.() || acct.owner) === TOKEN_2022) {
    for (const e of acct.data.parsed.info.extensions || []) {
      const st = e.state || {};
      if (e.extension === "permanentDelegate" && st.delegate) flags.push({ level: "danger", text: "Has a permanent delegate: someone can take or burn tokens from any wallet, including yours" });
      if (e.extension === "nonTransferable") flags.push({ level: "danger", text: "Tokens can't be transferred or sold at all" });
      if (e.extension === "defaultAccountState" && st.accountState === "frozen") flags.push({ level: "danger", text: "New holders start frozen: you may not be able to sell" });
      if (e.extension === "pausableConfig" || e.extension === "pausable") flags.push({ level: "danger", text: "Creator can pause all transfers" });
      if (e.extension === "transferHook" && st.programId) flags.push({ level: "risk", text: "Every transfer runs the creator's own program, which can block or tax sells" });
      if (e.extension === "transferFeeConfig") {
        const bps = +(st.newerTransferFee?.transferFeeBasisPoints ?? st.olderTransferFee?.transferFeeBasisPoints ?? 0);
        if (bps >= 1000) flags.push({ level: "danger", text: `Takes a ${bps / 100}% fee on every transfer` });
        else if (bps > 0) flags.push({ level: "risk", text: `Takes a ${bps / 100}% fee on every transfer` });
        if (st.transferFeeConfigAuthority) flags.push({ level: "risk", text: "Creator can raise the transfer fee later" });
      }
    }
  }

  // Name / logo control and copycats
  if (metaR.status === "fulfilled" && metaR.value) {
    const mm = decodeMetaMutability(metaR.value.data);
    if (mm && mm.isMutable && mm.updateAuthority !== "11111111111111111111111111111111")
      flags.push({ level: "caution", text: "Creator can still change the name and logo" });
  }
  const sym = String(prof?.symbol || "").toUpperCase().replace(/^\$/, "");
  if (sym && REAL_SOLANA[sym] && REAL_SOLANA[sym] !== mint)
    flags.push({ level: "danger", text: `Pretends to be ${sym}, but it isn't the real ${sym} address: copycat` });

  const w = chain.top10WalletPct ?? chain.top10HolderPct;
  if (w != null && w >= 60) flags.push({ level: "risk", text: `Top 10 wallets hold ${Math.round(w)}%: they can dump on everyone` });
  else if (w != null && w >= 35) flags.push({ level: "caution", text: `Top 10 wallets hold ${Math.round(w)}%` });

  const onCurve = !!(prof && prof.curve && !prof.curve.complete);
  // second market source: the same one the scanner's liquidity box uses
  let ds = null, dsOk = false;
  try {
    const d = await (await withTimeout(fetch(`https://api.dexscreener.com/latest/dex/tokens/${mint}`), 8000, "dex market")).json();
    dsOk = true;
    const p = trustedDexPair(d.pairs, mint);
    const liqAll = (d.pairs || []).filter((x) => x.chainId === "solana" && x.baseToken?.address === mint)
      .reduce((a, x) => a + (+x.liquidity?.usd || 0), 0);
    if (p) { const tx = p.txns?.h24 || {};
      ds = { liq: Math.max(+p.liquidity?.usd || 0, liqAll), mcap: +p.marketCap || +p.fdv || 0, vol24: +p.volume?.h24 || 0, buys24: +tx.buys || 0, sells24: +tx.sells || 0,
             ch24: Number.isFinite(+p.priceChange?.h24) ? +p.priceChange.h24 : null, ch1: Number.isFinite(+p.priceChange?.h1) ? +p.priceChange.h1 : null,
             createdAt: p.pairCreatedAt || null, pair: p.pairAddress || null }; }
  } catch {}
  const profOk = !!prof && !prof.marketLookupFailed;
  const seen = (prof && (prof.source === "pool" || prof.source === "curve")) || !!ds;
  const coverage = { onchain: true, market: seen || (profOk && dsOk), trades: false, second: false };
  if (seen) {
    const m = { onCurve, progress: onCurve ? +prof.curve.progress : null,
      liq: Math.max(prof?.liq || 0, ds?.liq || 0), mcap: prof?.mcap || ds?.mcap || 0,
      vol24: Math.max(prof?.vol24 || 0, ds?.vol24 || 0),
      buys24: Math.max(prof?.buys24 || 0, ds?.buys24 || 0), sells24: Math.max(prof?.sells24 || 0, ds?.sells24 || 0),
      ch24: prof?.ch24 ?? ds?.ch24 ?? null, createdAt: prof?.createdAt || ds?.createdAt || null };
    marketFlags(m, flags);
    if (prof && !prof.poolAddress && ds?.pair) prof.poolAddress = ds.pair;
    if (prof && prof.ch1 == null && ds?.ch1 != null) prof.ch1 = ds.ch1;
  } else if (profOk && dsOk && !onCurve && !prof?.curveLookupFailed) {
    // both sources answered and neither has a market: that's real, not a lookup glitch
    marketFlags({ onCurve: false, liq: 0, mcap: 0 }, flags);
  }

  // one wallet sitting on a big bag
  const t1 = chain.top1WalletPct;
  if (t1 != null && t1 >= 40) flags.push({ level: "danger", text: `One wallet holds ${Math.round(t1)}% of the supply and can dump it on everyone` });
  else if (t1 != null && t1 >= 20) flags.push({ level: "risk", text: `One wallet holds ${Math.round(t1)}% of the supply` });

  // fast crash
  if (prof && prof.ch1 != null && prof.ch1 <= -50) flags.push({ level: "danger", text: `Down ${Math.round(-prof.ch1)}% in the last hour: rug or dump in progress` });

  // graduation: the riskiest hours on pump.fun
  let graduation = null;
  if (onCurve) {
    const pr = +prof.curve.progress;
    graduation = { status: "on curve", progress: pr };
    if (pr >= 85) flags.push({ level: "caution", text: `${pr.toFixed(0)}% to graduation: snipers often dump right as it graduates` });
  } else if (/pump$/.test(mint) && prof && prof.source === "pool") {
    const ago = prof.createdAt ? Date.now() - prof.createdAt : null;
    graduation = { status: "graduated", pool: prof.dex || null, since: prof.createdAt || null };
    if (ago != null && ago < 3 * 3600e3) flags.push({ level: "caution", text: `Graduated ${Math.max(1, Math.round(ago / 60000))} minutes ago: the hours after graduation are when early buyers usually cash out` });
  }

  // the trade tape: wash trading, bundles, dumps
  let tape = null;
  if (prof && !prof.poolAddress) {
    try { const d = await gecko(`/tokens/${mint}/pools?page=1`, 8000);
      const p = (d?.data || []).find((x) => x?.attributes?.address); if (p) prof.poolAddress = p.attributes.address; } catch {}
  }
  if (prof && prof.poolAddress) {
    try {
      const d = await gecko(`/pools/${prof.poolAddress}/trades`, 8000);
      const trades = (d?.data || []).map((x) => { const a = x.attributes || {};
        return { kind: a.kind === "sell" ? "sell" : "buy", usd: +a.volume_in_usd || 0, wallet: a.tx_from_address || null,
                 block: a.block_number || null, at: a.block_timestamp ? Date.parse(a.block_timestamp) : null,
                 price: +(a.kind === "sell" ? a.price_from_in_usd : a.price_to_in_usd) || null }; });
      tape = tapeFlags(trades, prof.liq || 0, prof.createdAt || null);
      flags.push(...tape.flags); coverage.trades = true;
    } catch {}
  }

  // who launched it: pump.fun curve creator, otherwise whoever controls the metadata
  let creator = null;
  try { const cv = await readBondingCurve(mint); if (cv && cv.creator) creator = cv.creator; } catch {}
  if (!creator && metaR.status === "fulfilled" && metaR.value) {
    const mm = decodeMetaMutability(metaR.value.data);
    if (mm && mm.updateAuthority && mm.updateAuthority !== "11111111111111111111111111111111" && PublicKey.isOnCurve(new PublicKey(mm.updateAuthority).toBytes())) creator = mm.updateAuthority;
  }
  const cRec = creator ? rugReg.get(creator) : null;
  if (cRec) flags.push({ level: "danger", text: `The creator's wallet is a known rugger: ${rugLine(cRec)}` });
  if (creator && typeof MP !== "undefined" && MP.creators.get(creator)?.length >= 5)
    flags.push({ level: "risk", text: `The creator launched ${MP.creators.get(creator).length} tokens in the last 24 hours: serial launcher` });
  // top holders checked against the rug list
  const bad = (chain.topOwners || []).filter((h) => h.owner !== creator && rugReg.has(h.owner));
  if (bad.length) {
    const big = bad.reduce((a, h) => (h.pct > a.pct ? h : a), bad[0]);
    flags.push({ level: big.pct >= 5 ? "danger" : "risk",
      text: `${bad.length} of the top holders ${bad.length === 1 ? "is a wallet" : "are wallets"} tied to past rugs (biggest holds ${big.pct}%: ${rugLine(rugReg.get(big.owner))})` });
  }

  // can it actually be sold? (graduated tokens only; curve tokens always sell back to the curve)
  if (!onCurve && prof && prof.source === "pool" && prof.price > 0) {
    const sr = await sellRoute(mint, 100, prof.price, chain.decimals == null ? 6 : chain.decimals, solUsd.v || 150).catch(() => null);
    if (sr && sr.checked && !sr.ok) flags.push({ level: "danger", text: "No sell route: Jupiter can't find any way to sell this token. You may not be able to sell it." });
    else if (sr && sr.checked && sr.impactPct >= 25) flags.push({ level: "risk", text: `Selling just $100 of it would move the price about ${Math.round(sr.impactPct)}%: very hard to get out` });
    else if (sr && sr.checked && sr.impactPct >= 10) flags.push({ level: "caution", text: `Selling just $100 of it would move the price about ${Math.round(sr.impactPct)}%` });
  }
  const so = await secondP;
  if (so) {
    coverage.second = true;
    for (const x of so.risks) {
      if (!x.name) continue;
      const lvl = x.level === "danger" ? "risk" : "caution";
      flags.push({ level: lvl, text: `Second opinion: ${x.name}${x.text ? ": " + x.text : ""}` });
      if (creator && /rug/i.test(x.name + " " + x.text)) markRug(creator, { role: "creator", mint, sym: prof?.symbol, how: "second opinion: " + x.name });
    }
    const lpWarned = so.risks.some((x) => /lp|liquidity/i.test(x.name) && /unlock/i.test(x.name + " " + x.text));
    if (!onCurve && !/pump$/.test(mint) && lpWarned && so.lpLockedPct != null && so.lpLockedPct < 10)
      flags.push({ level: "risk", text: `Only ${Math.round(so.lpLockedPct)}% of the liquidity is locked: the creator could pull it` });
  }
  // what this scan proves goes into the registry
  const pulled = flags.some((f) => f.level === "danger" && /Liquidity (looks pulled|is basically gone)|No working market/.test(f.text));
  const dumping = flags.some((f) => /a dump is happening|rug or dump in progress|possible rug in progress/.test(f.text));
  if (pulled && creator && prof && (prof.source === "pool")) markRug(creator, { role: "creator", mint, sym: prof?.symbol, how: "liquidity pulled" });
  if (dumping && tape?.stats?.bundleWallets) for (const w of tape.stats.bundleWallets) markRug(w, { role: "bundler", mint, sym: prof?.symbol, how: "bundled the launch, then the dump" });

  // brand-new launches: thin liquidity and a few big wallets are normal before the creator finishes setting up
  const ageMs = (prof?.createdAt || ds?.createdAt) ? Date.now() - (prof?.createdAt || ds?.createdAt) : null;
  const early = onCurve || (ageMs != null && ageMs < 6 * 3600e3);
  if (early) {
    for (const f of flags) {
      if (f.level === "caution") continue;
      const holderish = /^Top 10 wallets hold|^Second opinion: (Low Liquidity|Top 10 holders|Single holder|High ownership|Low amount of LP Providers|High market cap per holder)/.test(f.text)
        || (/^One wallet holds/.test(f.text) && f.level !== "danger") || /^Very thin liquidity/.test(f.text);
      if (holderish) { f.level = "caution"; f.text += " (common in the first hours of a launch)"; }
    }
  }

  const missing = Object.entries(coverage).filter(([, v]) => !v).map(([k]) => ({ market: "market", trades: "trade tape", second: "second opinion", onchain: "on-chain" }[k]));
  if (missing.length) flags.push({ level: "caution", text: `Not fully checked: couldn't run the ${missing.join(", ")} check${missing.length > 1 ? "s" : ""}. Treat it as unverified.` });
  return { verified: true, complete: !missing.length, coverage, flags, symbol: prof?.symbol || null, name: prof?.name || null, graduation,
           tape: tape ? { ...tape.stats, bundleWallets: undefined } : null, creator: creator || null, early };
}

async function evmRisk(chain, addr) {
  const flags = [], cid = GOPLUS[chain];
  let g = null, market = null;
  const gid = await resolveGecko(chain).catch(() => null);
  const [gR, mR] = await Promise.allSettled([
    cid ? withTimeout(fetch(`https://api.gopluslabs.io/api/v1/token_security/${cid}?contract_addresses=${addr}`), 10000, "goplus").then((r) => r.json()) : Promise.resolve(null),
    gid ? geckoAny(`/networks/${gid}/tokens/${addr}/pools?page=1`) : Promise.resolve(null),
  ]);
  if (gR.status === "fulfilled" && gR.value) {
    const res0 = gR.value.result || {};
    g = normalizeGoPlus(res0[addr] || Object.entries(res0).find(([k]) => k.toLowerCase() === addr)?.[1], chain);
  }
  if (mR.status === "fulfilled" && mR.value?.data?.length) {
    const best = mR.value.data.reduce((a, b) => (+b.attributes?.reserve_in_usd || 0) > (+a.attributes?.reserve_in_usd || 0) ? b : a);
    const a = best.attributes || {}, tx = a.transactions?.h24 || {};
    market = { liq: +a.reserve_in_usd || 0, mcap: +a.market_cap_usd || +a.fdv_usd || 0, vol24: +a.volume_usd?.h24 || 0,
               buys24: +tx.buys || 0, sells24: +tx.sells || 0, ch24: Number.isFinite(+a.price_change_percentage?.h24) ? +a.price_change_percentage.h24 : null,
               createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null, name: String(a.name || "") };
  }
  const verified = !!(g && g.ok);
  if (verified) {
    if (g.honeypot) flags.push({ level: "danger", text: "Honeypot: you can buy but you can't sell" });
    if (g.cannotSellAll) flags.push({ level: "danger", text: "You can't sell your whole bag" });
    if (g.cannotBuy) flags.push({ level: "risk", text: "Buying is blocked right now" });
    if (g.ownerChangeBalance) flags.push({ level: "danger", text: "Owner can change anyone's balance, including yours" });
    if (g.takeBackOwnership) flags.push({ level: "danger", text: "Owner can take back control after 'renouncing'" });
    if (g.selfdestruct) flags.push({ level: "danger", text: "Contract can self-destruct" });
    if (g.sellTax != null && g.sellTax >= 0.5) flags.push({ level: "danger", text: `Sell tax is ${Math.round(g.sellTax * 100)}%` });
    else if (g.sellTax != null && g.sellTax >= 0.1) flags.push({ level: "risk", text: `Sell tax is ${Math.round(g.sellTax * 100)}%` });
    if (g.buyTax != null && g.buyTax >= 0.1) flags.push({ level: "risk", text: `Buy tax is ${Math.round(g.buyTax * 100)}%` });
    if (g.hiddenOwner) flags.push({ level: "risk", text: "Has a hidden owner" });
    if (g.blacklist) flags.push({ level: "risk", text: "Owner can blacklist wallets from selling" });
    if (g.pausable) flags.push({ level: "risk", text: "Owner can pause trading" });
    if (g.taxModifiable) flags.push({ level: "risk", text: "Owner can change the taxes at any time" });
    if (g.mintable && !g.ownerRenounced) flags.push({ level: "risk", text: "Owner can mint more tokens" });
    if (g.openSource === false) flags.push({ level: "risk", text: "Contract code isn't public, so nobody can check it" });
    if (g.proxy) flags.push({ level: "caution", text: "Upgradeable contract: the rules can be changed later" });
    if (g.top10WalletPct != null && g.top10WalletPct >= 60) flags.push({ level: "risk", text: `Top 10 wallets hold ${Math.round(g.top10WalletPct)}%` });
    if (g.symbol && FAMOUS.has(String(g.symbol).toUpperCase())) flags.push({ level: "risk", text: `Uses a famous name (${g.symbol}): make sure this is the real contract` });
  } else {
    flags.push({ level: "caution", text: GOPLUS[chain] ? "Contract safety data isn't available yet for this token" : "SLAPBOT can't verify contract safety on this chain, so treat it as risky" });
  }
  marketFlags(market, flags);
  let tape = null;                                  // same tape checks on Ethereum-style chains
  if (gid && mR.status === "fulfilled" && mR.value?.data?.length) {
    try {
      const best = mR.value.data.reduce((x, y) => (+y.attributes?.reserve_in_usd || 0) > (+x.attributes?.reserve_in_usd || 0) ? y : x);
      const d = await geckoAny(`/networks/${gid}/pools/${best.attributes.address}/trades`, 8000);
      const trades = (d?.data || []).map((x) => { const a = x.attributes || {};
        return { kind: a.kind === "sell" ? "sell" : "buy", usd: +a.volume_in_usd || 0, wallet: a.tx_from_address || null,
                 block: a.block_number || null, at: a.block_timestamp ? Date.parse(a.block_timestamp) : null }; });
      tape = tapeFlags(trades, market?.liq || 0, market?.createdAt || null); flags.push(...tape.flags);
    } catch {}
  }
  return { verified, flags, symbol: g?.symbol || null, name: g?.name || null, tape: tape ? tape.stats : null };
}

const riskCache = new Map();
app.get("/api/risk/:chain/:address", async (req, res) => {
  const chain = String(req.params.chain || "").toLowerCase(), raw = String(req.params.address || "");
  if (!DEX_CHAINS.includes(chain)) return res.status(400).json({ error: "Unknown chain" });
  const isSol = chain === "solana";
  const address = isSol ? raw : raw.toLowerCase();
  if (isSol ? !SOL_ADDR.test(address) : !/^0x[0-9a-f]{40}$/.test(address)) {
    if (!isSol && !/^0x/.test(raw)) return res.json({ chain, address: raw, verdict: "UNVERIFIED", score: null,
      flags: [{ level: "caution", text: "SLAPBOT can't verify contract safety on this chain, so treat it as risky" }], checkedAt: Date.now() });
    return res.status(400).json({ error: "Invalid token address" });
  }
  const key = chain + ":" + address, hit = riskCache.get(key);
  if (hit && Date.now() - hit.checkedAt < 60000) return res.json(hit);
  try {
    const r = isSol ? await solanaRisk(address) : await evmRisk(chain, address);
    const weight = { danger: 45, risk: 18, caution: 6 };
    const score = Math.max(0, 100 - r.flags.reduce((s, f) => s + (weight[f.level] || 0), 0));   // 100 = cleanest
    const order = { danger: 0, risk: 1, caution: 2 };
    const out = { chain, address, symbol: r.symbol, name: r.name, verdict: verdictOf(r.flags, r.verified, r.complete !== false), score, coverage: r.coverage || null,
                  graduation: r.graduation || null, tape: r.tape || null, creator: r.creator || null, early: !!r.early,
                  flags: r.flags.sort((a, b) => order[a.level] - order[b.level]), checkedAt: Date.now() };
    riskCache.set(key, out);
    if (riskCache.size > 3000) riskCache.delete(riskCache.keys().next().value);
    if (out.verdict === "DANGER") log("flagged_rug", `${chain} ${address.slice(0, 8)}… → ${out.flags.filter((f) => f.level === "danger").map((f) => f.text).join(" | ")}`);
    res.json(out);
  } catch (err) {
    log("error", `risk ${chain} ${raw.slice(0, 8)}: ${err.message}`);
    res.status(502).json({ error: "Couldn't finish the scan. Try again." });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ⑮ MASTERPEACE — private launch sniper, PAPER MODE (no real money moves)
// ═══════════════════════════════════════════════════════════════════════
/**
 * Watches every new pump.fun launch live, waits a short moment so the launch can show
 * its hand, runs SLAPBOT-style filters, and paper-buys only the ones that pass. Then it
 * manages each paper position with take-profit, stop-loss and a time limit, priced
 * straight from the bonding curve, with real-world costs (pump.fun fee, priority fee,
 * Jito tip, slippage) taken off so the results are honest.
 *
 * Nothing here holds a key or sends a transaction. Owner-only.
 */
/**
 * PROVEN_V2: the safe starting profile. Bigger, fewer bets (costs eat tiny ones), no blind first-seconds buying,
 * strict momentum entries, tighter stops, and a short leash on bad days. Your saved settings from older versions
 * are moved onto this once (cfgVersion), because old saved values otherwise override every improvement.
 */
/** Every store registers a saver here. flushAll() runs them all: on a schedule, and the instant the server is told to shut down (an upload restarts it). */
const FLUSHERS = [];
const TG_NAME = "FUFLOPBOT";                                                   // the sniper bot's name in Telegram (the scanner website stays SLAPBOT)
const regFlush = (fn) => { FLUSHERS.push(fn); return fn; };
function flushAll() { let n = 0; for (const f of FLUSHERS) { try { f(); n++; } catch {} } return n; }
const PROVEN_V2 = { slots: 4, fastLane: 0, momentum: 1, momBuyers60: 10, momBuyShare: 65, momNetSol: 3, momRise2m: 20, momMaxRise2m: 100, momMaxMcap: 30000,
  tpPct: 60, tp1SellPct: 70, slPct: 20, trailPct: 20, trailAt5x: 12, trailAt10x: 8, maxHoldMin: 20, moonHoldMin: 120,
  dailyStopPct: 12, maxLossStreak: 3, pauseMin: 180, cashOutMcap: 80000, minProgress: 8, maxTop10Pct: 30, maxTop1Pct: 10, maxDevPct: 5,
  labFilter: 1, labMinLift: 1.2, labBoost: 1.5, gradOn: 1, gradMaxOpen: 2, gradSl: 12, copyOn: 0, gridOn: 0, learn: 1, cfgVersion: 3 };
/** Staged exits (V1.0): sell 25% of the original position at +20%, +35% and +60%; the last 25% rides a trailing stop. */
const MP_LADDER = [[20, 0.25], [35, 0.25], [60, 0.25]];
/**
 * V1.0: strict, bankroll-based rules for a realistic test. A $1,000 PAPER account (so 1% is $10 and fixed costs are tiny), 1% per trade,
 * 3 positions at most, a 3% daily loss limit, strict safety, and staged exits. The one deliberate difference from "stop for the day after
 * 3 losses": it cools off for 90 minutes instead, so the test still gathers data (raise pauseMin to 1440 for the real-money phase).
 */
const V10 = { startUsd: 1000, slots: 0, autoSlots: 0, riskPct: 1, maxBetPct: 2, maxOpen: 3, maxLossPct: 0, minTradeUsd: 1,
  dailyStopPct: 3, maxLossStreak: 3, pauseMin: 90, slPct: 15, ladderOn: 1, tpPct: 20, tp1SellPct: 25, trailPct: 20, trailAt5x: 12, trailAt10x: 8, maxHoldMin: 30, moonHoldMin: 120,
  cashOutMcap: 100000, fastLane: 0, momentum: 1, momWindowMin: 4, momBuyers60: 10, momBuyShare: 65, momNetSol: 3, momRise2m: 20, momMaxRise2m: 100, momMaxMcap: 30000,
  minProgress: 8, maxTop10Pct: 30, maxTop1Pct: 10, maxDevPct: 5, gradOn: 1, gradWindowMin: 15, gradMinLiq: 25000, gradMinLiqPct: 5, gradMinVol24: 50000, gradMaxCh5: 25, gradMaxImpact: 3, gradMaxOpen: 3,
  labFilter: 1, labMinLift: 1.2, copyOn: 0, gridOn: 0, learn: 1, cfgVersion: 3 };
/** V1.1 = V1.0 with FIXED-RISK sizing: risk 1% of all the money per trade, sized from the stop distance (the professional rule). */
const V11 = { ...V10, sizeByRisk: 1, riskPerTradePct: 1, maxBetPct: 10, riskPct: 1, sizeByWorst: 1, gradWorstPct: 100 };
const MP = {
  on: !/^(0|off|false)$/i.test(String(process.env.MP_ON || "1")),
  settings: {
    startUsd: 50,         // starting paper bankroll
    slots: 10,            // split the money into this many snipes at once ($5 → ten $0.50 snipes). 0 = use riskPct instead
    riskPct: 10,          // (when slots is 0) each snipe uses this % of the trading balance
    minTradeUsd: 0.25,    // never trade smaller than this
    maxLossPct: 0,        // safety cap: one snipe can never put more than this % of ALL your money at risk (0 = off, 1 = 1%)
    vaultAtX: 3,          // when the trading balance reaches 3× the start...
    keepX: 1,             // ...lock everything above 1× start in the vault (never traded again)
    dailyStopPct: 30,     // down 30% on the day: stop trading until tomorrow
    maxLossStreak: 5,     // 5 losses in a row: pause
    pauseMin: 120,        // ...for 2 hours
    learn: 1,             // 1 = learn from its own results and skip setups that keep losing
    learnMin: 12,         // a setup needs at least this many trades before it's judged
    // offense
    tp1SellPct: 50,       // at the take-profit, sell this % (gets your money back) and let the rest ride
    trailPct: 25,         // after +100%, the riding part sells if it falls this % from its high
    trailAt5x: 15,        // tighter once it's up 5×
    trailAt10x: 10,       // tighter still once it's up 10× (protect the big wins)
    moonHoldMin: 180,     // the riding part sells after this long no matter what
    smartBoost: 1.5,      // bet bigger when a top smart wallet bought the same launch
    favorBoost: 1.5,      // bet bigger on setups that have been winning
    maxBetPct: 20,        // but never more than this % of the trading balance on one launch
    // Launch Shot: buy in the first seconds of a launch (around $5K market cap)
    fastLane: 0,          // 1 = on (off by default: buying in the first seconds is blind)
    fastMaxMcap: 8000,    // only if it's still under this market cap when we see it
    fastBetPct: 5,        // smaller bets: the earliest entries are the riskiest
    fastMaxPerMin: 3,     // at most this many fast buys a minute
    fastMaxOpen: 4,       // and at most this many fast positions at once
    fastMaxDevPct: 15,    // skip if the creator bought more than this % at launch
    // GRADUATE strategy: buy tokens that already graduated off pump.fun, once real buying shows up on the trading pool
    gradOn: 1, gradWindowMin: 30, gradMinLiq: 20000, gradMinMcap: 50000, gradMaxMcap: 300000, gradBuys5: 25, gradBuyShare: 58, gradMinCh5: 3, gradMaxCh5: 40, gradMinCh1: -20, gradMaxOpen: 3,
    gradTp: 35, gradTp1Sell: 60, gradSl: 15, gradTrail: 15, gradHold: 45,
    // COPY trading: follow the best Smart Wallets (off until you turn it on)
    copyOn: 0, copyTopN: 10, copyMinUsd: 150, copyMinWallets: 1, copyMaxOpen: 3, copyTp: 50, copyTp1Sell: 60, copySl: 20, copyTrail: 20, copyHold: 60,
    // GRID trading (its own small paper pool): buy dips and sell bounces on calm, liquid tokens
    gridOn: 0, gridStartUsd: 50, gridMax: 2, gridLevels: 4, gridStepPct: 5, gridHoldMin: 180, gridMinLiq: 60000, gridFeePct: 0.3, gridSlipPct: 0.5,
    // AUTOPILOT: protects the account by itself (no one needs to be watching)
    autopilot: 1,         // 1 = on
    autoFresh: 1,         // 1 = when the PAPER account runs out, start a fresh V1.0 test by itself (no waiting for you)
    autoSlots: 1,         // 1 = fewer, bigger bets as the balance shrinks (fixed costs hurt small bets most)
    ddBrake1Pct: 25,      // down this % from the peak: switch to Defense settings
    ddBrake2Pct: 40,      // down this %: also pause new trades for 8 hours
    killAvgPct: -12,      // an entry type averaging worse than this % per trade...
    killMinTrades: 12,    // ...over at least this many trades in 24 h gets switched off (or tightened)
    cfgVersion: 3,
    // BAND lane: buy when a token's market cap crosses the buy line, sell all when it reaches the sell line (default OFF until the study says it works)
    bandOn: 0, bandBuyK: 25, bandSellK: 30, bandStopPct: 15, bandMaxImpactPct: 2, dailyGoalUsd: 800,
    sizeByRisk: 0,        // 1 = FIXED-RISK sizing: each trade is sized so that if its stop-loss hits, you lose only riskPerTradePct of ALL the money
    riskPerTradePct: 1,   // ...this %, e.g. 1 (risk $10 of $1,000). Position = risk / stop distance (risk 1% with a 15% stop = a 6.7% position)
    goalDailyPct: 1,      // the daily-return goal the dashboard measures against
    courtMinTrades: 100,  // STRATEGY COURT: trades needed before anything can be called proven
    courtMinDays: 5,      // ...spread over at least this many days
    courtMaxDdPct: 15,    // ...with a worst drawdown no bigger than this %
    playbookOn: 1,        // 1 = patterns the Playbook has CONFIRMED to lose are skipped
    playbookStrict: 0,    // 1 = also buy ONLY signals that match a confirmed winning pattern (once one exists)
    gxMinRunners: 20,     // GRADUATE INDEX, fixed in advance: no conclusion before this many sustained 10x runners...
    gxMinTokens: 300,     // ...and this many graduates tracked
    goalPerTrade: 3,      // the scoreboard: average NET profit wanted per trade, in dollars...
    goalWindow: 40,       // ...judged over this many of the latest trades
    rhythmOn: 0,          // 1 = only open trades in times of day that historically graduate at least rhythmMinLift x the average
    rhythmMinLift: 0.9,   // blocks the worst times of day (0.9 = below 90% of average)
    paceMaxPerHour: 0,    // 0 = no limit; otherwise at most this many new trades per hour
    ladderOn: 0,          // 1 = staged exits (+20% / +35% / +60%, 25% each, then trail the last 25%) instead of one take-profit
    gradMinLiqPct: 0,     // graduates: liquidity must be at least this % of market cap (0 = off)
    gradMinVol24: 0,      // graduates: 24-hour volume must be at least this many $ (0 = off)
    gradMaxImpact: 12,    // graduates: selling a $100 test must move the price less than this %
    autoTune: 1,          // 1 = every 6 h, adopt the Sweet Spot's settings when they proved better on BOTH halves of the data
    labFilter: 0,         // 1 = skip launches the Winner Lab scores below labMinLift (only once the lab has 300 finished launches)
    labMinLift: 1.0,      // 1.0 = "no better than a random launch"
    labBoost: 1.5,        // bet bigger when the lab scores a launch 2.5× or better
    cashOutMcap: 100000,  // RUG ZONE: a fast mover that reaches this market cap gets sold completely (0 = off)
    fastTimeoutSec: 180,  // if it hasn't lifted off by then...
    fastMinGainPct: 30,   // ...(up at least this %), get out
    // MOMENTUM ENTRY: after a launch passes the safety checks, watch it live and buy only when real buying shows up
    momentum: 1,          // 1 = on (buy on momentum) · 0 = old way (buy right at 90 seconds)
    momWindowMin: 6,      // watch each launch this many minutes for momentum, then give up
    momBuyers60: 8,       // at least this many DIFFERENT wallets buying in the last minute
    momBuyShare: 60,      // buys must be at least this % of trades in the last minute
    momNetSol: 2,         // at least this much SOL flowing IN (buys minus sells) in the last minute
    momRise2m: 15,        // price up at least this % over the last 2 minutes
    momMaxRise2m: 100,    // ...but NOT more than this %: a token that already rose 3x in 2 minutes is a blow-off top, not a start (0 = no cap)
    momMaxMcap: 40000,    // too late if it's already above this market cap
    // defense
    devExit: 1,           // 1 = sell everything the moment the creator dumps their bag
    // savings
    autoSend: 1,          // 1 = every time profit gets locked, send it to your savings wallet
    waitSec: 90,          // let the launch play out this long before judging it
    minProgress: 5,       // curve must be at least this % filled by then (real demand)
    maxDevPct: 8,         // creator may hold at most this % of supply
    maxTop10Pct: 35,      // top 10 real wallets (curve excluded) may hold at most this %
    maxTop1Pct: 12,       // biggest single real wallet
    sizeByWorst: 1,       // size each trade by its WORST case (the curve floor, or a full loss on a pool token), not just the stop
    gradWorstPct: 100,    // the worst case assumed for pool tokens (graduates): liquidity can be pulled
    tpPct: 100,           // take profit at +100%
    slPct: 30,            // stop loss at −30%
    maxHoldMin: 30,       // sell after 30 minutes no matter what
    maxOpen: 8,           // never more than this many paper positions
    maxEvalPerMin: 10,    // keep the server and data budget healthy
    feePct: 1,            // pump.fun trading fee each way
    priorityFeeSol: 0.0001, jitoTipSol: 0.0001, slippagePct: 3,
  },
  seen: 0, queue: [], evaluated: [], positions: [], closed: [], creators: new Map(),
  skips: {}, startedAt: Date.now(), feed: { connected: false, lastEventAt: null, subId: null, decodeFails: 0 },
  bank: null, outcomes: [], report: {}, events: [], tape: [], launchTimes: [], watch: new Map(),
  auto: { log: [], typeAt: {}, eqPeak: 0, dd: 0, lastPause: 0, lastDefense: 0 }, runs: [],
};
Object.assign(MP.settings, PROVEN_V2);                                  // fresh installs and Resets start from the safe profile
function mpNewBank(start) {
  const d = new Date().toISOString().slice(0, 10);
  return { start, cash: start, vault: 0, sent: 0, sends: [], day: d, dayStart: start, streak: 0, pausedUntil: 0, pauseWhy: null, peak: start };
}
/** Move the vault to your savings wallet. Paper mode records it; live mode will make the real transfer. */
function mpSendVault(why) {
  const B = MP.bank, amt = +(B.vault || 0).toFixed(2);
  if (!(amt > 0)) return 0;
  const to = MP.settings.savingsWallet || MY_WALLET || "";
  B.vault = 0; B.sent = +((B.sent || 0) + amt).toFixed(2);
  B.sends = [{ at: Date.now(), usd: amt, to, why, paper: true }, ...(B.sends || [])].slice(0, 50);
  mpEvent(`Sent $${amt.toFixed(2)} of profit to your savings wallet ${to ? to.slice(0, 4) + "…" + to.slice(-4) : ""} (paper: in live mode this is a real transfer)`);
  return amt;
}
MP.bank = mpNewBank(MP.settings.startUsd);
function mpEvent(text) { MP.events.unshift({ at: Date.now(), text }); MP.events = MP.events.slice(0, 50); log("alkaid", text); if (typeof tgEvent === "function") tgEvent(text); }

// ── saved to the server's disk, so paper results survive restarts and updates ──
const MP_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "masterpeace.json") : "";
try {
  if (MP_FILE && nodeFs.existsSync(MP_FILE)) {
    const d = JSON.parse(nodeFs.readFileSync(MP_FILE, "utf8"));
    if (d.settings) {
      const old = (d.settings.cfgVersion || 1) < 2, keepSavings = d.settings.savingsWallet, keepStart = d.settings.startUsd;
      Object.assign(MP.settings, d.settings);
      if (old) { Object.assign(MP.settings, PROVEN_V2); if (keepSavings) MP.settings.savingsWallet = keepSavings; if (keepStart) MP.settings.startUsd = keepStart; MP.migrated = true; }   // one time: old saved settings -> the safe profile
    }
    if ((MP.settings.cfgVersion || 1) < 3) { MP.settings.gridOn = 0; MP.settings.cfgVersion = 3; }    // v3: Grid off (a distraction with a negative edge); the new spike cap arrives as its default
    // open trades come back too: before, an upload (which restarts the server) made every open trade vanish and its money was never returned
    if (Array.isArray(d.positions)) MP.positions = d.positions.filter((p) => p && typeof p.mint === "string" && p.entry > 0 && p.tokens > 0 && p.costUsd > 0);
    for (const k of ["bank", "closed", "report", "skips", "events", "startedAt", "seen", "outcomes", "auto", "runs"]) if (d[k] != null) MP[k] = d[k];
    if (!MP.bank || !Number.isFinite(MP.bank.cash)) MP.bank = mpNewBank(MP.settings.startUsd);
    // a daily stop that is still running STAYS running: a restart (an upload, a crash) must never switch off a risk control.
    // Only an expired one, or an impossible one (more than 26 hours away), is cleared.
    { const tUntil = MP.bank.pausedUntil, nowT = Date.now();
      if (MP.bank.pauseWhy === "daily stop" && (!(tUntil > nowT) || tUntil - nowT > 26 * 3600e3)) { MP.bank.pausedUntil = 0; MP.bank.pauseWhy = null; MP.bank.dayPnl = 0; } }
  }
} catch (e) { log("error", `loading ALKAID: ${e.message}`); }
function mpSaveNow() {
  if (!MP_FILE) return;
  try { const tmp = MP_FILE + ".tmp";
    nodeFs.writeFileSync(tmp, JSON.stringify({ settings: MP.settings, bank: MP.bank, closed: MP.closed, report: MP.report, skips: MP.skips,
      events: MP.events, startedAt: MP.startedAt, seen: MP.seen, outcomes: MP.outcomes.slice(-600), auto: MP.auto, runs: MP.runs, positions: MP.positions, savedAt: Date.now() }));
    nodeFs.renameSync(tmp, MP_FILE); } catch (e) { log("error", `saving ALKAID: ${e.message}`); }
}
regFlush(mpSaveNow); setInterval(mpSaveNow, 30e3);

/** Pure: which "setup" a trade belongs to, so it can learn what works. */
function mpBuckets(x) {
  const b = [];
  if (x.fast) { b.push("Launch Shot entries"); return b; }
  const pr = x.progressAtBuy;
  if (pr != null) b.push(pr < 10 ? "bought at 5–10% bonded" : pr < 20 ? "bought at 10–20% bonded" : pr < 40 ? "bought at 20–40% bonded" : "bought at 40%+ bonded");
  if (x.top10 != null) b.push(x.top10 < 15 ? "top 10 hold under 15%" : x.top10 < 25 ? "top 10 hold 15–25%" : "top 10 hold 25%+");
  if (x.devPct != null) b.push(x.devPct < 0.5 ? "creator sold or holds nothing" : x.devPct < 3 ? "creator holds under 3%" : "creator holds 3%+");
  return b;
}
/** Pure: average result per setup from closed trades. Setups that keep losing get skipped. */
function mpLearned(closed, minN) {
  const by = {};
  for (const t of closed) for (const k of mpBuckets(t)) { const s = by[k] || (by[k] = { n: 0, sum: 0, wins: 0 }); s.n++; s.sum += t.pnlPct; if (t.pnlPct > 0) s.wins++; }
  return Object.entries(by).map(([k, s]) => ({ setup: k, trades: s.n, avgPct: +(s.sum / s.n).toFixed(1), winRate: Math.round((s.wins / s.n) * 100),
    verdict: s.n < minN ? "learning" : s.sum / s.n < -10 ? "skip" : s.sum / s.n > 10 ? "favor" : "neutral" })).sort((a, b) => b.trades - a.trades);
}
/** Pure: how big the next snipe is. With slots, all the money (cash + what's in trades) is split evenly. */
function mpBetSize(bank, S, openPositions, mult = 1, pctOverride = null, sol = 150, stopPct = null, worstPct = null) {
  let size;
  if (S.sizeByRisk && stopPct > 0 && pctOverride == null) {
    // FIXED-RISK: if the stop hits, you lose riskPerTradePct of ALL the money (cash + vault + what is in trades), costs included. position = risk / (stop distance + costs)
    const all = bank.cash + bank.vault + openPositions.reduce((a, p) => a + (p.costUsd || 0), 0);
    let lossFrac = (stopPct + 2 * (S.feePct + S.slippagePct)) / 100;         // the REAL loss at the stop: the stop distance plus fees and slippage on the way in and out
    if (S.sizeByWorst && worstPct > 0) lossFrac = Math.max(lossFrac, Math.min(100, worstPct) / 100);   // a stop does not limit a rug: size by the WORST case
    size = ((all * S.riskPerTradePct) / 100 / lossFrac) * mult;
  } else if (S.slots > 0 && pctOverride == null) {
    // each slot gets an equal share of ALL the money, and the bet is sized so fees + tips fit inside that share
    const inTrades = openPositions.reduce((a, p) => a + (p.costUsd || 0), 0);
    const share = (bank.cash + inTrades) / S.slots, fixed = (S.priorityFeeSol + S.jitoTipSol) * sol;
    size = ((share - fixed) / (1 + S.feePct / 100)) * mult;
  } else size = (bank.cash * (pctOverride ?? S.riskPct) * mult) / 100;
  const cap = (bank.cash * S.maxBetPct) / 100;
  if ((S.slots <= 0 || S.sizeByRisk) && cap > S.minTradeUsd) size = Math.min(size, cap);
  size = Math.min(bank.cash, Math.max(S.minTradeUsd, size));
  if (S.maxLossPct > 0) {                       // worst case (a rug takes the whole bet) stays within maxLossPct of everything
    const all = bank.cash + bank.vault + openPositions.reduce((a, p) => a + (p.costUsd || 0), 0);
    const limit = (all * S.maxLossPct) / 100;
    if (limit < S.minTradeUsd) return 0;          // too small to trade safely: don't trade
    size = Math.min(size, limit);
  }
  return size;
}
const mpMaxOpen = (S) => (S.slots > 0 ? S.slots : S.maxOpen);
/** Pure: what one snipe costs, round trip, as a % of the bet (fees, tips, slippage). */
function mpCostPct(S, bet, sol) {
  if (!(bet > 0)) return null;
  const fixed = 2 * (S.priorityFeeSol + S.jitoTipSol) * sol;
  return +(((fixed + bet * (2 * S.feePct + 2 * S.slippagePct) / 100) / bet) * 100).toFixed(1);
}

/**
 * Pure: WHY AM I LOSING? Reads the closed trades and says, in plain words, what's costing money, with a fix
 * that can be applied in one tap.
 */
function mpDiagnose(closed, S, sol = 150) {
  const T = closed.filter((x) => x.pnlUsd != null), n = T.length, out = [];
  const byReason = {};
  for (const x of T) {
    const w = String(x.why || ""), k = /take profit/.test(w) ? "take profit" : /moon bag: trailing/.test(w) ? "trailing stop on the riding half" : /moon bag: time/.test(w) ? "riding half hit its time limit"
      : /stop loss/.test(w) ? "stop loss" : /no lift-off/.test(w) ? "Launch Shot never took off" : /time limit/.test(w) ? "time limit (never took off)" : /rug zone/.test(w) ? "rug zone cash-out"
      : /creator dumped/.test(w) ? "creator dumped" : /graduated/.test(w) ? "graduated, cashed out" : "other";
    const r = byReason[k] || (byReason[k] = { reason: k, trades: 0, pnlUsd: 0, wins: 0 }); r.trades++; r.pnlUsd += x.pnlUsd; if (x.pnlUsd > 0) r.wins++;
  }
  const reasons = Object.values(byReason).map((r) => ({ ...r, pnlUsd: +r.pnlUsd.toFixed(2) })).sort((a, b) => a.pnlUsd - b.pnlUsd);
  if (n < 5) return { trades: n, reasons, findings: [{ level: "info", text: `Only ${n} closed trade${n === 1 ? "" : "s"} so far. The diagnosis starts at 5.` }] };
  const W = T.filter((x) => x.pnlUsd > 0), Lo = T.filter((x) => x.pnlUsd <= 0);
  const avgWin = W.length ? W.reduce((a, x) => a + x.pnlPct, 0) / W.length : 0, avgLoss = Lo.length ? Lo.reduce((a, x) => a + x.pnlPct, 0) / Lo.length : 0;
  const lossUsd = -Lo.reduce((a, x) => a + x.pnlUsd, 0);
  // what fees, tips and slippage cost on every trade (in and out)
  const feeUsd = T.reduce((a, x) => a + (x.costUsd || 0) * ((2 * S.feePct + 2 * S.slippagePct) / 100) + 2 * (S.priorityFeeSol + S.jitoTipSol) * sol, 0);
  const avgBet = T.reduce((a, x) => a + (x.sizeUsd || x.costUsd || 0), 0) / n;
  if (lossUsd > 0 && feeUsd / lossUsd > 0.4)
    out.push({ level: "bad", text: `Fees are eating you: about $${feeUsd.toFixed(2)} of costs (fees, tips, slippage) against $${lossUsd.toFixed(2)} of losses, because each bet is only about $${avgBet.toFixed(2)}. Smaller bets lose a bigger share to fixed costs.`,
      fix: { slots: 3 }, fixText: "Use 3 bigger snipes instead of 10 small ones" });
  const fast = T.filter((x) => x.fast), fastL = fast.filter((x) => x.pnlUsd <= 0);
  if (fast.length >= 5 && fastL.length / fast.length >= 0.7)
    out.push({ level: "bad", text: `Buying in the first seconds is losing: ${fastL.length} of ${fast.length} Launch Shot trades lost money.`, fix: { fastLane: 0 }, fixText: "Turn Launch Shot off" });
  const dead = T.filter((x) => /no lift-off|time limit/.test(x.why || ""));
  if (dead.length / n >= 0.4)
    out.push({ level: "bad", text: `${dead.length} of ${n} buys never moved and were sold on the timer. The bot is buying launches with no real demand.`,
      fix: S.momentum ? { momBuyers60: Math.min(30, S.momBuyers60 + 4), momNetSol: +(S.momNetSol + 1).toFixed(1) } : { momentum: 1 },
      fixText: S.momentum ? "Demand more buyers and more SOL before buying" : "Switch to Momentum entry" });
  const quick = T.filter((x) => /stop loss/.test(x.why || "") && x.closedAt - x.openedAt < 3 * 60e3);
  if (quick.length / n >= 0.3)
    out.push({ level: "bad", text: `${quick.length} of ${n} trades hit the stop loss within 3 minutes: it's buying right before dumps.`,
      fix: { momentum: 1, maxDevPct: Math.min(S.maxDevPct, 5), maxTop10Pct: Math.min(S.maxTop10Pct, 30) }, fixText: "Momentum entry + stricter creator and top-10 limits" });
  if (W.length && Lo.length && Math.abs(avgLoss) > avgWin * 1.3 && W.length / n < 0.5)
    out.push({ level: "bad", text: `Losers are bigger than winners: average loss ${avgLoss.toFixed(0)}% vs average win +${avgWin.toFixed(0)}%, with only ${Math.round((W.length / n) * 100)}% wins.`,
      fix: { slPct: Math.max(12, Math.min(S.slPct, 20)), tpPct: Math.min(S.tpPct, 75) }, fixText: "Tighter stop (−20%) and earlier profit (+75%)" });
  // each way of entering gets its own report card
  const byType = {};
  for (const x of T) { const k = x.entryType || (x.fast ? "launch shot" : "at 90s"), r = byType[k] || (byType[k] = { type: k, trades: 0, wins: 0, pnlUsd: 0, sumPct: 0 }); r.trades++; if (x.pnlUsd > 0) r.wins++; r.pnlUsd += x.pnlUsd; r.sumPct += x.pnlPct || 0; }
  const types = Object.values(byType).map((r) => ({ type: r.type, trades: r.trades, wins: r.wins, pnlUsd: +r.pnlUsd.toFixed(2), avgPct: +(r.sumPct / r.trades).toFixed(1) })).sort((a, b) => a.pnlUsd - b.pnlUsd);
  const typeFix = { graduate: { gradOn: 0 }, copy: { copyOn: 0 }, "launch shot": { fastLane: 0 } };
  for (const t of types) if (t.trades >= 8 && t.avgPct < -10 && typeFix[t.type])
    out.push({ level: "bad", text: `The "${t.type}" way of entering is losing: ${t.trades} trades, average ${t.avgPct}%, ${tgMoneyPlain(t.pnlUsd)} total. Other entry types are not dragging as hard.`, fix: typeFix[t.type], fixText: `Turn off ${t.type} entries` });
  const pf = lossUsd > 0 ? W.reduce((a, x) => a + x.pnlUsd, 0) / lossUsd : 99;
  if (!out.length && pf >= 1.3) out.push({ level: "good", text: `It's working: winners outweigh losers ${pf.toFixed(2)}× after costs. Keep the current rules.` });
  else if (!out.length) out.push({ level: "info", text: `No single cause stands out yet: ${W.length} wins, ${Lo.length} losses, winners outweigh losers ${pf.toFixed(2)}×. Let it collect more trades.` });
  return { trades: n, winRate: Math.round((W.length / n) * 100), avgWinPct: +avgWin.toFixed(1), avgLossPct: +avgLoss.toFixed(1), profitFactor: +pf.toFixed(2),
    feesUsd: +feeUsd.toFixed(2), avgBetUsd: +avgBet.toFixed(2), reasons, types, findings: out };
}
const tgMoneyPlain = (n) => (n < 0 ? "−$" : "+$") + Math.abs(+n || 0).toFixed(2);
/** Plain English: exactly what the bot is doing right now. */
function mpStrategyText(S) {
  const entry = S.momentum
    ? `It watches each safe launch for up to ${S.momWindowMin} minutes and buys only when real buying shows up: ${S.momBuyers60}+ different buyers in the last minute, buys at least ${S.momBuyShare}% of trades, ${S.momNetSol}+ SOL flowing in, and the price up ${S.momRise2m}%+ over 2 minutes, while still under $${Math.round(S.momMaxMcap / 1000)}K.`
    : `It buys right at 90 seconds if the launch is at least ${S.minProgress}% bonded.`;
  return [
    `SAFETY FIRST: skips known ruggers, copycats, creators spamming launches, tokens the creator can print or freeze, creators holding over ${S.maxDevPct}%, top 10 wallets over ${S.maxTop10Pct}%, or one wallet over ${S.maxTop1Pct}%.`,
    `ENTRY: ${entry}${S.fastLane ? " Launch Shot is ON (also buys some launches in the first seconds)." : ""}`,
    ...(S.gradOn ? [`GRADUATES: also watches tokens that graduate off pump.fun for ${S.gradWindowMin} minutes and buys when real buying shows up on the trading pool (${S.gradBuys5}+ buys in 5 min, ${S.gradBuyShare}%+ buys, liquidity over $${Math.round(S.gradMinLiq / 1000)}K, market cap $${Math.round(S.gradMinMcap / 1000)}K–$${Math.round(S.gradMaxMcap / 1000)}K), only if Jupiter confirms it can be sold. Exits: +${S.gradTp}% sell ${S.gradTp1Sell}%, stop −${S.gradSl}%.`] : []),
    ...(S.copyOn ? [`COPY: follows the top ${S.copyTopN} Smart Wallets when they buy $${S.copyMinUsd}+, after our own safety checks, and gets out when they sell.`] : []),
    `SIZE: ${S.slots > 0 ? `splits the money into ${S.slots} snipes` : `${S.riskPct}% of the balance per snipe`}${S.maxLossPct ? `, never risking more than ${S.maxLossPct}% of everything on one` : ""}.`,
    `EXIT: at +${S.tpPct}% it sells ${S.tp1SellPct}% (money back) and lets the rest ride with a ${S.trailPct}% trailing stop (tighter higher up). Stop loss −${S.slPct}%. Sells after ${S.maxHoldMin} min if it never took off. Sells everything at $${Math.round(S.cashOutMcap / 1000)}K (rug zone) or the moment the creator dumps.`,
    `PROTECTION: stops for the day at −${S.dailyStopPct}%, pauses after ${S.maxLossStreak} losses in a row, locks profit in the vault at ${S.vaultAtX}× the start.`,
  ];
}

/**
 * Pure: the scorecard that decides when real money is allowed.
 * A strategy has to PROVE an edge over many trades before it scales: positive average result after
 * all costs, winners outweighing losers, and no deep drawdowns. Until then it stays on paper.
 */
function mpScorecard(closed, start) {
  const t = closed.slice().reverse();                       // oldest first
  const n = t.length, wins = t.filter((x) => x.pnlUsd > 0);
  const grossWin = wins.reduce((a, x) => a + x.pnlUsd, 0), grossLoss = -t.filter((x) => x.pnlUsd <= 0).reduce((a, x) => a + x.pnlUsd, 0);
  const avgPct = n ? t.reduce((a, x) => a + (x.pnlPct || 0), 0) / n : 0;
  let eq = start, peak = start, maxDD = 0;
  for (const x of t) { eq += x.pnlUsd || 0; peak = Math.max(peak, eq); maxDD = Math.max(maxDD, peak > 0 ? (peak - eq) / peak : 0); }
  const pf = grossLoss > 0 ? grossWin / grossLoss : (grossWin > 0 ? 99 : 0);
  const gates = [
    { test: "200+ paper trades", ok: n >= 200, now: `${n}` },
    { test: "average trade positive after all fees", ok: n > 0 && avgPct > 0, now: `${avgPct >= 0 ? "+" : ""}${avgPct.toFixed(1)}%` },
    { test: "winners outweigh losers 1.3× or more", ok: pf >= 1.3, now: `${pf.toFixed(2)}×` },
    { test: "worst drop under 30%", ok: n > 0 && maxDD < 0.3, now: `${(maxDD * 100).toFixed(0)}%` },
  ];
  return { trades: n, winRate: n ? Math.round((wins.length / n) * 100) : null, avgPct: +avgPct.toFixed(1), profitFactor: +pf.toFixed(2),
           maxDrawdownPct: +(maxDD * 100).toFixed(1), gates, readyForLive: gates.every((g) => g.ok) };
}

/** Pure: daily reset, then is trading allowed right now? */
function mpBankGate(bank, S, now = Date.now(), open = (typeof MP !== "undefined" ? MP.positions : [])) {
  const d = new Date(now).toISOString().slice(0, 10);
  if (bank.day !== d) {
    // the day starts from ALL the trading money: cash on hand + what's sitting in open trades
    bank.day = d; bank.dayStart = bank.cash + (open || []).reduce((a, p) => a + (p.costUsd || 0), 0); bank.dayPnl = 0;
    if (bank.pauseWhy === "daily stop") { bank.pausedUntil = 0; bank.pauseWhy = null; }
  }
  if (bank.pausedUntil > now) return `paused: ${bank.pauseWhy}`;
  if (bank.cash < S.minTradeUsd) return "trading balance too low (the vault is safe)";
  return null;
}
/** Pure: after a trade closes — streaks, daily stop, and locking profits in the vault. Returns messages. */
function mpAfterClose(bank, S, pnlUsd, now = Date.now()) {
  const msgs = [];
  bank.streak = pnlUsd > 0 ? 0 : bank.streak + 1;
  if (bank.streak >= S.maxLossStreak) { bank.pausedUntil = now + S.pauseMin * 60e3; bank.pauseWhy = `${bank.streak} losses in a row`; bank.streak = 0;
    msgs.push(`Paused ${S.pauseMin} minutes after ${S.maxLossStreak} losses in a row`); }
  // daily stop counts real results only: money parked in open trades is not a loss
  bank.dayPnl = (bank.dayPnl || 0) + pnlUsd;
  if (bank.dayStart > 0 && bank.dayPnl <= -bank.dayStart * (S.dailyStopPct / 100)) {
    const t = new Date(now); t.setUTCHours(24, 0, 0, 0);
    bank.pausedUntil = t.getTime(); bank.pauseWhy = "daily stop";
    msgs.push(`Down ${S.dailyStopPct}% today: stopped until tomorrow`);
  }
  if (bank.cash >= bank.start * S.vaultAtX) {
    const keep = bank.start * S.keepX, moved = bank.cash - keep;
    if (moved > 0) { bank.vault += moved; bank.cash = keep; msgs.push(`Locked $${moved.toFixed(2)} of profit in the vault, kept $${keep.toFixed(2)} trading`); }
  }
  bank.peak = Math.max(bank.peak || 0, bank.cash + bank.vault);
  return msgs;
}
const CREATE_EVENT_ID = crypto.createHash("sha256").update("event:CreateEvent").digest().subarray(0, 8);
const FAMOUS_TICKERS = new Set(["SOL", "USDC", "USDT", "BONK", "WIF", "JUP", "TRUMP", "POPCAT", "PEPE", "DOGE", "SHIB", "BTC", "ETH", "PNUT", "MOODENG", "FARTCOIN", "PENGU"]);

/** Pure: decode pump.fun's CreateEvent from a "Program data:" log line. Returns null if it isn't one. */
function decodeCreateEvent(b64) {
  try {
    const buf = Buffer.from(b64, "base64");
    if (buf.length < 8 + 12 + 96 || !buf.subarray(0, 8).equals(CREATE_EVENT_ID)) return null;
    let o = 8;
    const str = (max) => { const n = buf.readUInt32LE(o); o += 4; if (n > max || o + n > buf.length) throw 0; const v = buf.subarray(o, o + n).toString("utf8"); o += n; return v; };
    const key = () => { if (o + 32 > buf.length) throw 0; const k = new PublicKey(buf.subarray(o, o + 32)).toBase58(); o += 32; return k; };
    const name = str(200), symbol = str(50), uri = str(400);
    const mint = key(), curve = key(), creator = key();
    return { name: name.replace(/[<>\u0000]/g, "").slice(0, 60), symbol: symbol.replace(/[<>\u0000]/g, "").slice(0, 20), uri, mint, curve, creator };
  } catch { return null; }
}


// ═══════════════════════════════════════════════════════════════════════
// 🧪 WINNER LAB — study every launch, find what the winners had in common, score new ones early
// ═══════════════════════════════════════════════════════════════════════
/**
 * For every launch ALKAID judges (winners AND losers), the lab writes down what the launch looked like
 * at ~90 seconds: how far along the curve, who holds it, what the creator did before, whether it has a
 * website / X / Telegram, when it launched, what it's called. Later it checks what happened:
 *   WIN  = graduated, OR showed up on the trending list, OR reached a $100K market cap
 * Then it counts, feature by feature, how much more (or less) often winners had each trait: the "lift".
 * New launches get a score from those lifts, at 90 seconds, long before they trend.
 * Until it has 300 finished launches it only shows its starting guesses (from published research) and
 * does not influence trading.
 */
const LAB_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-lab.json") : "";
const LAB = { snaps: [], devs: new Map(), trended: new Map(), cache: null, cacheAt: 0 };
const LAB_CP = [20 * 60e3, 2 * 3600e3, 12 * 3600e3];          // outcome checkpoints after launch
const LAB_MATURE = LAB_CP[LAB_CP.length - 1] + 30 * 60e3;   // a launch counts in the lifts only after its last check (12.5 h): before that only its WINS were final, which flattered every trait of recent launches
const LAB_READY_AT = 300;                                     // finished launches needed before the lab may steer trading
try { if (LAB_FILE && nodeFs.existsSync(LAB_FILE)) { const d = JSON.parse(nodeFs.readFileSync(LAB_FILE, "utf8")); LAB.snaps = d.snaps || []; for (const [k, v] of d.devs || []) LAB.devs.set(k, v); } } catch {}
const labSave = () => { if (!LAB_FILE) return; try { const t = LAB_FILE + ".tmp";
  nodeFs.writeFileSync(t, JSON.stringify({ snaps: LAB.snaps.slice(-4000), devs: [...LAB.devs].slice(-20000) })); nodeFs.renameSync(t, LAB_FILE); } catch {} };
regFlush(labSave); setInterval(labSave, 2 * 60e3);

async function labSocial(uri) {                                // website / X / Telegram, read from the token's own metadata file
  if (!/^https:\/\//.test(uri || "")) return null;
  try {
    const j = await (await withTimeout(fetch(uri), 3500, "token meta")).json();
    const has = (x) => typeof x === "string" && x.trim().length > 3;
    return [has(j.twitter), has(j.telegram), has(j.website)].filter(Boolean).length;
  } catch { return null; }
}
/** Write down what this launch looked like. Safe to call more than once. */
function labSnap(ev, m, devPct, nonStd) {
  const old = LAB.snaps.find((x) => x.mint === ev.mint); if (old) return old;
  const d = LAB.devs.get(ev.creator) || { l: 0, g: 0 }, nm = String(ev.name || ""), at = ev.launchedAt || Date.now();
  const s = { mint: ev.mint, sym: ev.symbol, name: ev.name, creator: ev.creator, at, hour: new Date(at).getUTCHours(),
    progress: +(+m.progress).toFixed(2), mcap: Math.round(m.mcap), top10: null, top1: null, devPct: devPct == null ? null : +devPct.toFixed(2),
    ...(() => { const fs = flowStats(FLOW.get(ev.mint)); return { fBuyers: fs.buyersTotal, fNet: fs.netTotal, fShare: fs.buyShare60 }; })(),
    dev24: (MP.creators.get(ev.creator) || []).length, devL: d.l, devG: d.g, social: null, nameLen: nm.length,
    emoji: /[^\x00-\x7F]/.test(nm + (ev.symbol || "")) ? 1 : 0, cp: 0, peak: nonStd ? 0 : Math.round(m.mcap), ns: nonStd ? 1 : 0, grad: false, trended: false, win: false, done: false };
  d.l++; LAB.devs.set(ev.creator, d); if (LAB.devs.size > 30000) LAB.devs.delete(LAB.devs.keys().next().value);
  LAB.snaps.push(s); if (LAB.snaps.length > 5000) LAB.snaps.splice(0, LAB.snaps.length - 5000);
  labSocial(ev.uri).then((v) => { s.social = v; }).catch(() => {});
  return s;
}
function labFeat(mint, obj) { const s = LAB.snaps.find((x) => x.mint === mint); if (s) Object.assign(s, obj); }

/** What happened to each one? Checked at 20 min, 2 h and 12 h. */
setInterval(async () => {
  const now = Date.now(); let n = 0;
  if (typeof rpcBudgetOk === "function" && !rpcBudgetOk()) return;
  for (const [k, t] of LAB.trended) if (now - t > 36 * 3600e3) LAB.trended.delete(k);
  for (const s of LAB.snaps) {
    if (n >= 6) break;
    if (s.done || s.at + LAB_CP[s.cp] > now) continue;
    n++;
    try {
      const c = await readBondingCurve(s.mint);
      let mc = null;
      if (c && c.complete) { s.grad = true; const dx = await mpDexPrice(s.mint); mc = dx ? dx.mcap : null; }
      else if (c && !s.ns) mc = curveMarket(c, await getSolUsd(), 6).mcap;   // a non-standard curve's market cap can't be computed: never a "$100K winner"
      if (mc) s.peak = Math.max(s.peak || 0, Math.round(mc));
    } catch { continue; }
    if (LAB.trended.has(s.mint)) s.trended = true;
    if (s.grad || s.trended || (s.peak >= 100000 && !s.ns)) s.win = true;
    if (s.grad && !s.gradCounted) { s.gradCounted = true; const d = LAB.devs.get(s.creator); if (d) d.g++; }
    s.cp++;
    if (s.win || s.cp >= LAB_CP.length) s.done = true;        // a win is final; a loss is final only after the 12 h look
  }
}, 15000);

const LAB_FEATURES = [
  ["How far along the curve at 90s", (s) => s.progress, [[0, 3, "under 3% bonded"], [3, 6, "3–6% bonded"], [6, 12, "6–12% bonded"], [12, 25, "12–25% bonded"], [25, 101, "25%+ bonded"]]],
  ["Market cap at 90s", (s) => s.mcap, [[0, 6000, "market cap under $6K"], [6000, 9000, "market cap $6–9K"], [9000, 15000, "market cap $9–15K"], [15000, 1e12, "market cap over $15K"]]],
  ["Top 10 holders", (s) => s.top10, [[0, 15, "top 10 hold under 15%"], [15, 25, "top 10 hold 15–25%"], [25, 40, "top 10 hold 25–40%"], [40, 101, "top 10 hold 40%+"]]],
  ["Biggest single wallet", (s) => s.top1, [[0, 5, "biggest wallet under 5%"], [5, 10, "biggest wallet 5–10%"], [10, 20, "biggest wallet 10–20%"], [20, 101, "biggest wallet 20%+"]]],
  ["Creator's bag", (s) => s.devPct, [[0, 0.5, "creator holds almost nothing"], [0.5, 2, "creator holds 0.5–2%"], [2, 5, "creator holds 2–5%"], [5, 10, "creator holds 5–10%"], [10, 101, "creator holds 10%+"]]],
  ["Creator's launches today", (s) => s.dev24, [[0, 2, "creator's first launch today"], [2, 3, "creator's second launch today"], [3, 999, "creator launched 3+ today"]]],
  ["Creator's track record", (s) => s.devG, [[0, 1, "creator has no past graduates"], [1, 999, "creator already graduated a token"]]],
  ["Website / X / Telegram", (s) => s.social, [[0, 1, "no website, X or Telegram"], [1, 2, "1 social link"], [2, 3, "2 social links"], [3, 4, "website + X + Telegram"]]],
  ["Hour launched (UTC)", (s) => s.hour, [[0, 6, "launched 00–06 UTC"], [6, 12, "launched 06–12 UTC"], [12, 18, "launched 12–18 UTC"], [18, 24, "launched 18–24 UTC"]]],
  ["Name length", (s) => s.nameLen, [[0, 5, "very short name (≤4)"], [5, 9, "short name (5–8)"], [9, 15, "medium name (9–14)"], [15, 999, "long name (15+)"]]],
  ["Emoji in the name", (s) => s.emoji, [[0, 1, "no emoji in the name"], [1, 2, "emoji in the name"]]],
  ["Different buyers in the first 90s", (s) => s.fBuyers, [[0, 5, "under 5 buyers in 90s"], [5, 15, "5–15 buyers in 90s"], [15, 40, "15–40 buyers in 90s"], [40, 1e9, "40+ buyers in 90s"]]],
  ["Net SOL in, first 90s", (s) => s.fNet, [[-1e9, 0, "more SOL out than in"], [0, 2, "0–2 SOL in"], [2, 8, "2–8 SOL in"], [8, 1e9, "8+ SOL in"]]],
  ["Buy share, last minute", (s) => s.fShare, [[0, 50, "sells outnumber buys"], [50, 65, "50–65% buys"], [65, 80, "65–80% buys"], [80, 101, "80%+ buys"]]],
];
// starting guesses from published pump.fun research, used only until the lab has enough of its own data
const LAB_PRIOR = { "no website, X or Telegram": 0.5, "1 social link": 1.6, "2 social links": 4, "website + X + Telegram": 9, "creator already graduated a token": 5 };
const labBucket = (bins, v) => { if (v == null || Number.isNaN(v)) return null; for (const [lo, hi, label] of bins) if (v >= lo && v < hi) return label; return null; };

/** Count, feature by feature, how much more (or less) often winners had each trait. Cached 20 s. */
function labAnalyze() {
  const now = Date.now(); if (LAB.cache && now - LAB.cacheAt < 20000) return LAB.cache;
  const L = LAB.snaps.filter((s) => (s.win || s.done) && now - s.at >= LAB_MATURE), W = L.filter((s) => s.win).length, base = L.length ? W / L.length : 0, K = 20;
  const rows = [], table = new Map();
  for (const [feat, get, bins] of LAB_FEATURES) for (const [lo, hi, label] of bins) {
    const inB = L.filter((s) => { const v = get(s); return v != null && v >= lo && v < hi; });
    if (inB.length < 5) continue;
    const w = inB.filter((s) => s.win).length, rate = (w + base * K) / (inB.length + K), lift = base > 0 ? rate / base : 1;
    rows.push({ feat, label, n: inB.length, wins: w, ratePct: +(rate * 100).toFixed(2), lift: +lift.toFixed(2) }); table.set(label, lift);
  }
  const ready = L.length >= LAB_READY_AT && W >= 8;
  LAB.cache = { L: L.length, W, base, ready, rows, table }; LAB.cacheAt = now; return LAB.cache;
}
/** The launch's lift: how many times better than a random launch, from the lifts of each trait it has. */
function labLift(s, A = labAnalyze()) {
  if (!s) return 1;
  if (typeof rugReg !== "undefined" && rugReg.has(s.creator)) return 0.05;       // a known rugger's launch is never a "winner"
  let sum = 0;
  for (const [feat, get, bins] of LAB_FEATURES) {
    const label = labBucket(bins, get(s)); if (!label) continue;
    let l = A.ready ? A.table.get(label) : LAB_PRIOR[label];
    if (l == null) continue;
    sum += Math.log(Math.min(4, Math.max(0.25, l)));
  }
  return Math.exp(0.6 * sum);                                                    // dampened: traits overlap, so don't count them in full
}
function labPublic() {
  const A = labAnalyze(), now = Date.now();
  const win = A.rows.filter((r) => r.n >= 20 && r.lift >= 1.4).sort((a, b) => b.lift - a.lift).slice(0, 8);
  const avoid = A.rows.filter((r) => r.n >= 20 && r.lift <= 0.6).sort((a, b) => a.lift - b.lift).slice(0, 6);
  const hot = LAB.snaps.filter((s) => !s.done && now - s.at < 30 * 60e3).map((s) => ({ s, lift: labLift(s, A) }))
    .sort((a, b) => b.lift - a.lift).slice(0, 8).map(({ s, lift }) => ({ mint: s.mint, symbol: s.sym, name: s.name, progress: s.progress, mcap: s.mcap, social: s.social, at: s.at,
      lift: +lift.toFixed(2), oddsPct: +Math.min(95, A.base * lift * 100).toFixed(1) }));
  const graduated = LAB.snaps.filter((s) => s.grad).length, trended = LAB.snaps.filter((s) => s.trended).length;
  return { collected: LAB.snaps.length, finished: A.L, wins: A.W, graduated, trended, baselinePct: +(A.base * 100).toFixed(2), ready: A.ready, readyAt: LAB_READY_AT,
    winners: win, avoid, hot, starter: !A.ready };
}


// ═══════════════════════════════════════════════════════════════════════
// 🎯 SWEET SPOT FINDER — record real price paths, replay them under hundreds of rule sets, keep what wins
// ═══════════════════════════════════════════════════════════════════════
/**
 * Every launch the bot judges gets its price recorded every 15 s for 45 minutes (one batched chain read
 * covers up to 100 launches, so this is cheap). The finder then replays those real paths under hundreds of
 * combinations of take-profit, sell-amount, stop-loss, trailing window and hold time, plus entry filters,
 * with every fee, tip and slippage counted. To avoid fooling itself with luck, it splits the data in two
 * (older and newer), drops each half's single best trade, and only trusts settings that make money in BOTH.
 */
const PATH_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-paths.json") : "";
const PATH_STEP = 15000, PATH_LEN = (45 * 60e3) / PATH_STEP;
const PATHS = { list: [], live: new Map(), best: null, bestAt: 0, tunedAt: 0 };
try { if (PATH_FILE && nodeFs.existsSync(PATH_FILE)) PATHS.list = JSON.parse(nodeFs.readFileSync(PATH_FILE, "utf8")) || []; } catch {}
const pathSave = () => { if (!PATH_FILE) return; try { const t = PATH_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(PATHS.list.slice(-4000))); nodeFs.renameSync(t, PATH_FILE); } catch {} };
regFlush(pathSave); setInterval(pathSave, 5 * 60e3);
function pathStart(ev, m) {
  if (PATHS.live.has(ev.mint) || PATHS.live.size >= 300 || !(m.price > 0)) return;
  let curve; try { curve = PublicKey.findProgramAddressSync([Buffer.from("bonding-curve"), new PublicKey(ev.mint).toBuffer()], PUMP_PROGRAM)[0]; } catch { return; }
  PATHS.live.set(ev.mint, { mint: ev.mint, curve, p0: m.price, mcap0: m.mcap || null, at: Date.now(), pts: [1], grad: false });
}
function pathEnd(x) {
  PATHS.live.delete(x.mint);
  PATHS.list.push({ mint: x.mint, at: x.at, mcap0: x.mcap0, pts: x.pts, grad: x.grad });
  try { ledAdd(PATHS.list[PATHS.list.length - 1]); } catch {}
  if (PATHS.list.length > 4000) PATHS.list.splice(0, PATHS.list.length - 4000);
}
async function pathTick() {
  const live = [...PATHS.live.values()]; if (!live.length) return;
  if (typeof rpcBudgetOk === "function" && !rpcBudgetOk()) return;
  const sol = await getSolUsd().catch(() => null); if (!sol) return;
  for (let i = 0; i < live.length; i += 100) {
    const batch = live.slice(i, i + 100);
    let infos; try { infos = await withTimeout(connection.getMultipleAccountsInfo(batch.map((x) => x.curve)), 8000, "price paths"); } catch { continue; }
    batch.forEach((x, j) => {
      const acct = infos && infos[j], c = acct ? decodeBondingCurve(acct.data) : null;
      if (c && c.complete) { x.grad = true; pathEnd(x); return; }
      x.pts.push(c ? +(curveMarket(c, sol, 6).price / x.p0).toFixed(4) : x.pts[x.pts.length - 1]);
      if (x.pts.length >= PATH_LEN) pathEnd(x);
    });
  }
}
setInterval(() => { pathTick().catch(() => {}); }, PATH_STEP);

/** Pure: replay one recorded path (prices ÷ the price when judged) under a rule set. Net % result after every cost. */
function simPath(pts, R, fixedFrac, mcap0) {
  const slip = R.slippagePct / 100, fee = R.feePct / 100, entry = 1 + slip, step = PATH_STEP / 60000;
  let left = 1, got = 0, sells = 0, moon = false, mh = 0;
  const sell = (frac, px) => { got += left * frac * (px * (1 - slip) * (1 - fee)) / entry; left -= left * frac; sells++; };
  for (let i = 1; i < pts.length && left > 1e-9; i++) {
    const px = pts[i], ch = (px / entry - 1) * 100, age = i * step;
    if (R.cashOutMcap > 0 && mcap0 && mcap0 * px >= R.cashOutMcap) { sell(1, px); break; }
    if (!moon) {
      if (ch >= R.tpPct) { if (R.tp1SellPct >= 100) { sell(1, px); break; } sell(R.tp1SellPct / 100, px); moon = true; mh = px; continue; }
      if (ch <= -R.slPct || age > R.maxHoldMin) { sell(1, px); break; }
    } else {
      mh = Math.max(mh, px); const run = mh / entry;
      const trail = run >= 10 ? Math.min(R.trailPct, R.trailAt10x) : run >= 5 ? Math.min(R.trailPct, R.trailAt5x) : R.trailPct;
      if (px <= mh * (1 - trail / 100) || age > R.moonHoldMin) { sell(1, px); break; }
    }
  }
  if (left > 1e-9) sell(1, pts[pts.length - 1]);                 // recording ended or it graduated: out at the last price
  const cost = (1 + fee) + fixedFrac, back = got - fixedFrac * sells;
  return ((back - cost) / cost) * 100;
}
const sumTrim = (rs) => (rs.length ? rs.reduce((a, b) => a + b, 0) - Math.max(...rs) : 0);   // drop the single luckiest trade

/** Search the rules. Returns the best set, how it did on each half, and how your current rules did on the same data. */
function sweetSpot(S, sol = 150) {
  const snaps = new Map(LAB.snaps.map((x) => [x.mint, x]));
  const rows = PATHS.list.slice(-2000).filter((p) => p.pts && p.pts.length >= 12).map((p) => ({ p, s: snaps.get(p.mint) })).filter((x) => x.s).sort((a, b) => a.p.at - b.p.at);
  const need = 120;
  if (rows.length < need) return { ready: false, paths: PATHS.list.length, usable: rows.length, need };
  const bet = Math.max(S.minTradeUsd || 0.25, 1), fixedFrac = ((S.priorityFeeSol + S.jitoTipSol) * sol) / bet;
  const half = Math.floor(rows.length / 2);
  const passes = (s, E) => s.progress >= E.minProgress && (s.top10 == null || s.top10 <= E.maxTop10Pct) && (s.devPct == null || s.devPct <= E.maxDevPct) && (!E.labMinLift || labLift(s) >= E.labMinLift);
  const judge = (Rx, E) => {
    const A = [], B = [];
    rows.forEach((x, i) => { if (!passes(x.s, E)) return; const r = simPath(x.p.pts, Rx, fixedFrac, x.p.mcap0); (i < half ? A : B).push(r); });
    const all = A.concat(B), wins = all.filter((r) => r > 0).length;
    const ok = A.length >= 15 && B.length >= 15;
    return { score: ok ? Math.min(sumTrim(A) / A.length, sumTrim(B) / B.length) : -1e9, trades: all.length, winRate: all.length ? Math.round((wins / all.length) * 100) : 0,
      avgPct: all.length ? +(all.reduce((a, b) => a + b, 0) / all.length).toFixed(1) : 0, olderAvg: A.length ? +(sumTrim(A) / A.length).toFixed(1) : null,
      newerAvg: B.length ? +(sumTrim(B) / B.length).toFixed(1) : null, ok };
  };
  const curE = { minProgress: S.minProgress, maxTop10Pct: S.maxTop10Pct, maxDevPct: S.maxDevPct, labMinLift: S.labFilter ? S.labMinLift : 0 };
  const current = judge(S, curE);
  // step 1: exits
  let bestR = null, bestRes = null;
  for (const tpPct of [40, 60, 100, 150, 250]) for (const tp1SellPct of [50, 75, 100]) for (const slPct of [15, 25, 35]) for (const trailPct of [15, 25, 35]) for (const maxHoldMin of [10, 20, 40]) {
    const Rx = { ...S, tpPct, tp1SellPct, slPct, trailPct, maxHoldMin }, res = judge(Rx, curE);
    if (!bestRes || res.score > bestRes.score) { bestRes = res; bestR = { tpPct, tp1SellPct, slPct, trailPct, maxHoldMin }; }
  }
  // step 2: entry filters, with the best exits
  let bestE = curE, best = bestRes;
  for (const minProgress of [3, 5, 8, 12, 18]) for (const maxTop10Pct of [25, 35, 50]) for (const maxDevPct of [3, 8, 15]) for (const labMinLift of [0, 1, 1.5]) {
    const E = { minProgress, maxTop10Pct, maxDevPct, labMinLift }, res = judge({ ...S, ...bestR }, E);
    if (res.score > best.score) { best = res; bestE = E; }
  }
  const settings = { ...bestR, minProgress: bestE.minProgress, maxTop10Pct: bestE.maxTop10Pct, maxDevPct: bestE.maxDevPct, labFilter: bestE.labMinLift ? 1 : 0, labMinLift: bestE.labMinLift || S.labMinLift };
  return { ready: true, paths: PATHS.list.length, usable: rows.length, settings, best, current, betterBy: best.ok && current.ok ? +(best.avgPct - current.avgPct).toFixed(1) : null,
    trustworthy: best.ok && best.olderAvg > 0 && best.newerAvg > 0 };
}
function sweetRun() {
  try { PATHS.best = sweetSpot(MP.settings, solUsd.v || 150); } catch (e) { PATHS.best = { ready: false, error: e.message, paths: PATHS.list.length }; }
  PATHS.bestAt = Date.now(); PATHS.computing = false; return PATHS.best;
}
/** Never makes a page wait: returns the last answer and refreshes it in the background every 20 minutes. */
function sweetCached(force) {
  if (force) return sweetRun();
  if ((!PATHS.best || Date.now() - PATHS.bestAt > 20 * 60e3) && !PATHS.computing) { PATHS.computing = true; setTimeout(sweetRun, 50); }
  return PATHS.best || { ready: false, computing: true, paths: PATHS.list.length, usable: 0, need: 120 };
}
/** Auto-tune: every 6 hours, adopt the sweet spot, but only when it made money in BOTH halves and beats your current rules. */
function sweetApply(r, why) {
  Object.assign(MP.settings, r.settings);
  mpEvent(`Sweet spot ${why}: take profit +${r.settings.tpPct}%, sell ${r.settings.tp1SellPct}%, stop −${r.settings.slPct}%, trail ${r.settings.trailPct}%, hold ${r.settings.maxHoldMin}m, min ${r.settings.minProgress}% bonded`);
}
setInterval(() => {
  if (!MP.settings.autoTune) return;
  const r = sweetCached(true);
  if (r.ready && r.trustworthy && r.betterBy != null && r.betterBy > 2 && Date.now() - PATHS.tunedAt > 6 * 3600e3) { PATHS.tunedAt = Date.now(); sweetApply(r, "auto-applied"); }
}, 30 * 60e3);


// ═══════════════════════════════════════════════════════════════════════
// 🎓 GRADUATE strategy · 👥 COPY trading · 🧪 EXPERIMENTS · ▦ GRID
// ═══════════════════════════════════════════════════════════════════════
const symOf = (m) => { const l = LAB.snaps.find((x) => x.mint === m); if (l && l.sym) return l.sym; const g = GR.grads.find((x) => x.mint === m); if (g && g.sym) return g.sym;
  const t = typeof TOP !== "undefined" ? TOP.list.find((x) => x.addr === m) : null; return t ? t.sym : "?"; };
const gradRules = (S) => ({ tpPct: S.gradTp, tp1SellPct: S.gradTp1Sell, slPct: S.gradSl, trailPct: S.gradTrail, trailAt5x: 10, trailAt10x: 8, maxHoldMin: S.gradHold, moonHoldMin: 180, cashOutMcap: 0 });
const copyRules = (S) => ({ tpPct: S.copyTp, tp1SellPct: S.copyTp1Sell, slPct: S.copySl, trailPct: S.copyTrail, trailAt5x: 12, trailAt10x: 8, maxHoldMin: S.copyHold, moonHoldMin: 180, cashOutMcap: 0 });

/** After a token graduates, watch its trading pool and buy only when real buying shows up. */
const GW = new Map();
function gradWatchAdd(mint) {
  if (!MP.settings.gradOn || GW.has(mint)) return;
  GW.set(mint, { mint, t0: Date.now(), until: Date.now() + MP.settings.gradWindowMin * 60e3, sym: symOf(mint), why: ["just graduated"] });
  if (GW.size > 200) GW.delete(GW.keys().next().value);
}
async function gradTick() {
  const S = MP.settings; if (!S.gradOn || !MP.on || !GW.size) return;
  const sol = await getSolUsd().catch(() => null); if (!sol) return;
  const now = Date.now(), mints = [...GW.keys()].slice(0, 30), info = await dexBatch(mints);
  for (const mint of mints) {
    const w = GW.get(mint), d = info.get(mint); if (!w) continue;
    if (now > w.until) { GW.delete(mint); continue; }
    if (!d) { w.why = ["waiting for the trading pool to appear"]; continue; }
    if (w.sym === "?") w.sym = symOf(mint);
    w.last = d;
    if (MP.positions.some((p) => p.mint === mint)) { GW.delete(mint); continue; }
    const tot = d.buys5 + d.sells5, share = tot ? (d.buys5 / tot) * 100 : 0, why = [];
    if (d.liq < S.gradMinLiq) why.push(`liquidity $${Math.round(d.liq / 1000)}K (need $${Math.round(S.gradMinLiq / 1000)}K)`);
    if (d.mcap < S.gradMinMcap) why.push(`market cap $${Math.round(d.mcap / 1000)}K is below $${Math.round(S.gradMinMcap / 1000)}K`);
    if (d.mcap > S.gradMaxMcap) { GW.delete(mint); mpSkipGrad(w, `already above $${Math.round(S.gradMaxMcap / 1000)}K`); continue; }
    if (S.gradMinLiqPct > 0 && d.mcap > 0 && (d.liq / d.mcap) * 100 < S.gradMinLiqPct) why.push(`liquidity is only ${((d.liq / d.mcap) * 100).toFixed(1)}% of market cap (need ${S.gradMinLiqPct}%)`);
    if (S.gradMinVol24 > 0 && d.vol24 < S.gradMinVol24) why.push(`24h volume $${Math.round(d.vol24 / 1000)}K (need $${Math.round(S.gradMinVol24 / 1000)}K)`);
    if (d.buys5 < S.gradBuys5) why.push(`${d.buys5}/${S.gradBuys5} buys in 5 min`);
    if (share < S.gradBuyShare) why.push(`${Math.round(share)}% buys (need ${S.gradBuyShare}%)`);
    if (d.ch5 == null || d.ch5 < S.gradMinCh5) why.push(`5-min change ${d.ch5 == null ? "?" : d.ch5}% (need +${S.gradMinCh5}%)`);
    else if (d.ch5 > S.gradMaxCh5) why.push(`5-min change +${d.ch5}%: too hot, not chasing`);
    if (d.ch1 != null && d.ch1 < S.gradMinCh1) why.push(`1-hour change ${d.ch1}%: falling`);
    w.why = why; if (why.length) continue;
    if (MP.positions.filter((p) => p.entryType === "graduate").length >= S.gradMaxOpen) { w.why = ["all graduate slots are full"]; continue; }
    GW.delete(mint);                                                                // judged once: buy or drop
    const chk = await getMintCheck(mint).catch(() => null);
    if (!chk || !chk.found) { mpSkipGrad(w, "couldn't check the contract"); continue; }
    if (!chk.mintAuthorityRenounced || !chk.freezeAuthorityRenounced) { mpSkipGrad(w, "creator can print or freeze"); continue; }
    const sr = await sellRoute(mint, 100, d.price, chk.decimals == null ? 6 : chk.decimals, sol);
    if (!sr.checked) { mpSkipGrad(w, "couldn't confirm it can be sold"); continue; }
    if (!sr.ok) { mpSkipGrad(w, "no sell route (can't sell it)"); continue; }
    if (sr.impactPct > S.gradMaxImpact) { mpSkipGrad(w, `selling just $100 would move the price ${sr.impactPct}% (limit ${S.gradMaxImpact}%)`); continue; }
    mpOpen({ mint, symbol: w.sym, name: w.sym, creator: null, uri: null }, { price: d.price, mcap: d.mcap, progress: 100 },
      { top10: chk.top10WalletPct, top1: chk.top1WalletPct, devPct: null, labA: null, labL: 1, sol, entryType: "graduate", rules: gradRules(S),
        momentum: `after graduation: ${d.buys5} buys/5m, ${Math.round(share)}% buys, +${d.ch5}% in 5m`,
        why: `GRADUATE · ${d.buys5} buys in 5m · ${Math.round(share)}% buys · +${d.ch5}% 5m · liquidity $${Math.round(d.liq / 1000)}K · $${Math.round(d.mcap / 1000)}K cap · sells ok (${sr.impactPct}% impact)` });
  }
}
function mpSkipGrad(w, reason) { MP.skips["graduate: " + reason] = (MP.skips["graduate: " + reason] || 0) + 1; mpTape(w.mint, "skipped: graduate: " + reason); }
setInterval(() => { gradTick().catch(() => {}); }, 20000);

/** COPY trading: a top Smart Wallet just bought something. If it passes our own safety checks, follow it (paper). */
async function mpCopyBuy(wallet, mint, sym, usd, rank, stack) {
  const S = MP.settings; if (!S.copyOn || !MP.on) return;
  if (rank == null || rank > S.copyTopN || usd < S.copyMinUsd || stack < S.copyMinWallets) return;
  if (MP.positions.some((p) => p.mint === mint) || MP.closed.slice(0, 80).some((p) => p.mint === mint && Date.now() - p.closedAt < 6 * 3600e3)) return;
  if (MP.positions.filter((p) => p.entryType === "copy").length >= S.copyMaxOpen) return;
  const sol = await getSolUsd().catch(() => null); if (!sol) return;
  let m = null; const c = await readBondingCurve(mint).catch(() => null);
  if (c && !c.complete) { const cm = curveMarket(c, sol, 6); if (cm.progress < 3) return mpSkipCopy(mint, sym, "too early on the curve"); m = { price: cm.price, mcap: cm.mcap, progress: cm.progress }; }
  else { const dx = await mpDexPrice(mint); if (!dx) return mpSkipCopy(mint, sym, "no price"); if (dx.liq < 10000) return mpSkipCopy(mint, sym, `liquidity only $${Math.round(dx.liq / 1000)}K`); m = { price: dx.price, mcap: dx.mcap, progress: 100 }; }
  const chk = await getMintCheck(mint).catch(() => null);
  if (!chk || !chk.found) return mpSkipCopy(mint, sym, "couldn't check the contract");
  if (!chk.mintAuthorityRenounced || !chk.freezeAuthorityRenounced) return mpSkipCopy(mint, sym, "creator can print or freeze");
  if (m.progress >= 100) { const sr = await sellRoute(mint, 100, m.price, chk.decimals == null ? 6 : chk.decimals, sol); if (!sr.checked || !sr.ok || sr.impactPct > 12) return mpSkipCopy(mint, sym, "can't confirm it can be sold"); }
  mpOpen({ mint, symbol: sym, name: sym, creator: null, uri: null }, m, { top10: chk.top10WalletPct, top1: chk.top1WalletPct, devPct: null, labA: null, labL: 1, sol,
    entryType: "copy", rules: copyRules(S), extra: { copyOf: wallet, copyRank: rank }, momentum: `copying smart wallet #${rank}`,
    why: `COPY · smart wallet #${rank} bought $${Math.round(usd)} · ${stack} smart wallet${stack > 1 ? "s" : ""} in · $${Math.round(m.mcap / 1000)}K cap` });
}
function mpSkipCopy(mint, sym, reason) { MP.skips["copy: " + reason] = (MP.skips["copy: " + reason] || 0) + 1; }
/** The wallet we copied sold: get out too. */
function mpCopySell(wallet, mint) { for (const p of MP.positions) if (p.copyOf === wallet && p.mint === mint && !p.forceExit) p.forceExit = "copied wallet sold: got out"; }

/**
 * EXPERIMENTS: every real entry is also opened, as a $100 paper bet, under several different exit rule sets.
 * Same entries, different exits, so the comparison is fair. Results are kept (and saved) so you can see
 * which way of selling makes the most money on YOUR trades.
 */
const EXP_SETS = [
  { id: "mine", name: "Your rules (as set)", rules: null },
  { id: "scalp", name: "Quick scalp", rules: { tpPct: 40, tp1SellPct: 100, slPct: 15, trailPct: 15, maxHoldMin: 10, moonHoldMin: 20, cashOutMcap: 0 } },
  { id: "tight", name: "Tight stop", rules: { tpPct: 60, tp1SellPct: 70, slPct: 12, trailPct: 18, maxHoldMin: 20, moonHoldMin: 60, cashOutMcap: 0 } },
  { id: "balanced", name: "Balanced", rules: { tpPct: 100, tp1SellPct: 50, slPct: 30, trailPct: 25, maxHoldMin: 30, moonHoldMin: 180, cashOutMcap: 100000 } },
  { id: "ladder", name: "V1.0 staged exits", rules: { ladderOn: 1, slPct: 15, trailPct: 20, maxHoldMin: 30, moonHoldMin: 120, cashOutMcap: 0 } },
  { id: "runner", name: "Let it run", rules: { tpPct: 150, tp1SellPct: 40, slPct: 35, trailPct: 30, trailAt5x: 18, trailAt10x: 12, maxHoldMin: 45, moonHoldMin: 240, cashOutMcap: 0 } },
];
const EXP_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-experiments.json") : "";
const EXP = { open: [], book: {} };
EXP_SETS.forEach((e) => { EXP.book[e.id] = { n: 0, wins: 0, sumPct: 0, gw: 0, gl: 0, closed: [] }; });
try { if (EXP_FILE && nodeFs.existsSync(EXP_FILE)) { const d = JSON.parse(nodeFs.readFileSync(EXP_FILE, "utf8")); for (const k of Object.keys(EXP.book)) if (d[k]) EXP.book[k] = d[k]; } } catch {}
const expSave = () => { if (!EXP_FILE) return; try { const t = EXP_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(EXP.book)); nodeFs.renameSync(t, EXP_FILE); } catch {} };
regFlush(expSave); setInterval(expSave, 5 * 60e3);
/** A band entry's own exit, expressed as the plain take-profit % that the shadow bets understand. */
function mpMineRules(S, pos) {
  const r = { ...S, ...pos.rules };
  if (r.sellMcap > 0 && pos.mcapAtBuy > 0) { r.tpPct = Math.max(1, (r.sellMcap / pos.mcapAtBuy - 1) * 100); r.tp1SellPct = 100; r.ladderOn = 0; }
  return r;
}
function expOpen(pos) {
  const S = MP.settings;
  for (const e of EXP_SETS) EXP.open.push({ id: e.id, mint: pos.mint, sym: pos.symbol, entry: pos.entry, t0: Date.now(), left: 1, got: 0, sells: 0, moon: false, mh: 0, type: pos.entryType,
    rules: e.id === "mine" ? (pos.rules ? mpMineRules(S, pos) : null) : { ...S, ...e.rules }, last: pos.entry, lastT: Date.now() });
  if (EXP.open.length > 800) EXP.open.splice(0, EXP.open.length - 800);
}
/** Pure: advance one shadow bet. Returns { pct, why } when it closes. */
function expStep(sp, px, mcap, now, force) {
  const S = MP.settings, R = sp.rules || S, slip = S.slippagePct / 100, fee = S.feePct / 100, sol = (typeof solUsd !== "undefined" && solUsd.v) || 150;
  const fixedFrac = ((S.priorityFeeSol + S.jitoTipSol) * sol) / 100, entry = sp.entry, ch = (px / entry - 1) * 100, age = (now - sp.t0) / 60000;
  const sell = (frac) => { sp.got += (sp.left * frac * (px * (1 - slip) * (1 - fee))) / entry; sp.left -= sp.left * frac; sp.sells++; };
  let why = null;
  if (force) { sell(1); why = force; }
  else if (R.cashOutMcap > 0 && mcap >= R.cashOutMcap) { sell(1); why = "rug zone"; }
  else if (!sp.moon) {
    if (R.ladderOn) {
      sp.ladderI = sp.ladderI || 0; let rung = false;
      while (sp.ladderI < MP_LADDER.length && ch >= MP_LADDER[sp.ladderI][0]) { sell(Math.min(1, MP_LADDER[sp.ladderI][1] / Math.max(1e-9, sp.left))); sp.ladderI++; rung = true; }
      if (rung) { if (sp.ladderI >= MP_LADDER.length) { sp.moon = true; sp.mh = px; } }
      else if (ch <= -R.slPct) { sell(1); why = "stop loss"; }
      else if (age > R.maxHoldMin) { sell(1); why = "time limit"; }
    }
    else if (ch >= R.tpPct) { if (R.tp1SellPct >= 100) { sell(1); why = "take profit"; } else { sell(R.tp1SellPct / 100); sp.moon = true; sp.mh = px; } }
    else if (ch <= -R.slPct) { sell(1); why = "stop loss"; }
    else if (age > R.maxHoldMin) { sell(1); why = "time limit"; }
  } else {
    sp.mh = Math.max(sp.mh, px); const run = sp.mh / entry;
    const trail = run >= 10 ? Math.min(R.trailPct, R.trailAt10x) : run >= 5 ? Math.min(R.trailPct, R.trailAt5x) : R.trailPct;
    if (px <= sp.mh * (1 - trail / 100)) { sell(1); why = "trailing stop"; } else if (age > R.moonHoldMin) { sell(1); why = "time limit"; }
  }
  if (!why && age > 240) { sell(1); why = "4-hour cutoff"; }
  if (!why) return null;
  const cost = 1 + fee + fixedFrac, back = sp.got - fixedFrac * sp.sells;
  return { pct: ((back - cost) / cost) * 100, why };
}
function expBook(sp, r) {
  const b = EXP.book[sp.id]; b.n++; if (r.pct > 0) { b.wins++; b.gw += r.pct; } else b.gl += -r.pct; b.sumPct += r.pct;
  b.closed.unshift({ sym: sp.sym, pct: +r.pct.toFixed(1), why: r.why, type: sp.type, at: Date.now() }); if (b.closed.length > 40) b.closed.length = 40;
}
/** One chain read for many curve tokens, then the trading pool for graduated ones. */
async function priceBatch(mints, sol) {
  const out = new Map(), toDex = [], curves = [];
  for (const m of mints) { try { curves.push({ m, k: PublicKey.findProgramAddressSync([Buffer.from("bonding-curve"), new PublicKey(m).toBuffer()], PUMP_PROGRAM)[0] }); } catch { toDex.push(m); } }
  for (let i = 0; i < curves.length; i += 100) {
    const b = curves.slice(i, i + 100); let infos = null;
    try { infos = await withTimeout(connection.getMultipleAccountsInfo(b.map((x) => x.k)), 8000, "shadow prices"); } catch {}
    b.forEach((x, j) => { const a = infos && infos[j], c = a ? decodeBondingCurve(a.data) : null;
      if (c && !c.complete) { const mk = curveMarket(c, sol, 6); out.set(x.m, { price: mk.price, mcap: mk.mcap }); } else toDex.push(x.m); });
  }
  if (toDex.length) { const d = await dexBatch(toDex); for (const [m, v] of d) out.set(m, { price: v.price, mcap: v.mcap }); }
  return out;
}
async function expTick() {
  if (!EXP.open.length) return;
  if (typeof rpcBudgetOk === "function" && !rpcBudgetOk()) return;
  const sol = await getSolUsd().catch(() => null); if (!sol) return;
  const now = Date.now(), px = await priceBatch([...new Set(EXP.open.map((x) => x.mint))], sol), keep = [];
  for (const sp of EXP.open) {
    const q = px.get(sp.mint);
    if (q) { sp.last = q.price; sp.lastMc = q.mcap; sp.lastT = now; }
    const stale = !q && now - sp.lastT > 30 * 60e3;
    const r = q || stale ? expStep(sp, q ? q.price : sp.last, q ? q.mcap || 0 : sp.lastMc || 0, now, stale ? "lost sight of it" : null) : null;
    if (r) expBook(sp, r); else keep.push(sp);
  }
  EXP.open = keep;
}
setInterval(() => { expTick().catch(() => {}); }, 10000);
function expPublic() {
  const rows = EXP_SETS.map((e) => { const b = EXP.book[e.id], pf = b.gl > 0 ? b.gw / b.gl : (b.gw > 0 ? 99 : 0);
    return { id: e.id, name: e.name, trades: b.n, winRate: b.n ? Math.round((b.wins / b.n) * 100) : null, avgPct: b.n ? +(b.sumPct / b.n).toFixed(1) : null, per100: +b.sumPct.toFixed(0), pf: +pf.toFixed(2),
      open: EXP.open.filter((x) => x.id === e.id).length, rules: e.rules }; });
  const ranked = rows.filter((r) => r.trades >= 10).sort((a, b) => b.avgPct - a.avgPct);
  return { rows, best: ranked.length ? ranked[0].id : null, openBets: EXP.open.length / EXP_SETS.length };
}

/** GRID: buy dips and sell bounces on calm, liquid tokens, in its own small paper pool. */
const GRID = { cash: null, start: 0, active: [], done: [], pnlUsd: 0, trades: 0, wins: 0 };
async function gridPick(sol) {
  const S = MP.settings; if (GRID.active.length >= S.gridMax) return;
  const have = new Set(GRID.active.map((g) => g.mint)); for (const g of GRID.done.slice(0, 40)) have.add(g.mint);
  const cand = [...new Set([...GR.grads.slice(-60).map((x) => x.mint), ...(typeof TOP !== "undefined" ? TOP.list.slice(0, 60).map((x) => x.addr) : [])])].filter((m) => !have.has(m)).slice(0, 30);
  if (!cand.length) return;
  const info = await dexBatch(cand);
  const good = [...info].filter(([, d]) => d.liq >= S.gridMinLiq && d.mcap >= 100000 && Math.abs(d.ch1 || 0) <= 8 && Math.abs(d.ch5 || 0) <= 3 && d.vol5 >= 1500).sort((a, b) => b[1].liq - a[1].liq);
  for (const [m, d] of good.slice(0, S.gridMax - GRID.active.length)) {
    const lot = Math.max(S.minTradeUsd, GRID.start / (S.gridLevels * S.gridMax));
    GRID.active.push({ mint: m, sym: symOf(m), center: d.price, step: S.gridStepPct, lotUsd: lot, t0: Date.now(), until: Date.now() + S.gridHoldMin * 60e3, pnl: 0, rounds: 0,
      lots: Array.from({ length: S.gridLevels }, (_, i) => ({ k: i + 1, open: false })), last: d.price, liq: d.liq });
  }
}
async function gridTick() {
  const S = MP.settings; if (!S.gridOn || !MP.on) return;
  if (GRID.cash == null) { GRID.cash = S.gridStartUsd; GRID.start = S.gridStartUsd; }
  const sol = await getSolUsd().catch(() => null); if (!sol) return;
  if (GRID.active.length < S.gridMax && Date.now() - (GRID.lastPick || 0) > 120000) { GRID.lastPick = Date.now(); await gridPick(sol).catch(() => {}); }
  if (!GRID.active.length) return;
  const info = await dexBatch(GRID.active.map((g) => g.mint)), now = Date.now(), fee = S.gridFeePct / 100, slip = S.gridSlipPct / 100, fixed = (S.priorityFeeSol + S.jitoTipSol) * sol;
  const sellLot = (g, lot, px) => { const back = Math.max(0, lot.tokens * px * (1 - slip) * (1 - fee) - fixed), pnl = back - lot.cost; GRID.cash += back; g.pnl += pnl; GRID.pnlUsd += pnl; GRID.trades++; if (pnl > 0) GRID.wins++; g.rounds++; lot.open = false; return pnl; };
  for (const g of GRID.active.slice()) {
    const d = info.get(g.mint); if (!d) continue; const px = d.price; g.last = px; g.liq = d.liq;
    for (const lot of g.lots) {                                              // sell bounces first
      if (lot.open && px >= lot.sellPx) sellLot(g, lot, px);
    }
    for (const lot of g.lots) {                                              // then buy dips
      const trig = g.center * (1 - (lot.k * g.step) / 100), cost = g.lotUsd * (1 + fee) + fixed;
      if (!lot.open && px <= trig && GRID.cash >= cost) { GRID.cash -= cost; lot.open = true; lot.buyPx = px; lot.cost = cost; lot.tokens = g.lotUsd / (px * (1 + slip)); lot.sellPx = px * (1 + g.step / 100); }
    }
    const broke = px < g.center * (1 - ((S.gridLevels + 1) * g.step) / 100), thin = d.liq < S.gridMinLiq * 0.5, timeUp = now > g.until;
    if (broke || thin || timeUp) {                                           // the range broke or time's up: sell everything left
      for (const lot of g.lots) if (lot.open) sellLot(g, lot, px);
      g.status = broke ? "range broke, sold the rest" : thin ? "liquidity dried up" : "time's up"; g.closedAt = now;
      GRID.active = GRID.active.filter((x) => x !== g); GRID.done.unshift(g); if (GRID.done.length > 60) GRID.done.length = 60;
      if (g.rounds > 0) mpEvent(`Grid on ${g.sym} finished (${g.status}): ${g.pnl >= 0 ? "+" : "−"}$${Math.abs(g.pnl).toFixed(2)} over ${g.rounds} round${g.rounds === 1 ? "" : "s"}`);
    }
  }
}
setInterval(() => { gridTick().catch(() => {}); }, 20000);
function gridPublic() {
  const S = MP.settings, open = GRID.active.reduce((a, g) => a + g.lots.filter((l) => l.open).reduce((b, l) => b + l.cost, 0), 0);
  return { on: !!S.gridOn, cash: GRID.cash == null ? S.gridStartUsd : +GRID.cash.toFixed(2), start: GRID.start || S.gridStartUsd, inLots: +open.toFixed(2), pnlUsd: +GRID.pnlUsd.toFixed(2), trades: GRID.trades,
    winRate: GRID.trades ? Math.round((GRID.wins / GRID.trades) * 100) : null,
    active: GRID.active.map((g) => ({ mint: g.mint, sym: g.sym, center: g.center, last: g.last, step: g.step, pnl: +g.pnl.toFixed(2), rounds: g.rounds, open: g.lots.filter((l) => l.open).length, levels: g.lots.length, leftMin: Math.max(0, Math.round((g.until - Date.now()) / 60000)) })),
    done: GRID.done.slice(0, 6).map((g) => ({ mint: g.mint, sym: g.sym, pnl: +g.pnl.toFixed(2), rounds: g.rounds, status: g.status })) };
}
/** Public summaries for the dashboard. */
function typeStats(type) {
  const T = MP.closed.filter((x) => (x.entryType || "at 90s") === type && x.pnlUsd != null), W = T.filter((x) => x.pnlUsd > 0);
  return { trades: T.length, wins: W.length, pnlUsd: +T.reduce((a, x) => a + x.pnlUsd, 0).toFixed(2), avgPct: T.length ? +(T.reduce((a, x) => a + x.pnlPct, 0) / T.length).toFixed(1) : null, open: MP.positions.filter((p) => p.entryType === type).length };
}
function gradPublic() {
  const S = MP.settings;
  return { on: !!S.gradOn, ...typeStats("graduate"), watching: [...GW.values()].slice(-12).reverse().map((w) => ({ mint: w.mint, sym: w.sym, leftMin: Math.max(0, Math.round((w.until - Date.now()) / 60000)), why: w.why || [],
    liq: w.last ? w.last.liq : null, mcap: w.last ? w.last.mcap : null, buys5: w.last ? w.last.buys5 : null, ch5: w.last ? w.last.ch5 : null })) };
}
function copyPublic() { return { on: !!MP.settings.copyOn, ...typeStats("copy"), skips: Object.entries(MP.skips).filter(([k]) => k.startsWith("copy: ")).map(([k, v]) => ({ reason: k.slice(6), n: v })).slice(0, 6) }; }


/*TOP_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🏆 TOP 100 RECORDER — who is on the trending list, how they got there, and whether we saw them first
// ═══════════════════════════════════════════════════════════════════════
const TOP_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-top100.json") : "";
const TOP = { list: [], tokens: new Map(), entries: [], at: 0 };
try { if (TOP_FILE && nodeFs.existsSync(TOP_FILE)) { const d = JSON.parse(nodeFs.readFileSync(TOP_FILE, "utf8")); for (const [k, v] of d.tokens || []) TOP.tokens.set(k, v); TOP.entries = d.entries || []; } } catch {}
const topSave = () => { if (!TOP_FILE) return; try { const t = TOP_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify({ tokens: [...TOP.tokens].slice(-1500), entries: TOP.entries.slice(0, 400) })); nodeFs.renameSync(t, TOP_FILE); } catch {} };
regFlush(topSave); setInterval(topSave, 10 * 60e3);
/** Every 5 minutes: the whole top 100 (5 pages), stamped with when each token first showed up and what it looked like then. */
async function topRecord() {
  const pools = [];
  for (let page = 1; page <= 5; page++) {
    try { pools.push(...mapGecko(await gecko(`/trending_pools?include=base_token&duration=1h&page=${page}`, 9000, "bg"))); } catch { break; }
    await new Promise((r) => setTimeout(r, 1500));
  }
  if (pools.length < 10) return;
  const now = Date.now(); pools.forEach((p, i) => { p.rank = i + 1; }); TOP.list = pools.slice(0, 100); TOP.at = now;
  for (const p of TOP.list) {
    if (typeof LAB !== "undefined") LAB.trended.set(p.addr, now);
    let t = TOP.tokens.get(p.addr);
    if (!t) {
      const snap = typeof LAB !== "undefined" ? LAB.snaps.find((x) => x.mint === p.addr) : null, tot = p.buys + p.sells;
      t = { addr: p.addr, sym: p.sym, name: p.name, firstAt: now, firstRank: p.rank, bestRank: p.rank, mcap0: Math.round(p.fdv || 0), liq0: Math.round(p.liq), vol0: Math.round(p.vol), ch1_0: p.ch1,
        ageMin0: p.createdAt ? Math.round((now - p.createdAt) / 60000) : null, buyShare0: tot ? Math.round((p.buys / tot) * 100) : null, pump: /pump$/.test(p.addr),
        sawBefore: !!snap, leadMin: snap ? Math.round((now - snap.at) / 60000) : null, lift: snap ? +labLift(snap).toFixed(2) : null, social: snap ? snap.social : null, scans: 0 };
      TOP.tokens.set(p.addr, t); TOP.entries.unshift({ ...t }); if (TOP.entries.length > 400) TOP.entries.length = 400;
      if (TOP.tokens.size > 3000) TOP.tokens.delete(TOP.tokens.keys().next().value);
    }
    t.bestRank = Math.min(t.bestRank, p.rank); t.lastRank = p.rank; t.lastAt = now; t.scans++;
  }
  if (typeof anOnTop === "function") anOnTop(TOP.list, now);              // the Analyst: who made the top 100 / top 20, and which words are trending
}
setInterval(() => { topRecord().catch(() => {}); }, 5 * 60e3); setTimeout(() => { topRecord().catch(() => {}); }, 40000);
const topMed = (a) => { const v = a.filter((x) => x != null && Number.isFinite(x)).sort((x, y) => x - y); return v.length ? v[Math.floor(v.length / 2)] : null; };
function topPublic() {
  const now = Date.now(), recent = TOP.entries.filter((e) => now - e.firstAt < 24 * 3600e3), pct = (n) => (recent.length ? Math.round((n / recent.length) * 100) : null);
  return { at: TOP.at, count: TOP.list.length, tracked: TOP.tokens.size,
    list: TOP.list.slice(0, 40).map((p) => ({ rank: p.rank, addr: p.addr, sym: p.sym, name: p.name, mcap: Math.round(p.fdv || 0), liq: Math.round(p.liq), ch1: p.ch1, vol: Math.round(p.vol), ageMin: p.createdAt ? Math.round((now - p.createdAt) / 60000) : null, pump: /pump$/.test(p.addr) })),
    entries: recent.slice(0, 10).map((e) => ({ addr: e.addr, sym: e.sym, name: e.name, at: e.firstAt, rank: e.firstRank, mcap: e.mcap0, ageMin: e.ageMin0, buyShare: e.buyShare0, sawBefore: e.sawBefore, leadMin: e.leadMin, lift: e.lift, social: e.social })),
    stats: { newEntries24h: recent.length, medianMcapAtEntry: topMed(recent.map((e) => e.mcap0)), medianAgeMinAtEntry: topMed(recent.map((e) => e.ageMin0)), medianLiqAtEntry: topMed(recent.map((e) => e.liq0)),
      medianBuyShare: topMed(recent.map((e) => e.buyShare0)), pumpPct: pct(recent.filter((e) => e.pump).length), sawBeforePct: pct(recent.filter((e) => e.sawBefore).length), medianLeadMin: topMed(recent.filter((e) => e.sawBefore).map((e) => e.leadMin)) } };
}
/*TOP_END*/


/*ANALYST_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🔬 ANALYST — the beginning before the beginning: a birth record for every launch, and what the top 20 had at birth
// ═══════════════════════════════════════════════════════════════════════
/**
 * No list ranks a token before it exists. The bot's "top 20" is page 1 of GeckoTerminal's trending list (Solana, last hour),
 * which ranks pools on people viewing them, volume, transactions, liquidity and safety checks. So the only "before" is what was
 * lined up ahead of the launch, and that leaves fingerprints the bot can record:
 *   BEFORE LAUNCH   how new the creator's wallet is, who funded it, whether that funder had funded other creators (and winners),
 *                   the creator's launches in the last 24 hours and past winners, the X link (a tweet, an account, a community),
 *                   a name riding a word that is trending right now
 *   FIRST SECONDS   the creator's own buy; how many wallets bought within 2 seconds (a bundle) and with how much SOL;
 *                   proven early buyers (wallets that were among the first 10 buyers of 2+ winners, at 15%+ of their early picks)
 *   FIRST 90 SEC    how much of the curve sold, how many different buyers, net SOL in
 * Every launch is followed for 24 hours: did it graduate, reach the top 100, reach the top 20, and how fast?
 * The study counts only a random sample (so the rates are fair), only after each launch's 24 hours are over (so early winners
 * can't flatter the numbers), compares launches WITH a trait to launches WITHOUT it, and calls a trait proven only if it
 * held up in the first half AND the second half of the data. Creator-wallet checks cost 2 chain reads each, so they run on
 * a random part of the sample, at most 6 a minute, and stop when the daily RPC cap is reached. Nothing here trades.
 */
const AN_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-analyst.json") : "";
const AN_H = 24 * 3600e3;                        // the outcome window: what happened in a launch's first 24 hours
const AN_SAMPLE = 0.2;                           // share of launches in the random study sample (winners outside it are kept for the lists, never counted)
const AN_DEEP_PER_MIN = 6;                       // creator-wallet checks a minute, at most (2 chain reads each)
const AN_FIRST_N = 10;                           // first buyers scored for "proven early buyers"
const AN_KEEP_OTHERS = 8 * 3600e3;              // launches outside the sample are kept 8 hours (for the top-20 notes), longer only if they win
const AN_MAX_LIVE = 45000, AN_MAX_SAMPLED = 25000, AN_MAX_DONE = 15000, AN_MAX_WALLETS = 60000, AN_MAX_FUNDERS = 20000, AN_MAX_CREATORS = 80000;
const AN_HEAP_LEAN = 450e6;                      // past this much server memory the Analyst keeps only the study sample (the study itself is untouched)
const AN_OUT = ["t20", "g", "t100"];             // outcomes: reached the top 20, graduated, reached the top 100 (each within 24 hours)
const AN_CURVE_K = 30 * 1073000000;              // standard pump.fun curve: virtual SOL × virtual tokens stays at this
const AN_KEYS = ["m", "s", "n", "c", "t", "smp", "fin", "gap", "cl", "cw", "nl", "ne", "hk", "hw", "sn", "nf", "dev", "ew", "es", "ep", "pb", "b90", "net90", "p90", "std",
  "dp", "dr", "age", "busy", "tx", "fu", "fa", "fn", "fw", "tw", "tg", "web", "g", "t100", "t20", "br"];
const AN = { births: new Map(), done: [], doneIdx: new Map(), agg: {}, snapQ: [], deepQ: [], recent: [], wallets: new Map(), funders: new Map(), creators: new Map(), cwins: new Map(),
  hot: new Map(), hot20: new Set(), hotAt: 0, upSince: Date.now(), since: Date.now(), cache: null, cacheAt: 0, wTrimAt: 0, memAt: 0, lean: false, liveSampled: 0,
  diag: { launches: 0, sampled: 0, snaps: 0, noFeed: 0, deep: 0, deepFail: 0, deepErr: null, metaOk: 0, metaFail: 0, grads: 0, top100: 0, top20: 0 } };
const anPack = (r) => AN_KEYS.map((k) => (r[k] === undefined ? null : r[k]));
/** One birth record. Every record has all its fields from the start and none is ever deleted: that keeps tens of thousands of them small in memory. */
const anBlank = () => ({ m: "", s: "", n: "", c: "", u: null, t: 0, smp: 0, fin: 0, gap: 0, cl: null, cw: 0, nl: 0, ne: 0, hk: 0, hw: "", sn: 0, nf: 0,
  dev: null, ew: null, es: null, ep: null, pb: null, b90: null, net90: null, p90: null, std: null, dp: 0, dr: null, dq: 0, age: null, busy: 0, tx: null,
  fu: null, fa: null, fn: null, fw: null, tw: null, tg: null, web: null, g: 0, t100: 0, t20: 0, br: 0, first: null, wc: 0, wf: 0, wcr: 0, ag: 0 });
const anUnpack = (a) => { const r = anBlank(); AN_KEYS.forEach((k, i) => { if (a[i] !== null && a[i] !== undefined) r[k] = a[i]; }); return r; };
try {
  if (AN_FILE && nodeFs.existsSync(AN_FILE)) {
    const d = JSON.parse(nodeFs.readFileSync(AN_FILE, "utf8")) || {};
    if (d.since) AN.since = d.since;
    for (const a of d.done || []) { const r = anUnpack(a); if (r.m) { AN.done.push(r); AN.doneIdx.set(r.m, r); } }
    for (const a of d.live || []) { const r = anUnpack(a); if (!r.m) continue; r.gap = 1; if (!r.sn) { r.sn = 1; r.nf = 1; } AN.births.set(r.m, r); if (r.smp) AN.liveSampled++; }   // followed across a restart: flagged
    if (d.agg && typeof d.agg === "object") AN.agg = d.agg;
    for (const [k, e, w] of d.wallets || []) AN.wallets.set(k, Math.min(e, 1e6) * 1024 + Math.min(w, 1023));
    for (const [k, ct, wt, l] of d.funders || []) AN.funders.set(k, { ct: ct || [], wt: wt || [], l: l || 0 });
    for (const [k, v] of d.creators || []) AN.creators.set(k, v);
    for (const [k, n] of d.cwins || []) AN.cwins.set(k, n);
  }
} catch {}
const anSave = () => {
  if (!AN_FILE) return;
  try {
    const now = Date.now(), live = [], wal = [], fun = [], cre = [];
    for (const r of AN.births.values()) if (r.smp || r.g || r.t20 || r.t100) live.push(anPack(r));
    for (const [k, v] of AN.wallets) if (v % 1024 >= 1) wal.push([k, Math.floor(v / 1024), v % 1024]);
    for (const [k, v] of AN.funders) fun.push([k, v.ct, v.wt, v.l]);
    const mn = Math.floor(now / 60000); for (const [k, v] of AN.creators) if (mn - (Array.isArray(v) ? v[v.length - 1] : v) < 1440) cre.push([k, v]);
    const t = AN_FILE + ".tmp";
    nodeFs.writeFileSync(t, JSON.stringify({ v: 2, since: AN.since, agg: AN.agg, done: AN.done.map(anPack), live, wallets: wal, funders: fun, creators: cre, cwins: [...AN.cwins] }));
    nodeFs.renameSync(t, AN_FILE);
  } catch {}
};
regFlush(anSave); setInterval(anSave, 10 * 60e3);

/** Words in a token's name, for matching names to what is trending. Chinese, Japanese and Korean words count whole. */
const AN_STOP = new Set(["the", "and", "for", "you", "your", "with", "this", "that", "coin", "token", "official", "sol", "solana", "pump", "fun", "inu", "meme",
  "just", "not", "are", "was", "all", "get", "its", "our", "from", "dev", "who", "has", "but", "out", "now", "new", "one", "his", "her", "him"]);
function anWords(text) {
  const out = new Set();
  for (const w of String(text || "").toLowerCase().split(/[^a-z0-9぀-ヿ㐀-鿿가-힯]+/)) {
    if (!w) continue;
    if (/^[a-z0-9]+$/.test(w)) { if (w.length >= 3 && !/^\d+$/.test(w) && !AN_STOP.has(w)) out.add(w); }
    else out.add(w);
  }
  return [...out];
}
/** The trending word this name rides, "" for none, null when the trending list is too old to judge. */
function anHotWord(name, sym, now = Date.now()) {
  if (!AN.hotAt || now - AN.hotAt > 30 * 60e3) return null;
  const S = String(sym || "").toUpperCase().replace(/^\$/, "");
  if (S && AN.hot20.has(S)) return "$" + S;                                // same ticker as a token in the top 20 right now
  let best = "";
  for (const w of anWords(name + " " + sym)) if (AN.hot.has(w) && w.length > best.length) best = w;
  return best;
}
/** How many creators to check a minute → chance a sampled launch gets checked. Keeps the checks spread evenly over the day. */
function anDeepP(now = Date.now()) {
  let n = 0; for (let i = AN.recent.length - 1; i >= 0 && now - AN.recent[i] < 60e3; i--) n++;
  return Math.min(1, AN_DEEP_PER_MIN / Math.max(1, n * AN_SAMPLE));
}
/** A launch was just created on pump.fun: start its birth record. Instant, no chain reads. */
function anOnLaunch(ev) {
  try {
    if (!ev || !ev.mint || AN.births.has(ev.mint)) return;
    const now = Date.now(), nm = String(ev.name || ""), sy = String(ev.symbol || ""), c = String(ev.creator || "");
    AN.diag.launches++; AN.recent.push(now); if (AN.recent.length > 900) AN.recent.splice(0, AN.recent.length - 900);
    let cl = null, cw = 0;
    if (c) {
      const mn = Math.floor(now / 60000), v = AN.creators.get(c), ts = (v == null ? [] : Array.isArray(v) ? v : [v]).filter((x) => mn - x < 1440); ts.push(mn);
      AN.creators.delete(c); AN.creators.set(c, ts.length === 1 ? mn : ts.slice(-50)); cl = ts.length; cw = AN.cwins.get(c) || 0;
      if (AN.creators.size > AN_MAX_CREATORS) AN.creators.delete(AN.creators.keys().next().value);
    }
    const smp = AN.liveSampled < AN_MAX_SAMPLED && Math.random() < AN_SAMPLE ? 1 : 0;   // when too many are being followed, fewer NEW ones are sampled (never by outcome)
    if (!smp && AN.lean) return;                                                        // short on memory: keep only the study sample
    const r = anBlank();
    r.m = ev.mint; r.s = sy.slice(0, 20); r.n = smp ? nm.slice(0, 32) : ""; r.c = c; r.u = String(ev.uri || "").slice(0, 300) || null; r.t = now; r.smp = smp;   // the metadata address is kept until checked, so a top-20 launch outside the sample still gets its socials read
    r.cl = cl; r.cw = cw; r.nl = nm.length; r.ne = /[^\x00-\x7F]/.test(nm + sy) ? 1 : 0;
    AN.births.set(ev.mint, r); AN.snapQ.push(r); if (AN.snapQ.length > 20000) AN.snapQ.splice(0, AN.snapQ.length - 20000);
    if (smp) { AN.liveSampled++; AN.diag.sampled++; if (AN.deepQ.length < 40 && Math.random() < anDeepP(now)) { r.dq = 1; AN.deepQ.push({ m: ev.mint, dr: 1 }); } }
    if (AN.births.size > AN_MAX_LIVE) for (const [k, x] of AN.births) { if (AN.births.size <= AN_MAX_LIVE * 0.95) break; if (!x.smp && !(x.g || x.t20 || x.t100)) AN.births.delete(k); }   // the sample is never trimmed
  } catch {}
}
/** 90 seconds after launch: what the first seconds and the first 90 seconds looked like, straight from the live feed. */
function anSnap(r, now = Date.now()) {
  r.sn = 1; AN.diag.snaps++;
  const f = typeof FLOW !== "undefined" ? FLOW.get(r.m) : null;
  if (!f) { r.nf = 1; AN.diag.noFeed++; return; }
  const end = f.t0 + 90e3, seen = new Set(), first = [];
  let net = 0, lastP = null;
  for (const x of f.trades) {
    if (x.t > end) break;
    net += x.b ? x.sol : -x.sol; if (x.p > 0) lastP = x.p;
    if (x.b && x.u && x.u !== f.creator && !seen.has(x.u)) { seen.add(x.u); if (first.length < AN_FIRST_N) first.push(x.u.slice(0, 16)); }
  }
  r.b90 = seen.size; r.net90 = +net.toFixed(2);
  r.dev = +(f.devBuy || 0).toFixed(2); r.ew = f.earlyU ? f.earlyU.size : 0; r.es = +(f.earlySol || 0).toFixed(2); r.ep = +(((f.early || 0) / 1e9) * 100).toFixed(2);
  r.std = f.std == null ? null : f.std;
  if (f.std === 0) r.p90 = null;
  else if (lastP > 0) { const vTok = Math.sqrt(AN_CURVE_K / lastP); r.p90 = +Math.max(0, Math.min(100, ((1073000000 - vTok) / 793100000) * 100)).toFixed(2); }
  else r.p90 = 0;
  let pb = 0; for (const k of first) if (anProven(AN.wallets.get(k))) pb++;
  r.pb = pb;
  for (const k of first) { const v = AN.wallets.get(k) || 0; AN.wallets.delete(k); AN.wallets.set(k, v + 1024); }   // one more early buy (most recent last)
  r.first = first;
  const hw = anHotWord(r.n, r.s, now); r.hk = hw == null ? 0 : 1; r.hw = hw || "";
  if ((r.g || r.t20) && !r.wc) anWin(r, now);                     // it won before its 90-second mark: credit its buyers now, after its own score was taken
}
/** A proven early buyer: among the first buyers of 2+ winners, and of 15%+ of everything it bought early. (Stored as early buys × 1024 + wins.) */
const anProven = (v) => v != null && v % 1024 >= 2 && (v % 1024) / Math.max(1, Math.floor(v / 1024)) >= 0.15;
/** A launch won (graduated or reached the top 20 inside its first 24 hours): its funder, creator and first buyers get the credit, once. */
function anWin(r, now = Date.now()) {
  if (r.fu && !r.wf) { r.wf = 1; const F = AN.funders.get(r.fu); if (F) { F.wt.push(now); if (F.wt.length > 60) F.wt.splice(0, F.wt.length - 60); } }
  if (r.c && !r.wcr) { r.wcr = 1; AN.cwins.set(r.c, (AN.cwins.get(r.c) || 0) + 1); if (AN.cwins.size > 20000) AN.cwins.delete(AN.cwins.keys().next().value); }
  if (!r.sn || r.wc) return;
  r.wc = 1; for (const k of r.first || []) { const v = AN.wallets.get(k); if (v != null && v % 1024 < 1023) AN.wallets.set(k, v + 1); }
}
function anOnGrad(mint, now = Date.now()) {
  try { const r = AN.births.get(mint); if (!r || r.g || now - r.t > AN_H) return; r.g = now; AN.diag.grads++; anWin(r, now); } catch {}
}
/** Every 5 minutes, with the top 100: which launches made the top 100 / top 20, and which words are trending. */
function anOnTop(list, now = Date.now()) {
  try {
    if (!Array.isArray(list) || !list.length) return;
    const cnt = new Map(), t20 = new Set();
    for (const p of list) {
      for (const w of anWords((p.name || "") + " " + (p.sym || ""))) { const c = cnt.get(w) || { n: 0, best: 999 }; c.n++; c.best = Math.min(c.best, p.rank); cnt.set(w, c); }
      if (p.rank <= 20 && p.sym) t20.add(String(p.sym).toUpperCase().replace(/^\$/, ""));
    }
    AN.hot = new Map([...cnt].filter(([, c]) => c.n >= 2 || c.best <= 20)); AN.hot20 = t20; AN.hotAt = now;
    for (const p of list) {
      const r = AN.births.get(p.addr); if (!r || now - r.t > AN_H) continue;
      if (!r.t100) { r.t100 = now; AN.diag.top100++; }
      r.br = Math.min(r.br || 999, p.rank);
      if (p.rank <= 20 && !r.t20) {
        r.t20 = now; AN.diag.top20++; anWin(r, now);
        if (!r.dp && !r.dq && r.c) { r.dq = 1; AN.deepQ.unshift({ m: r.m, dr: 0 }); }   // a top-20 launch outside the random checks: check it anyway (shown, never counted)
      }
    }
  } catch {}
}
/** Who first sent SOL to the creator's wallet, from its first transaction. */
function anFunder(tx, me) {
  try {
    if (!tx || !tx.transaction || !tx.transaction.message) return null;
    const msg = tx.transaction.message, ins = [...(msg.instructions || []), ...(((tx.meta && tx.meta.innerInstructions) || []).flatMap((x) => x.instructions || []))];
    let best = null;
    for (const i of ins) {
      const p = i && i.parsed; if (!p || !p.info) continue;
      const to = p.info.destination || p.info.newAccount, from = p.info.source || p.info.from;
      if (/^(transfer|transferWithSeed|createAccount|createAccountWithSeed)$/.test(p.type || "") && to === me && from && from !== me) {
        const sol = (+p.info.lamports || 0) / 1e9; if (!best || sol > best.sol) best = { from, sol };
      }
    }
    if (best) return { from: best.from, sol: +best.sol.toFixed(3) };
    const keys = msg.accountKeys || [], key = (x) => (typeof x === "string" ? x : x && x.pubkey ? (x.pubkey.toBase58 ? x.pubkey.toBase58() : String(x.pubkey)) : x && x.toBase58 ? x.toBase58() : "");
    const payer = key(keys[0]), idx = keys.findIndex((x) => key(x) === me);
    if (payer && payer !== me && idx >= 0 && tx.meta && tx.meta.preBalances && tx.meta.postBalances) {
      const d = (tx.meta.postBalances[idx] - tx.meta.preBalances[idx]) / 1e9; if (d > 0) return { from: payer, sol: +d.toFixed(3) };
    }
  } catch {}
  return null;
}
/** What kind of X (Twitter) link the token gives. */
function anTwKind(u) {
  const x = String(u || "").trim().toLowerCase(); if (x.length < 4) return "none";
  if (/\/status(es)?\/\d+/.test(x)) return "tweet";
  if (/\/(i\/)?communities\//.test(x)) return "community";
  if (/(^|\/\/|\.)(x|twitter)\.com\/[a-z0-9_]{1,15}\/?(\?.*)?$/.test(x) || /^@?[a-z0-9_]{1,15}$/.test(x)) return "account";
  return "other";
}
/** The token's own metadata: which socials it lists. */
async function anMeta(uri) {
  if (!/^https:\/\//.test(uri || "")) return null;
  try {
    const res = await withTimeout(fetch(uri), 6000, "token meta");
    const len = res && res.headers && typeof res.headers.get === "function" ? +res.headers.get("content-length") || 0 : 0; if (len > 300000) return null;
    const j = await withTimeout(res.json(), 5000, "token meta body"); if (!j || typeof j !== "object") return null;
    const s = (v) => (typeof v === "string" ? v.trim() : "");
    return { tw: anTwKind(s(j.twitter)), tg: s(j.telegram).length > 3 ? 1 : 0, web: s(j.website).length > 3 ? 1 : 0 };
  } catch { return null; }
}
/** The creator's wallet before launch: how old, how busy, who funded it, and what that funder had done before. 2 chain reads. */
async function anDeep(r) {
  if (!r || r.dp || !r.c || typeof connection === "undefined" || !connection || typeof connection.getSignaturesForAddress !== "function") return false;
  const launchSec = Math.floor(r.t / 1000);
  let sigs;
  try { sigs = await withTimeout(connection.getSignaturesForAddress(new PublicKey(r.c), { limit: 100 }), 12000, "creator history"); }
  catch (e) { AN.diag.deepFail++; AN.diag.deepErr = typeof rpcErrSafe === "function" ? rpcErrSafe(e) : String((e && e.message) || e).slice(0, 120); return false; }
  if (!Array.isArray(sigs)) return false;
  r.dp = 1; AN.diag.deep++;
  r.tx = sigs.filter((s) => s && s.blockTime && s.blockTime < launchSec - 1).length;
  if (sigs.length >= 100) r.busy = 1;                                      // 100+ transactions: an old or busy wallet (its start is out of reach in one read)
  else if (sigs.length) {
    const first = sigs[sigs.length - 1];                                    // newest first, so the last one is the wallet's first transaction ever
    if (first && first.blockTime) r.age = +Math.max(0, (launchSec - first.blockTime) / 3600).toFixed(2);
    try {
      const tx = await withTimeout(connection.getParsedTransaction(first.signature, { maxSupportedTransactionVersion: 0 }), 12000, "creator funding");
      const f = anFunder(tx, r.c);
      if (f) {
        const F = AN.funders.get(f.from) || { ct: [], wt: [], l: 0 };
        r.fu = f.from; r.fa = f.sol; r.fn = F.ct.filter((t) => t < r.t).length; r.fw = F.wt.filter((t) => t < r.t).length;
        F.ct.push(r.t); if (F.ct.length > 20) F.ct.splice(0, F.ct.length - 20);   // one entry per creator checked (each record is checked once)
        F.l = Date.now(); AN.funders.delete(f.from); AN.funders.set(f.from, F);
        if (AN.funders.size > AN_MAX_FUNDERS) AN.funders.delete(AN.funders.keys().next().value);
        if ((r.g || r.t20) && !r.wf) { r.wf = 1; F.wt.push(r.g || r.t20); }
      }
    } catch (e) { AN.diag.deepFail++; AN.diag.deepErr = typeof rpcErrSafe === "function" ? rpcErrSafe(e) : String((e && e.message) || e).slice(0, 120); }
  }
  const meta = r.u ? await anMeta(r.u) : null;
  if (meta) { r.tw = meta.tw; r.tg = meta.tg; r.web = meta.web; AN.diag.metaOk++; } else AN.diag.metaFail++;
  r.u = null;
  return true;
}
let anDeepBusy = false;
async function anDeepTick() {
  if (anDeepBusy || !AN.deepQ.length) return;
  if (typeof rpcBudgetOk === "function" && !rpcBudgetOk()) return;          // background research stops at the daily RPC cap; trading never does
  anDeepBusy = true;
  try {
    const q = AN.deepQ.shift(), r = q ? AN.births.get(q.m) : null;
    if (r && !r.dp) { if (q.dr) r.dr = 1; else if (r.dr == null) r.dr = 0; await anDeep(r); }
  } catch {} finally { anDeepBusy = false; }
}
/** After 24 hours a launch's record is final: a sampled one is added to the study's daily totals; winners are kept for the lists.
 *  Launches outside the sample that did not win are let go after 12 hours. */
function anFinalize(now = Date.now()) {
  for (const [m, r] of AN.births) {
    if (r.first && now - r.t > 2 * 3600e3) r.first = null;
    const won = r.g || r.t20 || r.t100;
    if (!r.smp && !won && now - r.t >= AN_KEEP_OTHERS) { AN.births.delete(m); continue; }
    if (now - r.t < AN_H) continue;
    AN.births.delete(m); r.u = null; r.first = null; r.dq = 0; r.fin = 1;
    if (r.smp) { AN.liveSampled = Math.max(0, AN.liveSampled - 1); anAggAdd(r); }
    if (r.smp || won) { AN.done.push(r); AN.doneIdx.set(m, r); }
  }
  if (AN.done.length > AN_MAX_DONE) for (const r of AN.done.splice(0, AN.done.length - AN_MAX_DONE)) if (AN.doneIdx.get(r.m) === r) AN.doneIdx.delete(r.m);
  if (AN.wallets.size > AN_MAX_WALLETS) for (const [k, v] of AN.wallets) { if (AN.wallets.size <= AN_MAX_WALLETS * 0.8) break; if (v % 1024 === 0) AN.wallets.delete(k); }
  if (now - AN.wTrimAt > 3600e3) {
    AN.wTrimAt = now;
    const mn = Math.floor(now / 60000); for (const [k, v] of AN.creators) if (mn - (Array.isArray(v) ? v[v.length - 1] : v) >= 1440) AN.creators.delete(k);
  }
  if (now - AN.memAt > 60e3) {                                          // a small server: keep only the study sample once memory runs high
    AN.memAt = now;
    try { const lim = require("v8").getHeapStatistics().heap_size_limit || Infinity; AN.lean = process.memoryUsage().heapUsed > Math.min(AN_HEAP_LEAN, lim * 0.6); } catch {}
  }
  AN.cache = null;
}
/** A finished sample launch joins its day's running totals, trait by trait. The study is built from these totals: all history, almost no memory. */
function anAggAdd(r) {
  if (!r || !r.smp || r.ag) return; r.ag = 1;
  const day = new Date(r.t).toISOString().slice(0, 10), D = AN.agg[day] || (AN.agg[day] = { n: 0, h: [0, 0, 0], dp: 0, tr: {} }), y = AN_OUT.map((k) => (r[k] ? 1 : 0));
  D.n++; y.forEach((v, i) => { D.h[i] += v; }); if (anDeepOk(r)) D.dp++;
  for (const [, label, test] of AN_TRAITS) {
    let v; try { v = test(r); } catch { v = null; } if (v == null) continue;
    const c = D.tr[label] || (D.tr[label] = [0, 0, 0, 0, 0, 0, 0, 0]), o = v ? 0 : 4;   // [with: n, top-20, graduated, top-100 · without: the same]
    c[o]++; y.forEach((x, i) => { c[o + 1 + i] += x; });
  }
  const days = Object.keys(AN.agg).sort(); while (days.length > 120) delete AN.agg[days.shift()];
}
function anTick(now = Date.now()) { while (AN.snapQ.length && now - AN.snapQ[0].t >= 90e3) { const r = AN.snapQ.shift(); if (!r.sn) anSnap(r, now); } }
setInterval(() => { try { anTick(); } catch {} }, 5000);
setInterval(() => { anDeepTick().catch(() => {}); }, 10000);
setInterval(() => { try { anFinalize(); } catch {} }, 60e3);

/** The traits the study tests. Each returns true (has it), false (doesn't), or null (unknown: left out of that line). */
const anDeepOk = (r) => r.dp && r.dr;
const AN_TRAITS = [
  ["before", "Creator wallet under 1 day old", (r) => (anDeepOk(r) && !r.busy && r.age != null ? r.age < 24 : null)],
  ["before", "Creator wallet over 30 days old", (r) => (anDeepOk(r) && !r.busy && r.age != null ? r.age > 720 : null)],
  ["before", "Busy creator wallet (100+ transactions)", (r) => (anDeepOk(r) ? !!r.busy : null)],
  ["before", "Funder had funded other creators", (r) => (anDeepOk(r) && r.fu ? r.fn >= 1 : null)],
  ["before", "Funder funded 20+ creators (exchange-like)", (r) => (anDeepOk(r) && r.fu ? r.fn >= 20 : null)],
  ["before", "Funder had a winner before", (r) => (anDeepOk(r) && r.fu ? r.fw >= 1 : null)],
  ["before", "X link is a tweet (news or a viral post)", (r) => (anDeepOk(r) && r.tw ? r.tw === "tweet" : null)],
  ["before", "X link is an account", (r) => (anDeepOk(r) && r.tw ? r.tw === "account" : null)],
  ["before", "X link is a community", (r) => (anDeepOk(r) && r.tw ? r.tw === "community" : null)],
  ["before", "No X, Telegram or website", (r) => (anDeepOk(r) && r.tw ? r.tw === "none" && !r.tg && !r.web : null)],
  ["before", "Has a website", (r) => (anDeepOk(r) && r.tw ? !!r.web : null)],
  ["before", "Creator's first launch in 24 hours", (r) => (r.cl == null ? null : r.cl <= 1)],
  ["before", "Creator's 3rd+ launch in 24 hours", (r) => (r.cl == null ? null : r.cl >= 3)],
  ["before", "Creator had a winner before", (r) => (r.cw == null ? null : r.cw >= 1)],
  ["before", "Name rides a word trending right now", (r) => (r.sn && r.hk ? !!r.hw : null)],
  ["before", "Chinese/Korean/Japanese or emoji name", (r) => (r.ne == null ? null : !!r.ne)],
  ["before", "Short name (5 characters or fewer)", (r) => (r.nl == null ? null : r.nl <= 5)],
  ["seconds", "Creator bought 1+ SOL at launch", (r) => (r.sn && !r.nf ? r.dev >= 1 : null)],
  ["seconds", "Creator bought nothing", (r) => (r.sn && !r.nf ? !(r.dev > 0) : null)],
  ["seconds", "3+ wallets bought in the first 2 seconds", (r) => (r.sn && !r.nf ? r.ew >= 3 : null)],
  ["seconds", "First-2-second buyers took 10%+ of supply", (r) => (r.sn && !r.nf ? r.ep >= 10 : null)],
  ["seconds", "A proven early buyer in the first 10", (r) => (r.sn && !r.nf ? r.pb >= 1 : null)],
  ["ninety", "30%+ of the curve sold at 90 seconds", (r) => (r.sn && !r.nf && r.p90 != null ? r.p90 >= 30 : null)],
  ["ninety", "50+ different buyers in 90 seconds", (r) => (r.sn && !r.nf ? r.b90 >= 50 : null)],
  ["ninety", "10+ SOL net in at 90 seconds", (r) => (r.sn && !r.nf ? r.net90 >= 10 : null)],
];
/** 95% range for a rate (Wilson). */
function anWilson(k, n, z = 1.96) {
  if (!n) return [0, 1];
  const p = k / n, d = 1 + (z * z) / n, c = (p + (z * z) / (2 * n)) / d, h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}
/** The study: for each trait, how often finished sample launches WITH it won vs those WITHOUT it, from the daily totals. Cached 1 minute.
 *  "Proven" needs the effect in the earlier days AND the later days (split near the middle), and a 95% range clear of the others' rate. */
function anStudy(now = Date.now()) {
  if (AN.cache && now - AN.cacheAt < 60e3) return AN.cache;
  const days = Object.keys(AN.agg).sort(), n = days.reduce((a, d) => a + AN.agg[d].n, 0), H = [0, 0, 0];
  for (const d of days) AN.agg[d].h.forEach((v, i) => { H[i] += v; });
  const hits = { t20: H[0], g: H[1], t100: H[2] }, oi = H[0] >= 20 ? 0 : 1, outcome = AN_OUT[oi];
  const early = new Set(); let cum = 0; for (const d of days) { if (cum < n / 2) early.add(d); cum += AN.agg[d].n; }
  const sm = (h, k) => (h + 0.5) / (k + 1), rows = [];
  for (const [sec, label] of AN_TRAITS) {
    const Tt = [0, 0, 0, 0], A = [[0, 0, 0, 0], [0, 0, 0, 0]];
    for (const d of days) {
      const c = AN.agg[d].tr[label]; if (!c) continue;
      const v = [c[0], c[1 + oi], c[4], c[5 + oi]], h = A[early.has(d) ? 0 : 1];
      for (let k = 0; k < 4; k++) { Tt[k] += v[k]; h[k] += v[k]; }
    }
    const [nw, hw, no, ho] = Tt; if (!nw && !no) continue;
    const lift = sm(hw, nw) / sm(ho, no), l1 = sm(A[0][1], A[0][0]) / sm(A[0][3], A[0][2]), l2 = sm(A[1][1], A[1][0]) / sm(A[1][3], A[1][2]);
    const [lo, hi] = anWilson(hw, nw), rw = nw ? hw / nw : 0, ro = no ? ho / no : 0, both = A[0][0] + A[0][2] > 0 && A[1][0] + A[1][2] > 0;
    let verdict = "weak";
    if (nw < 30 || no < 30 || hw + ho < 5) verdict = "few";
    else if (both && hw >= 8 && A[0][1] >= 3 && A[1][1] >= 3 && l1 >= 1.5 && l2 >= 1.5 && lo > ro) verdict = "proven";
    else if (both && ho >= 8 && nw >= 50 && l1 <= 0.67 && l2 <= 0.67 && hi < ro) verdict = "lower";
    rows.push({ sec, label, nWith: nw, hitsWith: hw, nWithout: no, hitsWithout: ho, ratePct: +(rw * 100).toFixed(2), otherPct: +(ro * 100).toFixed(2),
      lift: +lift.toFixed(2), liftFirstHalf: +l1.toFixed(2), liftSecondHalf: +l2.toFixed(2), verdict });
  }
  AN.cache = { at: now, n, hits, outcome, basePct: n ? +((H[oi] / n) * 100).toFixed(2) : 0, rows, deep: days.reduce((a, d) => a + (AN.agg[d].dp || 0), 0),
    days: days.length, from: days[0] || null, to: days[days.length - 1] || null, following: AN.births.size, since: AN.since, lean: AN.lean };
  AN.cacheAt = now; return AN.cache;
}
const anAgeTxt = (h) => (h < 1 ? Math.max(1, Math.round(h * 60)) + " min" : h < 48 ? Math.round(h) + " h" : Math.round(h / 24) + " days");
const anMinTxt = (ms) => { const m = ms / 60000; return m < 90 ? Math.max(1, Math.round(m)) + " min" : (m / 60).toFixed(1) + " h"; };
const anSocTxt = (r) => (r.tw == null ? "metadata unreadable" : ({ tweet: "X: a tweet link", account: "X: an account", community: "X: a community", other: "X: another link", none: "no X" }[r.tw] || "no X") + (r.tg ? " · Telegram" : "") + (r.web ? " · website" : ""));
/** Short notes on what a launch looked like at birth, for lists. */
function anNotes(r) {
  const out = [];
  if (r.dp) {
    out.push(r.busy ? "busy creator wallet" : r.age != null ? "creator wallet " + anAgeTxt(r.age) + " old" : "creator wallet age ?");
    if (r.fu) out.push(r.fn >= 20 ? "exchange-like funder" : r.fn >= 1 ? `funder had ${r.fn} other creator${r.fn === 1 ? "" : "s"}${r.fw ? " (" + r.fw + " won)" : ""}` : "first-time funder");
    if (r.tw && r.tw !== "none") out.push("X " + r.tw);
  }
  if (r.cl >= 3) out.push(`creator's launch #${r.cl} in 24 h`); else if (r.cw) out.push(`creator had ${r.cw} winner${r.cw === 1 ? "" : "s"}`);
  if (r.sn && !r.nf) {
    out.push(`${r.ew} wallet${r.ew === 1 ? "" : "s"} in 2s${r.es ? " (" + r.es + " SOL)" : ""}`);
    out.push(r.dev > 0 ? `creator ${r.dev} SOL` : "creator bought 0");
    if (r.pb) out.push(`${r.pb} proven buyer${r.pb === 1 ? "" : "s"}`);
    if (r.p90 != null) out.push(`${Math.round(r.p90)}% sold at 90s`);
    out.push(`${r.b90} buyers`);
  } else if (r.sn) out.push("no feed data");
  if (r.hw) out.push(`word "${r.hw}"`);
  if (r.t20) out.push(`top 20 after ${anMinTxt(r.t20 - r.t)}`);
  return out;
}
const anCut = (t, n) => (t.length > n ? t.slice(0, n - 1).replace(/ ·? ?[^·]*$/, "") + " …" : t);
function anFind(addr) { return AN.births.get(addr) || AN.doneIdx.get(addr) || null; }
/** One line for the token scan: what the bot saw at its birth. */
function anBirthLine(addr) { const r = anFind(addr); return r ? "🔬 At birth: " + anNotes(r).join(" · ") + " · /birth for more" : null; }
/** The top 20 right now, each with its birth record when the bot saw it born. */
function anTop20Data() {
  const L = typeof TOP !== "undefined" && Array.isArray(TOP.list) ? TOP.list.filter((p) => p.rank <= 20) : [];
  return L.map((p) => { const r = anFind(p.addr); return { rank: p.rank, addr: p.addr, sym: p.sym, name: p.name, mcap: Math.round(p.fdv || 0), ageMin: p.createdAt ? Math.round((Date.now() - p.createdAt) / 60000) : null,
    pump: /pump$/.test(p.addr), birth: r ? { at: r.t, notes: anNotes(r) } : null }; });
}
function anPublic() { return { study: anStudy(), top20: anTop20Data(), following: AN.births.size, sampledFollowing: AN.liveSampled, lean: AN.lean, diag: AN.diag, since: AN.since, hotWords: [...AN.hot.keys()].slice(0, 30) }; }
const AN_CSV = ["mint", "symbol", "name", "launched_utc", "in_sample", "final", "restart_during", "creator", "creator_launches_24h", "creator_past_winners", "name_len", "non_english",
  "hot_list_ready", "hot_word", "creator_buy_sol", "wallets_first_2s", "sol_first_2s", "supply_pct_first_2s", "proven_early_buyers", "buyers_90s", "net_sol_90s", "bonded_pct_90s",
  "curve_standard", "feed_seen", "deep_checked", "deep_random", "creator_wallet_age_h", "creator_wallet_busy", "creator_txs_before_launch", "funder", "funding_sol",
  "funder_creators_before", "funder_winners_before", "x_link", "telegram", "website", "graduated", "grad_min", "top100", "top100_min", "top20", "top20_min", "best_rank"];
function anCsvRow(r) {
  const mins = (x) => (x ? ((x - r.t) / 60000).toFixed(1) : "");
  return [r.m, r.s, r.n, new Date(r.t).toISOString(), r.smp ? 1 : 0, r.fin ? 1 : 0, r.gap ? 1 : 0, r.c, r.cl, r.cw, r.nl, r.ne, r.sn ? (r.hk ? 1 : 0) : "", r.hw || "",
    r.dev, r.ew, r.es, r.ep, r.pb, r.b90, r.net90, r.p90, r.std, r.sn ? (r.nf ? 0 : 1) : "",
    r.dp ? 1 : 0, r.dp ? (r.dr ? 1 : 0) : "", r.age, r.dp ? (r.busy ? 1 : 0) : "", r.tx, r.fu, r.fa, r.fn, r.fw, r.tw, r.tg, r.web,
    r.g ? 1 : 0, mins(r.g), r.t100 ? 1 : 0, mins(r.t100), r.t20 ? 1 : 0, mins(r.t20), r.br].map(csvQ).join(",");
}
/** Every birth record: the finished study sample, finished winners, and the sample still being followed (final=0). */
function anCsv() {
  const lines = [AN_CSV.join(",")];
  for (const r of AN.done) lines.push(anCsvRow(r));
  for (const r of AN.births.values()) if (r.smp || r.g || r.t20 || r.t100) lines.push(anCsvRow(r));
  return lines.join("\n");
}
function tgAnalyst() {
  const st = anStudy(), D = AN.diag, head = "🔬 <b>Analyst</b> · what the winners had at birth\n";
  if (st.n < 300) return head + `⏳ <b>Collecting.</b> Each launch is followed for a full 24 hours before it counts, so early luck can't flatter the numbers. ` +
    `First results about a day after this update; trustworthy ones after a few days.\n\nSince the last restart: ${D.launches.toLocaleString()} launches recorded · ${AN.births.size.toLocaleString()} being followed · ` +
    `${D.deep.toLocaleString()} creator wallets checked · ${D.top20} reached the top 20 and ${D.grads} graduated while being followed. Finished in the study so far: ${st.n.toLocaleString()} (300 needed).${AN.lean ? " ⚠️ The server is short on memory, so only the study sample is being kept." : ""}\n\n` +
    "Meanwhile, /top20 shows the top 20 right now with what each one looked like at birth.";
  const icon = { proven: "✅", lower: "🔻", weak: "⚠️", few: "⏳" }, fl = (x) => (x >= 10 ? String(Math.round(x)) : x.toFixed(1)) + "×";
  const sec = (k, title) => {
    const rows = st.rows.filter((x) => x.sec === k).sort((a, b) => (b.verdict === "proven") - (a.verdict === "proven") || b.lift - a.lift);
    return rows.length ? `\n\n<b>${title}</b>\n` + rows.map((x) => `${icon[x.verdict]} <b>${fl(x.lift)}</b> ${x.label} · ${x.ratePct}% vs ${x.otherPct}% (${x.nWith.toLocaleString()})`).join("\n") : "";
  };
  return head + `Studied <b>${st.n.toLocaleString()}</b> launches over ${st.days} day${st.days === 1 ? "" : "s"} (${st.from}${st.days > 1 ? " to " + st.to : ""}; a random sample, each followed 24 hours) · <b>${st.hits.t20}</b> reached the top 20 · <b>${st.hits.g}</b> graduated\n` +
    `Judged by <b>${st.outcome === "t20" ? "reaching the top 20" : "graduating"}</b> (${st.basePct}% of launches)${st.outcome === "g" ? ` · switches to the top 20 once 20 have made it (now ${st.hits.t20})` : ""}\n` +
    "Each line: how many times more often launches WITH the trait made it · their rate vs launches without it · (how many had it)" +
    sec("before", "Before launch") + sec("seconds", "First seconds") + sec("ninety", "First 90 seconds") +
    `\n\n✅ proven: held up in both halves of the data · ⚠️ not proven · 🔻 fewer winners · ⏳ not enough yet\nCreator wallets checked in the sample: ${st.deep.toLocaleString()}`;
}
function tgTop20() {
  const L = anTop20Data(); if (!L.length) return "🏆 The top-20 list is still loading. Try again in a few minutes.";
  const seen = L.filter((x) => x.birth).length;
  const head = `🏆 <b>Top 20 now</b> · GeckoTerminal trending, Solana, last hour · ${tgAgo(TOP.at)} ago\n\n`;
  const foot = `\n\nSeen at birth: ${seen} of ${L.length} · /birth and an address for the full record\n<i>GeckoTerminal ranks pools on people viewing them, volume, transactions, liquidity and safety checks over the last hour.</i>`;
  const rows = L.map((x) => ({ top: `${x.rank}. <b>${tgEsc(x.sym)}</b> $${tgK(x.mcap)}${x.ageMin != null ? " · " + anMinTxt(x.ageMin * 60000) + " old" : ""}`,
    notes: x.birth ? x.birth.notes.join(" · ") : null, tail: x.pump ? " · no birth record" : " · not a pump.fun launch" }));
  let cap = 400, out = "";
  const build = () => head + rows.map((r) => r.top + (r.notes != null ? "\n   🔬 " + tgEsc(anCut(r.notes, cap)) : r.tail)).join("\n") + foot;
  out = build(); while (out.length > 3750 && cap > 40) { cap -= 10; out = build(); }   // full notes when they fit; otherwise every row is trimmed evenly
  return out;
}
function tgBirth(addr) {
  const r = anFind(addr);
  if (!r) return `🔬 No birth record for <code>${tgEsc(addr)}</code>.\nThe bot writes one for every pump.fun launch it sees live and keeps it 24 hours (3 days for the study sample and for anything that reached the top 20 or graduated). Older tokens and tokens from other launchpads have none.`;
  const L = [`🔬 <b>Birth record</b> · ${tgEsc(r.s)} ${tgEsc(r.n)}`, `Born ${new Date(r.t).toISOString().slice(0, 16).replace("T", " ")} UTC (${tgAgo(r.t)} ago) · in the study sample: ${r.smp ? "yes" : "no"}${r.gap ? " · ⚠️ a restart happened while it was followed" : ""}`, "", "<b>Before launch</b>"];
  if (r.dp) {
    L.push(`• Creator wallet: ${r.busy ? "busy (100+ transactions)" : r.age != null ? anAgeTxt(r.age) + " old" : "age unknown"}${!r.busy && r.tx != null ? ` · ${r.tx} transaction${r.tx === 1 ? "" : "s"} before launch` : ""}`);
    if (r.fu) L.push(`• Funded by <code>${tgEsc(r.fu.slice(0, 4) + "…" + r.fu.slice(-4))}</code> with ${r.fa} SOL · that wallet had funded ${r.fn} other creator${r.fn === 1 ? "" : "s"}${r.fw ? ` (${r.fw} winner${r.fw === 1 ? "" : "s"})` : ""} before`);
    else if (!r.busy) L.push("• Funder: not found");
    L.push("• Socials: " + anSocTxt(r));
  } else L.push(`• Creator wallet and funder: ${r.dq ? "check queued" : "not checked (checks run on a random sample)"}`);
  L.push(`• Creator's launches in the last 24 hours: ${r.cl == null ? "?" : r.cl}${r.cw ? ` · ${r.cw} earlier winner${r.cw === 1 ? "" : "s"}` : ""}`);
  L.push(`• Name: ${r.nl} characters${r.ne ? " · non-English or emoji" : ""}${r.sn && r.hk ? (r.hw ? ` · rides the trending word "${tgEsc(r.hw)}"` : " · no trending word") : ""}`);
  L.push("", "<b>First seconds</b>");
  if (!r.sn) L.push("• Not measured yet (it is measured at 90 seconds)");
  else if (r.nf) L.push("• No feed data (a very busy moment, or a restart)");
  else {
    L.push(`• Creator bought ${r.dev || 0} SOL · ${r.ew} wallet${r.ew === 1 ? "" : "s"} bought in the first 2 seconds (${r.es} SOL, ${r.ep}% of supply)`);
    L.push(`• Proven early buyers among the first ${AN_FIRST_N}: ${r.pb}`);
    L.push("", "<b>First 90 seconds</b>", `• ${r.p90 != null ? Math.round(r.p90) + "% of the curve sold" : "curve % unknown (non-standard curve)"} · ${r.b90} different buyers · net ${r.net90 >= 0 ? "+" : ""}${r.net90} SOL`);
  }
  const out = [r.g ? "graduated after " + anMinTxt(r.g - r.t) : null, r.t100 ? "top 100 after " + anMinTxt(r.t100 - r.t) : null, r.t20 ? "top 20 after " + anMinTxt(r.t20 - r.t) : null, r.br ? "best rank #" + r.br : null].filter(Boolean);
  L.push("", "<b>What happened</b> (first 24 hours)", "• " + (out.length ? out.join(" · ") : r.fin ? "it never graduated or reached the top 100" : "nothing yet (still being followed)"));
  L.push("", `<code>${tgEsc(r.m)}</code>`);
  return L.join("\n");
}
function anReportLine() {
  const st = anStudy(), pr = st.rows.filter((x) => x.verdict === "proven").sort((a, b) => b.lift - a.lift)[0];
  return st.n >= 300 ? `🔬 Analyst: ${st.n.toLocaleString()} launches studied · ${st.hits.t20} reached the top 20, ${st.hits.g} graduated · ${pr ? "strongest proven sign: " + pr.label.toLowerCase() + " (" + pr.lift + "×)" : "no sign proven yet"}`
    : `🔬 Analyst: collecting (${AN.births.size.toLocaleString()} launches being followed, ${st.n} finished of the 300 the first results need)`;
}
/*ANALYST_END*/



/*AUTO_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🤖 AUTOPILOT — protects the account and fixes its own mistakes, with nobody watching
// ═══════════════════════════════════════════════════════════════════════
/**
 * Every 5 minutes it checks three things:
 *  1. DRAWDOWN: down 25% from the best the account has been -> switch to Defense settings. Down 40% -> also pause new trades 8 hours.
 *  2. LOSING WAYS OF ENTERING: any entry type that, over its last 12+ trades today, averages worse than -12% and wins under
 *     35% of the time gets switched off (Launch Shot, Graduates, Copy) or made stricter (Momentum). Each is only touched once per 6 hours.
 *  3. BET SIZE: as the balance shrinks it uses fewer, bigger bets, because fixed fees hurt small bets most.
 * Everything it does is written down (dashboard + Telegram), so the morning report says what it changed and why.
 */
/** Start a fresh paper account. The old run is boiled down to a summary first, so what it taught you is never lost. */
function mpResetAll(opts = {}) {
  const S = MP.settings, T = MP.closed.filter((x) => x.pnlUsd != null);
  if (MP.bank && T.length >= 3) {
    const W = T.filter((x) => x.pnlUsd > 0), by = {};
    for (const x of T) { const k = mpEntryType(x), r = by[k] || (by[k] = { type: k, n: 0, pnl: 0, w: 0 }); r.n++; r.pnl += x.pnlUsd; if (x.pnlUsd > 0) r.w++; }
    MP.runs.unshift({ at: Date.now(), from: MP.startedAt, start: MP.bank.start, end: +mpEquity().toFixed(2), trades: T.length, winRate: Math.round((W.length / T.length) * 100),
      avgPct: +(T.reduce((a, x) => a + (x.pnlPct || 0), 0) / T.length).toFixed(1), byType: Object.values(by).map((r) => ({ type: r.type, trades: r.n, wins: r.w, pnlUsd: +r.pnl.toFixed(2) })).sort((a, b) => a.pnlUsd - b.pnlUsd),
      did: MP.auto.log.slice(0, 5).map((x) => x.text) });
    if (MP.runs.length > 12) MP.runs.length = 12;
  }
  if (opts.profile === "v10") Object.assign(S, V10); else if (opts.profile === "v11") Object.assign(S, V11); else if (opts.safe) Object.assign(S, PROVEN_V2);
  MP.closed = []; MP.positions = []; MP.evaluated = []; MP.skips = {}; MP.seen = 0; MP.startedAt = Date.now(); MP.watch.clear();
  MP.bank = mpNewBank(S.startUsd); MP.report = {}; MP.outcomes = []; MP.events = [];
  MP.auto = { log: [], typeAt: {}, eqPeak: 0, dd: 0, lastPause: 0, lastDefense: 0 };
  mpSaveNow();                                                            // a fresh start is saved at once, so a restart of the server can't undo it
  mpEvent(`Started fresh with $${S.startUsd}${opts.profile === "v11" ? " on the V1.1 rules (risk 1% of the money per trade, sized from the stop, 3 positions, 3% daily stop, staged exits)" : opts.profile === "v10" ? " on the V1.0 rules (1% bets, 3 positions, 3% daily stop, staged exits)" : opts.safe ? " on the safe profile" : ""}`);
}
/** Make the risk settings stricter, never looser, and never touch how bets are sized. */
function mpTighten(S) {
  const lower = ["slPct", "trailPct", "maxHoldMin", "moonHoldMin", "dailyStopPct", "maxLossStreak", "maxTop10Pct", "maxTop1Pct", "maxDevPct", "momMaxMcap", "momMaxRise2m", "gradMaxOpen", "gradSl", "tpPct", "gradMaxCh5", "gradMaxImpact"];
  const higher = ["momBuyers60", "momBuyShare", "momNetSol", "momRise2m", "minProgress", "pauseMin", "labMinLift", "tp1SellPct", "gradMinLiq", "gradMinLiqPct", "gradMinVol24"];
  for (const k of lower) if (PROVEN_V2[k] != null && S[k] != null && !(S.ladderOn && k === "tpPct")) S[k] = Math.min(S[k], PROVEN_V2[k]);
  for (const k of higher) if (PROVEN_V2[k] != null && S[k] != null) S[k] = Math.max(S[k], PROVEN_V2[k]);
  S.fastLane = 0; S.momentum = 1; S.labFilter = 1;
  if (!(S.momMaxRise2m > 0)) S.momMaxRise2m = PROVEN_V2.momMaxRise2m;              // a cap switched off is switched back on
}
function mpEquity() {
  const B = MP.bank, S = MP.settings;
  return B.cash + B.vault + (B.sent || 0) + MP.positions.reduce((a, p) => a + (p.tokensLeft == null ? p.tokens : p.tokensLeft) * p.last * (1 - S.feePct / 100), 0);
}
function mpAuto(text, kind) { MP.auto.log.unshift({ at: Date.now(), text, kind }); if (MP.auto.log.length > 60) MP.auto.log.length = 60; mpEvent("Autopilot: " + text); }
const mpEntryType = (x) => x.entryType || (x.fast ? "launch shot" : "at 90s");
function mpAutopilot(now = Date.now()) {
  const S = MP.settings; if (!S.autopilot || !MP.bank) return;
  const A = MP.auto, B = MP.bank, eq = mpEquity();
  if (!A.eqPeak) A.eqPeak = Math.max(eq, B.peak || 0, B.start || 0, 0.01);        // the first time it looks: measure from the account's best, not from "now"
  A.eqPeak = Math.max(A.eqPeak, eq); A.dd = +Math.max(0, (1 - eq / A.eqPeak) * 100).toFixed(1);
  // 0) ruin stop: when the account is nearly gone, fixed costs eat every trade, so stop and say so
  if (eq < Math.max(6, 0.15 * (B.start || 0))) {
    if (S.autoFresh) {                                                     // it's paper money: don't sit idle waiting for a tap, start the next test and keep learning
      const before = eq, start0 = B.start;
      mpResetAll({ profile: "v10" });
      mpAuto(`the account ran out ($${before.toFixed(2)} of $${(start0 || 0).toFixed(2)}). It's paper money, so I started a fresh $${MP.settings.startUsd.toLocaleString()} test on the V1.0 rules. What the old run taught is saved under Past runs.`, "restart");
      return;
    }
    if (!(B.pausedUntil > now && /too small/.test(B.pauseWhy || ""))) {
      B.pausedUntil = now + 7 * 24 * 3600e3; B.pauseWhy = "account too small: start fresh";
      mpAuto(`the account is down to $${eq.toFixed(2)}. At this size the fixed costs eat every trade, so trading is stopped. Start fresh (Telegram /fresh, or Reset on the dashboard) for a new test on the safe profile`, "ruin");
    }
    return;
  }
  // 1) drawdown brakes
  if (A.dd >= S.ddBrake2Pct && now - (A.lastPause || 0) > 12 * 3600e3) {
    mpTighten(S); B.pausedUntil = now + 8 * 3600e3; B.pauseWhy = "drawdown brake"; A.lastPause = A.lastDefense = now;
    mpAuto(`down ${Math.round(A.dd)}% from its peak: paused new trades for 8 hours and switched to the safest settings`, "brake"); A.eqPeak = eq;
  } else if (A.dd >= S.ddBrake1Pct && now - (A.lastDefense || 0) > 12 * 3600e3) {
    mpTighten(S); A.lastDefense = now;
    mpAuto(`down ${Math.round(A.dd)}% from its peak: made the risk settings stricter`, "brake");
  }
  // 2) switch off the ways of entering that are bleeding
  const recent = MP.closed.filter((x) => x.pnlUsd != null && now - x.closedAt <= 24 * 3600e3);
  A.since = A.since || {};
  for (const type of ["launch shot", "graduate", "copy", "momentum", "at 90s"]) {
    // only trades closed AFTER the last change count: otherwise the same old trades get "punished" again and again until nothing can qualify
    const T = recent.filter((x) => mpEntryType(x) === type && x.closedAt > (A.since[type] || 0)).slice(0, 25); if (T.length < S.killMinTrades) continue;
    const avg = T.reduce((a, x) => a + (x.pnlPct || 0), 0) / T.length, wr = (T.filter((x) => x.pnlUsd > 0).length / T.length) * 100;
    if (avg > S.killAvgPct || wr > 35 || now - (A.typeAt[type] || 0) < 6 * 3600e3) continue;
    const why = `${T.length} trades, average ${avg.toFixed(0)}%, ${Math.round(wr)}% wins`;
    if (type === "launch shot" && S.fastLane) { S.fastLane = 0; A.typeAt[type] = A.since[type] = now; mpAuto(`switched OFF Launch Shot (${why})`, "kill"); }
    else if (type === "graduate" && S.gradOn) { S.gradOn = 0; A.typeAt[type] = A.since[type] = now; mpAuto(`switched OFF Graduate entries (${why})`, "kill"); }
    else if (type === "copy" && S.copyOn) { S.copyOn = 0; A.typeAt[type] = A.since[type] = now; mpAuto(`switched OFF Copy trading (${why})`, "kill"); }
    else if (type === "at 90s" && !S.momentum) { S.momentum = 1; A.typeAt[type] = A.since[type] = now; mpAuto(`switched to Momentum entries (buying at 90 seconds: ${why})`, "kill"); }
    else if (type === "momentum") {
      // stricter = more real demand and no chasing. It never RAISES the minimum rise: that would push entries later into a pump that already happened.
      S.momBuyers60 = Math.min(30, S.momBuyers60 + 2); S.momNetSol = Math.min(15, +(S.momNetSol + 0.5).toFixed(1));
      S.momMaxRise2m = S.momMaxRise2m > 0 ? Math.max(40, S.momMaxRise2m - 10) : 100; A.typeAt[type] = A.since[type] = now;
      mpAuto(`made Momentum entries stricter: now needs ${S.momBuyers60} buyers and ${S.momNetSol} SOL in, and skips anything already up more than ${S.momMaxRise2m}% in 2 min (${why}). It will judge the change on the next ${S.killMinTrades} trades.`, "kill");
    }
  }
  // 3) bet size follows the balance
  if (S.autoSlots) { const want = Math.max(2, Math.min(6, Math.round(eq / 8))); if (S.slots !== want) { S.slots = want; A.slotsNote = `${want} bets at a time (balance $${eq.toFixed(0)})`; } }
}
setInterval(() => { try { mpAutopilot(); } catch (e) { log("error", `autopilot: ${e.message}`); } }, 5 * 60e3);
setTimeout(() => { try { if (MP.migrated) { mpAuto("moved the old saved settings onto the safe starting profile (Launch Shot off, strict Momentum entries, tighter stops, bigger bets, 12% daily stop)", "setup"); MP.migrated = false; } mpAutopilot(); } catch {} }, 20000);
function mpRunsLine() {
  const r = MP.runs[0]; if (!r) return "";
  const worst = r.byType && r.byType[0] && r.byType[0].pnlUsd < 0 ? `, worst way of entering: ${r.byType[0].type} (${r.byType[0].pnlUsd < 0 ? "−$" : "+$"}${Math.abs(r.byType[0].pnlUsd).toFixed(2)})` : "";
  return `Last run: $${r.start.toFixed(2)} → $${r.end.toFixed(2)} over ${r.trades} trades (${r.winRate}% won, ${r.avgPct}% per trade)${worst}`;
}
function mpAutoPublic() {
  const S = MP.settings, A = MP.auto, eq = MP.bank ? mpEquity() : 0, b = MP.bank || {};
  return { on: !!S.autopilot, equity: +eq.toFixed(2), peak: +(A.eqPeak || 0).toFixed(2), ddPct: A.dd || 0, brake1: S.ddBrake1Pct, brake2: S.ddBrake2Pct, slots: S.slots, autoSlots: !!S.autoSlots, slotsNote: A.slotsNote || null,
    paused: b.pausedUntil > Date.now() ? b.pauseWhy : null, log: A.log.slice(0, 12), runs: MP.runs.slice(0, 4) };
}
/** The morning report: what happened, what it changed, where things stand. */
function mpReportText() {
  const S = MP.settings, B = MP.bank, now = Date.now(), eq = mpEquity(), A = MP.auto;
  const T = MP.closed.filter((x) => x.pnlUsd != null && now - x.closedAt <= 24 * 3600e3), W = T.filter((x) => x.pnlUsd > 0), pnl = T.reduce((a, x) => a + x.pnlUsd, 0);
  const by = {}; for (const x of T) { const k = mpEntryType(x), r = by[k] || (by[k] = { n: 0, pnl: 0, w: 0 }); r.n++; r.pnl += x.pnlUsd; if (x.pnlUsd > 0) r.w++; }
  const money = (n) => (n < 0 ? "−$" : "+$") + Math.abs(n).toFixed(2);
  const acts = A.log.filter((x) => now - x.at <= 24 * 3600e3);
  const lines = [`📰 <b>${TG_NAME} · last 24 hours</b>`,
    `Account <b>$${eq.toFixed(2)}</b> (started $${B.start.toFixed(2)}, ${eq >= B.start ? "+" : ""}${(((eq / B.start) - 1) * 100).toFixed(1)}%) · best so far $${(A.eqPeak || eq).toFixed(2)} · now ${A.dd || 0}% below it`,
    T.length ? `Trades <b>${T.length}</b> · ${W.length} won (${Math.round((W.length / T.length) * 100)}%) · <b>${money(pnl)}</b>` : `No trades closed in the last 24 hours.`];
  const rows = Object.entries(by).sort((a, b) => a[1].pnl - b[1].pnl).map(([k, r]) => `• ${k}: ${r.n} trades, ${r.w} won, ${money(r.pnl)}`); if (rows.length) lines.push("By way of entering:\n" + rows.join("\n"));
  lines.push(acts.length ? "🤖 Autopilot did:\n" + acts.slice(0, 5).map((x) => "• " + x.text).join("\n") : "🤖 Autopilot: nothing needed changing.");
  { const c = mpCourt(); lines.push(`🏛️ Court: <b>${c.overall.verdict}</b> · ${c.overall.n} trades (${MP.settings.courtMinTrades} needed) · ${c.overall.passed} of ${c.overall.gates.length} tests passed${c.proven.length ? " · proven: " + c.proven.join(", ") : ""}`); }
  if (MP.feed.glitches) lines.push(`🛡 Impossible price readings caught and ignored since the last restart: ${MP.feed.glitches}`);
  try { const p = mpPlan(), pb = pbPublic(), gx = gxPublic(), led = ledPublic();
    lines.push(`🗺️ Plan: day ${p.day} of ${p.days} · ${p.gates.filter((g) => g.ok).length} of ${p.gates.length} gates met${p.verdict ? " · VERDICT " + p.verdict : ""}`);
    lines.push(`📘 Playbook: ${pb.kept.length} kept · ${pb.avoid.length} confirmed to avoid · ${pb.testing.length} being tested · 📒 ${led.n} tokens in the ledger (${led.skipped.wins} skipped winners)${gx.n ? ` · 🎓 Index: ${gx.n} graduates, ${gx.runners10} runners 10x+, line ${gx.ret >= 0 ? "+" : ""}${gx.ret}%` : ""}`); } catch {}
  { const g = mpGoal(); if (g.n) lines.push(`🎯 Goal $${g.goal} per trade: averaging <b>${g.avg >= 0 ? "$" : "−$"}${Math.abs(g.avg).toFixed(2)}</b> over the last ${g.n} trades${g.hit ? " ✅" : ""}.`); }
  try { if (typeof anReportLine === "function") lines.push(anReportLine()); } catch {}
  if (MP.runs[0]) lines.push("📚 " + mpRunsLine());
  lines.push(`Now: ${B.pausedUntil > now ? "⏸ paused (" + B.pauseWhy + ")" : "🟢 trading"} · ${S.momentum ? "momentum entries" : "buy at 90s"}${S.gradOn ? " + graduates" : ""}${S.fastLane ? " + launch shot" : ""} · stop −${S.slPct}% · ${S.sizeByRisk ? `risk ${S.riskPerTradePct}% a trade, up to ${S.maxOpen} at a time` : S.slots > 0 ? `${S.slots} bets at a time` : `${S.riskPct}% a bet, up to ${S.maxOpen} at a time`} · daily stop ${S.dailyStopPct}%`);
  return lines.join("\n\n");
}
/*AUTO_END*/


/*GOAL_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🎯 GOAL SCOREBOARD and 🎵 RHYTHM FINDER
// ═══════════════════════════════════════════════════════════════════════
/** Profit per trade is a RESULT, not a setting. This measures it honestly, over the latest N trades, after every cost. */
function mpGoal() {
  const S = MP.settings, goal = S.goalPerTrade, W = S.goalWindow;
  const T = MP.closed.filter((x) => x.pnlUsd != null).slice(0, W), n = T.length;
  const base = { goal, window: W, n };
  if (!n) return { ...base, verdict: `Collecting trades: 0 of ${W}.`, progressPct: 0 };
  const sum = T.reduce((a, x) => a + x.pnlUsd, 0), avg = sum / n, avgPct = T.reduce((a, x) => a + (x.pnlPct || 0), 0) / n;
  const avgBet = T.reduce((a, x) => a + (x.sizeUsd || x.costUsd || 0), 0) / n, wins = T.filter((x) => x.pnlUsd > 0).length;
  const span = Math.max(1, (T[0].closedAt - T[n - 1].closedAt) / 3600e3), perDay = n > 1 ? +((n / span) * 24).toFixed(1) : null;
  const needBet = avgPct > 0 ? goal / (avgPct / 100) : null, needBankroll = needBet != null && S.riskPct > 0 ? needBet / (S.riskPct / 100) : null;
  const lanes = {}; for (const x of T) { const k = mpEntryType(x), r = lanes[k] || (lanes[k] = { type: k, n: 0, pnl: 0 }); r.n++; r.pnl += x.pnlUsd; }
  let verdict;
  if (n < Math.min(10, W)) verdict = `Collecting trades: ${n} of ${W}. Too early to judge.`;
  else if (avg >= goal) verdict = `✅ On target: averaging $${avg.toFixed(2)} per trade over the last ${n} (goal $${goal}).`;
  else if (avgPct <= 0) verdict = `No edge yet: averaging ${avgPct.toFixed(1)}% per trade after costs. Bigger bets would only lose faster. The goal needs a positive edge first.`;
  else verdict = `Edge is positive (+${avgPct.toFixed(1)}% per trade). To average $${goal} per trade you'd need bets of about $${needBet.toFixed(0)}${needBankroll ? ` (a bankroll near $${Math.round(needBankroll).toLocaleString()} at ${S.riskPct}% per trade)` : ""}. Bets now average $${avgBet.toFixed(2)}.`;
  return { ...base, avg: +avg.toFixed(2), avgPct: +avgPct.toFixed(1), avgBet: +avgBet.toFixed(2), winRate: Math.round((wins / n) * 100), total: +sum.toFixed(2), hit: avg >= goal && n >= Math.min(10, W),
    progressPct: Math.max(0, Math.min(100, (avg / goal) * 100)), needBet: needBet == null ? null : +needBet.toFixed(2), needBankroll: needBankroll == null ? null : Math.round(needBankroll),
    tradesPerDay: perDay, projectedPerDay: perDay == null ? null : +(avg * perDay).toFixed(2), verdict,
    lanes: Object.values(lanes).map((r) => ({ type: r.type, trades: r.n, pnlUsd: +r.pnl.toFixed(2), avgUsd: +(r.pnl / r.n).toFixed(2) })).sort((a, b) => b.avgUsd - a.avgUsd) };
}
/** How many launches, and how many graduated, in each hour: kept per hour, saved to disk, 14 days. */
const RH_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-rhythm.json") : "";
const RH = { hr: {} };
try { if (RH_FILE && nodeFs.existsSync(RH_FILE)) RH.hr = JSON.parse(nodeFs.readFileSync(RH_FILE, "utf8")).hr || {}; } catch {}
const rhSave = () => { try {
  const cut = Date.now() - 14 * 24 * 3600e3; for (const k of Object.keys(RH.hr)) if (Date.parse(k + ":00:00Z") < cut) delete RH.hr[k];
  if (RH_FILE) { const t = RH_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify({ hr: RH.hr })); nodeFs.renameSync(t, RH_FILE); } } catch {} };
regFlush(rhSave); setInterval(rhSave, 5 * 60e3);
function rhCount(kind, t) { const k = new Date(t).toISOString().slice(0, 13), v = RH.hr[k] || (RH.hr[k] = { l: 0, g: 0 }); v[kind]++; }
const pad2 = (n) => String(n).padStart(2, "0");
/** Which times of day (UTC, 3-hour blocks) launches graduate more or less often than average. */
function mpRhythm() {
  const cutoff = Date.now() - 2 * 3600e3, blk = Array.from({ length: 8 }, (_, i) => ({ from: i * 3, to: i * 3 + 3, l: 0, g: 0, wn: 0, wd: 0, tn: 0, tp: 0, tc: 0 }));
  let L = 0, G = 0, hours = 0;
  for (const [k, v] of Object.entries(RH.hr)) { const t = Date.parse(k + ":00:00Z"); if (!(t <= cutoff)) continue; const b = blk[Math.floor(new Date(t).getUTCHours() / 3)]; b.l += v.l; b.g += v.g; L += v.l; G += v.g; hours++; }
  const base = L ? G / L : 0;
  for (const s of LAB.snaps) if ((s.win || s.done) && Number.isFinite(s.hour)) { const b = blk[Math.floor(s.hour / 3)]; b.wd++; if (s.win) b.wn++; }
  for (const x of MP.closed) if (x.pnlUsd != null && x.openedAt) { const b = blk[Math.floor(new Date(x.openedAt).getUTCHours() / 3)]; b.tn++; b.tp += x.pnlUsd; b.tc += x.pnlPct || 0; }
  const rows = blk.map((b) => ({ block: `${pad2(b.from)}–${pad2(b.to)} UTC`, from: b.from, launches: b.l, grads: b.g, gradRatePct: b.l >= 300 ? +((b.g / b.l) * 100).toFixed(2) : null,
    lift: b.l >= 300 && base > 0 ? +((b.g / b.l) / base).toFixed(2) : null, winnersPct: b.wd >= 30 ? Math.round((b.wn / b.wd) * 100) : null,
    trades: b.tn, tradePnl: +b.tp.toFixed(2), avgPct: b.tn ? +(b.tc / b.tn).toFixed(1) : null }));
  const ok = rows.filter((r) => r.lift != null);
  const best = ok.length ? ok.reduce((a, b) => (b.lift > a.lift ? b : a)) : null, worst = ok.length ? ok.reduce((a, b) => (b.lift < a.lift ? b : a)) : null, cur = rows[Math.floor(new Date(Date.now()).getUTCHours() / 3)];
  return { rows, basePct: +(base * 100).toFixed(2), best, worst, nowBlock: cur.block, nowLift: cur.lift, hoursOfData: hours, ready: ok.length >= 6 };
}
/** Returns a reason when "rhythm" says not to open anything now; null when it's fine (or there isn't enough data to say). */
function mpRhythmGate() {
  const S = MP.settings; if (!S.rhythmOn) return null;
  const r = mpRhythm(); if (!r.ready || r.nowLift == null) return null;
  return r.nowLift < S.rhythmMinLift ? `rhythm: this time of day (${r.nowBlock}) graduates ${r.nowLift}× the average` : null;
}
/*GOAL_END*/


/*BAND_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🎯 BAND: "buy at $25K, sell at $30K". Is it a good idea? Measure it on the real launches before trusting it.
// ═══════════════════════════════════════════════════════════════════════
/** pump.fun's curve starts with 30 SOL of virtual SOL (constant product). How far does buying $X at market cap $M move the price? */
function curveImpactPct(mcapUsd, betUsd, sol) {
  const p = mcapUsd / (1e9 * sol), vSol = Math.sqrt(30 * 1.073e9 * p), dx = betUsd / sol;
  return (Math.pow((vSol + dx) / vSol, 2) - 1) * 100;
}
/** The biggest buy that moves the price by no more than impactPct. */
function curveMaxBetUsd(mcapUsd, impactPct, sol) {
  const p = mcapUsd / (1e9 * sol), vSol = Math.sqrt(30 * 1.073e9 * p);
  return vSol * (Math.sqrt(1 + impactPct / 100) - 1) * sol;
}
const curveRealPoolUsd = (mcapUsd, sol) => Math.max(0, Math.sqrt(30 * 1.073e9 * (mcapUsd / (1e9 * sol))) - 30) * sol;
const bandRules = (S) => ({ sellMcap: S.bandSellK * 1000, tpPct: 9999, tp1SellPct: 100, ladderOn: 0, slPct: S.bandStopPct, maxHoldMin: 20, moonHoldMin: 60, cashOutMcap: 0 });
function mpSkipBand(mint, reason) { MP.skips["band: " + reason] = (MP.skips["band: " + reason] || 0) + 1; }
/** A token just crossed the buy line. Same safety as every other entry; then buy no more than the curve can absorb. */
async function mpBandBuy(mint) {
  const S = MP.settings; if (!S.bandOn || !MP.on || MP.positions.some((p) => p.mint === mint)) return;
  const snap = LAB.snaps.find((x) => x.mint === mint); if (!snap) return mpSkipBand(mint, "never judged at launch");
  if (typeof rugReg !== "undefined" && rugReg.has(snap.creator)) return mpSkipBand(mint, "creator is a known rugger");
  const sol = await getSolUsd().catch(() => null); if (!sol) return;
  const chk = await getMintCheck(mint).catch(() => null);
  if (!chk || !chk.found) return mpSkipBand(mint, "couldn't check the contract");
  if (!chk.mintAuthorityRenounced || !chk.freezeAuthorityRenounced) return mpSkipBand(mint, "creator can print or freeze");
  if (chk.top10WalletPct != null && chk.top10WalletPct > S.maxTop10Pct) return mpSkipBand(mint, `top 10 hold ${Math.round(chk.top10WalletPct)}%`);
  if (chk.top1WalletPct != null && chk.top1WalletPct > S.maxTop1Pct) return mpSkipBand(mint, `one wallet holds ${Math.round(chk.top1WalletPct)}%`);
  let devPct = null; try { devPct = ((await balanceOf(snap.creator, mint)) / 1e9) * 100; } catch {}
  if (devPct != null && devPct > S.maxDevPct) return mpSkipBand(mint, `creator holds ${devPct.toFixed(1)}%`);
  const labA = labAnalyze(), labL = labLift(snap, labA);
  if (S.labFilter && labA.ready && labL < S.labMinLift) return mpSkipBand(mint, `Winner Lab score ${labL.toFixed(1)}× is below your line`);
  const c = await readBondingCurve(mint).catch(() => null); if (!c || c.complete) return mpSkipBand(mint, "already graduated");
  const m = curveMarket(c, sol, 6);
  if (m.mcap < S.bandBuyK * 1000 * 0.95 || m.mcap > S.bandSellK * 1000 * 0.97) return mpSkipBand(mint, "price moved away from the buy line");
  mpOpen({ mint, symbol: snap.sym || "?", name: snap.name || "", creator: snap.creator, uri: null }, m,
    { top10: chk.top10WalletPct, top1: chk.top1WalletPct, devPct, labA, labL, sol, entryType: "band", rules: bandRules(S), maxBetUsd: curveMaxBetUsd(m.mcap, S.bandMaxImpactPct, sol),
      momentum: `band: crossed $${S.bandBuyK}K`, why: `BAND · crossed $${S.bandBuyK}K (now $${(m.mcap / 1000).toFixed(1)}K) · target $${S.bandSellK}K · stop −${S.bandStopPct}% · top10 ${chk.top10WalletPct != null ? Math.round(chk.top10WalletPct) + "%" : "?"}` });
}
/** Replay one recorded path: enter when the market cap first crosses the buy line, exit at the sell line, the stop, or after 20 minutes. */
function bandRun(pts, mcap0, buy, sell, stopPct, S, sol, refBet) {
  if (!(mcap0 > 0) || mcap0 >= buy) return null;
  const slip = Math.max(S.slippagePct, curveImpactPct(buy, refBet, sol)) / 100, fee = S.feePct / 100, fixed = ((S.priorityFeeSol + S.jitoTipSol) * sol) / refBet;
  let i0 = -1; for (let i = 1; i < pts.length; i++) if (mcap0 * pts[i] >= buy) { i0 = i; break; }
  if (i0 < 0) return null;
  const entry = pts[i0] * (1 + slip), maxI = Math.min(pts.length - 1, i0 + 80);
  let exit = pts[maxI], kind = "time";
  for (let j = i0 + 1; j <= maxI; j++) {
    if (mcap0 * pts[j] >= sell) { exit = pts[j]; kind = "win"; break; }
    if (pts[j] <= entry * (1 - stopPct / 100)) { exit = pts[j]; kind = "stop"; break; }
  }
  const back = (exit * (1 - slip) * (1 - fee)) / entry - fixed;
  return { kind, net: ((back - (1 + fee) - fixed) / (1 + fee + fixed)) * 100 };
}
function bandStats(buyK, sellK, stopPct, S, sol) {
  const rows = PATHS.list.filter((p) => p.pts && p.pts.length >= 12 && p.mcap0 > 0), refBet = 100;
  let crossed = 0, wins = 0, stops = 0, times = 0, sumAll = 0, sumW = 0, sumN = 0;
  for (const p of rows) {
    const r = bandRun(p.pts, p.mcap0, buyK * 1000, sellK * 1000, stopPct, S, sol, refBet); if (!r) continue;
    crossed++; sumAll += r.net; if (r.kind === "win") { wins++; sumW += r.net; } else { sumN += r.net; if (r.kind === "stop") stops++; else times++; }
  }
  const nonW = crossed - wins, avgW = wins ? sumW / wins : 0, avgN = nonW ? sumN / nonW : 0;
  const breakeven = wins && nonW && avgW > 0 && avgN < 0 ? (-avgN / (avgW - avgN)) * 100 : null;
  return { buyK, sellK, stopPct, tokens: rows.length, crossed, wins, stops, times, pWinPct: crossed ? +((wins / crossed) * 100).toFixed(1) : null, avgNetPct: crossed ? +(sumAll / crossed).toFixed(2) : null,
    avgWinPct: wins ? +avgW.toFixed(1) : null, avgLossPct: nonW ? +avgN.toFixed(1) : null, breakevenPct: breakeven == null ? null : +breakeven.toFixed(1) };
}
function mpBandStudy() {
  const S = MP.settings, sol = (typeof solUsd !== "undefined" && solUsd.v) || 150;
  const mine = bandStats(S.bandBuyK, S.bandSellK, S.bandStopPct, S, sol);
  const grid = [];
  for (const b of [15, 20, 25, 30, 40]) for (const g of [15, 20, 30, 50]) for (const st of [10, 15, 20]) {
    const sellK = Math.round(b * (1 + g / 100) * 10) / 10; if (sellK >= 69) continue;
    const r = bandStats(b, sellK, st, S, sol); if (r.crossed >= 30) grid.push(r);
  }
  grid.sort((a, c) => c.avgNetPct - a.avgNetPct);
  const ats = PATHS.list.map((p) => p.at).filter(Boolean), days = ats.length ? Math.max(0.1, (Math.max(...ats) - Math.min(...ats)) / 86400e3) : 0;
  const buy = S.bandBuyK * 1000, capBet = curveMaxBetUsd(buy, S.bandMaxImpactPct, sol);
  const netPerTradeUsd = mine.avgNetPct != null ? (mine.avgNetPct / 100) * capBet : null, candidatesPerDay = days >= 0.5 ? +(mine.crossed / days).toFixed(0) : null;
  const tradesNeeded = netPerTradeUsd > 0 ? Math.ceil(S.dailyGoalUsd / netPerTradeUsd) : null;
  let verdict;
  if (mine.crossed < 30) verdict = `Collecting: only ${mine.crossed} recorded tokens have crossed $${S.bandBuyK}K so far (it needs 30+ before it can say anything). The bot records every judged launch for 45 minutes, so this fills in over the next day or two.`;
  else if (mine.avgNetPct <= 0) verdict = `So far, no: of ${mine.crossed} tokens that crossed $${S.bandBuyK}K, ${mine.pWinPct}% reached $${S.bandSellK}K before the −${S.bandStopPct}% stop, and ${mine.stops} hit the stop. After costs that averages ${mine.avgNetPct}% per trade. It would need about ${mine.breakevenPct == null ? "more" : mine.breakevenPct + "%"} winners to break even.`;
  else verdict = `Promising: ${mine.pWinPct}% of ${mine.crossed} tokens reached $${S.bandSellK}K before the stop, averaging +${mine.avgNetPct}% per trade after costs (break-even needs ${mine.breakevenPct}% winners).`;
  return { ...mine, days: +days.toFixed(1), top: grid.slice(0, 5), bottom: grid.slice(-1)[0] || null,
    capacity: { impactPer100: +curveImpactPct(buy, 100, sol).toFixed(2), maxBetUsd: Math.round(capBet), poolUsd: Math.round(curveRealPoolUsd(buy, sol)), maxImpactPct: S.bandMaxImpactPct },
    plan: { goalUsd: S.dailyGoalUsd, netPerTradeUsd: netPerTradeUsd == null ? null : +netPerTradeUsd.toFixed(2), tradesNeeded, candidatesPerDay,
      feasible: tradesNeeded != null && candidatesPerDay != null ? tradesNeeded <= candidatesPerDay * 0.5 : null }, verdict, on: !!S.bandOn };
}
let bandCache = null, bandAt = 0, bandBusy = false;
function mpBandCached() {                                                  // never makes a page wait: last answer now, refreshed in the background every 10 minutes
  if ((!bandCache || Date.now() - bandAt > 10 * 60e3) && !bandBusy) { bandBusy = true; setTimeout(() => { try { bandCache = mpBandStudy(); } catch (e) { bandCache = { error: e.message }; } bandAt = Date.now(); bandBusy = false; }, 50); }
  return bandCache || { collecting: true };
}
function tgBand() {
  const b = mpBandStudy(); if (b.error) return "🎯 Couldn't compute the band study right now.";
  const m = (n) => (n < 0 ? "−$" : "+$") + Math.abs(n).toFixed(2);
  return `🎯 <b>Buy $${b.buyK}K → sell $${b.sellK}K</b> (stop −${b.stopPct}%) ${b.on ? "· lane ON" : "· lane off"}\n${b.verdict}\n\n` +
    `Capacity: a $100 buy at $${b.buyK}K moves the price ${b.capacity.impactPer100}%. The whole pool holds about $${b.capacity.poolUsd.toLocaleString()}. Biggest sensible bet (${b.capacity.maxImpactPct}% impact): <b>$${b.capacity.maxBetUsd}</b>.\n` +
    (b.plan.tradesNeeded ? `To make $${b.plan.goalUsd} a day at ${m(b.plan.netPerTradeUsd)} a trade: about <b>${b.plan.tradesNeeded}</b> trades a day. About ${b.plan.candidatesPerDay} tokens a day cross the line.` : `A $${b.plan.goalUsd} a day goal can't be planned yet: the average trade isn't positive.`);
}
/*BAND_END*/


/*COURT_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🏛️ STRATEGY COURT — the proof gate: nothing is "winning" until it survives these tests
// ═══════════════════════════════════════════════════════════════════════
/**
 * Real money is allowed only for something that passes ALL of these, judged on trades already closed after every cost:
 *   enough trades · positive average · positive with 95% confidence (bootstrap) · still positive if costs were 50% worse ·
 *   positive in BOTH the older and the newer half · spread over several days · worst drawdown under the limit.
 * Every way of entering is judged on its own, so a loser can't hide behind a winner (and a winner isn't dragged down by a loser).
 */
function courtBoot(vals, iters = 1000, seed = 20261020) {
  const n = vals.length; if (n < 5) return [null, null];
  let st = seed >>> 0; const rnd = () => (st = (st * 1664525 + 1013904223) >>> 0) / 4294967296, means = new Array(iters);
  for (let i = 0; i < iters; i++) { let sum = 0; for (let j = 0; j < n; j++) sum += vals[(rnd() * n) | 0]; means[i] = sum / n; }
  means.sort((a, b) => a - b); return [means[Math.floor(iters * 0.025)], means[Math.min(iters - 1, Math.floor(iters * 0.975))]];
}
function courtLane(name, newestFirst, S) {
  const T = newestFirst.filter((x) => x.pnlUsd != null).slice().reverse(), n = T.length;                       // oldest first
  const pct = T.map((x) => x.pnlPct || 0), mean = n ? pct.reduce((a, b) => a + b, 0) / n : 0;
  const [lo, hi] = courtBoot(pct), cost = 2 * (S.feePct + S.slippagePct), stress = mean - 0.5 * cost;
  const half = Math.floor(n / 2), avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0), h1 = avg(pct.slice(0, half)), h2 = avg(pct.slice(half));
  const wins = T.filter((x) => x.pnlUsd > 0), gw = wins.reduce((a, x) => a + x.pnlUsd, 0), gl = -T.filter((x) => x.pnlUsd <= 0).reduce((a, x) => a + x.pnlUsd, 0);
  const dayMap = {}; for (const x of T) { const d = new Date(x.closedAt || 0).toISOString().slice(0, 10); dayMap[d] = (dayMap[d] || 0) + x.pnlUsd; }
  const days = Object.keys(dayMap).length, posDays = Object.values(dayMap).filter((v) => v > 0).length;
  let eq = S.startUsd, peak = eq, mdd = 0; for (const x of T) { eq += x.pnlUsd; peak = Math.max(peak, eq); mdd = Math.max(mdd, peak > 0 ? ((peak - eq) / peak) * 100 : 0); }
  const rr = T.filter((x) => x.rMult != null).map((x) => x.rMult), meanR = rr.length ? rr.reduce((a, b) => a + b, 0) / rr.length : null;
  const gates = [
    { ok: n >= S.courtMinTrades, label: `At least ${S.courtMinTrades} trades`, value: `${n}` },
    { ok: n > 0 && mean > 0, label: "The average trade is positive after costs", value: `${mean >= 0 ? "+" : ""}${mean.toFixed(1)}%` },
    { ok: lo != null && lo > 0, label: "Positive with 95% confidence", value: lo == null ? "too few trades" : `range ${lo.toFixed(1)}% to ${hi >= 0 ? "+" : ""}${hi.toFixed(1)}%` },
    { ok: n > 0 && stress > 0, label: "Still positive if costs were 50% worse", value: `${stress >= 0 ? "+" : ""}${stress.toFixed(1)}%` },
    { ok: n >= 10 && h1 > 0 && h2 > 0, label: "Positive in both the older and the newer half", value: n >= 10 ? `${h1.toFixed(1)}% then ${h2.toFixed(1)}%` : "too few trades" },
    { ok: days >= S.courtMinDays, label: `Seen across at least ${S.courtMinDays} days`, value: `${days} day${days === 1 ? "" : "s"}` },
    { ok: n > 0 && mdd <= S.courtMaxDdPct, label: `Worst drawdown under ${S.courtMaxDdPct}%`, value: `${mdd.toFixed(1)}%` },
  ];
  let verdict;
  if (n < 30) verdict = "COLLECTING";
  else if (hi != null && hi < 0) verdict = "FAILING";                                                       // statistically negative: even the best case of the range loses
  else if (gates.every((g) => g.ok)) verdict = "PROVEN";
  else if (mean > 0) verdict = "PROMISING";
  else verdict = "NOT PROVEN";
  return { name, n, meanR: meanR == null ? null : +meanR.toFixed(2), mean: +mean.toFixed(2), lo: lo == null ? null : +lo.toFixed(2), hi: hi == null ? null : +hi.toFixed(2), stress: +stress.toFixed(2), winRate: n ? Math.round((wins.length / n) * 100) : null,
    pf: gl > 0 ? +(gw / gl).toFixed(2) : gw > 0 ? 99 : 0, h1: +h1.toFixed(2), h2: +h2.toFixed(2), days, posDays, mdd: +mdd.toFixed(1), gates, verdict, passed: gates.filter((g) => g.ok).length };
}
function mpCourt() {
  const S = MP.settings, closed = MP.closed.filter((x) => x.pnlUsd != null), by = {};
  for (const x of closed) { const k = mpEntryType(x); (by[k] || (by[k] = [])).push(x); }
  const overall = courtLane("everything together", closed, S), lanes = Object.entries(by).map(([k, v]) => courtLane(k, v, S)).sort((a, b) => b.mean - a.mean);
  const proven = lanes.filter((l) => l.verdict === "PROVEN").map((l) => l.name), failing = lanes.filter((l) => l.verdict === "FAILING").map((l) => l.name);
  const stage = overall.verdict === "PROVEN" || proven.length ? 2 : 1;
  let text;
  if (stage === 2) text = `${proven.length ? "Proven: " + proven.join(", ") : "The whole bot is proven"}. Next: a small, capped, hand-placed trial. Do not scale anything yet.`;
  else if (overall.verdict === "COLLECTING") text = `Collecting: ${overall.n} of ${S.courtMinTrades} trades. Too early for any verdict. Real money stays locked.`;
  else if (overall.verdict === "FAILING") text = `Not a winner: it averages ${overall.mean}% per trade, and even the best case of the 95% range (${overall.hi}%) loses.${failing.length ? " Failing ways of entering: " + failing.join(", ") + "." : ""} Real money stays locked.`;
  else text = `${overall.verdict === "PROMISING" ? "Promising but not proven" : "Not proven"}: ${overall.passed} of ${overall.gates.length} tests passed after ${overall.n} trades. Keep testing. Real money stays locked.`;
  return { stage, overall, lanes, proven, failing, minTrades: S.courtMinTrades, text, built: Date.now() };
}
let courtCache = null, courtKey = "";
function mpCourtCached() {                                                                                    // the bootstrap is cheap, but the dashboard asks every few seconds
  const key = MP.closed.length + ":" + (MP.closed[0] ? MP.closed[0].closedAt : 0) + ":" + MP.settings.courtMinTrades + ":" + MP.settings.courtMinDays + ":" + MP.settings.courtMaxDdPct;
  if (!courtCache || key !== courtKey || Date.now() - courtCache.built > 120e3) { courtCache = mpCourt(); courtKey = key; }
  return courtCache;
}
function tgCourt() {
  const c = mpCourt(), o = c.overall, mark = (g) => (g.ok ? "✅" : "❌");
  return `🏛️ <b>Strategy Court</b> · stage ${c.stage} of 3\n<b>${o.verdict}</b>: ${c.text.replace(/[<>&]/g, "")}\n\n` + o.gates.map((g) => `${mark(g)} ${g.label}: ${g.value}`).join("\n") +
    (c.lanes.length ? "\n\n<b>By way of entering</b>\n" + c.lanes.map((l) => `${l.verdict === "PROVEN" ? "🟢" : l.verdict === "FAILING" ? "🔴" : "🟡"} ${l.name}: ${l.verdict} · ${l.n} trades · ${l.mean >= 0 ? "+" : ""}${l.mean}% each`).join("\n") : "");
}
/*COURT_END*/


/*DAILY_BEGIN*/
/** Daily return, in plain numbers: what each day made as a % of the account, and what 1% a day would actually require. */
function mpDaily() {
  const S = MP.settings, B = MP.bank, target = S.goalDailyPct;
  const T = MP.closed.filter((x) => x.pnlUsd != null).slice().reverse();                                       // oldest first
  const yearly = +Math.pow(1 + target / 100, 365).toFixed(1);
  if (!T.length || !B) return { target, days: [], nDays: 0, n: 0, yearlyMultiple: yearly, riskPct: S.riskPerTradePct, sizeByRisk: !!S.sizeByRisk };
  const map = {}; for (const x of T) { const d = new Date(x.closedAt).toISOString().slice(0, 10), r = map[d] || (map[d] = { date: d, pnl: 0, n: 0 }); r.pnl += x.pnlUsd; r.n++; }
  let eq = B.start;
  const days = Object.values(map).sort((a, b) => (a.date < b.date ? -1 : 1)).map((d) => { const pct = eq > 0 ? (d.pnl / eq) * 100 : 0, o = { date: d.date, trades: d.n, pnlUsd: +d.pnl.toFixed(2), pct: +pct.toFixed(2) }; eq += d.pnl; return o; });
  const avg = days.reduce((a, d) => a + d.pct, 0) / days.length, perDay = T.length / days.length, rs = T.filter((x) => x.rMult != null).map((x) => x.rMult);
  const avgR = rs.length ? rs.reduce((a, b) => a + b, 0) / rs.length : null, needR = perDay > 0 && S.riskPerTradePct > 0 ? target / (perDay * S.riskPerTradePct) : null;
  return { target, days: days.slice(-14), nDays: days.length, n: T.length, avgPct: +avg.toFixed(2), hit: days.filter((d) => d.pct >= target).length,
    best: Math.max(...days.map((d) => d.pct)), worst: Math.min(...days.map((d) => d.pct)), tradesPerDay: +perDay.toFixed(1), avgR: avgR == null ? null : +avgR.toFixed(2),
    needR: needR == null ? null : +needR.toFixed(2), riskPct: S.riskPerTradePct, sizeByRisk: !!S.sizeByRisk, yearlyMultiple: yearly,
    projectedYearPct: +((Math.pow(1 + avg / 100, 365) - 1) * 100).toFixed(0) };
}
/*DAILY_END*/


/*SIG_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🔬 SIGNAL LAB — what actually works, measured on EVERY qualifying signal (taken, blocked, or skipped by a rule)
// ═══════════════════════════════════════════════════════════════════════
/**
 * The bot only takes a few trades a day (daily stop, cool-offs, position limits), so learning from trades alone is slow.
 * Every time a token passes the momentum test, the signal is recorded with its numbers (buyers, SOL in, rise, size, hour).
 * ~25 minutes later it is replayed on the recorded price path under the current exit rules AND each alternative exit style.
 * Then the lab asks, with honest statistics: which conditions make money after costs, and which exit style is best?
 */
const SIG_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-signals.json") : "";
const SIG = { list: [], seen: new Set() };
try { if (SIG_FILE && nodeFs.existsSync(SIG_FILE)) { SIG.list = JSON.parse(nodeFs.readFileSync(SIG_FILE, "utf8")) || []; for (const x of SIG.list) SIG.seen.add(x.mint); } } catch {}
function sigSave() { if (!SIG_FILE) return; try { const t = SIG_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(SIG.list.slice(-3000))); nodeFs.renameSync(t, SIG_FILE); } catch {} }
regFlush(sigSave); setInterval(sigSave, 5 * 60e3);
function sigLog(ev, fs, mcapUsd) {
  if (!ev || !ev.mint || SIG.seen.has(ev.mint)) return null;
  SIG.seen.add(ev.mint);
  const x = { mint: ev.mint, sym: ev.symbol || "?", at: Date.now(), mcap: Math.round(mcapUsd || 0), buyers: fs.buyers60, share: fs.buyShare60, net: fs.net60, rise: fs.rise2m, hour: new Date(Date.now()).getUTCHours(), took: false, why: null };
  SIG.list.push(x); if (SIG.list.length > 3000) SIG.list.splice(0, SIG.list.length - 3000);
  return x;
}
function sigMark(mint, took, why) { for (let i = SIG.list.length - 1; i >= 0; i--) if (SIG.list[i].mint === mint) { SIG.list[i].took = !!took; SIG.list[i].why = took ? null : why || "not bought"; return; } }
/** Replay a recorded path from the moment of the signal. Same rules as the live manager, incl. staged exits. Net % after every cost. */
function simFrom(pts, i0, R, fixedFrac, mcap0) {
  const slip = R.slippagePct / 100, fee = R.feePct / 100, entry = pts[i0] * (1 + slip), step = PATH_STEP / 60000;
  let left = 1, got = 0, sells = 0, moon = false, mh = 0, li = 0;
  const sell = (frac, px) => { got += (left * frac * (px * (1 - slip) * (1 - fee))) / entry; left -= left * frac; sells++; };
  for (let i = i0 + 1; i < pts.length && left > 1e-9; i++) {
    const px = pts[i], ch = (px / entry - 1) * 100, age = (i - i0) * step;
    if (R.cashOutMcap > 0 && mcap0 && mcap0 * px >= R.cashOutMcap) { sell(1, px); break; }
    if (!moon) {
      if (R.ladderOn) {
        let rung = false;
        while (li < MP_LADDER.length && ch >= MP_LADDER[li][0]) { sell(Math.min(1, MP_LADDER[li][1] / Math.max(1e-9, left)), px); li++; rung = true; }
        if (rung) { if (li >= MP_LADDER.length) { moon = true; mh = px; } continue; }
      } else if (ch >= R.tpPct) { if (R.tp1SellPct >= 100) { sell(1, px); break; } sell(R.tp1SellPct / 100, px); moon = true; mh = px; continue; }
      if (ch <= -R.slPct || age > R.maxHoldMin) { sell(1, px); break; }
    } else {
      mh = Math.max(mh, px); const run = mh / entry;
      const trail = run >= 10 ? Math.min(R.trailPct, R.trailAt10x) : run >= 5 ? Math.min(R.trailPct, R.trailAt5x) : R.trailPct;
      if (px <= mh * (1 - trail / 100) || age > R.moonHoldMin) { sell(1, px); break; }
    }
  }
  if (left > 1e-9) sell(1, pts[pts.length - 1]);
  const cost = (1 + fee) + fixedFrac, back = got - fixedFrac * sells;
  return ((back - cost) / cost) * 100;
}
function sigResolve() {
  const now = Date.now(), pend = SIG.list.filter((x) => x.res === undefined && now - x.at > 25 * 60e3);
  if (!pend.length) return 0;
  const S = MP.settings, sol = (typeof solUsd !== "undefined" && solUsd.v) || 150, fixedFrac = ((S.priorityFeeSol + S.jitoTipSol) * sol) / 40;
  const byMint = new Map(PATHS.list.map((p) => [p.mint, p])); let n = 0;
  for (const x of pend) {
    const p = byMint.get(x.mint);
    if (!p || !p.pts) { if (now - x.at > 90 * 60e3) x.res = null; continue; }               // not recorded (yet): wait; give up after 90 minutes
    const i0 = Math.round((x.at - p.at) / PATH_STEP);
    if (!(i0 >= 1) || i0 > p.pts.length - 4) { x.res = null; continue; }
    const res = {};
    for (const e of EXP_SETS) res[e.id] = +simFrom(p.pts, i0, e.rules ? { ...S, ...e.rules } : S, fixedFrac, p.mcap0).toFixed(2);
    x.res = res; n++;
  }
  if (n) sigSave();
  return n;
}
setInterval(() => { try { sigResolve(); } catch {} }, 60e3);
function sigBoot(vals, iters = 600, alpha = 0.05, seed = 7771) {
  const n = vals.length; if (n < 8) return [null, null];
  let st = seed >>> 0; const rnd = () => (st = (st * 1664525 + 1013904223) >>> 0) / 4294967296, means = new Array(iters);
  for (let i = 0; i < iters; i++) { let sum = 0; for (let j = 0; j < n; j++) sum += vals[(rnd() * n) | 0]; means[i] = sum / n; }
  means.sort((a, b) => a - b); return [means[Math.floor(iters * (alpha / 2))], means[Math.min(iters - 1, Math.floor(iters * (1 - alpha / 2)))]];
}
function sigStat(label, items, key = "mine") {
  const v = items.map((x) => x.res[key]), n = v.length, mean = n ? v.reduce((a, b) => a + b, 0) / n : 0, [lo, hi] = sigBoot(v);
  const half = Math.floor(n / 2), avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0), h1 = avg(v.slice(0, half)), h2 = avg(v.slice(half));
  let verdict = "few";
  if (n >= 30) verdict = hi < 0 ? "bad" : lo > 0 && h1 > 0 && h2 > 0 ? "good" : mean > 0 ? "maybe" : "weak";
  return { label, n, mean: +mean.toFixed(1), lo: lo == null ? null : +lo.toFixed(1), hi: hi == null ? null : +hi.toFixed(1), win: n ? Math.round((v.filter((r) => r > 0).length / n) * 100) : null, h1: +h1.toFixed(1), h2: +h2.toFixed(1), verdict };
}
const SIG_DIMS = [
  { key: "rise", name: "How far it already rose in 2 minutes", edges: [30, 60, 100, 200], fmt: (a, b) => (a == null ? `under ${b}%` : b == null ? `over ${a}%` : `${a} to ${b}%`) },
  { key: "buyers", name: "Different buyers in the last minute", edges: [10, 15, 25, 40], fmt: (a, b) => (a == null ? `under ${b}` : b == null ? `over ${a}` : `${a} to ${b}`) },
  { key: "net", name: "Net SOL bought in the last minute", edges: [3, 6, 12, 25], fmt: (a, b) => (a == null ? `under ${b} SOL` : b == null ? `over ${a} SOL` : `${a} to ${b} SOL`) },
  { key: "share", name: "Share of trades that are buys", edges: [65, 72, 80], fmt: (a, b) => (a == null ? `under ${b}%` : b == null ? `over ${a}%` : `${a} to ${b}%`) },
  { key: "mcap", name: "Market cap when it fired", edges: [6000, 9000, 12000, 20000], fmt: (a, b) => { const k = (n) => `$${n / 1000}K`; return a == null ? `under ${k(b)}` : b == null ? `over ${k(a)}` : `${k(a)} to ${k(b)}`; } },
  { key: "hour", name: "Time of day (UTC; 13:00 is 8 am Central)", edges: [3, 6, 9, 12, 15, 18, 21], fmt: (a, b) => `${String(a ?? 0).padStart(2, "0")} to ${String(b ?? 24).padStart(2, "0")}` },
];
function sigLab() {
  const S = MP.settings, all = SIG.list, res = all.filter((x) => x.res && x.res.mine != null).sort((a, b) => a.at - b.at);
  const blocked = {}; for (const x of all) if (!x.took && x.why) { const k = x.why.replace(/\d+/g, "N").slice(0, 60); blocked[k] = (blocked[k] || 0) + 1; }
  const out = { logged: all.length, resolved: res.length, took: all.filter((x) => x.took).length, waiting: all.filter((x) => x.res === undefined).length,
    blocked: Object.entries(blocked).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([why, n]) => ({ why, n })), overall: null, dims: [], exits: [], testedBins: 0, cap: S.momMaxRise2m };
  if (!res.length) return out;
  out.overall = sigStat("every signal", res);
  let bins = 0;
  for (const d of SIG_DIMS) {
    const e = d.edges, rows = [];
    for (let i = 0; i <= e.length; i++) {
      const a = i === 0 ? null : e[i - 1], b = i === e.length ? null : e[i];
      const items = res.filter((x) => { const v = x[d.key]; return v != null && (a == null || v >= a) && (b == null || v < b); });
      if (items.length) { rows.push({ ...sigStat(d.fmt(a, b), items), a, b }); bins++; }
    }
    out.dims.push({ key: d.key, name: d.name, bins: rows });
  }
  out.testedBins = bins;
  for (const e of EXP_SETS) {                                                                           // same signals, different exits: a PAIRED comparison against your current rules
    const v = res.map((x) => x.res[e.id]).filter((r) => r != null), diffs = res.filter((x) => x.res[e.id] != null).map((x) => x.res[e.id] - x.res.mine);
    const [lo, hi] = e.id === "mine" ? [null, null] : sigBoot(diffs, 600, 0.01);
    out.exits.push({ id: e.id, name: e.name, n: v.length, mean: +(v.reduce((a, b) => a + b, 0) / Math.max(1, v.length)).toFixed(1), winRate: Math.round((v.filter((r) => r > 0).length / Math.max(1, v.length)) * 100),
      diff: e.id === "mine" ? 0 : +(diffs.reduce((a, b) => a + b, 0) / Math.max(1, diffs.length)).toFixed(1), diffLo: lo == null ? null : +lo.toFixed(1), diffHi: hi == null ? null : +hi.toFixed(1) });
  }
  out.exits.sort((a, b) => b.mean - a.mean);
  const capOn = S.momMaxRise2m > 0, past = res.filter((x) => capOn && x.rise > S.momMaxRise2m), within = res.filter((x) => !capOn || x.rise <= S.momMaxRise2m);
  out.cutoff = capOn ? { cap: S.momMaxRise2m, skipped: past.length, skippedMean: past.length ? +(past.reduce((a, x) => a + x.res.mine, 0) / past.length).toFixed(1) : null, keptMean: within.length ? +(within.reduce((a, x) => a + x.res.mine, 0) / within.length).toFixed(1) : null } : null;
  return out;
}
let sigCache = null, sigKey = "";
function sigPublic() { const key = SIG.list.length + ":" + SIG.list.filter((x) => x.res !== undefined).length + ":" + MP.settings.momMaxRise2m; if (!sigCache || key !== sigKey || Date.now() - sigCache.at > 120e3) { sigCache = { at: Date.now(), v: sigLab() }; sigKey = key; } return sigCache.v; }
function tgSignals() {
  const g = sigLab(); if (!g.resolved) return `🔬 <b>Signal Lab</b>\n${g.logged} signals recorded, none judged yet (each is replayed about 25 minutes after it fires).${g.logged ? ` ${g.took} were bought; the rest were blocked or skipped by a rule.` : ""}`;
  const o = g.overall, mark = (v) => (v === "good" ? "🟢" : v === "bad" ? "🔴" : v === "few" ? "⚪" : "🟡");
  const flat = g.dims.flatMap((d) => d.bins.map((b) => ({ ...b, dim: d.name }))).filter((b) => b.n >= 30);
  const best = flat.slice().sort((a, b) => b.mean - a.mean)[0], worst = flat.slice().sort((a, b) => a.mean - b.mean)[0], topExit = g.exits[0];
  return `🔬 <b>Signal Lab</b>: ${g.resolved} signals judged (${g.took} bought, ${g.logged - g.took} not)\n${mark(o.verdict)} <b>Every signal</b>: ${o.mean >= 0 ? "+" : ""}${o.mean}% each after costs, ${o.win}% won${o.lo != null ? ` (95% range ${o.lo}% to ${o.hi >= 0 ? "+" : ""}${o.hi}%)` : ""}\n` +
    (best ? `Best group: ${best.dim.toLowerCase()} ${best.label}: ${best.mean >= 0 ? "+" : ""}${best.mean}% (${best.n})\nWorst group: ${worst.dim.toLowerCase()} ${worst.label}: ${worst.mean}% (${worst.n})\n` : "") +
    (g.cutoff ? `Skipping anything already up over ${g.cutoff.cap}% in 2 min: skipped ${g.cutoff.skipped} signals that averaged ${g.cutoff.skippedMean}%; kept ones average ${g.cutoff.keptMean}%.\n` : "") +
    (topExit ? `Best exit style on these signals: ${topExit.name} (${topExit.mean >= 0 ? "+" : ""}${topExit.mean}% each)${topExit.id !== "mine" && topExit.diffLo != null && topExit.diffLo > 0 ? `, beats yours with 99% confidence` : ""}.` : "") + `\n\nOne list of ${g.testedBins} groups was checked, so a lone "good" can be luck. Only the Court proves anything.`;
}
/*SIG_END*/


/*STORE_BEGIN*/
/** Proof, on screen, of what is being saved: every file, how big, and how long ago it was last written. */
const STORE_INFO = [
  ["masterpeace.json", "Your account: balance, every closed trade, open trades, settings, past runs", () => MP_FILE],
  ["cannon-signals.json", "Signal Lab: every qualifying signal and how it replayed", () => SIG_FILE],
  ["cannon-paths.json", "Recorded price paths (what the Lab replays)", () => PATH_FILE],
  ["cannon-lab.json", "Winner Lab: what winners looked like", () => LAB_FILE],
  ["cannon-experiments.json", "Exit-style experiments", () => EXP_FILE],
  ["cannon-rhythm.json", "Rhythm: launches and graduations by hour", () => RH_FILE],
  ["cannon-top100.json", "Top 100 recorder", () => TOP_FILE],
  ["cannon-ledger.json", "Token ledger: a win/loss row for every token judged", () => LED_FILE],
  ["cannon-playbook.json", "Playbook: patterns and lessons, kept forever", () => PB_FILE],
  ["cannon-gradindex.json", "Graduate Index: every graduate followed for 7 days", () => GX_FILE],
  ["cannon-analyst.json", "Analyst: birth records, proven early buyers, funders", () => (typeof AN_FILE !== "undefined" ? AN_FILE : "")],
];
function storageStatus() {
  const now = Date.now();
  const files = STORE_INFO.map(([name, what, f]) => { const p = f(); let st = null; try { if (p && nodeFs.existsSync(p)) st = nodeFs.statSync(p); } catch {} return { name, what, bytes: st ? st.size : 0, ago: st ? Math.max(0, Math.round((now - st.mtimeMs) / 1000)) : null }; });
  const acct = files[0];
  return { persistent: !!VOLUME_DIR, healthy: !!VOLUME_DIR && acct.ago != null && acct.ago < 180, openTrades: MP.positions.length, closedTrades: MP.closed.length, signals: SIG.list.length, files, savers: FLUSHERS.length };
}
function tgDataHealth() {
  const H = typeof HOLDDIAG !== "undefined" ? HOLDDIAG : null, C = typeof CURVEDIAG !== "undefined" ? CURVEDIAG : null;
  const lines = ["🧪 <b>Data health</b>"];
  if (H) lines.push(`Holders measured: ${H.feed} from the live feed, ${H.rpc} from the chain check · ${H.none} unmeasured, so skipped (never bought blind)`);
  if (H && H.rpcFails) lines.push(`The chain's holder call failed ${H.rpcFails} times${H.rpcErr ? " (last: " + tgEsc(H.rpcErr.slice(0, 80)) + ")" : ""}`);
  if (C) lines.push(`Curves: ${C.std} standard · ${C.nonStd} non-standard, skipped${C.tripped ? " · ⚠️ SAFETY SWITCH ON: the check is paused" : ""}`);
  if (typeof AN !== "undefined") {
    const D = AN.diag, esc = (x) => (typeof tgEsc === "function" ? tgEsc(x) : String(x));
    lines.push(`Analyst: ${D.launches} launches recorded since the restart · ${AN.births.size} being followed · creator wallets checked ${D.deep}${D.deepFail ? " (" + D.deepFail + " reads failed" + (D.deepErr ? ": " + esc(String(D.deepErr).slice(0, 60)) : "") + ")" : ""} · token metadata read ${D.metaOk} of ${D.metaOk + D.metaFail}`);
  }
  return lines.join("\n");
}
function tgSaved() {
  const g = storageStatus(), ago = (s) => (s == null ? "not yet" : s < 90 ? s + " s ago" : Math.round(s / 60) + " min ago"), kb = (b) => (b > 1e6 ? (b / 1e6).toFixed(1) + " MB" : Math.max(1, Math.round(b / 1000)) + " KB");
  if (!g.persistent) return "💾 <b>NOT SAVING.</b> This server has no data folder set, so everything is lost whenever it restarts. Tell me and I will fix it.";
  return `💾 <b>${g.healthy ? "Saving ✅" : "Saving, but the account file looks old ⚠️"}</b>\nOpen trades kept: ${g.openTrades} · closed trades: ${g.closedTrades} · signals: ${g.signals}\n\n` + g.files.map((f) => `${f.ago != null && f.ago < 900 ? "✅" : f.bytes ? "🟡" : "⚪"} ${f.name}: ${f.bytes ? kb(f.bytes) + ", saved " + ago(f.ago) : "nothing yet"}`).join("\n") +
    "\n\n" + tgDataHealth() + "\n\nEverything is also saved the instant the server shuts down, so an upload does not lose anything, and open trades come back after a restart.";
}
/*STORE_END*/


/*LEDGER_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 📒 TOKEN LEDGER — a permanent win/loss row for every token the bot judged
// ═══════════════════════════════════════════════════════════════════════
/**
 * One row per token: what it looked like, what the bot DECIDED (bought, or the exact reason it skipped), and what happened:
 * the real result if the bot traded it, otherwise a replay of "what if you had bought it at that moment under your current rules".
 * So you can see the bot's mistakes in both directions: trades that lost AND winners it let go by.
 */
const LED_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-ledger.json") : "";
const LED = { rows: [], idx: new Map(), notes: new Map(), trades: new Map() };
try { if (LED_FILE && nodeFs.existsSync(LED_FILE)) { LED.rows = JSON.parse(nodeFs.readFileSync(LED_FILE, "utf8")) || []; for (const r of LED.rows) LED.idx.set(r.m, r); } } catch {}
const ledSave = () => { if (!LED_FILE) return; try { const t = LED_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(LED.rows.slice(-25000))); nodeFs.renameSync(t, LED_FILE); } catch {} };
regFlush(ledSave); setInterval(ledSave, 5 * 60e3);
function ledNote(mint, text) { if (!mint) return; LED.notes.set(mint, String(text).slice(0, 90)); if (LED.notes.size > 8000) LED.notes.delete(LED.notes.keys().next().value); }
const ledResult = (r) => (r.pnl != null ? (r.pnl > 0 ? "WIN" : "LOSS") : r.rp != null ? (r.rp > 0 ? "WIN" : "LOSS") : null);
/** A recorded 45-minute path just finished: write the token's row. */
function ledAdd(path) {
  if (!path || !path.mint || LED.idx.has(path.mint) || !path.pts || path.pts.length < 12) return null;
  const snap = LAB.snaps.find((x) => x.mint === path.mint), pts = path.pts, S = MP.settings, sol = (typeof solUsd !== "undefined" && solUsd.v) || 150;
  let rp = null; try { rp = +simFrom(pts, 1, S, ((S.priorityFeeSol + S.jitoTipSol) * sol) / 40, path.mcap0).toFixed(1); } catch {}
  const tr = LED.trades.get(path.mint);
  const row = { m: path.mint, s: snap ? snap.sym : "?", at: path.at, mc: Math.round(path.mcap0 || (snap && snap.mcap) || 0), pr: snap ? snap.progress : null, d: LED.notes.get(path.mint) || null,
    took: tr ? 1 : 0, pnl: tr ? tr.pct : null, why: tr ? tr.why : null, lane: tr ? tr.lane : null, rp, pk: +Math.max(...pts).toFixed(2), en: +pts[pts.length - 1].toFixed(2), gr: path.grad || (snap && snap.grad) ? 1 : 0,
    f: snap ? { t10: snap.top10, dv: snap.devPct, d24: snap.dev24, sc: snap.social, h: snap.hour, nl: snap.nameLen, fb: snap.fBuyers, fn: snap.fNet, t1: snap.top1, sn: snap.snipe, hd: snap.holders, db: snap.devBuy, hs: snap.hsrc } : null };
  row.basis = tr ? "trade" : "replay"; row.res = ledResult(row);
  LED.rows.push(row); LED.idx.set(row.m, row);
  if (LED.rows.length > 25000) { const old = LED.rows.shift(); LED.idx.delete(old.m); }
  return row;
}
/** A trade closed: its real result replaces the "what if" replay in the ledger (or creates the row, for tokens bought after they graduated). */
function ledTrade(c) {
  if (!c || !c.mint) return;
  const t = { pct: c.pnlPct, usd: c.pnlUsd, why: c.why, lane: c.entryType || (c.fast ? "launch shot" : "at 90s") };
  LED.trades.set(c.mint, t); if (LED.trades.size > 3000) LED.trades.delete(LED.trades.keys().next().value);
  let r = LED.idx.get(c.mint);
  if (!r) {
    if (PATHS.live.has(c.mint)) return;                                    // its 45-minute path is still being recorded: the full row (with this result) is written when it ends
    r = { m: c.mint, s: c.symbol || "?", at: c.openedAt || Date.now(), mc: Math.round(c.mcapAtBuy || 0), pr: null, d: "bought · " + t.lane, rp: null, pk: null, en: null, gr: c.postGrad ? 1 : 0, f: null }; LED.rows.push(r); LED.idx.set(r.m, r);
  }
  r.took = 1; r.pnl = t.pct; r.why = t.why; r.lane = t.lane; r.basis = "trade"; r.res = ledResult(r);
}
const ledBucket = (d) => (!d ? "no decision recorded" : /^bought/.test(d) ? "bought" : String(d).replace(/\d+(\.\d+)?/g, "N").replace(/\s+/g, " ").slice(0, 46));
function ledPublic() {
  const rows = LED.rows, n = rows.length;
  const out = { n, wins: 0, losses: 0, bought: { n: 0, wins: 0, losses: 0, net: 0 }, skipped: { n: 0, wins: 0, losses: 0 }, runners3: 0, runners10: 0, graduated: 0, reasons: [], recent: [] };
  const by = {};
  for (const r of rows) {
    if (r.res === "WIN") out.wins++; else if (r.res === "LOSS") out.losses++;
    if (r.took) { out.bought.n++; if (r.res === "WIN") out.bought.wins++; else if (r.res === "LOSS") out.bought.losses++; out.bought.net += r.pnl || 0; }
    else { out.skipped.n++; if (r.res === "WIN") out.skipped.wins++; else if (r.res === "LOSS") out.skipped.losses++; }
    if (r.pk >= 3) out.runners3++; if (r.pk >= 10) out.runners10++; if (r.gr) out.graduated++;
    const k = ledBucket(r.d), b = by[k] || (by[k] = { why: k, n: 0, wins: 0, runners: 0 }); b.n++; if (r.res === "WIN") b.wins++; if (r.pk >= 3) b.runners++;
  }
  out.winPct = n ? Math.round((out.wins / Math.max(1, out.wins + out.losses)) * 100) : null;
  out.bought.net = +(out.bought.net / Math.max(1, out.bought.n)).toFixed(1);                                    // average net % per trade
  out.skipped.winPct = out.skipped.n ? Math.round((out.skipped.wins / out.skipped.n) * 100) : null;
  out.reasons = Object.values(by).sort((a, b) => b.n - a.n).slice(0, 8).map((b) => ({ ...b, winPct: Math.round((b.wins / b.n) * 100) }));
  out.recent = rows.slice(-25).reverse().map((r) => ({ m: r.m, s: r.s, at: r.at, d: r.d, took: r.took, res: r.res, basis: r.basis, pnl: r.pnl, rp: r.rp, pk: r.pk, gr: r.gr }));
  return out;
}
/** The whole ledger as a spreadsheet (opens in Numbers / Excel / Sheets). */
function ledCsv() {
  const q = (v) => (v == null ? "" : /[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
  const head = ["mint", "symbol", "found_utc", "mcap_when_found", "bonded_pct", "decision", "bought", "result", "result_based_on", "net_pct_if_traded", "exit_reason", "lane", "replay_net_pct_if_bought", "peak_x", "end_x_45min", "graduated",
    "top10_pct", "creator_pct", "creator_launches_today", "social_links", "hour_utc", "name_len", "buyers_90s", "net_sol_90s", "top1_pct", "sniper_pct", "holders", "creator_first_buy_sol", "holder_source"];
  const lines = [head.join(",")];
  for (const r of LED.rows) { const f = r.f || {};
    lines.push([r.m, r.s, new Date(r.at).toISOString(), r.mc, r.pr, r.d, r.took ? "yes" : "no", r.res, r.basis, r.pnl, r.why, r.lane, r.rp, r.pk, r.en, r.gr ? "yes" : "no", f.t10, f.dv, f.d24, f.sc, f.h, f.nl, f.fb, f.fn, f.t1, f.sn, f.hd, f.db, f.hs].map(q).join(",")); }
  return lines.join("\n");
}
function tgLedger() {
  const g = ledPublic(); if (!g.n) return "📒 <b>Token ledger</b>: nothing in it yet. Each token is written down about 45 minutes after the bot judges it.";
  const mark = (r) => (r.res === "WIN" ? "🟢" : r.res === "LOSS" ? "🔴" : "⚪");
  return `📒 <b>Token ledger</b>: ${g.n} tokens judged\n🟢 ${g.wins} wins · 🔴 ${g.losses} losses (${g.winPct}% by the bot's own rules)\n` +
    `Bought: ${g.bought.n} (${g.bought.wins} won, ${g.bought.losses} lost, average ${g.bought.net >= 0 ? "+" : ""}${g.bought.net}% a trade)\n` +
    `Skipped: ${g.skipped.n}, of which <b>${g.skipped.wins}</b> would have won (${g.skipped.winPct}%)\nRunners: ${g.runners3} reached 3x · ${g.runners10} reached 10x\n\n` +
    g.recent.slice(0, 10).map((r) => `${mark(r)} ${r.s} · ${r.took ? "bought" : "skipped"}${r.pk ? " · peak " + r.pk + "x" : ""}`).join("\n");
}
/*LEDGER_END*/


/*PLAYBOOK_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 📘 PLAYBOOK — what was found, what held up, what failed. Kept forever.
// ═══════════════════════════════════════════════════════════════════════
/**
 * A pattern is only KEPT if it still works on signals that arrived AFTER it was found. That one rule is what separates a real pattern
 * from luck in a list of dozens of groups. Kept patterns are never deleted; if one stops working it is marked RETIRED and stays in the
 * book with its history. "Avoid" patterns that are confirmed are skipped automatically; confirmed winners can optionally be required (playbookStrict).
 */
const PB_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-playbook.json") : "";
const PB = { items: [] }, PB_MIN = 30;
try { if (PB_FILE && nodeFs.existsSync(PB_FILE)) PB.items = JSON.parse(nodeFs.readFileSync(PB_FILE, "utf8")) || []; } catch {}
const pbSave = () => { if (!PB_FILE) return; try { const t = PB_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(PB.items)); nodeFs.renameSync(t, PB_FILE); } catch {} };
regFlush(pbSave); setInterval(pbSave, 5 * 60e3);
const pbFind = (id) => PB.items.find((x) => x.id === id);
function pbLog(it, note) { it.log = it.log || []; it.log.push({ at: Date.now(), note }); if (it.log.length > 40) it.log.shift(); }
const PB_SEEDS = [
  ["lesson:launch-shot", "Buying in the first seconds (Launch Shot) lost", "87 trades, 75 of them lost, average −10.7% a trade, −$33.55 in the first run. Retired and switched off."],
  ["lesson:costs", "Costs are the enemy", "Fees, tips and slippage take about 9 to 10% of every round trip, and tiny bets lose an even bigger share to fixed costs. An entry method needs an average edge above roughly 10% a trade just to break even."],
  ["lesson:creator-dumps", "Creators dump, fast", "50 of 110 trades in the first run ended with the creator selling (−$21.72). The bot now leaves the moment it sees the creator sell, instead of checking every 30 seconds."],
  ["lesson:slow-stops", "Slow stop-losses cost the most", "All 17 stop-loss exits in the first run were losses (−$32.30 total) because the bot only looked every 10 seconds. Exits now fire from the live trade feed the instant a line is crossed."],
  ["lesson:chasing", "Chasing a spike", "A token already up 276% in 2 minutes was bought and stopped out inside a minute. The bot now skips anything up more than 100% in 2 minutes, and the Signal Lab keeps checking whether that cap is right."],
  ["lesson:no-edge-yet", "No edge has shown up yet", "Across 180+ paper trades in the runs so far (110, 55 and 17 in the three reported, plus a smaller one), no way of entering has had a positive average after costs. Nothing is proven, and real money stays locked until the Strategy Court says otherwise."],
  ["lesson:restarts", "Open trades used to vanish on a restart", "Before this fix, an upload restarted the server and any open trade disappeared with its money. Open trades are now saved and restored, and everything is flushed to disk on shutdown."],
  ["lesson:impossible-prices", "CORRECTED: OBELIS's −61% was real, not a bad price", "Oct 30: OBELIS lost 61% on a −15% stop. It was first called impossible, but that check used the wrong SOL price. Corrected Oct 31 from the exported data: it was bought at 49% bonded, where the curve's floor allowed a fall of about 62% with costs, and it fell all the way to the floor (a rug). Lesson: the higher the % bonded at the buy, the bigger the worst case, and a stop does not cap it. All 36 curve trades checked: none lost more than the curve allows."],
  ["lesson:restart-wiped-stop", "A restart used to cancel the daily stop", "Oct 30: the daily stop (3%) was active until 7 PM, but an upload restarted the server at about 6:50 PM and a leftover startup rule wiped the stop, so the bot bought 2 minutes later. Fixed: a daily stop that is still running now survives restarts. Only an expired one is cleared."],
  ["lesson:one-bad-print", "Pool tokens can lose nearly everything in seconds", "4 of the first 44 graduate trades crashed 67% to 98% straight through a −12% stop: liquidity pulled or a dump between two price checks. These were real losses, not bad data. A one-step drop of 35% or more is still re-checked 1.5 seconds later before acting, and graduates are now sized as if they could lose everything."],
  ["lesson:holders-never-checked", "The holder limits were never applied", "Oct 31: the top-10 and top-1 wallet limits never ran. The chain call behind them failed silently on every token, and the filter read \"unknown\" as a pass: 0 of 80 trades and 0 of 4,158 judged launches had holder data. Fixed: holders are now counted exactly from the live trade feed (plus snipers in the first 2 seconds and the creator's first buy), and a token whose holders cannot be measured is skipped, never bought blind."],
  ["lesson:non-standard-curves", "1 in 5 tokens did not follow the standard curve", "Oct 31: about 19% of recorded tokens had a market cap that cannot match their curve (one showed $1 at 84% bonded). The bot's curve math does not apply to them, so they are now skipped and kept out of the Lab, the paths and the ledger. If most launches ever look non-standard, a safety switch pauses the check instead of skipping everything."],
  ["lesson:size-by-worst-case", "A stop does not limit a rug: size by the worst case", "Oct 31, from the first 80 trades: 9 crash trades (lost 41–98% each) made the whole loss (−$330 of −$325); the other 71 trades made +$5. Re-sized by their worst case, the same trades would have lost $96–$226 instead. Now each trade is sized so its worst case (the curve floor, or a full loss on a pool token) costs about 1% of the money."],
];
function pbSeed() {
  for (const [id, title, text] of PB_SEEDS) {
    const old = pbFind(id);
    if (!old) PB.items.push({ id, kind: "lesson", status: "learned", title, text, at: Date.now(), log: [] });
    else if (old.kind === "lesson" && (old.title !== title || old.text !== text)) {     // a lesson that was wrong gets corrected in place, and the old title stays in its history
      (old.log || (old.log = [])).push({ at: Date.now(), note: "corrected; it used to say: " + String(old.title).slice(0, 120) });
      old.title = title; old.text = text;
    }
  }
}
function pbLive(it, res, since) {
  const items = res.filter((x) => x.at > since && x[it.dim] != null && (it.a == null || x[it.dim] >= it.a) && (it.b == null || x[it.dim] < it.b));
  const st = sigStat("live", items);
  return { n: st.n, mean: st.mean, lo: st.lo, hi: st.hi };
}
function pbUpdate() {
  pbSeed();
  const lab = sigLab(), res = SIG.list.filter((x) => x.res && x.res.mine != null).sort((a, b) => a.at - b.at), latest = res.length ? res[res.length - 1].at : Date.now();
  const total = res.length, overall = lab.overall ? lab.overall.mean : 0;
  for (const d of lab.dims) for (const b of d.bins) {                                         // 1) new candidates from the Signal Lab
    if (b.n < 30 || (b.verdict !== "good" && b.verdict !== "bad")) continue;
    // a pattern must TELL SIGNALS APART: a group that holds most signals, or is no different from the average, is "everything", not a pattern.
    // (Otherwise, when the whole bot is losing, almost every group looks "bad", and confirming them would switch off all trading.)
    if (b.n > total * 0.6) continue;
    if (b.verdict === "good" ? b.mean - overall < 3 : overall - b.mean < 3) continue;
    const id = `sig:${d.key}:${b.label}`; if (pbFind(id)) continue;
    const it = { id, kind: b.verdict === "good" ? "good" : "avoid", status: "testing", title: `${d.name}: ${b.label}`, dim: d.key, a: b.a, b: b.b, since: latest,
      found: { at: Date.now(), n: b.n, mean: b.mean, lo: b.lo, hi: b.hi, h1: b.h1, h2: b.h2 }, live: null, log: [] };
    pbLog(it, `Found on ${b.n} signals: ${b.mean >= 0 ? "+" : ""}${b.mean}% each (95% range ${b.lo}% to ${b.hi}%). Now being tested on NEW signals only.`);
    PB.items.push(it); mpEvent(`Playbook: new ${it.kind === "good" ? "candidate pattern" : "pattern to avoid"}: ${it.title}. It must hold up on the next ${PB_MIN} new signals before it is kept.`);
  }
  for (const it of PB.items) {                                                                // 2) judge them on data that arrived AFTER they were found
    if (!it.dim || (it.status !== "testing" && it.status !== "validated")) continue;
    const live = pbLive(it, res, it.status === "validated" ? it.validatedAt : it.since); it.live = live;
    if (it.status === "testing" && live.n >= PB_MIN) {
      const holds = it.kind === "good" ? live.mean > 0 && live.mean >= it.found.mean * 0.5 : live.mean < 0 && live.mean <= it.found.mean * 0.5, weak = it.kind === "good" ? live.mean <= 0 : live.mean >= 0;
      if (holds) { it.status = "validated"; it.validatedAt = latest; pbLog(it, `HELD UP on ${live.n} new signals (${live.mean >= 0 ? "+" : ""}${live.mean}% each). Kept.`); mpEvent(`Playbook: KEPT: ${it.kind === "good" ? "winning pattern" : "pattern to avoid"} confirmed on new data: ${it.title}`); }
      else if (weak || live.n >= PB_MIN * 2) { it.status = "retired"; pbLog(it, `Did NOT hold up on ${live.n} new signals (${live.mean >= 0 ? "+" : ""}${live.mean}% each). It was luck. Retired.`); mpEvent(`Playbook: a ${it.kind === "good" ? "winning" : "losing"} pattern did not hold up on new data and was retired: ${it.title}`); }
    } else if (it.status === "validated" && live.n >= PB_MIN * 2) {
      if (it.kind === "good" ? live.mean <= 0 : live.mean >= 0) { it.status = "retired"; pbLog(it, `Stopped working: ${live.mean}% each over the last ${live.n} signals. Retired.`); mpEvent(`Playbook: a kept pattern stopped working and was retired: ${it.title}`); }
    }
  }
  const court = mpCourtCached();                                                              // 3) ways of entering, as judged by the Court
  for (const l of court.lanes) {
    const id = `lane:${l.name}`; let it = pbFind(id);
    const want = l.verdict === "PROVEN" ? "validated" : l.verdict === "FAILING" ? "retired" : null; if (!want) continue;
    if (!it) { it = { id, kind: "lane", status: null, title: "", text: "", at: Date.now(), log: [] }; PB.items.push(it); }
    it.found = { at: Date.now(), n: l.n, mean: l.mean, lo: l.lo, hi: l.hi };
    if (it.status !== want) { it.status = want; it.title = want === "validated" ? `Proven way of entering: ${l.name}` : `Retired: ${l.name} failed the Court`;
      it.text = `${l.n} trades, ${l.mean >= 0 ? "+" : ""}${l.mean}% each after costs (95% range ${l.lo}% to ${l.hi}%).`; pbLog(it, it.text); mpEvent(`Playbook: ${it.title}`); }
  }
}
/** Called for every momentum signal: returns a reason to skip, or null. */
function pbCheck(fs, mcapUsd) {
  const S = MP.settings; if (!S.playbookOn) return null;
  const val = { rise: fs.rise2m, buyers: fs.buyers60, net: fs.net60, share: fs.buyShare60, mcap: mcapUsd, hour: new Date(Date.now()).getUTCHours() };
  const inBin = (it) => val[it.dim] != null && (it.a == null || val[it.dim] >= it.a) && (it.b == null || val[it.dim] < it.b);
  for (const it of PB.items) if (it.status === "validated" && it.kind === "avoid" && it.dim && inBin(it)) return `playbook: confirmed to avoid (${it.title})`;
  if (S.playbookStrict) { const goods = PB.items.filter((it) => it.status === "validated" && it.kind === "good" && it.dim); if (goods.length && !goods.some(inBin)) return "playbook: not inside any confirmed winning pattern"; }
  return null;
}
function pbPublic() {
  pbSeed();                                                                // the lessons are always there, even in the first seconds after a restart
  const grp = (f) => PB.items.filter(f).map((it) => ({ id: it.id, kind: it.kind, status: it.status, title: it.title, text: it.text || null, found: it.found || null, live: it.live || null, need: PB_MIN, at: it.at || (it.found && it.found.at) || null, last: (it.log && it.log.length) ? it.log[it.log.length - 1] : null }));
  return { kept: grp((x) => x.status === "validated" && x.kind !== "avoid"), avoid: grp((x) => x.status === "validated" && x.kind === "avoid"), testing: grp((x) => x.status === "testing"), retired: grp((x) => x.status === "retired"), lessons: grp((x) => x.kind === "lesson"), need: PB_MIN };
}
function tgPlaybook() {
  const p = pbPublic(), L = (t) => t.replace(/[<>&]/g, "");
  return `📘 <b>Playbook</b> (kept forever)\n✅ Confirmed winners: ${p.kept.length}${p.kept.length ? "\n" + p.kept.map((x) => "• " + L(x.title)).join("\n") : ""}\n🚫 Confirmed to avoid: ${p.avoid.length}${p.avoid.length ? "\n" + p.avoid.map((x) => "• " + L(x.title)).join("\n") : ""}\n` +
    `🧪 Being tested on new data: ${p.testing.length}${p.testing.length ? "\n" + p.testing.slice(0, 6).map((x) => `• ${L(x.title)} (${x.live ? x.live.n : 0} of ${p.need} new signals)`).join("\n") : ""}\n🗑 Retired (turned out to be luck or stopped working): ${p.retired.length}\n\n` +
    `📕 Lessons so far:\n` + p.lessons.slice(0, 12).map((x) => "• " + L(x.title)).join("\n") + `\n\nA pattern is only kept if it still works on signals that arrived after it was found.`;
}
setInterval(() => { try { pbUpdate(); } catch (e) { log("error", `playbook: ${e.message}`); } }, 10 * 60e3);
setTimeout(() => { try { pbSeed(); pbUpdate(); } catch {} }, 25000);
/*PLAYBOOK_END*/


/*GX_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🎓 GRADUATE INDEX — hold a flat $10 of EVERY graduate for 7 days, and measure what really happens (rare 10x runners included)
// ═══════════════════════════════════════════════════════════════════════
/**
 * The honest baseline. Most graduated tokens fade, a few run 10x to 100x. Active trading has to beat "just hold one of everything",
 * and this is also the dataset a long-hold idea needs. The rules are fixed IN ADVANCE: no conclusion until gxMinTokens tokens AND gxMinRunners
 * SUSTAINED 10x runners (a one-reading spike does not count: the level must show up on two readings in a row). A runner is reported
 * apart from the rest so one rare token cannot hide, or fake, what the strategy did on everything else.
 */
const GX_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-gradindex.json") : "";
const GX = { list: [], by: new Map(), pending: new Map() }, GX_BET = 10, GX_COST = 0.02, GX_DAYS = 7, GX_MIN_LIQ = 5000;
try { if (GX_FILE && nodeFs.existsSync(GX_FILE)) { GX.list = JSON.parse(nodeFs.readFileSync(GX_FILE, "utf8")) || []; for (const r of GX.list) GX.by.set(r.m, r); } } catch {}
const gxSave = () => { if (!GX_FILE) return; try { const t = GX_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(GX.list.slice(-6000))); nodeFs.renameSync(t, GX_FILE); } catch {} };
regFlush(gxSave); setInterval(gxSave, 5 * 60e3);
/** A token just graduated: wait for its trading pool to show up, then start tracking it. */
function gxPending(mint) { if (!mint || GX.by.has(mint) || GX.pending.has(mint)) return; GX.pending.set(mint, { at: Date.now(), nx: Date.now() + 20e3 }); if (GX.pending.size > 400) GX.pending.delete(GX.pending.keys().next().value); }
function gxAdd(mint, d, now = Date.now()) {
  if (GX.by.has(mint) || !(d && d.price > 0) || d.liq < GX_MIN_LIQ) return null;
  const r = { m: mint, s: symOf(mint), t0: now, p0: d.price, mc0: Math.round(d.mcap), l0: Math.round(d.liq), pk: d.price, cf: d.price, last: d.price, lastAt: now, mcL: Math.round(d.mcap), lqL: Math.round(d.liq), n: 1, nx: now + 10 * 60e3, miss: 0, done: false, sr: [[0, 1]], dead: false, h: new Date(now).getUTCHours() };
  GX.list.push(r); GX.by.set(mint, r); if (GX.list.length > 6000) { const o = GX.list.shift(); GX.by.delete(o.m); }
  return r;
}
function gxUpdate(r, d, now = Date.now()) {
  if (!(d && d.price > 0)) { r.miss++; r.nx = now + 30 * 60e3; if (r.miss >= 8) r.dead = true; return; }
  r.miss = 0; const prev = r.last; r.last = d.price; r.lastAt = now; r.mcL = Math.round(d.mcap); r.lqL = Math.round(d.liq); r.n++;
  r.pk = Math.max(r.pk, d.price); r.cf = Math.max(r.cf, Math.min(prev, d.price));                       // cf = highest level seen on TWO readings in a row
  const age = now - r.t0; r.nx = now + (age < 6 * 3600e3 ? 10 * 60e3 : age < 48 * 3600e3 ? 3600e3 : 6 * 3600e3);
  (r.sr || (r.sr = [[0, 1]])).push([Math.round(age / 60000), +(d.price / r.p0).toPrecision(4)]); if (r.sr.length > 200) r.sr.splice(1, r.sr.length - 200);   // the price path, for testing hold and dip-buy over days
  if (r.last / r.p0 < 0.01) r.dead = true;
  if (age >= GX_DAYS * 86400e3) r.done = true;
}
async function gxTick(now = Date.now()) {
  const pend = [...GX.pending.entries()].filter(([, t]) => now >= t.nx).slice(0, 30);                    // 1) new graduates: wait for the pool
  if (pend.length) {
    const info = await dexBatch(pend.map(([m]) => m));
    for (const [m, t] of pend) { const d = info.get(m); if (d && d.price > 0 && d.liq >= GX_MIN_LIQ) { gxAdd(m, d, now); GX.pending.delete(m); } else if (now - t.at > 20 * 60e3) GX.pending.delete(m); else t.nx = now + 60e3; }   // thin pool: keep trying, many fill in a minute or two later
  }
  const due = GX.list.filter((r) => !r.done && now >= r.nx).slice(0, 150);                               // 2) follow the ones already tracked
  for (let i = 0; i < due.length; i += 30) {
    const chunk = due.slice(i, i + 30), info = await dexBatch(chunk.map((r) => r.m));
    for (const r of chunk) gxUpdate(r, info.get(r.m), now);
  }
}
setInterval(() => { gxTick().catch(() => {}); }, 60e3);
const gxVal = (r) => GX_BET * (r.last / r.p0) * (1 - GX_COST), gxInv = GX_BET * (1 + GX_COST);
function gxPublic(now = Date.now()) {
  const S = MP.settings, rows = GX.list, n = rows.length;
  const base = { n, active: rows.filter((r) => !r.done && !r.dead).length, minTokens: S.gxMinTokens, minRunners: S.gxMinRunners, bet: GX_BET, cost: GX_COST * 100, days: GX_DAYS };
  if (!n) return { ...base, runners10: 0, concluded: false, runners: [], dims: [], protocol: gxProtocol(0, 0) };
  const inv = n * gxInv, val = rows.reduce((a, r) => a + gxVal(r), 0), mult = rows.map((r) => r.last / r.p0).sort((a, b) => a - b);
  const runners = rows.filter((r) => r.cf / r.p0 >= 10).sort((a, b) => b.cf / b.p0 - a.cf / a.p0);
  const rest = rows.filter((r) => r.cf / r.p0 < 10), restInv = rest.length * gxInv, restVal = rest.reduce((a, r) => a + gxVal(r), 0);
  const retOf = (arr) => { const i = arr.length * gxInv; return i ? ((arr.reduce((a, r) => a + gxVal(r), 0) - i) / i) * 100 : null; };
  const net = rows.map((r) => (gxVal(r) - gxInv) / gxInv * 100), [lo, hi] = sigBoot(net, 600, 0.05, 4242);
  const DIMS = [
    { key: "mc0", name: "Market cap when found", edges: [75000, 100000, 150000], fmt: (a, b) => { const k = (v) => `$${v / 1000}K`; return a == null ? `under ${k(b)}` : b == null ? `over ${k(a)}` : `${k(a)} to ${k(b)}`; } },
    { key: "l0", name: "Pool liquidity when found", edges: [15000, 30000, 60000], fmt: (a, b) => { const k = (v) => `$${v / 1000}K`; return a == null ? `under ${k(b)}` : b == null ? `over ${k(a)}` : `${k(a)} to ${k(b)}`; } },
  ];
  const dims = DIMS.map((d) => ({ key: d.key, name: d.name, bins: Array.from({ length: d.edges.length + 1 }, (_, i) => {
    const a = i === 0 ? null : d.edges[i - 1], b = i === d.edges.length ? null : d.edges[i];
    const items = rows.filter((r) => (a == null || r[d.key] >= a) && (b == null || r[d.key] < b)); if (!items.length) return null;
    const v = items.map((r) => ((gxVal(r) - gxInv) / gxInv) * 100), [l, h] = sigBoot(v, 500, 0.05, 99), m = v.reduce((x, y) => x + y, 0) / v.length;
    const med = items.map((r) => r.last / r.p0).sort((x, y) => x - y)[Math.floor(items.length / 2)];
    return { label: d.fmt(a, b), n: items.length, ret: +m.toFixed(1), lo: l == null ? null : +l.toFixed(1), hi: h == null ? null : +h.toFixed(1), median: +med.toFixed(2), runners: items.filter((r) => r.cf / r.p0 >= 10).length, verdict: items.length < 30 ? "few" : h < 0 ? "bad" : l > 0 ? "good" : "maybe" };
  }).filter(Boolean) }));
  return { ...base, tracked: n, invested: +inv.toFixed(2), value: +val.toFixed(2), ret: +(((val - inv) / inv) * 100).toFixed(1), lo: lo == null ? null : +lo.toFixed(1), hi: hi == null ? null : +hi.toFixed(1),
    median: +mult[Math.floor(n / 2)].toFixed(2), pct2x: Math.round((mult.filter((x) => x >= 2).length / n) * 100), pct5x: Math.round((mult.filter((x) => x >= 5).length / n) * 100), pctHalf: Math.round((mult.filter((x) => x < 0.5).length / n) * 100),
    runners10: runners.length, retWithoutRunners: retOf(rest) == null ? null : +retOf(rest).toFixed(1), dead: rows.filter((r) => r.dead).length,
    runners: runners.slice(0, 5).map((r) => ({ m: r.m, s: r.s, mc0: r.mc0, l0: r.l0, peakX: +(r.cf / r.p0).toFixed(1), nowX: +(r.last / r.p0).toFixed(1), plusUsd: +(gxVal(r) - gxInv).toFixed(2), still: !r.done && !r.dead, mcL: r.mcL, lqL: r.lqL })),
    daysTracked: +((now - Math.min(...rows.map((r) => r.t0))) / 86400e3).toFixed(1), concluded: n >= S.gxMinTokens && runners.length >= S.gxMinRunners, protocol: gxProtocol(n, runners.length), dims };
}
function gxProtocol(n, r) {
  const S = MP.settings, c = n >= S.gxMinTokens && r >= S.gxMinRunners;
  return c ? "Enough data: the sample the plan required (set in advance) has been reached, so the result can now be read."
    : `Fixed in advance: no conclusion until ${S.gxMinTokens} graduates are tracked AND ${S.gxMinRunners} of them are sustained 10x runners. So far ${n} of ${S.gxMinTokens} tokens and ${r} of ${S.gxMinRunners} runners.`;
}
function tgIndex() {
  const g = gxPublic(); if (!g.n) return "🎓 <b>Graduate Index</b>: no graduates tracked yet. Each one is added when its trading pool appears, then followed for 7 days.";
  const m = (x) => (x >= 0 ? "+" : "−") + Math.abs(x) + "%";
  return `🎓 <b>Graduate Index</b>: $${g.bet} flat in EVERY graduate, ${g.cost}% cost each way\n${g.tracked} tracked (${g.active} still being followed) over ${g.daysTracked} days\nThe whole line: <b>${m(g.ret)}</b>${g.lo != null ? ` (95% range ${m(g.lo)} to ${m(g.hi)})` : ""} · without the runners: ${g.retWithoutRunners == null ? "n/a" : m(g.retWithoutRunners)}\n` +
    `Median token is now ${g.median}x · ${g.pct2x}% reached 2x · ${g.pct5x}% reached 5x · ${g.pctHalf}% lost half or more\n🏆 Sustained 10x runners: ${g.runners10}` + (g.runners.length ? "\n" + g.runners.slice(0, 3).map((r) => `• ${r.s}: found at $${Math.round(r.mc0 / 1000)}K, peak ${r.peakX}x, now ${r.nowX}x (${r.plusUsd >= 0 ? "+" : "−"}$${Math.abs(r.plusUsd)})`).join("\n") : "") + `\n\n${g.protocol}`;
}
/*GX_END*/


/*PLAN_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 🗺️ GAME PLAN — fixed in advance, so nobody (including me) can move the goalposts after seeing the results
// ═══════════════════════════════════════════════════════════════════════
function mpPlan(now = Date.now()) {
  const S = MP.settings, start = MP.startedAt || now, DAYS = 14, day = Math.floor((now - start) / 86400e3) + 1;
  const court = mpCourtCached(), sig = sigPublic(), led = ledPublic(), gx = gxPublic(now), pb = pbPublic();
  const gate = (label, have, need) => ({ label, have, need, value: `${Number(have).toLocaleString()} of ${Number(need).toLocaleString()}`, ok: have >= need });
  const gates = [gate("Days of data", Math.min(day, DAYS), DAYS), gate("Trades closed (Strategy Court)", court.overall.n, S.courtMinTrades), gate("Signals judged (Signal Lab)", sig.resolved || 0, 150),
    gate("Tokens in the ledger", led.n, 2000), gate("Graduates tracked (Index)", gx.n || 0, S.gxMinTokens), gate("Sustained 10x runners (Index)", gx.runners10 || 0, S.gxMinRunners)];
  const done = gates.every((g) => g.ok) || day > DAYS, proven = court.proven.length > 0 || court.overall.verdict === "PROVEN", kept = pb.kept.length;
  let verdict = null, next;
  if (!done) next = `Keep collecting. Day ${Math.min(day, DAYS)} of ${DAYS}. Do not reset and do not tune. Look at the Court and the Signal Lab around day 7 and again on day ${DAYS}.`;
  else if (proven || kept) { verdict = "A"; next = "Something held up on new data. Run ONLY that, on paper, for 7 more days. If it still holds, the next step is a hand-placed trial capped at $100. Nothing is scaled."; }
  else if (gx.concluded && gx.lo != null && gx.lo > 0) { verdict = "B"; next = "Holding every graduate beat its costs with 95% confidence. Next: design a hold strategy around it and test that on paper first."; }
  else { verdict = "C"; next = "Nothing beat its costs. Real money stays locked. The honest options: keep collecting for another 14 days, or put the effort into the scanner products, which earn without trading."; }
  return { phase: done ? 2 : 1, day: Math.min(day, DAYS), days: DAYS, startedAt: start, endsAt: start + DAYS * 86400e3, gates, done, verdict, next,
    rules: ["No resets and no tuning for the 14 days, except bug fixes. Every change is written in the Playbook with its date.", "Nothing is called winning until the Strategy Court says PROVEN on closed trades, after every cost.",
      "A pattern is only kept if it still works on signals that arrived AFTER it was found (the Playbook checks this).", "Real money stays locked. Stage 2 is a hand-placed trial capped at $100, and only after PROVEN.", "The Graduate Index has its sample size fixed in advance (see its panel)."] };
}
function tgPlan() {
  const p = mpPlan();
  return `🗺️ <b>Game plan</b> · phase ${p.phase} of 2 · day ${p.day} of ${p.days}\n` + p.gates.map((g) => `${g.ok ? "✅" : "⬜"} ${g.label}: ${g.value}`).join("\n") +
    `\n\n<b>${p.verdict ? "Verdict " + p.verdict : "Next"}:</b> ${p.next.replace(/[<>&]/g, "")}\n\nRules:\n` + p.rules.map((r) => "• " + r.replace(/[<>&]/g, "")).join("\n");
}
/*PLAN_END*/


/*EXPORT_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 📤 EXPORT — the raw data as spreadsheets, so patterns can be searched on the full record, not on a summary
// ═══════════════════════════════════════════════════════════════════════
const csvQ = (v) => (v == null ? "" : /[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
/** Every judged launch: what it looked like at 90 seconds and how it ended. (The same file the dashboard's download button gives.) */
function launchCsv() {
  const pm = new Map(PATHS.list.map((p) => [p.mint, p]));
  const head = ["mint", "symbol", "name", "launched_utc", "bonded_pct_90s", "mcap_90s", "top10_pct", "top1_pct", "creator_pct", "creator_launches_today",
    "creator_past_graduates", "social_links", "hour_utc", "name_len", "emoji", "graduated", "trended", "peak_mcap", "winner", "lab_score_x", "path_peak_x", "path_low_x", "path_minutes",
    "sniper_pct", "snipers", "holders", "creator_first_buy_sol", "biggest_buy_sol", "holder_source", "holder_coverage"];
  const lines = [head.join(",")];
  for (const s of LAB.snaps) {
    const p = pm.get(s.mint), pts = p ? p.pts : null;
    lines.push([s.mint, s.sym, s.name, new Date(s.at).toISOString(), s.progress, s.mcap, s.top10, s.top1, s.devPct, s.dev24, s.devG, s.social, s.hour, s.nameLen, s.emoji,
      s.grad ? 1 : 0, s.trended ? 1 : 0, s.peak, s.win ? 1 : s.done ? 0 : "", labLift(s).toFixed(2), pts ? Math.max(...pts).toFixed(3) : "", pts ? Math.min(...pts).toFixed(3) : "",
      pts ? ((pts.length - 1) * PATH_STEP / 60000).toFixed(1) : "", s.snipe, s.snipers, s.holders, s.devBuy, s.maxBuy, s.hsrc, s.hcov].map(csvQ).join(","));
  }
  return lines.join("\n");
}
/** The full recorded price path of each token (a multiple of its price at the 90-second mark, every 15 seconds for up to 45 minutes). Join on mint. */
function pathsCsv() {
  const lines = ["mint,started_utc,mcap_at_start,graduated,minutes,step_seconds,points_x_of_start"];
  for (const p of PATHS.list) if (p && p.pts && p.pts.length > 1) lines.push([p.mint, new Date(p.at).toISOString(), Math.round(p.mcap0 || 0), p.grad ? 1 : 0, ((p.pts.length - 1) * PATH_STEP / 60000).toFixed(1), PATH_STEP / 1000, p.pts.join(" ")].map(csvQ).join(","));
  return lines.join("\n");
}
/** Every momentum signal, whether or not the bot bought, with how each exit style would have done (net % after costs). */
function signalsCsv() {
  const ids = EXP_SETS.map((e) => e.id), lines = [["mint", "symbol", "signal_utc", "mcap_usd", "buyers_last_minute", "buy_share_pct", "net_sol_last_minute", "rise_2min_pct", "hour_utc", "bought", "not_bought_because", ...ids.map((i) => "net_pct_exit_" + i)].join(",")];
  for (const x of SIG.list) lines.push([x.mint, x.sym, new Date(x.at).toISOString(), x.mcap, x.buyers, x.share, x.net, x.rise, x.hour, x.took ? 1 : 0, x.why, ...ids.map((i) => (x.res && x.res[i] != null ? x.res[i] : ""))].map(csvQ).join(","));
  return lines.join("\n");
}
/** Every closed paper trade, newest first. */
function tradesCsv() {
  const lines = ["symbol,mint,lane,opened_utc,closed_utc,minutes_held,size_usd,pnl_usd,pnl_pct,r_multiple,exit_reason,mcap_at_buy,bonded_pct_at_buy,top10_pct,top1_pct,creator_pct,stop_pct,price_impact_pct"];
  for (const c of MP.closed) lines.push([c.symbol, c.mint, c.entryType || (c.fast ? "launch shot" : "at 90s"), c.openedAt ? new Date(c.openedAt).toISOString() : "", c.closedAt ? new Date(c.closedAt).toISOString() : "",
    c.openedAt && c.closedAt ? ((c.closedAt - c.openedAt) / 60000).toFixed(1) : "", c.sizeUsd, c.pnlUsd, c.pnlPct, c.rMult, c.why, c.mcapAtBuy, c.progressAtBuy, c.top10, c.top1, c.devPct, c.stopPct, c.impactPct].map(csvQ).join(","));
  return lines.join("\n");
}
/** Every graduate the Index follows: its price path for up to 7 days (minutes since found : multiple of the found price). */
function gxCsv() {
  const lines = ["mint,symbol,found_utc,found_mcap,found_liquidity,peak_x,last_x,days_followed,dead,points_minutes_x"];
  for (const r of GX.list) lines.push([r.m, r.s, new Date(r.t0).toISOString(), r.mc0, r.l0, (r.pk / r.p0).toFixed(3), (r.last / r.p0).toFixed(3), (((r.lastAt || r.t0) - r.t0) / 86400e3).toFixed(2), r.dead ? 1 : 0,
    (r.sr || [[0, 1]]).map(([mn, x]) => mn + ":" + x).join(" ")].map(csvQ).join(","));
  return lines.join("\n");
}
/*EXPORT_END*/

/** The live tape: every launch the bot sees, newest first, with what it decided. */
function mpTape(mint, status) { const t = MP.tape.find((x) => x.mint === mint); if (t) { t.status = status; t.doneAt = Date.now(); } }
const TRADE_EVENT_ID = crypto.createHash("sha256").update("event:TradeEvent").digest().subarray(0, 8);
const COMPLETE_EVENT_ID = crypto.createHash("sha256").update("event:CompleteEvent").digest().subarray(0, 8);
/** Pure: one pump.fun trade (buy or sell) from a "Program data:" log line, or null. */
function decodeTradeEvent(b64) {
  try {
    const buf = Buffer.from(b64, "base64");
    if (buf.length < 129 || !buf.subarray(0, 8).equals(TRADE_EVENT_ID)) return null;
    let o = 8; const key = () => { const k = new PublicKey(buf.subarray(o, o + 32)).toBase58(); o += 32; return k; };
    const mint = key(), sol = Number(buf.readBigUInt64LE(o)) / 1e9; o += 8;
    const tokens = Number(buf.readBigUInt64LE(o)) / 1e6; o += 8;
    const isBuy = buf[o] === 1; o += 1;
    const user = key(), ts = Number(buf.readBigInt64LE(o)); o += 8;
    const vSol = Number(buf.readBigUInt64LE(o)) / 1e9; o += 8;
    const vTok = Number(buf.readBigUInt64LE(o)) / 1e6; o += 8;
    if (!(sol >= 0) || !(vTok > 0)) return null;
    return { mint, sol, tokens, isBuy, user, ts, priceSol: vSol / vTok, vSol, vTok };
  } catch { return null; }
}
/** Pure: a pump.fun graduation (the curve completed) from a "Program data:" log line, or null. */
function decodeCompleteEvent(b64) {
  try {
    const buf = Buffer.from(b64, "base64");
    if (buf.length < 8 + 96 || !buf.subarray(0, 8).equals(COMPLETE_EVENT_ID)) return null;
    const k = (o) => new PublicKey(buf.subarray(o, o + 32)).toBase58();
    return { user: k(8), mint: k(40), curve: k(72) };
  } catch { return null; }
}

/**
 * LIVE FLOW: every buy and sell on every token for its first 20 minutes, straight from the feed (no extra
 * chain reads). This is what momentum is made of: how many different people are buying right now, whether
 * buys outnumber sells, how much SOL is flowing in, and how fast the price is moving.
 */
const FLOW = new Map();                      // mint → { t0, trades: [{ t, b, sol, u, p }], buyers: Set }
/**
 * INSTANT EXITS. Every trade on every token arrives the moment it happens, with the new price. If a token we HOLD just
 * crossed its stop-loss, take-profit or trailing line, or its creator just sold, we act now instead of waiting for the
 * next 10-second check (and the 30-second creator check). Fast exits are most of the difference between a −20% stop that
 * costs −20% and one that costs −40%.
 */
let mpNowAt = 0, mpNowTimer = null;
function mpManageNow() {                                              // at most one check a second, but a trigger inside that window is delayed, never dropped
  const wait = 1000 - (Date.now() - mpNowAt);
  if (wait <= 0) { mpNowAt = Date.now(); mpManage().catch(() => {}); return; }
  if (!mpNowTimer) mpNowTimer = setTimeout(() => { mpNowTimer = null; mpNowAt = Date.now(); mpManage().catch(() => {}); }, wait);
}
function mpInstant(p, tr) {
  const S = MP.settings, R = p.rules ? { ...S, ...p.rules } : S, sol = (typeof solUsd !== "undefined" && solUsd.v) || 0;
  if (!sol || !(tr.priceSol > 0) || !(p.entry > 0)) return;
  const px = tr.priceSol * sol; p.liveLast = px; p.liveAt = Date.now();
  if (!tr.isBuy && S.devExit && p.creator && tr.user === p.creator && tr.sol >= 0.2 && !p.forceExit) {
    p.forceExit = `creator dumped: saw the sell (${tr.sol.toFixed(1)} SOL)`; return mpManageNow();
  }
  if (p.phase === "moon") {
    p.moonHigh = Math.max(p.moonHigh || px, px);
    const run = p.moonHigh / p.entry, trail = run >= 10 ? Math.min(R.trailPct, R.trailAt10x) : run >= 5 ? Math.min(R.trailPct, R.trailAt5x) : R.trailPct;
    if (px <= p.moonHigh * (1 - trail / 100)) return mpManageNow();
  } else {
    const ch = (px / p.entry - 1) * 100;
    const tp = R.ladderOn ? (MP_LADDER[p.ladderI || 0] ? MP_LADDER[p.ladderI || 0][0] : Infinity) : R.tpPct;
    if (ch <= -R.slPct || ch >= tp) return mpManageNow();
    if (R.cashOutMcap > 0 && tr.priceSol * 1e9 * sol >= R.cashOutMcap) return mpManageNow();
    if (R.sellMcap > 0 && tr.priceSol * 1e9 * sol >= R.sellMcap) return mpManageNow();
  }
}
function mpOnTrade(tr) {
  const held = MP.positions.length ? MP.positions.find((x) => x.mint === tr.mint) : null;
  if (held) mpInstant(held, tr);
  const f = FLOW.get(tr.mint); if (!f) return;
  const t = Date.now(); if (t - f.t0 > 20 * 60e3) { FLOW.delete(tr.mint); return; }
  if (tr.tokens > 0 && tr.user) {                                     // who holds what, from the very first trade (exact; no chain calls)
    const h = f.hold || (f.hold = new Map()), cur = h.get(tr.user) || 0, next = tr.isBuy ? cur + tr.tokens : Math.max(0, cur - tr.tokens);
    if (next > 1e-6) h.set(tr.user, next); else h.delete(tr.user);
    if (h.size > 5000) h.delete(h.keys().next().value);
    if (f.ts0 == null && Number.isFinite(tr.ts)) f.ts0 = tr.ts;
    if (f.std == null && tr.vSol > 0 && tr.vTok > 0) f.std = Math.abs((tr.vSol * tr.vTok) / 3.219e10 - 1) < 0.003 ? 1 : 0;   // a standard pump.fun curve? (its reserves multiply to a fixed number)      // the chain's clock at the first trade (the creator's own buy)
    if (tr.isBuy) {
      if (f.creator && tr.user === f.creator) f.devBuy = (f.devBuy || 0) + tr.sol;
      else if (f.ts0 != null && Number.isFinite(tr.ts) && tr.ts - f.ts0 <= 2) { f.early = (f.early || 0) + tr.tokens; f.earlySol = (f.earlySol || 0) + tr.sol; (f.earlyU || (f.earlyU = new Set())).add(tr.user); }   // snipers / bundles: bought within 2 seconds of launch
      f.maxBuy = Math.max(f.maxBuy || 0, tr.sol);
    }
  }
  if (f.trades.length < 1500) f.trades.push({ t, b: tr.isBuy, sol: tr.sol, u: tr.user, p: tr.priceSol });
  if (tr.isBuy && f.buyers.size < 2000) f.buyers.add(tr.user);
  MP.feed.trades = (MP.feed.trades || 0) + 1;
  const S = MP.settings, sol = (typeof solUsd !== "undefined" && solUsd.v) || 0;
  if (S.bandOn && sol) {                                                  // BAND lane: did this trade carry the token across the buy line?
    const mc = tr.priceSol * 1e9 * sol, prev = f.lastMc; f.lastMc = mc;
    if (prev != null && prev < S.bandBuyK * 1000 && mc >= S.bandBuyK * 1000 && mc <= S.bandSellK * 1000 * 0.97 && !f.bandTried) { f.bandTried = true; mpBandBuy(tr.mint).catch(() => {}); }
  }
}
/** Pure: holder numbers from the live feed, as % of the 1B supply. ok = the feed saw (almost) every token the curve sold, so the numbers are complete. */
const PUMP_SUPPLY = 1e9;
function holdStats(f, soldTokens = null) {
  if (!f || !f.hold) return null;
  const v = [...f.hold.values()].sort((a, b) => b - a), held = v.reduce((a, x) => a + x, 0), pct = (x) => +((x / PUMP_SUPPLY) * 100).toFixed(2);
  const cov = soldTokens > 0 ? held / soldTokens : null;
  return { top1: pct(v[0] || 0), top10: pct(v.slice(0, 10).reduce((a, x) => a + x, 0)), devPct: f.creator ? pct(f.hold.get(f.creator) || 0) : null,
    holders: v.length, sniperPct: pct(f.early || 0), snipers: f.earlyU ? f.earlyU.size : 0, devBuySol: +(f.devBuy || 0).toFixed(3), maxBuySol: +(f.maxBuy || 0).toFixed(3),
    cov: cov == null ? null : +cov.toFixed(3), ok: soldTokens === 0 ? true : cov != null && cov >= 0.9 && cov <= 1.1 };
}
/**
 * STANDARD CURVE CHECK. Every standard pump.fun curve keeps three fixed relationships: virtual tokens minus real tokens is always
 * 279.9M, virtual SOL minus real SOL is always 30 SOL, and the supply is 1B. The bot's math (% bonded, market cap, the price floor)
 * relies on them. About 1 in 5 recorded tokens broke them (a market cap of $1 at 84% bonded), so those are skipped and kept out of
 * every statistic. Safety switch: if most launches suddenly look non-standard, pump.fun probably changed its constants, so the
 * check stands down (and says so) instead of skipping everything.
 */
const STD_TOK_GAP = 279900000000000n, STD_SOL_GAP = 30000000000n, STD_SUPPLY = 1000000000000000n;
function curveStd(c) {
  if (!c || typeof c.vTok !== "bigint" || typeof c.rTok !== "bigint" || typeof c.vSol !== "bigint" || typeof c.rSol !== "bigint" || typeof c.supply !== "bigint") return { ok: true, known: false };
  const near = (a, b) => (a > b ? a - b : b - a) * 1000n <= b;          // within 0.1%
  if (!near(c.vTok - c.rTok, STD_TOK_GAP)) return { ok: false, known: true, why: "token reserves" };
  if (!near(c.vSol - c.rSol, STD_SOL_GAP)) return { ok: false, known: true, why: "SOL reserves" };
  if (!near(c.supply, STD_SUPPLY)) return { ok: false, known: true, why: "supply" };
  return { ok: true, known: true };
}
const CURVEDIAG = { std: 0, nonStd: 0, why: {}, recent: [], tripped: false };
/** Where each judged token's holder numbers came from: the live trade feed, the chain check, or nowhere (then it is skipped). */
const HOLDDIAG = { feed: 0, rpc: 0, none: 0, lowCov: 0, rpcFails: 0, rpcErr: null, rpcErrAt: 0 };
function curveNote(r) {
  if (!r || !r.known) return;
  if (r.ok) CURVEDIAG.std++; else { CURVEDIAG.nonStd++; CURVEDIAG.why[r.why] = (CURVEDIAG.why[r.why] || 0) + 1; }
  CURVEDIAG.recent.push(r.ok ? 1 : 0); if (CURVEDIAG.recent.length > 200) CURVEDIAG.recent.shift();
  const n = CURVEDIAG.recent.length, bad = n - CURVEDIAG.recent.reduce((a, x) => a + x, 0);
  if (!CURVEDIAG.tripped && n >= 100 && bad / n > 0.5) { CURVEDIAG.tripped = true; mpEvent(`Safety switch: ${Math.round((bad / n) * 100)}% of recent launches look non-standard, so pump.fun may have changed its curve. The standard-curve check is paused until that is checked.`); }
  else if (CURVEDIAG.tripped && n >= 100 && bad / n < 0.3) { CURVEDIAG.tripped = false; mpEvent("Standard-curve check is back on: launches look normal again."); }
}
/** Pure: momentum numbers for one token. */
function flowStats(f, now = Date.now()) {
  if (!f || !f.trades.length) return { buyers60: 0, buys60: 0, sells60: 0, buyShare60: 0, net60: 0, rise2m: 0, buyersTotal: f ? f.buyers.size : 0, netTotal: 0, lastPriceSol: null };
  const w = f.trades.filter((x) => now - x.t <= 60000), u = new Set();
  let buys = 0, sells = 0, net = 0, netTotal = 0;
  for (const x of w) { if (x.b) { buys++; u.add(x.u); net += x.sol; } else { sells++; net -= x.sol; } }
  for (const x of f.trades) netTotal += x.b ? x.sol : -x.sol;
  const last = f.trades[f.trades.length - 1].p;
  let then = null; for (let i = f.trades.length - 1; i >= 0; i--) { if (now - f.trades[i].t >= 120000) { then = f.trades[i].p; break; } }
  if (then == null) then = f.trades[0].p;
  return { buyers60: u.size, buys60: buys, sells60: sells, buyShare60: buys + sells ? Math.round((buys / (buys + sells)) * 100) : 0, net60: +net.toFixed(2),
    rise2m: then > 0 ? +(((last / then) - 1) * 100).toFixed(1) : 0, buyersTotal: f.buyers.size, netTotal: +netTotal.toFixed(2), lastPriceSol: last };
}

/**
 * ALL LAUNCHES + ALL GRADUATIONS, kept for 48 hours: how many launch, how many graduate, how long it takes,
 * what time of day, and whether ALKAID had seen (and scored) each graduate early.
 */
const GR = { launches: [], grads: [], seen: new Map() };
function mpOnComplete(ev) {
  const now = Date.now(), seenAt = GR.seen.get(ev.mint), snap = LAB.snaps.find((x) => x.mint === ev.mint);
  GR.grads.push({ mint: ev.mint, t: now, launchedAt: seenAt || null, mins: seenAt ? +((now - seenAt) / 60000).toFixed(1) : null,
    sym: snap ? snap.sym : (MP.tape.find((x) => x.mint === ev.mint) || {}).symbol || null, name: snap ? snap.name : null,
    judged: !!snap, lift: snap ? +labLift(snap).toFixed(2) : null, held: MP.positions.some((p) => p.mint === ev.mint) || MP.closed.some((p) => p.mint === ev.mint) });
  if (GR.grads.length > 3000) GR.grads.splice(0, GR.grads.length - 3000);
  if (snap) { snap.grad = true; snap.win = true; }
  if (seenAt) rhCount("g", seenAt);                                       // a graduation counts for the hour the token was LAUNCHED
  MP.feed.grads = (MP.feed.grads || 0) + 1;
  gxPending(ev.mint);                                                      // the Graduate Index follows EVERY graduate, whether or not the bot trades it
  if (typeof anOnGrad === "function") anOnGrad(ev.mint, now);             // the Analyst: this birth record graduated
  if (typeof gradWatchAdd === "function") gradWatchAdd(ev.mint);
  if (typeof tgGraduated === "function") tgGraduated(ev.mint);
}
setInterval(() => {
  const cut = Date.now() - 48 * 3600e3;
  while (GR.launches.length && GR.launches[0].t < cut) GR.launches.shift();
  while (GR.grads.length && GR.grads[0].t < cut) GR.grads.shift();
  for (const [k, t] of GR.seen) if (t < cut) GR.seen.delete(k);
  for (const [k, f] of FLOW) if (Date.now() - f.t0 > 20 * 60e3) FLOW.delete(k);
}, 5 * 60e3);
function grStats() {
  const now = Date.now(), day = now - 24 * 3600e3;
  const L = GR.launches.filter((x) => x.t >= day), G = GR.grads.filter((x) => x.t >= day), Gk = G.filter((x) => x.launchedAt);
  const mins = Gk.map((x) => x.mins).sort((a, b) => a - b), med = mins.length ? mins[Math.floor(mins.length / 2)] : null;
  const byHour = new Array(24).fill(0).map(() => ({ l: 0, g: 0 }));
  for (const x of L) byHour[new Date(x.t).getUTCHours()].l++;
  for (const x of G) byHour[new Date(x.t).getUTCHours()].g++;
  let bestHour = null, bestRate = -1;
  byHour.forEach((h, i) => { if (h.l >= 50) { const r = h.g / h.l; if (r > bestRate) { bestRate = r; bestHour = i; } } });
  const judged = G.filter((x) => x.judged), high = judged.filter((x) => x.lift != null && x.lift >= 1.5);
  return { launches24h: L.length, grads24h: G.length, gradRatePct: L.length ? +((Gk.length / L.length) * 100).toFixed(2) : null,
    medianMinsToGrad: med, fastestMins: mins.length ? mins[0] : null, bestHourUtc: bestHour, bestHourRatePct: bestHour == null ? null : +(bestRate * 100).toFixed(2),
    gradsJudged: judged.length, gradsScoredHigh: high.length, gradsHeld: G.filter((x) => x.held).length,
    recent: G.slice(-12).reverse().map((x) => ({ mint: x.mint, symbol: x.sym, name: x.name, at: x.t, mins: x.mins, judged: x.judged, lift: x.lift, held: x.held })) };
}

function mpSkip(reason, ev) {
  MP.lastSkip = { mint: ev && ev.mint, reason };
  if (ev && ev.mint) ledNote(ev.mint, "skipped: " + reason);
  MP.skips[reason] = (MP.skips[reason] || 0) + 1;
  if (ev && ev.mint) mpTape(ev.mint, "skipped: " + reason);
  if (ev) { MP.evaluated.unshift({ ...ev, verdict: "skip", reason, at: Date.now() }); MP.evaluated = MP.evaluated.slice(0, 120); }
}

/** A new launch arrives: note the creator, queue it to be judged after the wait. */
function mpOnLaunch(ev) {
  MP.seen++; MP.feed.lastEventAt = Date.now();
  FLOW.set(ev.mint, { t0: Date.now(), trades: [], buyers: new Set(), hold: new Map(), creator: ev.creator || null, ts0: null, early: 0, earlyU: new Set(), devBuy: 0, maxBuy: 0 }); if (FLOW.size > 4000) FLOW.delete(FLOW.keys().next().value);
  GR.launches.push({ t: Date.now(), m: ev.mint }); GR.seen.set(ev.mint, Date.now()); rhCount("l", Date.now());
  if (GR.launches.length > 120000) GR.launches.splice(0, GR.launches.length - 120000);
  MP.launchTimes.push(Date.now()); if (MP.launchTimes.length > 600) MP.launchTimes.splice(0, MP.launchTimes.length - 600);
  MP.tape.unshift({ mint: ev.mint, symbol: ev.symbol, name: ev.name, creator: ev.creator, at: Date.now(), status: "watching" });
  if (MP.tape.length > 60) MP.tape.length = 60;
  const c = MP.creators.get(ev.creator) || [];
  c.push(Date.now()); MP.creators.set(ev.creator, c.filter((t) => Date.now() - t < 24 * 3600e3));
  if (MP.creators.size > 50000) MP.creators.delete(MP.creators.keys().next().value);
  if (typeof anOnLaunch === "function") anOnLaunch(ev);                   // the Analyst writes a birth record for EVERY launch (no chain reads)
  // instant rejects that need no chain reads
  if (!/pump$/.test(ev.mint)) { mpTape(ev.mint, "skipped: not a pump.fun mint"); return mpSkip("not a pump.fun mint"); }
  if (!ev.uri) { mpTape(ev.mint, "skipped: no metadata"); return mpSkip("no metadata"); }
  if (FAMOUS_TICKERS.has(ev.symbol.toUpperCase().replace(/^\$/, ""))) return mpSkip("copycat ticker", ev);
  if (MP.creators.get(ev.creator).length >= 3) return mpSkip("creator spamming launches", ev);
  if (rugReg.has(ev.creator)) return mpSkip("creator is a known rugger", ev);
  if (MP.settings.fastLane) mpFast(ev).catch(() => {});
  MP.queue.push({ ...ev, launchedAt: Date.now() });
  if (MP.queue.length > 400) MP.queue.splice(0, MP.queue.length - 400);
}

/** Fast lane: buy within seconds of the launch, while it's still around $5K. Only instant checks are possible this early. */
let mpFastTimes = [], mpFastTries = [];
async function mpFast(ev) {
  const S = MP.settings, t0 = Date.now();
  mpFastTimes = mpFastTimes.filter((t) => t0 - t < 60000);          // buys this minute
  mpFastTries = mpFastTries.filter((t) => t0 - t < 60000);          // looks this minute (keeps chain reads sane)
  if (mpFastTimes.length >= S.fastMaxPerMin || mpFastTries.length >= 20) return;
  if ((S.slots <= 0 && MP.positions.filter((p) => p.fast).length >= S.fastMaxOpen) || MP.positions.length >= mpMaxOpen(S)) return;
  if (mpBankGate(MP.bank, S)) return;
  mpFastTries.push(t0);
  const [cR, dR, sR] = await Promise.allSettled([readBondingCurve(ev.mint), balanceOf(ev.creator, ev.mint), getSolUsd()]);
  const c = cR.status === "fulfilled" ? cR.value : null, sol = sR.status === "fulfilled" ? sR.value : null;
  if (!c || c.complete || !sol) return;
  const m = curveMarket(c, sol, 6), devPct = dR.status === "fulfilled" ? (dR.value / 1e9) * 100 : null;
  if (m.mcap > S.fastMaxMcap) return mpSkip(`Launch Shot: already past $${Math.round(S.fastMaxMcap / 1000)}K`, ev);
  if (devPct != null && devPct > S.fastMaxDevPct) return mpSkip(`Launch Shot: creator bought ${devPct.toFixed(1)}% at launch`, ev);
  if (MP.positions.some((p) => p.mint === ev.mint)) return;
  const sizeUsd = S.slots > 0 ? mpBetSize(MP.bank, S, MP.positions, 1, null, sol) : mpBetSize(MP.bank, S, MP.positions, 1, S.fastBetPct, sol);
  if (!(sizeUsd > 0)) return mpSkip(`max loss ${S.maxLossPct}%: balance too small for a safe bet`, ev);
  const extraUsd = (S.priorityFeeSol + S.jitoTipSol) * sol, costUsd = sizeUsd * (1 + S.feePct / 100) + extraUsd;
  if (costUsd > MP.bank.cash) return;
  MP.bank.cash -= costUsd; mpFastTimes.push(t0);
  const entry = m.price * (1 + S.slippagePct / 100), tokens = sizeUsd / entry, ms = Date.now() - t0;
  MP.positions.push({ mint: ev.mint, symbol: ev.symbol, name: ev.name, creator: ev.creator, entry, entrySol: sol, tokens, sizeUsd, costUsd,
    costSol: costUsd / sol, openedAt: Date.now(), progressAtBuy: m.progress, mcapAtBuy: Math.round(m.mcap), high: entry, last: entry,
    devPct, top10: null, top1: null, tokensLeft: tokens, realizedUsd: 0, phase: "full", boosts: [`Launch Shot: in at $${(m.mcap / 1000).toFixed(1)}K, ${ms} ms after seeing it`], fast: true, devCheckedAt: 0 });
  mpTape(ev.mint, "BOUGHT (Launch Shot)");
  MP.evaluated.unshift({ ...ev, verdict: "paper buy", reason: `Launch Shot · $${(m.mcap / 1000).toFixed(1)}K market cap · ${m.progress.toFixed(1)}% bonded · creator ${devPct != null ? devPct.toFixed(1) + "%" : "?"} · ${ms} ms`, at: Date.now() });
  MP.evaluated = MP.evaluated.slice(0, 120);
  log("alkaid", `LAUNCH SHOT BUY ${ev.symbol} $${sizeUsd.toFixed(2)} at $${Math.round(m.mcap)} mcap in ${ms} ms`);
}

/** Judge one launch after the wait: real demand, no big dev/whale bags, clean contract. */
async function mpEvaluate(ev) {
  const S = MP.settings;
  let c;
  try { c = await readBondingCurve(ev.mint); } catch { return mpSkip("couldn't read curve", ev); }
  if (!c) return mpSkip("couldn't read curve", ev);
  if (c.complete) return mpSkip("already graduated", ev);
  const sol = await getSolUsd().catch(() => null);
  if (!sol) return mpSkip("no SOL price", ev);
  const m = curveMarket(c, sol, 6);
  const std = curveStd(c); curveNote(std);
  if (!std.ok && !CURVEDIAG.tripped) return mpSkip(`non-standard curve (${std.why}): the bot's curve math does not apply`, ev);
  const skipT = (reason, extra) => {          // skip, and remember the price so we can see later if the skip was right
    mpSkip(reason, { ...ev, ...(extra || {}) });
    MP.outcomes.push({ mint: ev.mint, sym: ev.symbol, reason: reason.replace(/[\d.]+%/g, "N%").replace(/\d+ /g, "N "), p0: m.price, due: Date.now() + 30 * 60e3 });
    if (MP.outcomes.length > 800) MP.outcomes.splice(0, MP.outcomes.length - 800);
  };
  // every launch with real money in it gets watched for a creator dump, pass or skip
  let devAt = null; try { devAt = ((await balanceOf(ev.creator, ev.mint)) / 1e9) * 100; } catch {}
  labSnap(ev, m, devAt, !std.ok);                               // the Winner Lab writes down what this launch looked like
  if (m.progress >= 1) pathStart(ev, m);                        // the Sweet Spot Finder records its price for 45 minutes
  // holders, counted exactly from the live feed (the chain's "largest holders" call failed on every token for weeks, silently)
  const soldTok = typeof c.rTok === "bigint" ? Number(INITIAL_REAL_TOKEN_RESERVES - (c.rTok < INITIAL_REAL_TOKEN_RESERVES ? c.rTok : INITIAL_REAL_TOKEN_RESERVES)) / 1e6 : null;
  const hs = holdStats(FLOW.get(ev.mint), soldTok);
  if (hs && hs.ok) labFeat(ev.mint, { top10: hs.top10, top1: hs.top1, snipe: hs.sniperPct, snipers: hs.snipers, holders: hs.holders, devBuy: hs.devBuySol, maxBuy: hs.maxBuySol, hcov: hs.cov, hsrc: "feed" });
  if (m.progress >= 3) { rugWatch.push({ mint: ev.mint, sym: ev.symbol, creator: ev.creator, peakSol: Number(c.rSol) / 1e9, devAt, due: Date.now() + 30 * 60e3, round: 0 }); if (rugWatch.length > 2000) rugWatch.shift(); }
  if (m.progress < S.minProgress) return skipT(`weak demand (<${S.minProgress}% bonded)`, { progress: m.progress });
  // creator's bag and holder concentration, curve excluded
  const chk = await getMintCheck(ev.mint, { holders: !(hs && hs.ok) }).catch(() => null);
  if (!chk || !chk.found) return mpSkip("couldn't check holders", ev);
  if (!chk.mintAuthorityRenounced || !chk.freezeAuthorityRenounced) return skipT("can print or freeze");
  let top10 = null, top1 = null, hsrc = "none";
  if (hs && hs.ok) { top10 = hs.top10; top1 = hs.top1; hsrc = "feed"; }
  else if (chk.top10WalletPct != null && chk.top1WalletPct != null) { top10 = chk.top10WalletPct; top1 = chk.top1WalletPct; hsrc = "rpc"; }
  HOLDDIAG[hsrc]++; if (hs && !hs.ok) HOLDDIAG.lowCov++;
  if (hsrc === "none") return skipT("couldn't measure holders: never trade blind");          // before: an unknown passed every holder limit
  labFeat(ev.mint, { top10: +(+top10).toFixed(1), top1: +(+top1).toFixed(1), hsrc });
  if (top1 > S.maxTop1Pct) return skipT(`one wallet holds ${Math.round(top1)}%`);
  if (top10 > S.maxTop10Pct) return skipT(`top 10 hold ${Math.round(top10)}%`);
  const devPct = devAt != null ? devAt : hs && hs.ok ? hs.devPct : null;
  if (devPct != null && devPct > S.maxDevPct) return skipT(`creator holds ${devPct.toFixed(1)}%`);
  // learned: setups that have kept losing money get skipped
  if (S.learn) {
    const bad = mpLearned(MP.closed, S.learnMin).filter((x) => x.verdict === "skip");
    const mine = mpBuckets({ progressAtBuy: m.progress, top10, devPct });
    const hit = bad.find((x) => mine.includes(x.setup));
    if (hit) return skipT(`learned: "${hit.setup}" averaged ${hit.avgPct}% over ${hit.trades} trades`);
  }
  // Winner Lab: only steers trading once it has enough finished launches of its own
  const labA = labAnalyze(), labS = LAB.snaps.find((x) => x.mint === ev.mint), labL = labS ? labLift(labS, labA) : 1;
  if (S.labFilter && labA.ready && labL < S.labMinLift) return skipT(`Winner Lab: ${labL.toFixed(1)}× the usual odds, below your ${S.labMinLift}× line`);
  if (S.momentum) {                                              // MOMENTUM: don't buy yet, watch for real buying
    if (!MP.watch.has(ev.mint)) MP.watch.set(ev.mint, { ev, until: (ev.launchedAt || Date.now()) + S.momWindowMin * 60e3, info: { top10, top1, devPct, labL }, since: Date.now() });
    mpTape(ev.mint, "WATCHING for momentum");
    return;
  }
  return mpOpen(ev, m, { top10, top1, devPct, labA, labL, sol, why: `${m.progress.toFixed(1)}% bonded · top10 ${top10 != null ? Math.round(top10) + "%" : "?"} · dev ${devPct != null ? devPct.toFixed(1) + "%" : "?"}` });
}

/** One place that buys (paper): protection first, then size from the balance. */
function mpOpen(ev, m, info) {
  const S = MP.settings, { top10, top1, devPct, labA, labL, sol } = info;
  const rg = mpRhythmGate(); if (rg) return mpSkip(rg, ev);
  if (S.paceMaxPerHour > 0) {
    const since = Date.now() - 3600e3, n = MP.positions.filter((p) => p.openedAt >= since).length + MP.closed.filter((p) => p.openedAt >= since).length;
    if (n >= S.paceMaxPerHour) return mpSkip(`pace limit: ${n} trades in the last hour`, ev);
  }
  // bankroll: protection first, then size from the balance
  if (MP.positions.some((p) => p.mint === ev.mint)) return mpSkip("already holding (Launch Shot)", ev);
  const gate = mpBankGate(MP.bank, S);
  if (gate) return mpSkip(gate, ev);
  if (MP.positions.length >= mpMaxOpen(S)) return mpSkip("all snipe slots are full", ev);
  // offense: bet bigger with evidence, never past the cap
  const boosts = [];
  let mult = 1;
  if (labA && labA.ready && labL >= 2.5 && S.labBoost > 1) { mult *= S.labBoost; boosts.push(`Winner Lab: ${labL.toFixed(1)}× the usual odds`); }
  if (info.momentum) boosts.push(info.momentum);
  if (S.learn) {
    const good = mpLearned(MP.closed, S.learnMin).filter((x) => x.verdict === "favor");
    const mine = mpBuckets({ progressAtBuy: m.progress, top10, devPct });
    const fav = good.find((x) => mine.includes(x.setup));
    if (fav) { mult *= S.favorBoost; boosts.push(`winning setup: ${fav.setup}`); }
  }
  try {
    const ranked = new Set(leaderboard().slice(0, 60).map((r) => r.wallet));
    const smartIn = recentBuys.filter((b) => b.t === ev.mint && ranked.has(b.w) && Date.now() - b.at < 15 * 60e3).length;
    if (smartIn) { mult *= S.smartBoost; boosts.push(`${smartIn} smart wallet${smartIn > 1 ? "s" : ""} bought it`); }
  } catch {}
  // the worst case: a curve token can fall to its floor; a pool token (graduate) can lose nearly everything when liquidity is pulled
  const onCurve = info.entryType !== "graduate" && m.floorRatio > 0 && m.floorRatio <= 1, cst = (S.slippagePct || 0) / 100, fee = (S.feePct || 0) / 100;
  const worstPct = !S.sizeByWorst ? null : onCurve ? (1 - (m.floorRatio * (1 - cst) * (1 - fee)) / ((1 + cst) * (1 + fee))) * 100 : S.gradWorstPct;
  let sizeUsd = mpBetSize(MP.bank, S, MP.positions, mult, null, sol, (info.rules && info.rules.slPct) || S.slPct, worstPct);
  if (info.maxBetUsd > 0) sizeUsd = Math.min(sizeUsd, info.maxBetUsd);          // e.g. the band lane never buys more than the curve can absorb
  if (!(sizeUsd > 0)) return mpSkip(`max loss ${S.maxLossPct}%: balance too small for a safe bet`, ev);
  const extraUsd = (S.priorityFeeSol + S.jitoTipSol) * sol, costUsd = sizeUsd * (1 + S.feePct / 100) + extraUsd;
  if (costUsd > MP.bank.cash) return mpSkip("trading balance too low (the vault is safe)", ev);
  MP.bank.cash -= costUsd;
  const impact = m.progress < 100 && m.mcap > 0 ? curveImpactPct(m.mcap, sizeUsd, sol) : 0;      // a big buy moves a thin curve: you pay for that too
  const entry = m.price * (1 + Math.max(S.slippagePct, impact) / 100);                              // you pay a little above the quote
  const tokens = sizeUsd / entry;
  const pos = { mint: ev.mint, symbol: ev.symbol, name: ev.name, creator: ev.creator, entry, entrySol: sol, tokens, sizeUsd, costUsd,
                costSol: costUsd / sol, openedAt: Date.now(), progressAtBuy: m.progress, high: entry, last: entry, devPct, top10, top1,
                tokensLeft: tokens, realizedUsd: 0, phase: "full", boosts, devCheckedAt: 0, entryType: info.entryType || (info.momentum ? "momentum" : "at 90s"), mcapAtBuy: Math.round(m.mcap || 0),
                impactPct: +impact.toFixed(2), curveFloorSol: m.priceSol > 0 && m.floorRatio > 0.02 && m.floorRatio <= 1 && m.progress < 100 ? m.priceSol * m.floorRatio : 0, stopPct: (info.rules && info.rules.slPct) || S.slPct, ...(info.rules ? { rules: info.rules } : {}), ...(info.extra || {}) };
  MP.positions.push(pos); ledNote(pos.mint, "bought · " + pos.entryType); mpSaveNow();                                       // a trade is on disk the moment it opens
  if (typeof expOpen === "function") expOpen(pos);
  if (typeof tgTradeOpened === "function") tgTradeOpened(pos);
  mpTape(ev.mint, info.momentum ? "BOUGHT on momentum" : "BOUGHT");
  MP.evaluated.unshift({ ...ev, verdict: "paper buy", reason: info.why, at: Date.now() });
  MP.evaluated = MP.evaluated.slice(0, 120);
  log("alkaid", `PAPER BUY ${ev.symbol} $${sizeUsd.toFixed(2)} at ${m.progress.toFixed(1)}% bonded${boosts.length ? " (" + boosts.join(", ") + ")" : ""}`);
}

/** Pure: is this the moment? Real buyers piling in, buys beating sells, SOL flowing in, price rising, not too late. */
function momentumOk(fs, S, mcapUsd) {
  const why = [];
  if (fs.buyers60 < S.momBuyers60) why.push(`${fs.buyers60}/${S.momBuyers60} buyers`);
  if (fs.buyShare60 < S.momBuyShare) why.push(`${fs.buyShare60}% buys`);
  if (fs.net60 < S.momNetSol) why.push(`${fs.net60} SOL in`);
  if (fs.rise2m < S.momRise2m) why.push(`+${fs.rise2m}% in 2m`);
  if (mcapUsd != null && S.momMaxMcap > 0 && mcapUsd > S.momMaxMcap) return { go: false, late: true, why: [`already $${Math.round(mcapUsd / 1000)}K`] };
  return { go: !why.length, why };
}
async function mpWatchTick() {
  if (!MP.on || !MP.watch.size) return;
  const S = MP.settings, now = Date.now(), sol = await getSolUsd().catch(() => null);
  if (!sol) return;
  for (const [mint, w] of MP.watch) {
    const fs = flowStats(FLOW.get(mint), now);
    w.last = fs;
    const mcapUsd = fs.lastPriceSol ? fs.lastPriceSol * 1e9 * sol : null;
    const v = momentumOk(fs, S, mcapUsd);
    if (v.late) { MP.watch.delete(mint); mpSkip("momentum came too late (already above your market-cap limit)", w.ev); continue; }
    if (!v.go) { if (now > w.until) { MP.watch.delete(mint); mpSkip(`no momentum within ${S.momWindowMin} min`, w.ev); } continue; }
    MP.watch.delete(mint);
    sigLog(w.ev, fs, mcapUsd);                                                   // every qualifying signal is recorded, whether or not the bot can take it
    { const pbv = pbCheck(fs, mcapUsd); if (pbv) { sigMark(mint, false, pbv); mpSkip(pbv, w.ev); continue; } }
    if (S.momMaxRise2m > 0 && fs.rise2m > S.momMaxRise2m) { sigMark(mint, false, `chase cap: already +${fs.rise2m}% in 2m`); mpSkip(`already +${fs.rise2m}% in 2m: a blow-off, not a start (cap +${S.momMaxRise2m}%)`, w.ev); continue; }
    let c; try { c = await readBondingCurve(mint); } catch {}                    // confirm the price straight from the chain
    if (!c || c.complete) { mpSkip(c && c.complete ? "graduated before momentum buy" : "couldn't read curve", w.ev); continue; }
    const m = curveMarket(c, sol, 6);
    // holders AGAIN, at the moment of buying: minutes after the first check, a whale or a bundle may have moved in
    const soldNow = typeof c.rTok === "bigint" ? Number(INITIAL_REAL_TOKEN_RESERVES - (c.rTok < INITIAL_REAL_TOKEN_RESERVES ? c.rTok : INITIAL_REAL_TOKEN_RESERVES)) / 1e6 : null;
    const hsNow = holdStats(FLOW.get(mint), soldNow); let info2 = w.info;
    if (hsNow && hsNow.ok) {
      const why = hsNow.top1 > S.maxTop1Pct ? `one wallet holds ${Math.round(hsNow.top1)}%` : hsNow.top10 > S.maxTop10Pct ? `top 10 hold ${Math.round(hsNow.top10)}%` : null;
      if (why) { sigMark(mint, false, why + " at the buy"); mpSkip(`${why} (checked again at the buy)`, w.ev); continue; }
      info2 = { ...w.info, top10: hsNow.top10, top1: hsNow.top1 };
    }
    mpOpen(w.ev, m, { ...info2, labA: labAnalyze(), sol, momentum: `momentum: ${fs.buyers60} buyers/min, ${fs.buyShare60}% buys, +${fs.net60} SOL, +${fs.rise2m}% in 2m`,
      why: `MOMENTUM · ${fs.buyers60} buyers in 60s · ${fs.buyShare60}% buys · +${fs.net60} SOL in · +${fs.rise2m}% in 2m · $${(m.mcap / 1000).toFixed(1)}K` });
    { const took = MP.positions.some((p) => p.mint === mint); sigMark(mint, took, took ? null : (MP.lastSkip && MP.lastSkip.mint === mint ? MP.lastSkip.reason : "not bought")); }
  }
}
setInterval(() => { mpWatchTick().catch(() => {}); }, 3000);

/** Price + market cap from the live trading pool (used once a token graduates off the pump.fun curve). Cached 8 s. */
const mpDexCache = new Map();
/** Pure: the numbers we care about from one DexScreener pair. */
function dexInfo(p) {
  const m5 = (p.txns && p.txns.m5) || {}, pc = p.priceChange || {}, vol = p.volume || {};
  return { price: +p.priceUsd, mcap: +p.marketCap || +p.fdv || 0, liq: +(p.liquidity && p.liquidity.usd) || 0,
    ch5: Number.isFinite(+pc.m5) ? +pc.m5 : null, ch1: Number.isFinite(+pc.h1) ? +pc.h1 : null,
    buys5: +m5.buys || 0, sells5: +m5.sells || 0, vol5: +vol.m5 || 0, vol1: +vol.h1 || 0, vol24: +vol.h24 || 0, pair: p.pairAddress || null, createdAt: p.pairCreatedAt || null };
}
const mpSleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function mpDexPrice(mint) {
  const h = mpDexCache.get(mint);
  if (h && Date.now() - h.ts < 8000) return h.v;
  let v = null;
  try {
    const d = await (await withTimeout(fetch(`https://api.dexscreener.com/latest/dex/tokens/${mint}`), 6000, "dex price")).json();
    const p = trustedDexPair(d.pairs, mint);
    if (p && +p.priceUsd > 0) v = dexInfo(p);
  } catch {}
  mpDexCache.set(mint, { v, ts: Date.now() });
  if (mpDexCache.size > 500) mpDexCache.delete(mpDexCache.keys().next().value);
  return v;
}
/** Up to 30 tokens in one call. Returns Map(mint → info). */
async function dexBatch(mints) {
  const out = new Map(), list = [...new Set(mints)].slice(0, 30); if (!list.length) return out;
  try {
    const d = await (await withTimeout(fetch(`https://api.dexscreener.com/latest/dex/tokens/${list.join(",")}`), 8000, "dex batch")).json();
    const by = new Map();
    for (const p of d.pairs || []) { const a = p.baseToken && p.baseToken.address; if (!a || p.chainId !== "solana") continue; (by.get(a) || by.set(a, []).get(a)).push(p); }
    for (const m of list) { const p = trustedDexPair(by.get(m) || [], m); if (p && +p.priceUsd > 0) { const v = dexInfo(p); out.set(m, v); mpDexCache.set(m, { v, ts: Date.now() }); } }
  } catch {}
  return out;
}
/**
 * Can this token actually be SOLD? Asks Jupiter for a real route for a test sale and measures how much the
 * price would move. ok:false = no route at all (a classic can't-sell trap); checked:false = couldn't ask (never treated as "unsafe").
 */
const sellCache = new Map();
async function sellRoute(mint, usd = 100, price = null, decimals = 6, sol = 150) {
  const k = mint + ":" + Math.round(usd / 25), h = sellCache.get(k);
  if (h && Date.now() - h.ts < 120000) return h.v;
  let v = { checked: false };
  try {
    if (!(price > 0)) throw new Error("no price");
    const raw = Math.floor((usd / price) * 10 ** decimals); if (!(raw > 0)) throw new Error("tiny");
    const r = await withTimeout(fetch(`https://lite-api.jup.ag/swap/v1/quote?inputMint=${mint}&outputMint=So11111111111111111111111111111111111111112&amount=${raw}&slippageBps=300`, { headers: { accept: "application/json" } }), 6000, "sell route");
    const j = await r.json().catch(() => ({}));
    if (r.ok && Array.isArray(j.routePlan) && j.routePlan.length && +j.outAmount > 0) {
      const gotUsd = (+j.outAmount / 1e9) * sol, shortfall = Math.max(0, (1 - gotUsd / usd) * 100), imp = Math.abs(+j.priceImpactPct || 0) * 100;
      v = { checked: true, ok: true, impactPct: +Math.max(shortfall, imp).toFixed(1), gotUsd: +gotUsd.toFixed(2) };
    } else if (/route|not tradable|no liquidity/i.test(JSON.stringify(j))) v = { checked: true, ok: false, error: String(j.error || j.message || "no route").slice(0, 80) };
  } catch {}
  sellCache.set(k, { v, ts: Date.now() }); if (sellCache.size > 2000) sellCache.delete(sellCache.keys().next().value);
  return v;
}

/**
 * Manage open paper positions.
 *   defense: stop-loss, time limit, and an instant exit if the creator dumps their bag
 *   offense: at the take-profit, sell part (your money back) and let the rest ride with a
 *            trailing stop, so one big runner can pay for many small losses
 */
async function mpManage() {
  if (MP.managing) { MP.manageAgain = true; return; }
  MP.managing = true;
  try { await mpManageInner(); }
  finally { MP.managing = false; if (MP.manageAgain) { MP.manageAgain = false; setTimeout(() => { mpManage().catch(() => {}); }, 50); } }
}
async function mpManageInner() {
  const S = MP.settings, sol = await getSolUsd().catch(() => null);
  if (!sol) return;
  const sell = (p, frac, price) => {                   // sell a fraction of what's left, at a realistic price
    const tok = p.tokensLeft * frac, exit = price * (1 - Math.max(S.slippagePct, p.impactPct || 0) / 100);
    const back = Math.max(0, tok * exit * (1 - S.feePct / 100) - (S.priorityFeeSol + S.jitoTipSol) * sol);
    p.tokensLeft -= tok; p.realizedUsd += back; MP.bank.cash += back;
    return back;
  };
  const close = (p, why) => {
    const cost = p.costUsd != null ? p.costUsd : p.costSol * sol;
    const pnlUsd = p.realizedUsd - cost;
    const stopD = p.stopPct || (p.rules && p.rules.slPct) || S.slPct, riskFrac = (stopD + 2 * (S.feePct + S.slippagePct)) / 100, rMult = cost > 0 && riskFrac > 0 ? +(pnlUsd / (cost * riskFrac)).toFixed(2) : null;     // R: -1 = lost what a stop was planned to cost, +2 = made twice that
    MP.closed.unshift({ ...p, exit: p.last, closedAt: Date.now(), why, pnlUsd: +pnlUsd.toFixed(2), pnlSol: +(pnlUsd / sol).toFixed(5), pnlPct: +((pnlUsd / cost) * 100).toFixed(1), rMult });
    MP.closed = MP.closed.slice(0, 500);
    MP.positions = MP.positions.filter((x) => x !== p);
    log("alkaid", `PAPER CLOSED ${p.symbol} ${why} ${pnlUsd >= 0 ? "+" : ""}$${pnlUsd.toFixed(2)}`);
    if (typeof tgTradeClosed === "function") tgTradeClosed(p, why, pnlUsd);
    for (const msg of mpAfterClose(MP.bank, S, pnlUsd)) mpEvent(msg);
    if (S.autoSend && MP.bank.vault > 0) mpSendVault("auto: profit locked");
    mpSaveNow();                                                          // ...and when it closes
    try { ledTrade(MP.closed[0]); } catch {}
  };
  for (const p of MP.positions.slice()) {
    if (p.tokensLeft == null) { p.tokensLeft = p.tokens; p.realizedUsd = 0; p.phase = "full"; }
    const R = p.rules ? { ...S, ...p.rules } : S;                     // graduate and copy trades carry their own exit rules
    let price = null, graduated = false;
    try {
      const c = await readBondingCurve(p.mint);
      if (!c) {
        if (p.curveFloorSol > 0 && !p.postGrad) {                         // bought on the curve: a failed chain read is NOT a reason to trust a different (slower, sometimes wrong) price source
          p.nullReads = (p.nullReads || 0) + 1;
          if (p.nullReads < 12) continue;                                  // wait for the next read; only after ~2 minutes of failures fall back to the pool price
        }
        const dx = await mpDexPrice(p.mint); if (dx) { price = dx.price; p.mcapNow = dx.mcap; p.postGrad = true; }   // never on a bonding curve: follow its pool
      }
      else if (c && !c.complete) {
        const m = curveMarket(c, sol, 6); price = m.price; p.mcapNow = m.mcap; p.nullReads = 0;
        if (p.curveFloorSol > 0 && m.priceSol < p.curveFloorSol * 0.95) { MP.feed.glitches = (MP.feed.glitches || 0) + 1; p.glitchAt = Date.now(); continue; }   // below the lowest price this curve can ever reach: not a real price, ignore it
      }
      else if (c && c.complete) {
        const dx = await mpDexPrice(p.mint);                              // graduated: keep following it on the trading pool
        if (dx) { price = dx.price; p.mcapNow = dx.mcap; p.postGrad = true; }
        else { price = p.last; graduated = true; }                         // no pool price yet: cash out at the last curve price
      }
    } catch {}
    if (price == null) continue;
    if (p.postGrad && p.last > 0 && price < p.last * 0.65) {                // a 35%+ drop in one step on a pool price: confirm with a fresh read before acting on it
      mpDexCache.delete(p.mint); await mpSleep(1500);
      const d2 = await mpDexPrice(p.mint);
      if (!d2 || !(d2.price > 0)) continue;                                  // can't confirm: don't act on a number we can't check; try again next tick
      if (d2.price > price * 1.25) MP.feed.glitches = (MP.feed.glitches || 0) + 1;   // the first reading was an outlier
      price = d2.price; p.mcapNow = d2.mcap;
    }
    p.last = price; p.high = Math.max(p.high, price);
    const ch = (price / p.entry - 1) * 100, age = Date.now() - p.openedAt;

    if (p.forceExit) { sell(p, 1, price); close(p, p.forceExit); continue; }         // e.g. the wallet we copied just sold
    // defense: creator dumped → out now (checked every 30 s per position)
    if (S.devExit && p.devPct != null && p.devPct >= 0.5 && Date.now() - (p.devCheckedAt || 0) > 30000) {
      p.devCheckedAt = Date.now();
      try { const now = ((await balanceOf(p.creator, p.mint)) / 1e9) * 100;
        if (now < 0.1) { sell(p, 1, price); close(p, "creator dumped: got out"); continue; } } catch {}
    }
    // RUG ZONE: fast movers that reach this market cap are usually being pumped to dump on late buyers. Take everything and go.
    if (R.cashOutMcap > 0 && p.mcapNow >= R.cashOutMcap) {
      const k = Math.round(p.mcapNow / 1000);
      sell(p, 1, price);
      MP.outcomes.push({ mint: p.mint, sym: p.symbol, reason: "cashed out in the rug zone", p0: price, due: Date.now() + 30 * 60e3, dex: true });
      mpEvent(`${p.symbol} reached $${k}K market cap: sold everything (rug zone)`);
      close(p, `rug zone: cashed out at $${k}K market cap (+${Math.round(ch)}%)`); continue;
    }
    if (R.sellMcap > 0 && p.mcapNow >= R.sellMcap) {                          // BAND lane: the market-cap target was reached
      sell(p, 1, price); close(p, `band target: reached $${Math.round(R.sellMcap / 1000)}K market cap (+${Math.round(ch)}%)`); continue;
    }
    if (graduated) { sell(p, 1, price); close(p, p.phase === "moon" ? "moon bag: graduated, cashed out" : "graduated, cashed out"); continue; }

    if (p.phase === "full") {
      if (R.ladderOn) {                              // V1.0 staged exits: +20% / +35% / +60%, 25% of the original each, then trail the last 25%
        p.ladderI = p.ladderI || 0; let rung = false;
        while (p.ladderI < MP_LADDER.length && ch >= MP_LADDER[p.ladderI][0]) {
          const [, share] = MP_LADDER[p.ladderI], frac = Math.min(1, (share * p.tokens) / Math.max(1e-12, p.tokensLeft));
          sell(p, frac, price); p.ladderI++; rung = true;
          mpEvent(`${p.symbol} hit +${Math.round(ch)}%: sold ${Math.round(share * 100)}% (step ${p.ladderI} of ${MP_LADDER.length})`);
        }
        if (rung) { if (p.ladderI >= MP_LADDER.length) { p.phase = "moon"; p.moonHigh = price; } continue; }
      }
      if (!R.ladderOn && ch >= R.tpPct) {            // offense: lock the win, keep a free ride
        if (R.tp1SellPct >= 100) { sell(p, 1, price); close(p, `take profit +${R.tpPct}%`); continue; }
        sell(p, R.tp1SellPct / 100, price);
        p.phase = "moon"; p.moonHigh = price;
        mpEvent(`${p.symbol} hit +${Math.round(ch)}%: sold ${R.tp1SellPct}%, letting the rest ride`);
        continue;
      }
      if (ch <= -R.slPct) { sell(p, 1, price); close(p, `stop loss −${R.slPct}%`); continue; }
      if (p.fast && age > S.fastTimeoutSec * 1000 && ch < S.fastMinGainPct) { sell(p, 1, price); close(p, `Launch Shot: no lift-off in ${Math.round(S.fastTimeoutSec / 60)}m`); continue; }
      if (age > R.maxHoldMin * 60e3) { sell(p, 1, price); close(p, `time limit ${R.maxHoldMin}m`); continue; }
    } else {                                         // moon bag: ride it, trail the high
      p.moonHigh = Math.max(p.moonHigh || price, price);
      const run = p.moonHigh / p.entry;
      const trail = run >= 10 ? Math.min(R.trailPct, R.trailAt10x) : run >= 5 ? Math.min(R.trailPct, R.trailAt5x) : R.trailPct;
      p.trailNow = trail;
      if (price <= p.moonHigh * (1 - trail / 100)) { sell(p, 1, price); close(p, `moon bag: trailing stop (peaked +${Math.round((p.moonHigh / p.entry - 1) * 100)}%)`); continue; }
      if (age > R.moonHoldMin * 60e3) { sell(p, 1, price); close(p, `moon bag: time limit ${R.moonHoldMin}m`); continue; }
    }
  }
}

/** Live feed of pump.fun launches, straight from the chain. */
function mpConnect() {
  if (!MP.on || MP.feed.subId != null) return;
  try {
    MP.feed.subId = connection.onLogs(PUMP_PROGRAM, (l) => {
      MP.feed.connected = true;
      if (l.err || !Array.isArray(l.logs)) return;
      const isCreate = l.logs.some((x) => x.includes("Instruction: Create"));
      for (const line of l.logs) {
        if (!line.startsWith("Program data: ")) continue;
        const data = line.slice(14);
        if (isCreate) { const ev = decodeCreateEvent(data); if (ev) { mpOnLaunch(ev); continue; } }
        const tr = decodeTradeEvent(data); if (tr) { mpOnTrade(tr); continue; }
        const cp = decodeCompleteEvent(data); if (cp) mpOnComplete(cp);
      }
    }, "confirmed");
    MP.feed.connected = true;
    log("alkaid", "watching pump.fun launches (paper mode)");
  } catch (e) { MP.feed.subId = null; log("error", `cannon feed: ${e.message}`); }
}
setTimeout(mpConnect, 8000);
// reconnect if launches stop arriving for 3 minutes (pump.fun is never that quiet)
setInterval(async () => {
  if (!MP.on) return;
  if (MP.feed.lastEventAt && Date.now() - MP.feed.lastEventAt > 180000 && MP.feed.subId != null) {
    try { await connection.removeOnLogsListener(MP.feed.subId); } catch {}
    MP.feed.subId = null; MP.feed.connected = false; mpConnect();
  }
}, 60000);
// judge launches whose wait is over, a few at a time
let mpEvalWindow = [];
setInterval(async () => {
  if (!MP.on) return;
  const now = Date.now(), S = MP.settings;
  mpEvalWindow = mpEvalWindow.filter((t) => now - t < 60000);
  while (MP.queue.length && now - MP.queue[0].launchedAt >= S.waitSec * 1000) {
    const ev = MP.queue.shift();
    if (now - ev.launchedAt > (S.waitSec + 120) * 1000) { mpSkip("too old by the time it was judged"); continue; }
    if (mpEvalWindow.length >= S.maxEvalPerMin) { mpSkip("busy (sampled out)"); continue; }
    mpEvalWindow.push(now);
    mpEvaluate(ev).catch(() => mpSkip("check failed", ev));
  }
}, 2000);
setInterval(() => { if (MP.on && MP.positions.length) mpManage().catch(() => {}); }, 10000);
setInterval(async () => {
  const now = Date.now(); let n = 0;
  for (let i = 0; i < MP.outcomes.length && n < 3; i++) {
    const o = MP.outcomes[i]; if (o.due > now) continue; n++;
    let verdict = null;
    try {
      if (o.dex) { const d = await mpDexPrice(o.mint); if (d) { const r = d.price / o.p0; verdict = r >= 1.6 ? "win" : r <= 0.5 ? "loss" : "flat"; } }
      else {
      const c = await readBondingCurve(o.mint);
      if (c && c.complete) verdict = "win";                                  // graduated: it ran
      else if (c) { const p = curveMarket(c, await getSolUsd(), 6).price, r = p / o.p0; verdict = r >= 2 ? "win" : r <= 0.5 ? "loss" : "flat"; }
      }
    } catch {}
    MP.outcomes.splice(i--, 1);
    if (!verdict) continue;
    const r = MP.report[o.reason] || (MP.report[o.reason] = { checked: 0, wouldWin: 0, wouldLose: 0 });
    r.checked++; if (verdict === "win") r.wouldWin++; if (verdict === "loss") r.wouldLose++;
  }
}, 30000);

/** Rug watcher: re-check launches at 30 minutes and 3 hours. Creator sold out + curve collapsed = rug. */
const rugWatch = [];
setInterval(async () => {
  const now = Date.now(); let checks = 0;
  for (let i = 0; i < rugWatch.length && checks < 4; i++) {
    const w = rugWatch[i]; if (w.due > now) continue;
    checks++;
    try {
      const c = await readBondingCurve(w.mint);
      if (!c || c.complete) { rugWatch.splice(i--, 1); continue; }            // graduated or gone: not a curve dump
      const solNow = Number(c.rSol) / 1e9; w.peakSol = Math.max(w.peakSol, solNow);
      let devNow = null; try { devNow = ((await balanceOf(w.creator, w.mint)) / 1e9) * 100; } catch {}
      const collapsed = w.peakSol >= 2 && solNow < w.peakSol * 0.35;
      const devDumped = w.devAt != null && w.devAt >= 1 && devNow != null && devNow < 0.1;
      if (collapsed && devDumped) {
        markRug(w.creator, { role: "creator", mint: w.mint, sym: w.sym, how: `sold out while the curve fell from ${w.peakSol.toFixed(1)} to ${solNow.toFixed(1)} SOL` });
        log("rugwatch", `${w.sym} creator ${w.creator.slice(0, 4)}… marked as rugger`);
        rugWatch.splice(i--, 1); continue;
      }
      if (++w.round >= 2) rugWatch.splice(i--, 1); else w.due = now + 150 * 60e3;   // second look at ~3 hours
    } catch { w.due = now + 10 * 60e3; }
  }
}, 30000);

function requireOwner(req, res) {
  const p = readPass(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
  if (!p || !MY_WALLET || p.w !== MY_WALLET) { res.status(403).json({ error: "Owner only." }); return false; }
  return true;
}
app.use("/api/mp", rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false, message: { error: "Too many requests." } }));

/**
 * ALKAID IS FOR ONE PERSON. There is no sharing, no view-only mode, no guest list and no subscription: the only way in
 * is the owner's wallet or the owner's own code. Any share link file left by an older version is erased at startup.
 */
try { const f = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-share.json") : ""; if (f && nodeFs.existsSync(f)) { nodeFs.unlinkSync(f); log("access", "removed an old share link: sharing no longer exists"); } } catch {}
function requireReader(req, res) { return requireOwner(req, res) ? "owner" : null; }

/** Owner-only: pick a new owner code (you must already be signed in as the owner, e.g. with your wallet). */
app.post("/api/mp/owner-code", (req, res) => {
  if (!requireOwner(req, res)) return;
  const code = (req.body || {}).code;
  if (typeof code !== "string" || code.length < 12 || code.length > 200) return res.status(400).json({ error: "Use at least 12 characters." });
  if (/^\s|\s$/.test(code)) return res.status(400).json({ error: "No spaces at the start or end." });
  const hash = crypto.createHash("sha256").update(code).digest();
  if (VOLUME_DIR) {
    try {
      const f = nodePath.join(VOLUME_DIR, "owner-code.json"), tmp = f + ".tmp";
      nodeFs.writeFileSync(tmp, JSON.stringify({ hash: hash.toString("hex"), at: Date.now() }), { mode: 0o600 }); nodeFs.renameSync(tmp, f);
    } catch (e) { log("error", `saving owner code: ${e.message}`); return res.status(500).json({ error: "Couldn't save it. Try again." }); }
  }
  ownerStored = hash; ownerStoredLoaded = true; ownerFails = []; ownerLockedUntil = 0;
  log("access", "owner code changed from the dashboard");
  res.json({ ok: true, saved: !!VOLUME_DIR });
});

/** Owner-only dashboard data */
app.get("/api/mp/state", (req, res) => {
  const role = requireReader(req, res); if (!role) return;
  const sol = solUsd.v || null;
  const done = MP.closed, wins = done.filter((x) => (x.pnlUsd ?? x.pnlSol) > 0).length;
  const pnl = done.reduce((a, x) => a + (x.pnlSol || 0), 0);
  mpBankGate(MP.bank, MP.settings);
  const openValue = MP.positions.reduce((a, p) => a + (p.tokensLeft ?? p.tokens) * p.last * (1 - MP.settings.feePct / 100), 0);
  const B = MP.bank, total = B.cash + B.vault + (B.sent || 0) + openValue;
  const bank = { start: B.start, trading: +B.cash.toFixed(2), vault: +B.vault.toFixed(2), inTrades: +openValue.toFixed(2), total: +total.toFixed(2),
    growthPct: +(((total / B.start) - 1) * 100).toFixed(1), today: +(B.dayPnl || 0).toFixed(2), peak: +(B.peak || 0).toFixed(2),
    paused: B.pausedUntil > Date.now() ? { why: B.pauseWhy, until: B.pausedUntil } : null, nextBetUsd: +mpBetSize(B, MP.settings, MP.positions, 1, null, sol || 150, MP.settings.slPct).toFixed(2),
    slots: mpMaxOpen(MP.settings), slotsUsed: MP.positions.length,
    sent: +(B.sent || 0).toFixed(2), sends: (B.sends || []).slice(0, 10), savingsWallet: MP.settings.savingsWallet || MY_WALLET || null };
  bank.costPct = mpCostPct(MP.settings, bank.nextBetUsd, sol || 150);
  if (MP.settings.maxLossPct > 0) bank.minSafeBalance = +((MP.settings.minTradeUsd * 100) / MP.settings.maxLossPct).toFixed(2);
  const filterReport = Object.entries(MP.report).map(([reason, r]) => ({ reason, ...r,
    verdict: r.checked < 10 ? "still checking" : r.wouldLose >= r.wouldWin ? "saving you money" : "may be costing you winners" })).sort((a, b) => b.checked - a.checked);
  const open = MP.positions.map((p) => ({ ...p, chPct: +(((p.last / p.entry) - 1) * 100).toFixed(1), ageMin: +((Date.now() - p.openedAt) / 60000).toFixed(1) }));
  const fastClosed = done.filter((x) => x.fast);
  const fast = { on: !!MP.settings.fastLane, trades: fastClosed.length, wins: fastClosed.filter((x) => x.pnlUsd > 0).length,
    pnlUsd: +fastClosed.reduce((a, x) => a + (x.pnlUsd || 0), 0).toFixed(2), open: MP.positions.filter((p) => p.fast).length,
    avgEntryMcap: fastClosed.length ? Math.round(fastClosed.reduce((a, x) => a + (x.mcapAtBuy || 0), 0) / fastClosed.length) : null };
  res.json({ role, mode: "paper", on: MP.on, fast, startedAt: MP.startedAt, solUsd: sol, settings: MP.settings,
    feed: { ...MP.feed, subId: undefined, perMin: MP.launchTimes.filter((t) => Date.now() - t < 60000).length }, tape: MP.tape.slice(0, 30), seen: MP.seen, queued: MP.queue.length,
    stats: { trades: done.length, wins, winRate: done.length ? Math.round((wins / done.length) * 100) : null, pnlSol: +pnl.toFixed(4), pnlUsd: sol ? +(pnl * sol).toFixed(2) : null,
             best: done.length ? Math.max(...done.map((x) => x.pnlPct)) : null, worst: done.length ? Math.min(...done.map((x) => x.pnlPct)) : null },
    skips: MP.skips, open, closed: done.slice(0, 60), evaluated: MP.evaluated.slice(0, 60),
    bank, events: MP.events.slice(0, 20), learned: mpLearned(done, MP.settings.learnMin), filterReport,
    scorecard: mpScorecard(done.filter((x) => x.pnlUsd != null), MP.bank.start), lab: labPublic(),
    graduate: gradPublic(), copy: copyPublic(), experiments: expPublic(), grid: gridPublic(), top100: topPublic(), autopilot: mpAutoPublic(), goal: mpGoal(), rhythm: mpRhythm(), band: mpBandCached(), court: mpCourtCached(), daily: mpDaily(), signals: sigPublic(), storage: storageStatus(), ledger: ledPublic(), playbook: pbPublic(), gradIndex: gxPublic(), plan: mpPlan(),
    // CUSTODY: stated plainly, and enforced by the self-test (it fails if any key-holding or signing code is ever added)
    build: BUILD_ID,
    custody: { keysOnServer: false, canSign: false, canSend: false, mode: "paper", liveTrading: "locked", realMoneyMoved: 0, owner: OWNER_WALLET.slice(0, 4) + "…" + OWNER_WALLET.slice(-4) },
    diagnosis: mpDiagnose(done, MP.settings, sol || 150), strategy: mpStrategyText(MP.settings), grads: grStats(),
    watch: [...MP.watch.values()].slice(0, 15).map((w) => ({ mint: w.ev.mint, symbol: w.ev.symbol, name: w.ev.name, leftSec: Math.max(0, Math.round((w.until - Date.now()) / 1000)), flow: w.last || null })),
    sweet: (() => { const r = sweetCached(); return { ...r, recording: PATHS.live.size }; })() });
});

/** Owner: adopt the Sweet Spot now. */
app.post("/api/mp/sweetspot/apply", (req, res) => {
  if (!requireOwner(req, res)) return;
  const r = sweetCached(true);
  if (!r.ready) return res.status(400).json({ error: `Not enough data yet (${r.usable || 0} of ${r.need || 120} launches recorded).` });
  sweetApply(r, "applied by you"); res.json({ ok: true, settings: MP.settings });
});
/** Owner: every launch studied, with its traits, what happened, and its price path summary, as a spreadsheet file. */
app.get("/api/mp/data.csv", (req, res) => {
  if (!requireOwner(req, res)) return;
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="the-cannon-data-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(launchCsv());
});


app.get("/api/mp/ledger.csv", (req, res) => {
  if (!requireOwner(req, res)) return;
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="alkaid-token-ledger-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(ledCsv());
});

/** Owner-only: change the rules (numbers are clamped to sane ranges) */
function mpApplySettings(b) {
  const S = MP.settings;
  const clamp = (k, lo, hi) => { if (b[k] == null) return; const v = Number(b[k]); if (Number.isFinite(v)) S[k] = Math.min(hi, Math.max(lo, v)); };
  clamp("gradWorstPct", 20, 100); clamp("sizeByWorst", 0, 1);
  clamp("startUsd", 1, 100000); clamp("slots", 0, 30); clamp("maxLossPct", 0, 100); clamp("riskPct", 1, 50); clamp("minTradeUsd", 0.1, 1000); clamp("vaultAtX", 1.2, 100); clamp("keepX", 0.2, 50);
  clamp("tp1SellPct", 10, 100); clamp("trailPct", 5, 90); clamp("moonHoldMin", 5, 2880); clamp("smartBoost", 1, 3); clamp("favorBoost", 1, 3);
  clamp("maxBetPct", 2, 50); clamp("devExit", 0, 1); clamp("gradOn", 0, 1); clamp("gradWindowMin", 5, 120); clamp("gradMinLiq", 5000, 5e6); clamp("gradMinMcap", 20000, 5e6); clamp("gradMaxMcap", 50000, 5e7); clamp("gradBuys5", 3, 1000); clamp("gradBuyShare", 40, 95);
  clamp("gradMinCh5", -20, 100); clamp("gradMaxCh5", 5, 500); clamp("gradMinCh1", -90, 100); clamp("gradMaxOpen", 1, 10); clamp("gradTp", 10, 500); clamp("gradTp1Sell", 10, 100); clamp("gradSl", 5, 60); clamp("gradTrail", 5, 60); clamp("gradHold", 5, 720);
  clamp("copyOn", 0, 1); clamp("copyTopN", 1, 100); clamp("copyMinUsd", 20, 100000); clamp("copyMinWallets", 1, 10); clamp("copyMaxOpen", 1, 10); clamp("copyTp", 10, 500); clamp("copyTp1Sell", 10, 100); clamp("copySl", 5, 60); clamp("copyTrail", 5, 60); clamp("copyHold", 5, 720);
  clamp("gridOn", 0, 1); clamp("gridStartUsd", 10, 100000); clamp("gridMax", 1, 6); clamp("gridLevels", 2, 8); clamp("gridStepPct", 1, 30); clamp("gridHoldMin", 20, 1440); clamp("gridMinLiq", 20000, 1e7); clamp("gridFeePct", 0, 3); clamp("gridSlipPct", 0, 5);
  clamp("bandOn", 0, 1); clamp("bandBuyK", 8, 60); clamp("bandSellK", 10, 69); if (S.bandSellK <= S.bandBuyK) S.bandSellK = Math.min(69, S.bandBuyK + 5); clamp("bandStopPct", 5, 50); clamp("bandMaxImpactPct", 0.5, 10); clamp("dailyGoalUsd", 10, 1e7);
  clamp("sizeByRisk", 0, 1); clamp("riskPerTradePct", 0.1, 5); clamp("goalDailyPct", 0.05, 20); clamp("courtMinTrades", 30, 2000); clamp("courtMinDays", 1, 60); clamp("courtMaxDdPct", 3, 60);
  clamp("playbookOn", 0, 1); clamp("playbookStrict", 0, 1); clamp("gxMinRunners", 3, 200); clamp("gxMinTokens", 30, 5000);
  clamp("goalPerTrade", 0.1, 10000); clamp("goalWindow", 10, 500); clamp("rhythmOn", 0, 1); clamp("rhythmMinLift", 0.1, 3); clamp("paceMaxPerHour", 0, 100); clamp("ladderOn", 0, 1); clamp("gradMinLiqPct", 0, 100); clamp("gradMinVol24", 0, 1e8); clamp("gradMaxImpact", 0.5, 50); clamp("autopilot", 0, 1); clamp("autoFresh", 0, 1); clamp("autoSlots", 0, 1); clamp("ddBrake1Pct", 5, 90); clamp("ddBrake2Pct", 10, 95); clamp("killAvgPct", -90, -1); clamp("killMinTrades", 5, 100);
  clamp("momentum", 0, 1); clamp("momWindowMin", 1, 30); clamp("momBuyers60", 1, 200); clamp("momBuyShare", 30, 100); clamp("momNetSol", 0, 200); clamp("momRise2m", 0, 500); clamp("momMaxRise2m", 0, 2000); clamp("momMaxMcap", 6000, 1000000);
  clamp("autoTune", 0, 1); clamp("labFilter", 0, 1); clamp("labMinLift", 0.3, 5); clamp("labBoost", 1, 3); clamp("cashOutMcap", 0, 100000000); if (S.cashOutMcap > 0 && S.cashOutMcap < 10000) S.cashOutMcap = 10000; clamp("autoSend", 0, 1); clamp("trailAt5x", 3, 90); clamp("trailAt10x", 2, 90);
  if (typeof b.savingsWallet === "string") {
    const w = b.savingsWallet.trim();
    if (w === "") S.savingsWallet = "";
    else if (SOL_ADDR.test(w)) S.savingsWallet = w;
    else return { error: "That isn't a valid Solana wallet address." };
  }
  if (b.sendVault === true) mpSendVault("you tapped Send");
  if (typeof b.vaultToCash === "number" && b.vaultToCash > 0) {            // bring locked profit back into the trading pot
    const amt = +Math.min(MP.bank.vault, b.vaultToCash).toFixed(2);
    if (amt > 0) { MP.bank.vault = +(MP.bank.vault - amt).toFixed(2); MP.bank.cash = +(MP.bank.cash + amt).toFixed(2); mpEvent(`Moved $${amt.toFixed(2)} from the vault back to trading cash`); }
  }
  if (b.resume === true) { MP.bank.pausedUntil = 0; MP.bank.pauseWhy = null; MP.bank.streak = 0; mpEvent("You resumed trading"); }
  clamp("fastLane", 0, 1); clamp("fastMaxMcap", 3000, 100000); clamp("fastBetPct", 1, 25); clamp("fastMaxPerMin", 1, 20); clamp("fastMaxOpen", 1, 20);
  clamp("fastMaxDevPct", 0, 100); clamp("fastTimeoutSec", 30, 3600); clamp("fastMinGainPct", 0, 500);
  clamp("dailyStopPct", 5, 100); clamp("maxLossStreak", 2, 50); clamp("pauseMin", 5, 1440); clamp("learn", 0, 1); clamp("learnMin", 5, 200);
  if (S.keepX >= S.vaultAtX) S.keepX = Math.max(0.2, S.vaultAtX - 0.2);
  clamp("waitSec", 10, 900); clamp("minProgress", 0, 90); clamp("maxDevPct", 0, 100);
  clamp("maxTop10Pct", 5, 100); clamp("maxTop1Pct", 1, 100); clamp("tpPct", 5, 2000); clamp("slPct", 5, 95);
  clamp("maxHoldMin", 1, 1440); clamp("maxOpen", 1, 30); clamp("maxEvalPerMin", 1, 30);
  if (typeof b.on === "boolean") { MP.on = b.on; if (MP.on) mpConnect(); }
  if (b.profile === "v10" || b.profile === "v11") mpResetAll({ profile: b.profile });
  else if (b.reset === true) mpResetAll({ safe: b.safe === true });
  return { ok: true };
}
app.post("/api/mp/settings", (req, res) => {
  if (!requireOwner(req, res)) return;
  const r = mpApplySettings(req.body || {});
  if (r.error) return res.status(400).json({ error: r.error });
  res.json({ ok: true, settings: MP.settings, on: MP.on });
});


/*TG_BEGIN*/
// ═══════════════════════════════════════════════════════════════════════
// 📲 TELEGRAM BOT — status, positions, alerts, token lookup, and one-tap controls (owner only)
// ═══════════════════════════════════════════════════════════════════════
/**
 * Private by design: the bot talks only to chats you pair with a one-time code made on your dashboard.
 * Anyone else gets "this bot is private" and nothing else. Risky buttons (pause, resume, presets) ask first.
 * It reads Telegram by long polling, so it needs no public address and no extra packages.
 */
const MP_PRESETS = {
  defense: { slots: 10, tpPct: 60, tp1SellPct: 70, slPct: 20, trailPct: 20, trailAt5x: 12, trailAt10x: 8, dailyStopPct: 15, maxLossStreak: 3, pauseMin: 180, cashOutMcap: 80000, minProgress: 8, maxTop10Pct: 30, maxTop1Pct: 10, maxDevPct: 5, fastLane: 0, maxHoldMin: 20, learn: 1, labFilter: 1, labMinLift: 1.2, labBoost: 1.5, momentum: 1, momBuyers60: 10, momBuyShare: 65, momNetSol: 3, momRise2m: 20, momMaxMcap: 30000, gradOn: 1, gradSl: 12, gradMaxOpen: 2, copyOn: 0 },
  balanced: { slots: 10, tpPct: 100, tp1SellPct: 50, slPct: 30, trailPct: 25, trailAt5x: 15, trailAt10x: 10, dailyStopPct: 30, maxLossStreak: 5, pauseMin: 120, cashOutMcap: 100000, minProgress: 5, maxTop10Pct: 35, maxTop1Pct: 12, maxDevPct: 8, fastLane: 0, maxHoldMin: 30, learn: 1, labFilter: 0, labMinLift: 1, labBoost: 1.5, momentum: 1, momBuyers60: 8, momBuyShare: 60, momNetSol: 2, momRise2m: 15, momMaxMcap: 40000, gradOn: 1, gradSl: 15, gradMaxOpen: 3, copyOn: 0 },
  offense: { slots: 6, tpPct: 150, tp1SellPct: 40, slPct: 35, trailPct: 30, trailAt5x: 18, trailAt10x: 12, dailyStopPct: 40, maxLossStreak: 7, pauseMin: 60, cashOutMcap: 100000, minProgress: 4, maxTop10Pct: 40, maxTop1Pct: 15, maxDevPct: 10, fastLane: 1, maxHoldMin: 45, learn: 1, labFilter: 0, labMinLift: 1, labBoost: 2, momentum: 1, momBuyers60: 6, momBuyShare: 55, momNetSol: 1.5, momRise2m: 10, momMaxMcap: 60000, gradOn: 1, gradSl: 18, gradMaxOpen: 4, copyOn: 1 },
};
const TG = { on: false, running: false, gen: 0, err: null, abort: null, conflictGraceMs: 60000, me: null, offset: 0, pair: null, sent: [], hello: new Map(), chats: new Set((CONN.tgChats || []).map(String)), alerts: CONN.tgAlerts !== false };
const tgEsc = (x) => String(x == null ? "" : x).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const tgMoney = (n) => (n < 0 ? "−$" : "$") + Math.abs(+n || 0).toFixed(2);
const tgK = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "K" : String(Math.round(n || 0)));
const tgAgo = (t) => { const s = Math.max(0, Math.round((Date.now() - t) / 1000)); return s < 60 ? s + "s" : s < 3600 ? Math.round(s / 60) + "m" : Math.round(s / 3600) + "h"; };
async function tgApi(method, body, signal) {
  if (!CONN.tgToken) throw new Error("no token");
  const r = await withTimeout(fetch(`https://api.telegram.org/bot${CONN.tgToken}/${method}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}), ...(signal ? { signal } : {}) }), method === "getUpdates" ? 40000 : 12000, "telegram " + method);
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(j.description || "telegram " + r.status);
  return j.result;
}
async function tgSend(chat, text, kb) {
  const body = { chat_id: chat, text: String(text).slice(0, 3800), parse_mode: "HTML", disable_web_page_preview: true };
  if (kb) body.reply_markup = { inline_keyboard: kb };
  try { return await tgApi("sendMessage", body); }
  catch (e) {
    if (/parse|entit/i.test(e.message)) {                                  // formatting trouble: send it as plain text instead of losing it
      const plain = { ...body, text: String(text).replace(/<[^>]+>/g, "").slice(0, 3800) }; delete plain.parse_mode;
      return tgApi("sendMessage", plain).catch((e2) => log("error", `telegram send: ${e2.message}`));
    }
    log("error", `telegram send: ${e.message}`);
  }
}
/** Plain-English reason for a Telegram failure, and never the token itself. */
function tgFail(e) {
  const m = String((e && e.message) || e || "");
  if (/unauthorized|401|not found|404/i.test(m)) return "Telegram rejected the token: it's wrong or was revoked. Paste the NEWEST token from @BotFather.";
  if (/conflict|409|webhook/i.test(m)) return "Something else is using this bot (another server or a webhook). Use a fresh token from @BotFather (/revoke).";
  if (/timed out|fetch failed|network|ENOTFOUND|ECONN|EAI_AGAIN/i.test(m)) return "This server couldn't reach Telegram just now. It keeps retrying.";
  return "Telegram said: " + m.replace(/\d{6,12}:[A-Za-z0-9_-]{30,}/g, "[token]").slice(0, 120);
}
function tgBroadcast(text, kb) {
  if (!TG.on || !TG.alerts || !TG.chats.size) return;
  const now = Date.now(); TG.sent = TG.sent.filter((t) => now - t < 60000); if (TG.sent.length >= 25) return;     // never flood
  TG.sent.push(now); for (const c of TG.chats) tgSend(c, text, kb);
}
const TG_MENU = [
  [{ text: "🔬 Analyst", callback_data: "analyst" }, { text: "🏆 Top 20 at birth", callback_data: "top20" }],
  [{ text: "📊 Status", callback_data: "status" }, { text: "📈 Positions", callback_data: "positions" }],
  [{ text: "🔥 Hot launches", callback_data: "hot" }, { text: "🎓 Graduates", callback_data: "grads" }],
  [{ text: "📉 Why losing", callback_data: "why" }, { text: "🧭 Strategy", callback_data: "strategy" }],
  [{ text: "🏆 Top 100", callback_data: "top" }, { text: "🎯 Sweet spot", callback_data: "sweet" }],
  [{ text: "🏛️ Court", callback_data: "court" }, { text: "🎯 $3 goal", callback_data: "goal" }, { text: "🎵 Rhythm", callback_data: "rhythm" }],
  [{ text: "🗺️ Plan", callback_data: "plan" }, { text: "📒 Ledger", callback_data: "ledger" }, { text: "📘 Playbook", callback_data: "playbook" }, { text: "🎓 Index", callback_data: "index" }],
  [{ text: "📐 25K→30K", callback_data: "band" }, { text: "🔬 Signal Lab", callback_data: "signals" }, { text: "💾 Saved?", callback_data: "saved" }],
  [{ text: "📤 Export my data", callback_data: "export" }],
  [{ text: "📰 Morning report", callback_data: "report" }, { text: "🔄 Fresh start", callback_data: "ask:fresh" }],
  [{ text: "🧾 V1.0 test ($1,000 paper)", callback_data: "ask:v10" }, { text: "🧾 V1.1: risk 1% a trade", callback_data: "ask:v11" }],
  [{ text: "⏸ Pause", callback_data: "ask:pause" }, { text: "▶ Resume", callback_data: "ask:resume" }],
  [{ text: "🛡 Defense", callback_data: "ask:defense" }, { text: "⚖ Balanced", callback_data: "ask:balanced" }, { text: "⚔ Offense", callback_data: "ask:offense" }],
  [{ text: "🔔 Alerts on/off", callback_data: "alerts" }],
];
function tgBank() {
  const B = MP.bank, open = MP.positions.reduce((a, p) => a + (p.tokensLeft == null ? p.tokens : p.tokensLeft) * p.last * (1 - MP.settings.feePct / 100), 0);
  return { B, total: B.cash + B.vault + (B.sent || 0) + open, open };
}
function tgStatus() {
  const S = MP.settings, { B, total } = tgBank(), paused = B.pausedUntil > Date.now() ? B.pauseWhy : null, perMin = MP.launchTimes.filter((t) => Date.now() - t < 60000).length;
  return `📊 <b>${TG_NAME}</b> · paper money\nTotal <b>${tgMoney(total)}</b> (started ${tgMoney(B.start)}, ${total >= B.start ? "+" : ""}${(((total / B.start) - 1) * 100).toFixed(1)}%)\n` +
    `Trading cash ${tgMoney(B.cash)} · Vault ${tgMoney(B.vault)} · Sent to savings ${tgMoney(B.sent || 0)}\nToday <b>${tgMoney(B.dayPnl || 0)}</b>\n` +
    `Open trades ${MP.positions.length}/${S.slots > 0 ? S.slots : S.maxOpen} · watching ${MP.watch.size} launches for momentum\n` +
    `Last launch ${MP.feed.lastEventAt ? tgAgo(MP.feed.lastEventAt) + " ago" : "—"} · ${perMin} a minute\n` +
    `Entries: ${S.momentum ? "momentum" : "buy at 90s"}${S.gradOn ? " · graduates" : ""}${S.copyOn ? " · copy" : ""}${S.fastLane ? " · launch shot" : ""}\n` +
    `State: ${paused ? "⏸ <b>PAUSED</b> (" + tgEsc(paused) + ")" : MP.on ? "🟢 <b>TRADING</b>" : "⏸ <b>OFF</b>"}`;
}
function tgPositions() {
  if (!MP.positions.length) return "📈 No open trades right now.";
  return "📈 <b>Open trades</b>\n\n" + MP.positions.slice(0, 10).map((p) => { const ch = ((p.last / p.entry) - 1) * 100;
    return `${ch >= 0 ? "🟢" : "🔴"} <b>${tgEsc(p.symbol)}</b> ${ch >= 0 ? "+" : ""}${ch.toFixed(1)}% · ${tgMoney(p.sizeUsd)} · ${tgEsc(p.entryType || "")}${p.phase === "moon" ? " · 🌙 riding" : ""}\n${p.mcapNow ? "cap $" + tgK(p.mcapNow) + " · " : ""}${tgAgo(p.openedAt)}\n<code>${p.mint}</code>`; }).join("\n\n");
}
function tgHot() {
  const L = labPublic(), rows = (L.hot || []).slice(0, 6);
  if (!rows.length) return "🔥 Nothing scored yet. Check again in a few minutes.";
  return `🔥 <b>Hot right now</b> (scored at 90s${L.starter ? ", starting guesses" : ""})\n\n` + rows.map((x) => `<b>${tgEsc(x.symbol)}</b> ${tgEsc(x.name || "")}\n${x.lift}× usual odds (~${x.oddsPct}%) · ${x.progress}% bonded · $${tgK(x.mcap)}\n<code>${x.mint}</code>`).join("\n\n");
}
function tgGrads() {
  const G = grStats(), gp = gradPublic();
  return `🎓 <b>Last 24h</b>: ${G.launches24h.toLocaleString()} launches · ${G.grads24h} graduated (${G.gradRatePct == null ? "—" : G.gradRatePct + "%"})${G.medianMinsToGrad != null ? " · median " + G.medianMinsToGrad + " min" : ""}\n` +
    `Graduate strategy: ${gp.on ? "ON" : "off"} · ${gp.trades} trades · ${tgMoney(gp.pnlUsd)} · ${gp.open} open · watching ${gp.watching.length}\n\n` +
    (G.recent.slice(0, 5).map((x) => `${x.held ? "✅ held" : x.judged ? "👀 saw" : "⚪ missed"} <b>${tgEsc(x.symbol || "?")}</b> · ${tgAgo(x.at)} ago${x.mins != null ? " · " + x.mins + " min after launch" : ""}\n<code>${x.mint}</code>`).join("\n\n") || "No graduations yet.");
}
function tgWhy() {
  const D = mpDiagnose(MP.closed, MP.settings, solUsd.v || 150);
  return `📉 <b>Why you're ${D.winRate != null && D.winRate >= 50 ? "doing OK" : "losing"}</b>\n${D.trades} closed trades${D.winRate != null ? " · " + D.winRate + "% wins · winners vs losers " + D.profitFactor + "×" : ""}\n\n` + D.findings.slice(0, 4).map((f) => (f.level === "bad" ? "❌ " : f.level === "good" ? "✅ " : "ℹ️ ") + tgEsc(f.text) + (f.fixText ? `\n   <i>Fix: ${tgEsc(f.fixText)} (dashboard)</i>` : "")).join("\n\n");
}
function tgStrategy() { return "🧭 <b>The strategy</b>\n\n" + mpStrategyText(MP.settings).map((t) => { const i = t.indexOf(":"); return `<b>${tgEsc(t.slice(0, i))}</b>${tgEsc(t.slice(i))}`; }).join("\n\n"); }
function tgTop() {
  const T = topPublic(); if (!T.count) return "🏆 The top-100 recorder is still collecting. Check again in a few minutes.";
  const st = T.stats;
  return `🏆 <b>Top 100 trending</b> · ${T.tracked} tracked\nNew in the last 24h: ${st.newEntries24h} · typical entry: cap $${tgK(st.medianMcapAtEntry || 0)}, ${st.medianAgeMinAtEntry != null ? st.medianAgeMinAtEntry + " min old" : "age ?"}, ${st.medianBuyShare != null ? st.medianBuyShare + "% buys" : ""}\nWe had seen ${st.sawBeforePct == null ? "—" : st.sawBeforePct + "%"} of them before they listed${st.medianLeadMin != null ? " (median " + st.medianLeadMin + " min earlier)" : ""}\n\n` +
    T.list.slice(0, 8).map((p) => `${p.rank}. <b>${tgEsc(p.sym)}</b> $${tgK(p.mcap)} · 1h ${p.ch1 > 0 ? "+" : ""}${p.ch1}%\n<code>${p.addr}</code>`).join("\n");
}
function tgSweet() {
  const r = sweetCached(); if (!r.ready) return `🎯 Still recording (${r.usable || 0} of ${r.need || 120} launches). The first result comes after about an hour.`;
  return `🎯 <b>Sweet spot</b> ${r.trustworthy ? "✅ proven on both halves" : "⚠️ not proven yet"}\nYour rules: ${r.current.avgPct}% per trade · sweet spot: ${r.best.avgPct}% per trade (${r.best.trades} trades, ${r.best.winRate}% wins)\nTake profit +${r.settings.tpPct}% · sell ${r.settings.tp1SellPct}% · stop −${r.settings.slPct}% · trail ${r.settings.trailPct}% · hold ${r.settings.maxHoldMin}m\n<i>Past results on recorded paths, not a promise. Apply it on the dashboard.</i>`;
}
function tgDailyLine() {
  const d = mpDaily(); if (!d.nDays) return `\n\n📆 Daily goal +${d.target}% (that is ${d.yearlyMultiple}× a year; the best fund in history averaged roughly 0.15 to 0.2% a day).`;
  return `\n\n📆 <b>Daily return</b> (goal +${d.target}%): averaging <b>${d.avgPct >= 0 ? "+" : ""}${d.avgPct}%</b> a day over ${d.nDays} day${d.nDays === 1 ? "" : "s"} · ${d.hit} reached the goal · best ${d.best}% · worst ${d.worst}%.\n` +
    `At ${d.tradesPerDay} trades a day and ${d.riskPct}% risked per trade, +${d.target}% a day needs about <b>+${d.needR}R</b> per trade (R = what the stop risks)${d.avgR != null ? `. You are at <b>${d.avgR >= 0 ? "+" : ""}${d.avgR}R</b>` : ""}.`;
}
function tgGoal() {
  const g = mpGoal(); if (!g.n) return `🎯 <b>Goal: $${g.goal} per trade</b>, judged over the latest ${g.window} trades.\n\nNo trades yet.` + tgDailyLine();
  return `🎯 <b>Goal: $${g.goal} per trade</b> (latest ${g.n} of ${g.window})\nAverage <b>${g.avg >= 0 ? "$" : "−$"}${Math.abs(g.avg).toFixed(2)}</b> per trade · ${g.avgPct}% · ${g.winRate}% won · total ${g.total >= 0 ? "+$" : "−$"}${Math.abs(g.total).toFixed(2)}\n` +
    (g.tradesPerDay ? `Pace ${g.tradesPerDay} trades a day, about ${g.projectedPerDay >= 0 ? "+$" : "−$"}${Math.abs(g.projectedPerDay).toFixed(2)} a day at this rate.\n` : "") + `\n${g.verdict.replace(/[<>&]/g, "")}` + tgDailyLine();
}
function tgRhythm() {
  const r = mpRhythm(); if (!r.ready) return `🎵 <b>Rhythm</b>: still learning (${r.hoursOfData} hours of launches recorded). It needs about 2 days before it can say which times of day are better.`;
  return `🎵 <b>Rhythm</b> (UTC; 13:00 UTC = 8 am Central)\nAverage launch graduates ${r.basePct}% of the time.\n` + r.rows.map((x) => `${x.lift == null ? "⚪" : x.lift >= 1.15 ? "🟢" : x.lift <= 0.85 ? "🔴" : "🟡"} ${x.block}: ${x.lift == null ? "not enough data" : x.lift + "× average"}${x.trades ? ` · ${x.trades} of our trades, ${x.avgPct}% each` : ""}`).join("\n") +
    `\n\nBest: ${r.best.block} (${r.best.lift}×) · worst: ${r.worst.block} (${r.worst.lift}×) · right now: ${r.nowBlock} (${r.nowLift == null ? "?" : r.nowLift + "×"})`;
}
function tgVault() { const B = MP.bank; return `🔒 Vault ${tgMoney(B.vault)} · sent to savings ${tgMoney(B.sent || 0)}\nMove vault money back to trading cash from the dashboard (Money section).`; }
/** Paste any Solana token address and get the safety scan. */
async function tgLookup(addr) {
  const base = `http://127.0.0.1:${PORT}`;
  const [rk, tk] = await Promise.allSettled([fetch(`${base}/api/risk/solana/${addr}`).then((r) => r.json()), fetch(`${base}/api/token/${addr}`).then((r) => r.json())]);
  const r = rk.status === "fulfilled" ? rk.value : null, t = tk.status === "fulfilled" ? tk.value : null;
  if (!r || r.error) return { text: "❔ I couldn't scan that address right now. Try again in a minute." };
  const icon = { DANGER: "🚨", RISKY: "⚠️", CAUTION: "🟡", PASSED: "🟢", UNVERIFIED: "❔" }[r.verdict] || "❔", lv = { danger: "🚨", risk: "⚠️", caution: "🟡" };
  const text = `${icon} <b>${tgEsc(r.verdict)}</b> · ${tgEsc(r.symbol || (t && t.symbol) || "?")} ${tgEsc(r.name || (t && t.name) || "")}${r.score != null ? " · score " + r.score + "/100" : ""}\n` +
    (t && t.price ? `Price $${t.price < 0.01 ? t.price.toPrecision(3) : t.price.toFixed(4)} · cap $${tgK(t.mcap || 0)} · liquidity $${tgK(t.liq || 0)} · vol 24h $${tgK(t.vol24 || 0)}\n` : "") +
    ((r.flags || []).slice(0, 6).map((f) => `${lv[f.level] || "•"} ${tgEsc(f.text)}`).join("\n") || "No warning signs found.") + (typeof anBirthLine === "function" && anBirthLine(addr) ? "\n\n" + tgEsc(anBirthLine(addr)) : "") + `\n\n<code>${tgEsc(addr)}</code>`;
  return { text, kb: [[{ text: "📈 Chart", url: `https://dexscreener.com/solana/${addr}` }, { text: "🔎 Full scan", url: `https://cryptobizmo2.github.io/SLAPBOT/?scan=${addr}` }]] };
}
async function tgAct(chat, what) {
  if (what === "pause") { MP.bank.pausedUntil = Date.now() + 24 * 3600e3; MP.bank.pauseWhy = "paused from Telegram"; mpEvent("Paused from Telegram: no new trades (open ones are still managed)"); return "⏸ Paused. No new trades; open trades are still managed. Tap Resume to continue."; }
  if (what === "resume") { MP.bank.pausedUntil = 0; MP.bank.pauseWhy = null; MP.bank.streak = 0; MP.on = true; mpConnect(); mpEvent("Resumed from Telegram"); return "▶ Trading again."; }
  if (what === "v11") { mpResetAll({ profile: "v11" }); return `🧾 <b>V1.1 test started.</b> A fresh <b>$${MP.settings.startUsd.toLocaleString()}</b> paper account that risks <b>${MP.settings.riskPerTradePct}% of all the money per trade</b>: each bet is sized from its stop-loss (about $${(MP.settings.startUsd * MP.settings.riskPerTradePct / 100 / ((MP.settings.slPct + 2 * (MP.settings.feePct + MP.settings.slippagePct)) / 100)).toFixed(0)} with a ${MP.settings.slPct}% stop, costs included). At most ${MP.settings.maxOpen} positions, ${MP.settings.dailyStopPct}% daily loss limit, strict safety checks, staged exits.`; }
  if (what === "v10") { mpResetAll({ profile: "v10" }); return `🧾 <b>V1.0 test started.</b> A fresh <b>$${MP.settings.startUsd.toLocaleString()}</b> paper account: 1% per trade (about $${(MP.settings.startUsd * MP.settings.riskPct / 100).toFixed(0)}), at most ${MP.settings.maxOpen} positions, ${MP.settings.dailyStopPct}% daily loss limit, strict safety checks, staged exits (+20% / +35% / +60%, then a trailing stop). The old run was saved as a summary.`; }
  if (what === "fresh") { mpResetAll({ safe: true }); return `🔄 <b>Fresh start.</b> New paper account with <b>$${MP.settings.startUsd}</b> on the safe profile. The old run was saved as a summary (see 📰 Morning report).`; }
  if (MP_PRESETS[what]) { mpApplySettings(MP_PRESETS[what]); mpEvent(`${what[0].toUpperCase() + what.slice(1)} preset applied from Telegram`); return `✅ <b>${what[0].toUpperCase() + what.slice(1)}</b> is on. It applies to the next launch.`; }
  return "Unknown action.";
}
async function tgCallback(chat, data) {
  if (data === "export") return tgExport(chat);
  const views = { analyst: tgAnalyst, top20: tgTop20, status: tgStatus, positions: tgPositions, hot: tgHot, grads: tgGrads, why: tgWhy, strategy: tgStrategy, top: tgTop, sweet: tgSweet, vault: tgVault, report: mpReportText, goal: tgGoal, rhythm: tgRhythm, band: tgBand, court: tgCourt, signals: tgSignals, saved: tgSaved, plan: tgPlan, ledger: tgLedger, playbook: tgPlaybook, index: tgIndex };
  if (views[data]) return tgSend(chat, views[data](), TG_MENU);
  if (data === "alerts") { TG.alerts = !TG.alerts; CONN.tgAlerts = TG.alerts; saveConn(); return tgSend(chat, TG.alerts ? "🔔 Alerts are ON." : "🔕 Alerts are OFF.", TG_MENU); }
  if (data.startsWith("ask:")) { const w = data.slice(4); return tgSend(chat, `Are you sure you want to <b>${tgEsc(w)}</b>?`, [[{ text: "✅ Yes, " + w, callback_data: "do:" + w }, { text: "✖ Cancel", callback_data: "no" }]]); }
  if (data.startsWith("do:")) return tgSend(chat, await tgAct(chat, data.slice(3)), TG_MENU);
  if (data === "no") return tgSend(chat, "Cancelled.", TG_MENU);
}
const tgSafeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
async function tgHandle(u) {
  const cb = u.callback_query, msg = u.message || (cb && cb.message); if (!msg || !msg.chat) return;
  const chat = String(msg.chat.id), allowed = TG.chats.has(chat), text = String((u.message && u.message.text) || "").trim();
  if (cb) { await tgApi("answerCallbackQuery", { callback_query_id: cb.id }).catch(() => {}); if (!allowed) return; return tgCallback(chat, String(cb.data || "")); }
  if (/^\/start\b/i.test(text)) {
    const code = (text.split(/\s+/)[1] || "").toUpperCase();
    if (allowed) return tgSend(chat, "👋 Welcome back. Pick something:", TG_MENU);
    if (TG.pair && Date.now() < TG.pair.exp && code && tgSafeEq(code, TG.pair.code)) {
      TG.chats.add(chat); CONN.tgChats = [...TG.chats]; saveConn(); TG.pair = null; mpEvent("Telegram paired with your phone"); tgCommandsFor(chat);
      return tgSend(chat, "✅ <b>You're connected to " + TG_NAME + ".</b>\nAlerts are on: every buy, sell, pause, and vault lock. Paste any Solana token address to scan it.", TG_MENU);
    }
  }
  if (!allowed) {                                                         // strangers get one polite line, at most every 10 minutes, and nothing else
    const last = TG.hello.get(chat) || 0; if (Date.now() - last < 600000) return; TG.hello.set(chat, Date.now()); if (TG.hello.size > 500) TG.hello.delete(TG.hello.keys().next().value);
    return tgSend(chat, /^\/start\b/i.test(text) ? "🔒 This bot is private. To connect your phone: open your ALKAID dashboard, go to Connections, tap Make a pairing code, then tap the green Open Telegram button it shows." : "🔒 This bot is private.");
  }
  const cmd = text.split(/[\s@]/)[0].toLowerCase(), arg = text.split(/\s+/)[1] || "";
  const views = { "/analyst": tgAnalyst, "/top20": tgTop20, "/status": tgStatus, "/positions": tgPositions, "/hot": tgHot, "/graduates": tgGrads, "/grads": tgGrads, "/why": tgWhy, "/strategy": tgStrategy, "/top": tgTop, "/sweet": tgSweet, "/vault": tgVault, "/report": mpReportText, "/goal": tgGoal, "/rhythm": tgRhythm, "/band": tgBand, "/court": tgCourt, "/signals": tgSignals, "/saved": tgSaved, "/plan": tgPlan, "/ledger": tgLedger, "/playbook": tgPlaybook, "/index": tgIndex };
  if (cmd === "/export") return tgExport(chat);
  if (views[cmd]) return tgSend(chat, views[cmd](), TG_MENU);
  if (cmd === "/pause" || cmd === "/resume" || cmd === "/defense" || cmd === "/balanced" || cmd === "/offense" || cmd === "/fresh" || cmd === "/v10" || cmd === "/v11") return tgCallback(chat, "ask:" + cmd.slice(1));
  if (cmd === "/alerts") { TG.alerts = !/^off$/i.test(arg); CONN.tgAlerts = TG.alerts; saveConn(); return tgSend(chat, TG.alerts ? "🔔 Alerts are ON." : "🔕 Alerts are OFF.", TG_MENU); }
  if (cmd === "/birth") return tgSend(chat, SOL_ADDR.test(arg) ? tgBirth(arg) : "🔬 Send /birth, a space, then the token address.", TG_MENU);
  const addr = SOL_ADDR.test(text) ? text : (cmd === "/lookup" || cmd === "/scan") && SOL_ADDR.test(arg) ? arg : null;
  if (addr) { await tgApi("sendChatAction", { chat_id: chat, action: "typing" }).catch(() => {}); const r = await tgLookup(addr); return tgSend(chat, r.text, r.kb); }
  return tgSend(chat, "Pick something, or paste a Solana token address to scan it:", TG_MENU);
}
/** The bot's name card and command menu, set automatically. Commands are shown only to paired phones; strangers see none. */
const TG_DESC = TG_NAME + " · private trading assistant.\n\nLive alerts, open positions, strategy reports and token safety scans for its owner.\n\nThis bot is private: it only answers phones paired from the owner's dashboard.";
const TG_SHORT = TG_NAME + " · private trading alerts and token safety scans.";
const TG_COMMANDS = [
  { command: "analyst", description: "What top-20 tokens had at birth" }, { command: "top20", description: "Top 20 now, with each one's birth record" },
  { command: "birth", description: "Birth record: /birth then the address" },
  { command: "status", description: "Balance, today, open trades" }, { command: "positions", description: "Open trades with live profit or loss" },
  { command: "hot", description: "Hottest launches right now" }, { command: "graduates", description: "Recent graduations" },
  { command: "why", description: "Why it's winning or losing" }, { command: "strategy", description: "What the bot is doing" },
  { command: "top", description: "Top 100 trending" }, { command: "sweet", description: "Best-performing rules" },
  { command: "vault", description: "Vault and savings" }, { command: "report", description: "24-hour report" }, { command: "goal", description: "Progress to the per-trade profit goal" }, { command: "rhythm", description: "Best and worst times of day" }, { command: "band", description: "Does buying at 25K and selling at 30K work?" }, { command: "court", description: "Strategy Court: is anything proven?" }, { command: "signals", description: "Signal Lab: what actually works" }, { command: "saved", description: "Is everything being saved?" }, { command: "export", description: "Send me all my data as spreadsheets" }, { command: "plan", description: "The game plan and where we are" }, { command: "ledger", description: "Win/loss row for every token" }, { command: "playbook", description: "Patterns kept forever, and lessons" }, { command: "index", description: "Graduate Index: hold every graduate" }, { command: "fresh", description: "New paper account on the safe profile" }, { command: "v10", description: "Start the V1.0 test ($1,000 paper)" }, { command: "v11", description: "Start V1.1: risk 1% of the money per trade" }, { command: "pause", description: "Stop new trades" },
  { command: "resume", description: "Start trading again" }, { command: "defense", description: "Safer settings" },
  { command: "balanced", description: "Default settings" }, { command: "offense", description: "Bolder settings" },
  { command: "alerts", description: "Turn alerts on or off" }, { command: "scan", description: "Scan a token: /scan then the address" },
  { command: "menu", description: "Show the buttons" },
];
const tgCommandsFor = (chat) => tgApi("setMyCommands", { commands: TG_COMMANDS, scope: { type: "chat", chat_id: Number(chat) } }).catch(() => {});
async function tgProfile() {
  await tgApi("setMyName", { name: TG_NAME }).catch(() => {});             // the name people see; the @username itself can only be changed in BotFather
  await tgApi("setMyDescription", { description: TG_DESC }).catch(() => {});
  await tgApi("setMyShortDescription", { short_description: TG_SHORT }).catch(() => {});
  await tgApi("deleteMyCommands", {}).catch(() => {});                   // the public sees no command list
  for (const c of TG.chats) await tgCommandsFor(c);                       // paired phones get the full menu
}
/** Stop listening: retire the current listener and cancel the request it's waiting on, so Telegram never sees two at once. */
function tgStop() {
  TG.gen++;
  if (TG.abort) { try { TG.abort.abort(); } catch {} TG.abort = null; }
  TG.running = false; TG.on = false;
}
/**
 * Connect: check the token with Telegram (getMe), then start listening in the background.
 * Resolves as soon as Telegram has answered, so the dashboard gets its reply right away.
 */
async function tgLoop() {
  tgStop();                                                               // never two listeners
  if (!CONN.tgToken) return false;
  const gen = TG.gen; TG.running = true; TG.err = null;
  try {
    const me = await tgApi("getMe"); if (gen !== TG.gen) return false;
    TG.me = me; await tgApi("deleteWebhook", { drop_pending_updates: false }).catch(() => {});
  } catch (e) {
    if (gen === TG.gen) { TG.err = tgFail(e); TG.running = false; TG.on = false; log("error", `telegram: ${TG.err}`); }
    return false;
  }
  if (gen !== TG.gen) return false;
  TG.on = true; TG.err = null; log("alkaid", `Telegram bot @${TG.me.username} is on`);
  tgProfile().catch(() => {});                                            // description + command menu, every time it connects
  tgListen(gen).catch(() => {});                                          // runs in the background
  return true;
}
async function tgListen(gen) {
  let conflictSince = 0;
  while (gen === TG.gen && CONN.tgToken) {
    const ac = typeof AbortController === "function" ? new AbortController() : null; TG.abort = ac;
    try {
      const ups = await tgApi("getUpdates", { offset: TG.offset, timeout: 25, allowed_updates: ["message", "callback_query"] }, ac ? ac.signal : undefined);
      if (gen !== TG.gen) break;
      TG.err = null; conflictSince = 0;
      for (const u of ups) { TG.offset = u.update_id + 1; await tgHandle(u).catch((e) => log("error", `telegram handler: ${e.message}`)); }
    } catch (e) {
      if (gen !== TG.gen) break;                                          // this listener was retired on purpose: stop quietly
      const why = tgFail(e);
      if (/Something else is using/.test(why)) {
        // usually just the previous listener's request winding down: only report it if it keeps happening
        if (!conflictSince) conflictSince = Date.now();
        if (Date.now() - conflictSince >= TG.conflictGraceMs) TG.err = why;
        await new Promise((r) => setTimeout(r, 2000));
      } else {
        TG.err = why;
        if (/rejected the token/.test(why)) { TG.on = false; break; }
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }
  if (gen === TG.gen) { TG.running = false; TG.on = false; }
}
setInterval(() => {                                                       // every morning at 13:00 UTC (8 am US Central): the 24-hour report, once
  try { const d = new Date(), day = d.toISOString().slice(0, 10);
    if (TG.on && TG.chats.size && d.getUTCHours() === 13 && TG.reportDay !== day) { TG.reportDay = day; tgBroadcast(mpReportText(), TG_MENU); } } catch {}
}, 60e3);
if (CONN.tgToken) setTimeout(() => { tgLoop().catch(() => {}); }, 6000);
// alerts
function tgTradeOpened(p) { tgBroadcast(`🟢 <b>BOUGHT ${tgEsc(p.symbol)}</b> · ${tgEsc(p.entryType || "")}\n${tgMoney(p.sizeUsd)}${p.mcapAtBuy ? " at $" + tgK(p.mcapAtBuy) + " cap" : ""}\n${tgEsc((p.boosts || []).join(" · "))}\n<code>${p.mint}</code>`); }
function tgTradeClosed(p, why, pnl) { tgBroadcast(`${pnl >= 0 ? "✅" : "🔴"} <b>SOLD ${tgEsc(p.symbol)}</b> ${tgMoney(pnl)}\n${tgEsc(why)}\n<code>${p.mint}</code>`); }
function tgEvent(text) { if (/vault|paused|stopped|rug zone|sweet spot|moved|resumed|savings|started fresh|autopilot|ran out|playbook/i.test(text) && !/hit \+/.test(text)) tgBroadcast("ℹ️ " + tgEsc(text)); }
function tgGraduated(mint) { const p = MP.positions.find((x) => x.mint === mint); if (p) tgBroadcast(`🎓 <b>${tgEsc(p.symbol)} just graduated</b> (we hold it)\n<code>${mint}</code>`); }

/** Send a file to a chat. Telegram wants a multipart upload for files, not JSON. */
async function tgSendDoc(chat, filename, text, caption) {
  if (!CONN.tgToken) throw new Error("no token");
  const fd = new FormData(); fd.append("chat_id", String(chat)); if (caption) fd.append("caption", String(caption).slice(0, 900));
  fd.append("document", new Blob([text], { type: "text/csv" }), filename);
  const r = await withTimeout(fetch(`https://api.telegram.org/bot${CONN.tgToken}/sendDocument`, { method: "POST", body: fd }), 60000, "sendDocument");
  const j = await r.json().catch(() => ({})); if (!j.ok) throw new Error(j.description || "telegram " + r.status);
  return j.result;
}
const TG_DOC_GAP = { ms: 900, last: 0 };                                          // Telegram allows about one message a second to a chat
async function tgExport(chat) {
  const now = Date.now();
  if (now - TG_DOC_GAP.last < 60e3) return tgSend(chat, "📤 I just sent the files. Give it a minute and tap again.", TG_MENU);
  TG_DOC_GAP.last = now;
  const files = [["fuflopbot-launches.csv", launchCsv(), "Every judged launch: what it looked like at 90 seconds and how it ended"], ["fuflopbot-paths.csv", pathsCsv(), "The full price path of each one (every 15 seconds, up to 45 minutes)"],
    ["fuflopbot-signals.csv", signalsCsv(), "Every momentum signal and how each exit style would have done"], ["fuflopbot-ledger.csv", ledCsv(), "A win/loss row for every token, with the bot's decision"], ["fuflopbot-trades.csv", tradesCsv(), "Every closed paper trade"],
    ["fuflopbot-index.csv", gxCsv(), "Every graduate followed for 7 days, with its price path (for testing hold and dip-buy over days)"],
    ["fuflopbot-births.csv", anCsv(), "Analyst: every launch's birth record (creator wallet, funder, first-second buyers, 90-second numbers) and whether it reached the top 20 or graduated within 24 hours. For fair rates use only rows with in_sample=1 and final=1."]];
  await tgSend(chat, `📤 Sending ${files.length} spreadsheets. This takes about ${Math.ceil((files.length * (TG_DOC_GAP.ms + 600)) / 1000)} seconds.`);
  let sent = 0;
  for (const [name, text, cap] of files) {
    const rows = Math.max(0, text.split("\n").length - 1);
    for (let attempt = 0; attempt < 2; attempt++) {
      try { await tgSendDoc(chat, name, text, `${cap}\n${rows.toLocaleString()} rows`); sent++; break; }
      catch (e) { const m = /retry after (\d+)/i.exec(e.message || ""); if (m && attempt === 0) { await new Promise((r) => setTimeout(r, (+m[1] + 1) * 1000)); continue; } await tgSend(chat, `⚠️ Couldn't send ${name}: ${tgEsc(e.message)}`); break; }
    }
    await new Promise((r) => setTimeout(r, TG_DOC_GAP.ms));
  }
  return tgSend(chat, `✅ Sent ${sent} of ${files.length}.\n\nTo get them to Claude: open each file, tap the share icon, choose <b>Save to Files</b>, then attach them in your chat with Claude.`, TG_MENU);
}
/*TG_END*/

/*CONN_BEGIN*/
// ═══ 🔌 CONNECTIONS (owner only): faster RPC, call meter, Telegram pairing ═══
try { const f = CONN_DIR ? nodePath.join(CONN_DIR, "rpc-meter.json") : ""; if (f && nodeFs.existsSync(f)) { const d = JSON.parse(nodeFs.readFileSync(f, "utf8")), now = new Date().toISOString();
  if (d.month === now.slice(0, 7)) { RPC.month = d.month; RPC.monthN = d.monthN || 0; } if (d.day === now.slice(0, 10)) { RPC.day = d.day; RPC.n = d.n || 0; RPC.by = d.by || {}; } } } catch {}
setInterval(() => { try { const f = CONN_DIR ? nodePath.join(CONN_DIR, "rpc-meter.json") : ""; if (f) nodeFs.writeFileSync(f, JSON.stringify(RPC)); } catch {} }, 5 * 60e3);
const maskTail = (v) => (v ? "…" + String(v).slice(-4) : "");
function connPublic() {
  let host = ""; try { host = new URL(SOLANA_RPC_URL).hostname; } catch {}
  return { rpc: { own: !!CONN.rpcUrl, using: host, today: RPC.n, month: RPC.monthN, cap: CONN.rpcDailyCap || 0, capHit: !rpcBudgetOk(), top: Object.entries(RPC.by).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([m, n]) => ({ m, n })) },
    telegram: { set: !!CONN.tgToken, bot: TG.me ? TG.me.username : null, on: TG.on, paired: TG.chats.size, alerts: TG.alerts, error: TG.err || null, saved: !!CONN_FILE,
      code: TG.pair && Date.now() < TG.pair.exp ? TG.pair.code : null,
      link: TG.pair && Date.now() < TG.pair.exp && TG.me ? `https://t.me/${TG.me.username}?start=${TG.pair.code}` : null } };
}
app.get("/api/mp/connections", (req, res) => { if (!requireOwner(req, res)) return; res.json(connPublic()); });
/** Owner-only: the Analyst's study, the top 20 with birth records, and every birth record as a spreadsheet. */
app.get("/api/mp/analyst", (req, res) => { if (!requireOwner(req, res)) return; res.json(anPublic()); });
app.get("/api/mp/births.csv", (req, res) => {
  if (!requireOwner(req, res)) return;
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="fuflopbot-births-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(anCsv());
});
app.post("/api/mp/connections", async (req, res) => {
  if (!requireOwner(req, res)) return;
  const b = req.body || {};
  if (!CONN_FILE) return res.status(400).json({ error: "This server has no saved storage, so connections can't be kept. (It should on your AWS server.)" });
  let restart = false;
  if (typeof b.rpcUrl === "string") {
    const v = b.rpcUrl.trim();
    if (v === "") { delete CONN.rpcUrl; restart = true; }
    else { let u; try { u = new URL(v); } catch { return res.status(400).json({ error: "That isn't a valid web address." }); }
      if (u.protocol !== "https:" || v.length > 400) return res.status(400).json({ error: "Use the full https:// address your provider gave you." });
      CONN.rpcUrl = v; restart = true; }
  }
  if (b.rpcDailyCap != null) { const n = Number(b.rpcDailyCap); if (Number.isFinite(n) && n >= 0 && n <= 1e8) CONN.rpcDailyCap = Math.round(n); }
  if (typeof b.tgToken === "string" && b.tgToken.trim()) {
    // accept the whole BotFather message, or just the token: pick the token out of whatever was pasted
    const m = b.tgToken.match(/\d{5,12}:[A-Za-z0-9_-]{30,60}/);
    if (!m) return res.status(400).json({ error: "I couldn't find a bot token in what you pasted. In BotFather, copy the message that has your token (it contains something like 123456789:ABC…) and paste it here." });
    const v = m[0];
    CONN.tgToken = v; TG.me = null; TG.err = null; TG.offset = 0;
    saveConn(); await tgLoop().catch(() => {});                           // returns as soon as Telegram has answered, so the reply below already knows
  }
  if (b.tgTest === true) {
    if (!TG.chats.size) return res.status(400).json({ error: "No phone is paired yet. Tap Make a pairing code first." });
    const sent = await Promise.all([...TG.chats].map((c) => tgApi("sendMessage", { chat_id: c, text: "✅ Test from " + TG_NAME + ": Telegram is working. You'll get an alert here for every buy, sell, pause and vault lock." }).then(() => true).catch((e) => { TG.err = tgFail(e); return false; })));
    return res.json({ ok: sent.some(Boolean), sent: sent.filter(Boolean).length, ...connPublic(), error: sent.some(Boolean) ? undefined : (TG.err || "Couldn't send.") });
  }
  if (b.tgNewCode === true) { if (!CONN.tgToken) return res.status(400).json({ error: "Add your Telegram bot token first." }); TG.pair = { code: crypto.randomBytes(5).toString("hex").toUpperCase(), exp: Date.now() + 15 * 60e3 }; }
  if (b.tgUnpair === true) { TG.chats.clear(); CONN.tgChats = []; }
  if (b.tgRemove === true) { delete CONN.tgToken; tgStop(); TG.err = null; TG.me = null; TG.chats.clear(); CONN.tgChats = []; }
  if (!saveConn()) return res.status(500).json({ error: "Couldn't save. Try again." });
  mpEvent("Connections updated" + (restart ? ": restarting to use the new chain connection" : ""));
  res.json({ ok: true, restart, ...connPublic() });
  if (restart) setTimeout(() => process.exit(0), 1500);                    // the service manager brings it straight back up
});
/*CONN_END*/


/*PAGE_BEGIN*/
/**
 * The dashboard page itself is served from this server (https://your-api-address/alkaid) and is built into this
 * very file (the ALKAID_EMBED block at the very end), so one upload updates the bot AND its screen together.
 * The page holds no secrets: every number on it comes from a signed-in request. It is also hidden from search engines.
 */
function alkaidPage(req, res) {
  let html;                                                  // the page travels INSIDE this file, so one upload can never leave it behind
  try { html = process.env.ALKAID_HTML ? nodeFs.readFileSync(process.env.ALKAID_HTML, "utf8") : zlib.gunzipSync(Buffer.from(ALKAID_EMBED_GZ, "base64")).toString("utf8"); }
  catch { return res.status(500).json({ error: "The dashboard couldn't be loaded." }); }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  res.send(html);
}
app.get(["/alkaid", "/alkaid.html"], alkaidPage);
/** A small, calm page that does only one thing: connect Telegram. It never refreshes or moves on its own. */
const TG_SETUP_PAGE = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>ALKAID · Telegram setup</title>\n<style>\n*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}\nbody{margin:0 auto;max-width:560px;padding:18px 16px 60px;background:#04080A;color:#E9F5EE;font:16px/1.5 -apple-system,system-ui,sans-serif}\nh1{font-size:23px;margin:8px 0 2px;letter-spacing:.04em}h1 b{color:#55F08F}\np{color:#9DB5A8;margin:6px 0 12px}\n.card{background:#0B1511;border:1px solid rgba(85,240,143,.28);border-radius:16px;padding:16px;margin:14px 0}\n.n{display:inline-flex;width:28px;height:28px;border-radius:50%;background:#55F08F;color:#04120A;align-items:center;justify-content:center;font-weight:800;margin-right:8px}\ninput{width:100%;padding:15px;border-radius:12px;border:1px solid rgba(85,240,143,.4);background:#06100B;color:#E9F5EE;font:15px ui-monospace,Menlo,monospace}\nbutton,a.btn{display:block;width:100%;margin-top:10px;padding:16px;border:0;border-radius:12px;background:#55F08F;color:#03110A;font:800 17px -apple-system,system-ui,sans-serif;text-align:center;text-decoration:none}\nbutton.alt{background:#10241A;color:#E9F5EE;border:1px solid rgba(85,240,143,.35)}\n.msg{margin-top:10px;font-weight:700;min-height:1.4em;word-break:break-word}.ok{color:#55F08F}.bad{color:#FF7A8A}\n.st{font-weight:700}small{color:#7E968A}code{background:#10241A;padding:2px 7px;border-radius:6px;font-size:15px}\n</style></head><body>\n<h1><b>ALK</b>AID · Telegram</h1>\n<p>Three taps. This page never moves or refreshes by itself.</p>\n<div class=\"card\" id=\"gate\" hidden><b class=\"bad\">You're not signed in on this browser.</b><p>Open your dashboard once and sign in, then come back to this page.</p><a class=\"btn\" href=\"/alkaid#owner\">Open the dashboard and sign in</a></div>\n<div id=\"app\" hidden>\n <div class=\"card\"><div class=\"st\" id=\"status\">Checking…</div><small id=\"detail\"></small></div>\n <div class=\"card\"><div><span class=\"n\">1</span><b>Paste your bot token</b></div>\n  <p>In <b>@BotFather</b>: send <code>/revoke</code>, tap your bot, then press and hold the reply with the new token and tap <b>Copy</b>. Paste it below. The whole message is fine.</p>\n  <input id=\"tok\" autocomplete=\"off\" autocapitalize=\"off\" autocorrect=\"off\" spellcheck=\"false\" placeholder=\"Paste here\">\n  <button id=\"save\">Save token</button><div class=\"msg\" id=\"m1\"></div></div>\n <div class=\"card\"><div><span class=\"n\">2</span><b>Connect your phone</b></div>\n  <button id=\"code\">Make my connect button</button><div id=\"link\"></div><div class=\"msg\" id=\"m2\"></div></div>\n <div class=\"card\"><div><span class=\"n\">3</span><b>Check that it works</b></div>\n  <button id=\"test\" class=\"alt\">Send me a test message</button><div class=\"msg\" id=\"m3\"></div></div>\n</div>\n<script>\n(function(){\n  var $=function(i){return document.getElementById(i)};\n  function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}\n  var s=null;try{s=JSON.parse(localStorage.getItem('mpSession')||'null')}catch(e){}\n  if(!s||!s.pass||s.exp<Date.now()){$('gate').hidden=false;return}\n  $('app').hidden=false;var pass=s.pass;\n  function call(body){return fetch('/api/mp/connections',{method:body?'POST':'GET',headers:{'Content-Type':'application/json',Authorization:'Bearer '+pass},body:body?JSON.stringify(body):undefined})\n    .then(function(r){return r.json().catch(function(){return{}}).then(function(j){j._s=r.status;return j})}).catch(function(){return{_s:0,error:'Couldn\\'t reach your server. Try again in a minute.'}})}\n  function expired(r){if(r._s===401||r._s===403){$('app').hidden=true;$('gate').hidden=false;return true}return false}\n  function show(r){\n    if(expired(r)||!r.telegram){$('status').textContent=r.error||'Couldn\\'t read the status.';return}\n    var t=r.telegram;\n    $('status').innerHTML=!t.set?'Not set up yet.':(t.on?'<span class=\"ok\">✅ Connected to @'+esc(t.bot||'your bot')+'</span>':'<span class=\"bad\">⚠️ The bot isn\\'t answering yet</span>');\n    $('detail').innerHTML=t.set?('Phones paired: <b>'+t.paired+'</b> · alerts '+(t.alerts?'on':'off')+(t.error?'<br><span class=\"bad\">'+esc(t.error)+'</span>':'')):'';\n    if(t.code){$('link').innerHTML=(t.link?'<a class=\"btn\" href=\"'+esc(t.link)+'\">Open Telegram and connect</a>':'')+'<p style=\"margin-top:12px\">Tap the green button, then tap <b>START</b>. If it doesn\\'t open Telegram, open <b>@'+esc(t.bot||'your bot')+'</b> yourself and send:<br><code>/start '+esc(t.code)+'</code><br><small>one-time code, good for 15 minutes</small></p>'}else $('link').innerHTML='';\n  }\n  call().then(show);\n  $('save').onclick=function(){var v=$('tok').value.trim();if(!v){$('m1').className='msg bad';$('m1').textContent='Paste the token first.';return}\n    $('m1').className='msg';$('m1').textContent='Saving…';\n    call({tgToken:v}).then(function(r){if(expired(r))return;\n      if(r.ok){$('tok').value='';var t=r.telegram||{};$('m1').className='msg '+(t.error?'bad':'ok');$('m1').textContent=t.error?('Saved, but: '+t.error):('✅ Saved and connected to @'+(t.bot||'your bot')+'. Now do step 2.');show(r)}\n      else{$('m1').className='msg bad';$('m1').textContent=r.error||'Not saved. Try again.'}})};\n  $('code').onclick=function(){$('m2').className='msg';$('m2').textContent='Making it…';\n    call({tgNewCode:true}).then(function(r){if(expired(r))return;if(r.ok){$('m2').className='msg ok';$('m2').textContent='';show(r)}else{$('m2').className='msg bad';$('m2').textContent=r.error||'Couldn\\'t make it.'}})};\n  $('test').onclick=function(){$('m3').className='msg';$('m3').textContent='Sending…';\n    call({tgTest:true}).then(function(r){if(expired(r))return;if(r.ok){$('m3').className='msg ok';$('m3').textContent='✅ Sent. Check Telegram.'}else{$('m3').className='msg bad';$('m3').textContent=r.error||'Couldn\\'t send.'}})};\n})();\n</script></body></html>\n";
function tgSetupPage(req, res) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  res.send(TG_SETUP_PAGE);
}
app.get("/alkaid/telegram", tgSetupPage);
/*PAGE_END*/

// ═══════════════════════════════════════════════════════════════════════
// health check
// ═══════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
// ⑥ DISCOVERY PROXY — real new/trending pools
// ═══════════════════════════════════════════════════════════════════════
/**
 * Browsers cannot call GeckoTerminal or DexScreener's /token-boosts/*
 * endpoints — those reject cross-origin requests (CORS), which is why the
 * frontend could only ever do name-based text search and never found new
 * launches. A server has no such restriction, so it fetches them here and
 * re-serves the result to our own frontend with permissive headers.
 *
 *   GET /api/pools/new       → pools created most recently
 *   GET /api/pools/trending  → highest current activity
 */
const poolCache = { new: { data: null, ts: 0 }, trending: { data: null, ts: 0 } };
const POOL_TTL = 45_000;

function mapPoolRows(raw) {
  const included = raw.included || [], n = (v) => (Number.isFinite(+v) ? +v : 0);
  return (raw.data || []).map((p) => {
    const a = p.attributes || {}, btId = p.relationships?.base_token?.data?.id || "", bt = included.find((x) => x.id === btId);
    const tx = a.transactions?.h24 || {}, buys = n(tx.buys), sells = n(tx.sells);
    return { addr: (btId.split("_")[1]) || "", pairAddress: a.address || "",
      sym: bt?.attributes?.symbol || (a.name || "").split("/")[0].trim() || "?", name: bt?.attributes?.name || "",
      logo: bt?.attributes?.image_url || null, price: n(a.base_token_price_usd), ch1: n(a.price_change_percentage?.h1),
      ch24: n(a.price_change_percentage?.h24), vol: n(a.volume_usd?.h24), liq: n(a.reserve_in_usd), fdv: n(a.fdv_usd),
      buys, sells, txns: buys + sells, createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
      dex: p.relationships?.dex?.data?.id || "" };
  }).filter((x) => x.addr && x.price > 0);
}
/** Pure: keep trending fresh. Pools over 7 days old drop off, unless that would leave fewer than 10. */
function freshTrending(pools, now = Date.now()) {
  const young = pools.filter((p) => p.createdAt && now - p.createdAt < 7 * 864e5);
  return young.length >= 10 ? young : pools;
}
const poolBusy = {};
async function refreshPools(type) {
  if (poolBusy[type]) return poolBusy[type];
  poolBusy[type] = (async () => {
    const base = "https://api.geckoterminal.com/api/v2/networks/solana/";
    let pools;
    if (type === "new") {
      pools = mapPoolRows(await (await withTimeout(gtFetch(base + "new_pools?include=base_token", "user"), 9000, "pools")).json());
    } else {
      // Trending used the default 24-hour window, which keeps old, steady tokens on top for weeks.
      // Rank by the last hour instead, and drop pools over a week old as long as enough fresh ones remain.
      let raw;
      try { raw = await (await withTimeout(gtFetch(base + "trending_pools?include=base_token&duration=1h", "user"), 9000, "pools")).json(); }
      catch { raw = await (await withTimeout(gtFetch(base + "trending_pools?include=base_token", "user"), 9000, "pools")).json(); }
      pools = freshTrending(mapPoolRows(raw));
    }
    poolCache[type] = { data: { source: "geckoterminal", type, count: pools.length, pools }, ts: Date.now() };
    if (type === "trending") for (const p of pools) LAB.trended.set(p.addr, Date.now());
    return poolCache[type].data;
  })().finally(() => { poolBusy[type] = null; });
  return poolBusy[type];
}
// keep both lists warm so the dashboard never waits (and never falls back)
setTimeout(() => { refreshPools("new").catch(() => {}); refreshPools("trending").catch(() => {}); }, 1500);
setInterval(() => { refreshPools("new").catch(() => {}); refreshPools("trending").catch(() => {}); }, 40000);

app.get("/api/pools/:type", async (req, res) => {
  const type = req.params.type === "new" ? "new" : "trending";
  const hit = poolCache[type];
  if (hit.data) {
    if (Date.now() - hit.ts >= POOL_TTL) refreshPools(type).catch(() => {});   // refresh behind the scenes
    return res.json(hit.data);                                                  // always answer instantly
  }
  try { res.json(await refreshPools(type)); }
  catch (err) { log("error", `pool discovery (${type}) failed: ${err.message}`); res.status(502).json({ error: "Market data unavailable right now.", pools: [] }); }
});

/**
 * GET /api/pools/dex/:dexId
 * Pools from ONE specific launchpad/DEX. Lets the frontend separate
 * pump.fun launches from Raydium LaunchLab launches (TEBFun and similar
 * branded launchpads all settle on raydium-launchlab).
 *
 * Useful dexIds: pump-fun · pumpswap · raydium-launchlab · meteora-dbc
 */
const dexCache = {};
app.get("/api/pools/dex/:dexId", async (req, res) => {
  const dexId = String(req.params.dexId || "").replace(/[^a-z0-9-]/gi, "");
  if (!dexId) return res.status(400).json({ error: "dexId required" });

  const now = Date.now();
  const hit = dexCache[dexId];
  if (hit && now - hit.ts < POOL_TTL) return res.json(hit.data);

  try {
    const r = await withTimeout(gtFetch(`https://api.geckoterminal.com/api/v2/networks/solana/dexes/${dexId}/pools?include=base_token&page=1`, "user"), 9000, "dex pools");
    const raw = await r.json();
    const included = raw.included || [];
    const n = (v) => (Number.isFinite(+v) ? +v : 0);

    const pools = (raw.data || []).map((p) => {
      const a = p.attributes || {};
      const btId = p.relationships?.base_token?.data?.id || "";
      const bt = included.find((x) => x.id === btId);
      const tx = a.transactions?.h24 || {};
      const buys = n(tx.buys), sells = n(tx.sells);
      return {
        addr: (btId.split("_")[1]) || "",
        pairAddress: a.address || "",
        sym: bt?.attributes?.symbol || (a.name || "").split("/")[0].trim() || "?",
        name: bt?.attributes?.name || "",
        logo: bt?.attributes?.image_url || null,
        price: n(a.base_token_price_usd),
        ch1: n(a.price_change_percentage?.h1),
        ch24: n(a.price_change_percentage?.h24),
        vol: n(a.volume_usd?.h24),
        liq: n(a.reserve_in_usd),
        fdv: n(a.fdv_usd),
        buys, sells, txns: buys + sells,
        createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
        dex: dexId,
      };
    }).filter((x) => x.addr && x.price > 0);

    const payload = { source: "geckoterminal", dex: dexId, count: pools.length, pools };
    dexCache[dexId] = { data: payload, ts: now };
    log("discovery", `${dexId}: ${pools.length} pools`);
    res.json(payload);
  } catch (err) {
    log("error", `dex feed (${dexId}) failed: ${err.message}`);
    if (hit) return res.json(hit.data);
    res.status(502).json({ error: "Market data unavailable right now.", pools: [] });
  }
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    // What actually opens the Exclusive page:
    exclusiveGate: { goldKey: { token: GOLD_MINT, hold: GOLD_MIN_HOLD }, holderKey: { token: GATE_MINT, holdUsd: GATE_MIN_USD } },
    allocationList: { listed: claims.size, savedPermanently: claimsPersistent },
    marketData: { keyed: !!CG_API_KEY, plan: CG_PRO ? "pro" : OWN_IP ? "own address, key as backup" : CG_API_KEY ? "demo key" : "keyless (shared)",
                  keyCallsToday: keyDay.n, keyDailyCap: KEY_PER_DAY,
                  callsLastMinute: gtTimes.filter((t) => Date.now() - t < 60000).length, budgetPerMinute: GT_PER_MIN, ...gtStats,
                  coolingDown: Date.now() < gtBackoffUntil, newPoolsAgeSec: poolCache.new.ts ? Math.round((Date.now() - poolCache.new.ts) / 1000) : null },
    lowSupply: { found: lowSupply.size, maxSupply: LOW_SUPPLY_MAX },
    engine: { build: BUILD_ID, running: MP.on && MP.feed.connected, tradesRead: MP.feed.trades || 0, graduationsSeen: MP.feed.grads || 0, telegram: TG.on,
              holders: { fromFeed: HOLDDIAG.feed, fromChainCheck: HOLDDIAG.rpc, unmeasuredSkipped: HOLDDIAG.none, chainCheckFailures: HOLDDIAG.rpcFails, lastChainError: HOLDDIAG.rpcErr },
              curves: { standard: CURVEDIAG.std, nonStandardSkipped: CURVEDIAG.nonStd, safetySwitchOn: CURVEDIAG.tripped } },   // details are owner-only (/api/mp/state)
    rugRegistry: { wallets: rugReg.size, watching: rugWatch.length, savedPermanently: !!RUG_FILE },
    smartWallets: { tracked: ledger.size, watching: watchList.length, liveWallets: liveSubs.size, alerts24h: alerts.length, learningSince: new Date(smartSince).toISOString(), savedPermanently: smartPersistent, priceUsd: SMART_PRICE_USD },
    time: new Date().toISOString(),
  });
});

// ── Unknown routes & errors: plain JSON, no framework fingerprint, no stack traces ──
function notFound(req, res) { res.status(404).json({ error: "Not found" }); }
function errorHandler(err, req, res, next) {        // 4 args = Express error handler
  const status = err && err.type === "entity.too.large" ? 413
               : err && err.type === "entity.parse.failed" ? 400
               : err && err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status >= 500) log("error", `${req.method} ${req.path}: ${err && err.message}`);
  res.status(status).json({ error: status === 413 ? "Request too large" : status < 500 ? "Malformed request" : "Something went wrong" });
}
app.use(notFound);
app.use(errorHandler);
process.on("unhandledRejection", (e) => log("error", `unhandled rejection: ${e && e.message}`));
let shuttingDown = false;
function shutdownSave(sig) { if (shuttingDown) return; shuttingDown = true; try { const n = flushAll(); log("init", `${sig}: saved everything (${n} files) before shutting down`); } catch {} setTimeout(() => process.exit(0), 300); }
process.on("SIGTERM", () => shutdownSave("SIGTERM")); process.on("SIGINT", () => shutdownSave("SIGINT"));

app.listen(PORT, () => {
  log("init", `BIG MOUF SLAPBOT backend running on port ${PORT}`);
  if (ALLOWED_ORIGINS.includes("*")) log("warn", "ALLOWED_ORIGIN is * — any website can call this API. Set it to your site URL.");
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) log("warn", "SESSION_SECRET is short — use 32+ random characters.");
  if (OWNER_CODE && OWNER_CODE.length < 12) log("warn", "OWNER_CODE is under 12 characters, so owner sign-in is switched OFF.");
  log("init", `Exclusive: Gold Key = ${GOLD_MIN_HOLD} of ${GOLD_MINT} · Holder Key = $${GATE_MIN_USD} of ${GATE_MINT}`);
});

/*ALKAID_EMBED_BEGIN*/
// The dashboard, compressed (gzip) and cut into short lines, so this file is easy to open and save on a phone.
const ALKAID_EMBED_GZ = [
"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",
"/twN+T+zRgjB3swRu74oX3/8G8RSGIZ9pZKfWdFHRkYQgUCI/TDGSzR/JNCP7VEIBek/7PZDR4s/HL7jW2vAsB/P4I8QBL5Zw4cu",
"WfaCXOjDDR7W1ZSfxJkOefTr66/DGdTdi2jv1dVcN8eOJ8MPx+sTC+lH/x2009TWH4hJ/08dH/Hm31+kru/KTrxoOP/+2/sof9Dx",
"z+h715+/XjoXlL/9iYS/VImXlnzBhPjPREe+edJ37mD8RSqMHe6ABP/+45dMw8eVNxdU/lwfAf59Be8T/wU6/QT9+ufa8S1FLf73",
"7/DNwn//eujz3//Zfn5nQi8qyPd9+/n5oir/jjJ8PuSXrvGfbdBXE/16nvCHLfphrP2q+or+9XcT/5Z985uQgR0h4xvi1Df7/J0C",
"cu6OOBD6Y/w+ZvC98V4BCka/Gu0zDtWPvuen4/e5f/zbzHU85OEvkx/M1bENx/vxd7Efg/we1JF3Ws5j6Lj+cPnFXn24jeFY/q+/",
"E7JC/5Rt9ENk6PLPduyDM/1qId9E2s+pVc/fj6kfej6ixW9fh78j7MHo4Q9I6I3q9lsK1H98uDVJvrn3c1/y+72fnMnPoT9E47/i",
"TN5R8r8fOpUMf/+M2PgP9f2953/aGf7W2T8+TOO3P9ftL6LC5+/+/vd/Flr+1O98mMH/3hzw/6Y5vI36xwYB/+8N4m2EP9Z77Hvq",
"+gUkf0Myf/n5Jciv9OQjzv5sVhD8XZ04g+868dbJH8UUGPs9kLwJ9f9HhXjBulfak1QHEsvyKIqb1yyyL5ONr7HRG1H7T0E8La/0",
"8Dtg6pOOvQQJfUbx/TEEf3duX+UfbxN5zzP+NZF9dFTBb19isndF/5y3/E/AwxtT8UvMr+35J8s7vzKqP1zah4hN/Agh5x9hDHzD",
"8J9pH/y1Wb1P8pfKH6efwiyvot++7Bp8b/DDz+Nvvxsn+iUc/dTkB/+3r+HioU/x8Nrqd8v89PYjizPycZ++6w++Me/fA81LKp9b",
"A/ypo5+H91m8J9NvCfQXYibfxDz56Z9Flj+m7Ya/S9v9nq99xWT+dXIPvc3zGP3nYN7+J+HndetY5t0390LYAaFQ4sPN8Hf1NPCH",
"3/4wu/qQb37d7efa9Or2K9v9ln39GOTIwr6U5O9FDP7t1z/N4N+n/Mzbj27mbemv+b+eHm+/fe0zP1fwP5DYm86Cv36mGO929XK3",
"hx7+TyD+P97u/KHyg8N9/m4cf+Ytvg1kyNsJx6uvd8b071UIeNu4L3f68338G3gBKQj99b+VEYCfRebzxyOI71n5R0/RtFP8uV/8",
"pxDuTTCfh6tX72929lEXfsawt2j3ZS0BFP6MwR2Cn9m7a/yO5N7rKmTQZ/DzrbTDt2dI7zv81vx9i7/Z1Lew9OFU4H+9sfDnkAf5",
"GI5+31n8q2373tra4V+uePHr9+0B/542fljtG9oBf3i31+PeX4L4wEvxj28/+8n0dpb0Hnj/+tdf3882Ptnwlzv01XFUt/z2LcX+",
"J2l+2uO3lh+E8ZGt//cCEh9378PxJ4F+VV3iuPVDuYVPY/nBIZd5in/9/cT0jUf/xaf/LUH+/d/fyfH/8BTkvyNv8jNxE9/a0Tcn",
"YF9XZBg+qwryPzgq+niM+i5w5F+rtPEL+i6KDzglrr80jM9O4d5+9sPXgD99G47+8vMz+44QPnTzWS8v0Pfh0Oy7lQiOnuox/aLg",
"zc/ogfC/dwj2HWfzOsz+3NuQr3UlbfvS5G/M69d/EkD+KJ2E3zcMfdfdAyp9OPJ7HSW+Oag/FvjHLl4eBoL/J8e83wTl309gvlPy",
"43tHdr8u2aFPbz7xlZS8Dun/8Ze/FXPdfal6HxXqY5D/af3lixoaH9TmtYqPB+Ofmo7h0FbVq9XUzmH26/v7Aw188OxvYn4b85df",
"Pt78qc2nabwrw98mv3uPCh+0AUHAz6e1vZ/n/OVvwXyAVusAc3/s8/4gKv3y7o3IT4Bs8acw++2fHYh/Dcneztj/8Zf/5x0J/b9f",
"rOFzh/Ufpw81vP7j9KHy3qu60/FPlD9/CA/wPf7nX9+Lgvz1h1eK+dN7h//512mY47/+13+cjnZftn4J8K//9Ze//PDDf4zxe3G5",
"D795Rbm//pBHH376r6PJ0Siv048N3usQ/fWHcQj/839e7OPOXCj7eN3Z96IXd/6qo+JVT4WrISi03qqsIbhsZptHA4/LmZBd04Qz",
"dJs3w4jfhEI07YrNlu52TUtpY0rRtD4U+7gf/ZVHP4x4vEruot+Pjsv/3cv6UOyDGSlz+abYB099KvbxVaENmz7WeKHSUHi1s7PX",
"PsjHHHXusrxer30I34txUBTLmAzHFOyF2UTj7nEXlhavdsdlox4W95FxZFDZwIQqbVi9lsMtEy0DbKfbavCqVV18ZiQFTywcJ7qr",
"xVsRkpSh3ot6fF2EhLlSi85enq8CIKPxVvxD1y8XimFehUc+FgA51phRq7DaNsMcc8r0TN90hClaR7qUyck/On8VK7kyumxQNEmd",
"JOj1TJ2XiNdHal8P2qnjfdhShPHZhbiGPb7KaJ+92fHVLkStcuvJg8NA9xQhdDiLfmiEaQ4hv6Cg++I82s6cDJ3V9PRwfJdiPY4w",
"HxLgC4WuNydm0MBu52EPdlOa6BflOfCTxUPzg0x1qQlzvhcA2YEkR1KZtDzDUxLCmCkIfKt0E+PxdNvShrYK4lDMEEv6oBXyrgEr",
"nZkmwrUIb0jSAuKVFZ1e2FeS4Z5XlBi8YVKFU2waHpy5MAucSArBfe1UX7V9WKJJaUtgSMT8ySIxMHGoFiYG6QH82i4+sD4DB4nI",
"BBxA9U6vTH3dMHKre5rcIJPMg7G7ezM4KbdCAm5+qlXGzBONr1VONODy+R4VYgflXg5JmpKdDymd5uHqJGr1+qoO13FTBecTuDTp",
"Lu1MpEUQ0CckxVoTK/myZVguSche8zjrVkgEYp4C/eTLrYNKvKOVvgNu6euRPCVhni9Rb0/m6Sp6u/J6XP/OCfxZC9V24E9XZIe4",
"F/PmMZM89aHboi8ZiwN+LOpcBDtq3ODcnSU4slc7GRz6iYnkOcZLxJA7SRNJ/AXNvNistUs+b7zDUyZc1s8jrAErZOoVcDLnAgMK",
"mY8dlPWoRH22i/E4l4TfKtdbIPhGZo4ockLyyOHn4RLoSXDhA6kORAZ/eHSHUYKFZgKkNaRUwwB9SyTvMqBsNUXFQ0j1WtjswgEL",
"6cn02rWcEBgblafdqtbJ9DLixiMZoNEYdEjM433ez3a51wE8bYwL3l9Qkavce7zK2X5JRAuxbX4ayFq9ZedeBUyBfVLYxcLJBqUB",
"RcBUeAblp1Q+ScoQCa5e5DjhGjC4A/JaCFKB2lsaaAbSDZZUl1nFI0U/rwIWR9rFW710Y/F4ZiSWtqRmZ63H9UpOYqQygtYXvB8r",
"t/r2CDtiCHzl7CPsRQrLRhRXi8PNy8RO6oTx+BQ0Ni8IVivB5zS/9A6IGdB9u6KK5qMi8NgxO6QQU7tN+ShfAkYJJbnzd1Bie6Oc",
"JbOxgfiaqKMxGQ92CZbRsCNuQUtVMJu0KXVNTtQ6hh3chibxasKRIJojTjpM2mB3VlM62Dbve9iVVDamaYGwyXZIRIrs/bJwSI1Z",
"5uNG7IFUBX1ePTiZPN0Kr4OTiEhuUcHpk1lXd/U8NE+oG27FZZNbFLKgJ0b2xXzHfYWZc5vYSrrlFzVWLy8yXGBrj8mIeqiNoquC",
"vhP6T1IkjJgELWLZJBLIFbW7Zsd8BC1wHjgk2NFFv13au4JWhs3oWJ+CA1SDPVJDsWSVidSKpbojnlgu9soXAJIV0UWL4XggZaeu",
"9AbFpyPpNU11gdQ9Fm+8UyoEyss+lx+ggUToh+9wZgcLk4xlameDh9Ph4xQvMLAS1nXw1gdhrdeaN6s7tNBpPu/30sQecvcMY42I",
"2ruDFWkyWM+xMwk5MawrCptWAJ5vqfbissZ4eidoFHx2Vfa5T36VajIM77Bk8PMLrwbk4Vj1OYbCvRVumm31KDkY9J0w/YC4nB7Q",
"De4ipreexuBnLquW/qDNHS+fLPzkV0/XuwPbHcBS/Y6ivN07Z0fSSJQ1sYizz+YoeIQUMHDzuJS3QqDBPcLJdfGLCdEiPlkJwHkQ",
"AU24gtLbs/g4oKDEZZG4genL3zZYrDyAM2F5HqEvp8vEwOKloFDrGiW4gtsq2GuORrTaOmhLVGf+I8Ymmq8MnoooFDRL4I6C5byx",
"9C70mvSEYRkB6ztAAofXsZ+Qfd50la/cagSWghbM2ahWL3HHkTQRdaRBZe0gjaQe/UVr9m6sMumAO8nSjt3OjPEuGwuVUZy6JI2N",
"ZR1P3bt6OKLydtlRyvG8ATkvIMuWrm1xlCp3W0wRfhfY2qnlH7k+SaP5yHCZr6nwVD151Gnv8l3tpersUJB6WSi0fjY8XCEJuOG5",
"kLkc2kIUdhNOwp2loAqUohKmMCmKhQNXRJwPlDoo5PCzc5pLJDUOT17DNNFigL3vD5cZX4wNGlJsYxphauXzwfUuOGN4950jvyiU",
"M27gK2AAimRdA3ny0dHHpee4+WC1rvbD2o+4LZ8luBHIirHJsV+1sb8Tcxdc7l5TwcmO2APs6yKj+Redy4Nk7ki19nvvUVtPdVYq",
"D3/t506fzPFuxYS4LdCtBre+EWwXKuyHOeBcD3VXpy9diIB4KqSfPNCAXRa7cdpUe1qhwYk6goh5RA4jSKszzxtLLKDQXAzWxJS3",
"5B6HmdpcS4Z4xuo2GEYzKtGTCdU+qEfmIVxTg3xWdmDhnn3RVZk0YP4A5jcRC3V65dd+JhhzqJylBJSYTklFolh6pFqbVXrJ2oTe",
"yNF5bMKSjvmnkwhEUtm30TDJVOmd5kgko3O1aTfk8hyHa1ne7RLvBOIqdXvU1EN5xQIm663VYUTQO2EPTSNFsh+iA0dKlWkrNGJB",
"Beo7j3yHsTueLWM4n+YWvdxRGZyuNcRewUoqm8uFu9KeBA+ke5uEpu2CXIC2Nevdw3yRe4aM2v2JQuUD5IzgYZWmu3XVuXPx6Zr1",
"tGXdrPEFArriOn8W3H8P/0N0GP+5yaeOL5ErerGc0dfSDvPm7iSTz6yuzs280jUUnroHZSNBfUSmkYaeS/FUkgcxhEQyPv24tNPJ",
"gO0zd8i6d/gyE7CS3NESkruYefglvuQx7vn0iAVweXgADZJdkbeqIJ9NhsabalUSUZlv2lTERzYI4AukrDMtuVVA3ATtJmDnTu06",
"OjzPw648l6ckSi1BxPbYBZrjG0R7waJnsA8PmCbu4DOT45MR+kFXyuJGA2QB8Mvhic1WVW2xSh5gu5RVdYrKwu5subMTDIPcB1zB",
"DWzZArsauMWgV03mTaXnUTZ83lDnfM9GGMflq+djt1thPvGR2BKqyJsFcOIgCwRwKsfd5RAO8pkbJQCalClXG9gvughvzsmtTGeG",
"uTC8X5wzaCESlkhND0ddoKc3HajRNZU7ESA3FUGegxvAKbBnweF/D2xKFvaZGnHAOBVuOE2n57wReO16Ta2XZ18l5Ra4AG17aoMC",
"TAw3OlSZGHuumzw6DpwnFRsQK6PyVGPDqSUWV5d7irteUKdqVaSqnirjzSwunRc84l4eFeKbeqL91o4V2W9c2K0ANe6Haxp2Gm+H",
"MbK14mkMLcyKhqkY9jk1MxM6XAH0+uQvwGxIExSqi45YWKrB9mTqZ9fAjVdd7+Y9kA6cFLOhRogaaRUHBsPHQSw947K2SOVcpQxO",
"jKkWehexZ8o36olMniFzkk/SSEyYLDZiIajFlZKT3OmTKp+cINQDB+yBnncO6Z1GkCpwAlkGjAihYVZPocfSxEp2Uhy3+4FXyH4v",
"98PQff6A4UoDl06RBWZyesWBMhpK7qZceNE1UKifMjftt8A6sDd5T06UtDuP+HLx5Nmyo+tyLJsJVpSmxGN2ggrvOdiEGOxfzweC",
"yzKIexqldCHsBjBcb5YibJp2S3LuIlGcKKWH7IdewqcWwv0gzxAeSCr3USrlNI/9+aEaWD73N00HMdcdXFJkhFGCbo+1mNX2pLb2",
"eHuUEVddbJ5OKR+HvIlJla2kcDHEMxLg98M1IsJON9YzWEOjFPXyocaIdjP7G/pw/RHM7hfbnuinatn44K6s9TR5OXnyXEKFlnM4",
"MvfMmFVnuqT/+jrqM4+PWOrXHmyIdijd7tqRjvVa7l86pS5qz79c8Z4hVoDf0BPPCo8ZtHOjog1cEbFrT9sRrEdEqj4UWYgmCapu",
"ltmw6UNcFzLe0r7M81rCgegMGXwe1gPNsOhAFZ3tdFhRoU1lPWZu23vyQD8xmqKmxnraBiiGScwLXCpHWKFCDj4zBaBB7eic+e5a",
"dTbX5Gm/4ptVMuemsBw9J0yDIx6hx8gbvM56t50eBNfQux4b52YZBPNBEIeFw3ijhtdalvTeXK5o5YbETBqtVajyeaLCBysDtDCV",
"K8zfHu524NHWzXTI9NMhHvLD7FMhHYSTZTscQUd29LDup3uvKfq5BLyHS7uZ5UOCW3Z2iQrCosdbf/hs7AXjLo0vSZh+gfPDd6dU",
"14zYvVNBB7qnRlkeEWCQMNHalZvdSRVFMSVOXZ9zAsfErYPDMfcQmwZxt5Rca9WLstlPTWEGbR5OPU9KWnCuBoHjIPGeGe42BRm4",
"hX6vYU42NcrcwqCLxCfFv7pzYe9B+kzBlgyL7Cnx2tZ5RxYESdhYuiqDPSdFAk6ShRN14pCXc3Jtp0qpD6zsdMnFRAkAPGYw5Fca",
"4d3OXMu94NnRO/nKmA4PnARKA+TBq2tOLVnydbNhEfRYGa/HBsKpnsHtARv+kDPdzDw8Y274fqYiZ0kyW0nk/FnhgyZnZVeuCHeG",
"HsFmQGZ7RHkjydIO4OxbEr7qQFwNqpxXxNj18EEai9a451GDe8luZW878Ep2I6SE3DQ0uY5hzzZQCfnFooGp3bpttV5Lcd9vD5s5",
"MUyxaZG9LYYCFjjGeZc5DE2BySZo8pQjbTmjaLF0WhI1aLX6klhG0jPyFkELYye5wbfsyAzaIVefhmeXaa8PF5CIkX3w3IAwzVZ8",
"zITg0q1XGwPWnTJSMu8lPNMKst/hR2A667i5sUrJN77aOy0gKnWy4BNdqiuEQRTKrzwFRMnj2P9bx+M+K/hRoB0Tu6BF5UZH5ADN",
"4HmLglvQgXSvHn6N33tIAizDetKyGA3I7Rmg5X4tOqal78jrZC9CQBDW8wodwmvYhzYjnppVuQXTXYRGqZKCI5c739PEDns4Xp2n",
"wwWPSDKpBfbMZI33Y2Mz3RHB/DSNQA7Dhyl0rpzJjpZqrtakJ268LkM3eDe1Zkwu1xRptQpCvzXPnUNTtaDjJ7FNFplqhekig55D",
"O3O7aKb0QCxAkDTs0UvjCsOFSUieIV8hBJt8hzEF8WEam+0xEg/YkDWa5O7M97ORYe7zRkyO6UaN0kU8DWZmKp9T7kJuvuv2d+HU",
"iW5ZmTXPTfQicvLJ7c6ThMteKwb1U0Am+/BKlRqFd3I9iX0R1XPesLHCX5odPQDuVNaatA+F6gfeNKrrghdeuIzJ3JyoW97wHO1Z",
"LnKpJrdxWrXGIymrkdqSN/aGMDFeWFphV5vZShf9aqKy7/CXkSCnPdLhbtUhyS50ehKxOAp4q6gq8eYjRSYcquTIgtO5wDMKAhsf",
"/YYCKQLYV0WBA4c/kKt6uM7iXIOhwOdDgyVc7kQ1DAOZMRMtqkx0pNPIuSPOlhkwGM+1NHM/JQO9lThRGEsaS3NSkX5Redl0vYJF",
"JPCXaQwO3wGIfU4IcmMEra7qFNg/pWLWEUdRqct9CR/7yhkHkgkKLayX0mwwNa+IXosui1QUeqWVJSMGRj9BXt/yh14uXNcf6ldZ",
"UldOnr6WDeUaR7S5pyGUCKFl23iCm9ntZt0fhYK3/mUfiK0gzPmE3lmFFUeympSllhciXkxHQpjewfdMkw81atVHN0WIALpMrnDO",
"czSAHm79SBqBEcOaDKYo251poLiFD/MsyuuFTnx4X6QZ7SHqdKVhsCnn2iYt4hoxBYm3A41yjHTvsEkCJcljSl5Qr1f13lXTjeZA",
"Zw7hrGipRg6OJAUs7wiJiyUVZahEsD6J75ZZsBGdhyhWTIMJu4Q0ydjsg9ltu14zqEr6p9JzrOAgTLJ2KamCdzhvagjKg7HaLvnN",
"JoLOvwjZ3MD14aPQspEsJC8jGbTGj6B/7o59oKjNDCmb8glCOTeXOFhEC5fXe+M5gOgJzlmAIbhV93MVJnp7tc9niOfvA9ePUcrv",
"q1fcAVAYnbQwQkqbU3VumiODo4ApUZVDEQa/8O1JlsRC5lt3DGUK78mdHB3+JmuI+Vzik14H0HjPE06/hDcXbU0FgRoOkqR0PKOi",
"4jf3DRXmklZzD45bvDzSo4XCd2DfU/gBF/QND5fOpGC08qjWO1GnxnvwZnAN7Bt9t2dlpXjCaE+11kt3ZDcmbLhVU6kgtZqWo4gc",
"xnJpOjeOG7/JNfWpQlfz0M14CG1VtMurXkTXGoE3Oe3NiEZJwwG0m18ZoDpKVxhh0tZWr6nfwk00gWtUJtw9AMj59jz2w/fJWSD6",
"2hz3ijWXR3VTns+r3gv2gomnI/UHCDdZbhq9OKccc2gum2EYU2pzm8YjNJuCe6XnpiB7Ig7MfvNYSwqr6ggODtydcmlaiPWpiIXl",
"ZtKdWkpJZafTLB0hB+IjNxzM5W7ZFUuErROYcCe75F7rlJ6dF+rcIoUbR3l1ES0P9HwYESstRxcLHCNY3chJPEfDoSUOPW6qsGnX",
"EWNHbE5M5QBwYEch5aHZuKFpF+JIpwtHj7GHolxj/Coj7Mxs8POCSwC6oZqvD1zCT0dIKwgjbS81IZMJvJvhidVILXPDAxtMajWd",
"p8AHjzS+tzL9yI9VeNrbSlPusW+1TgshMVoc4hlaGG4gttWHdgdJ4zytR/5AhcXOS0PoTDN7Ca+VeK1uSIVioqlovYU5ZJRvmDPF",
"uCuR6DaGYPOaUYefp12s4AMYAFupzS2i1npIX1CMD/JKby65S5gQoqLm48AErmRjxXwi7l1O8BabLu3Qp9m6Vps/RoAsWCSVkI5z",
"ICl/JrxZXRhij83ucCr0nXcBt2kcwERzIAjPXKW6zvOSCRdUMOVEoEB8UfNdTZTJzOUSXwUr6FMtvuXXpPezsBhXTIYgHX+aCsvH",
"1UNNStp5URBaQTZRRCPp0Cyu8GWlhhF+gFWeD1fKUTPJGfY9QLJiR0bAoS/DhXj4+FVT7cExr1nLnDuvwYVu4GKmv5YMtlxL4NJp",
"ctnLzqSvs6lAa1zPZMlqWP2UXVycyGh9GM9CWKhXvbPgAP6wXAcedzc1E6p17EBeuf6KCyL5LJw4SlxhT3Sl4vASo2/CkvLPEyU0",
"YnfRngd6aDNzLgyiVy4Y5OULxixNy1W3a+RIqGiqZKM7ETeDozn0Z0m9DpFF9P5wMbTI87gaBvoKVCWe6c52/EAPxDdtoECPzc1X",
"9XMLeLe9U66+wFwMB/LB856O3WyRMHoxhRaJ1klcJuKqK+rixxMpky3hPRyZ7jDaNEfxCk4qH5lwSbJzc0CqI73I1hcuC+wa3+Za",
"J7RYx3UTbSclWECUPgxmTWlJp1T2blbNZbMgrTLlXfJuT7C7ui4rLQpUq0t6JCdnSDI2AkgY6JEHN1V5RrfQhLOsGJ6TEF5CChNV",
"9WJHMu/loe9A29nCXOKaHW4UcS7CvRDoA9SQ+aUfANJyYPw5wT2XI9NwLdf9qd0uYBSr2YqIr73BoDBQ7sTMSMQeNiLdpxF4i9ZS",
"RAX9kor8XaaoaOnCjCJ7lPIaVr2dH8bml4g56b7VeHm8OH3RmiJKXz12KNVTzxlPnvTumgzR7HxtMKsNVXMybHUbFDRkJK5mCr1w",
"dv55R2Nd1Zi6CizRzCQQGA+ceuGe6VpM/OOhZA7UWepZnlasunMelwFk+aDOmJa4LOr0gozhwpmvV+fMAWB3K/yMkNKwwCB+ggKY",
"C2ooEm73IEUeT3DqKFSRxAVFThTvpIDBXu/Gmu4Ry7LyKIHxEjUs8iR0t7lZPNKfqPBy+Eo8OtckD5qgZrH0FZPOIE8KnZwHHf0M",
"VLIGXU4nMxcnSTXzV7jJE+ExYNjYXHEDfPY8g14U7zSxs1Ejj/pFkVMUFx6t/NcTEXlgGRNcMoG/sdLIGI4hRANan+ncBIvL5fY4",
"RWoLZIDidnZIOIQ4bakCJME6D+vqlrSHFhdS930r8IlYoEFVLWJ3pCNRTQXVKMFuvAbV+IyZdajYOJ+2uauWyG5gk17UuW4C/bYY",
"wRUhwMcC12ZbTQt2F49FIovGRKfCneYwANeiBW+4iE1HWhSd1yWk0fBJ1ePl8MwJaEVXdD1S9A532g5ErMaOjcEmNGQ/KzpDYKsQ",
"4ENLnGLyhIINTBO3cmzhcuIcgQ6nyriCIajS0OFg0GIbpEz0XbtHC8w+HdAJtp4WiJ35kPLLNMwW87mh/Kyw5N1htc5nlPlVYHc6",
"VK6ZjvvXS+8V6V4VInuL4yCF+wMjuFDn2yArgoLk8BbKtbW5vIoPFGeWaVrnKS4R1IHFSbBOmZo8euhSrZgdgK4GPq5VsOSb1XbG",
"eb2v6flI/rtEKeTqVtxMaHwyuIGsme+QKb3Y9ILxNs+rY0uCIXnEhmLxlLYrgn0XZ1u0SuWsMjddgQAZVdj2xBZFCtVY1SU5fRbh",
"2H3Q1Im0eNAu5tBa+aazz1OZx9UGbd6VMc3r1iXEYWgWSkqD8TTbcTXRfUOdJRDNgb88+COFUedMIIQ+HxF1glbN8Hy1FoDoIhUd",
"ns9n01hIg5TOVlSKtHWP83naOAdo0RIzh0Wj8cM3ez6xjZN3mdi26UE6N05GUyAFbDkX/8BkmSgEUqkMEGJBcJOd2cQtj/Qgh4Op",
"qHf1yAHOpn2hCdTOKFXOrgnakP0+r9n1AW6Y+pDu4SPo7CQWFm3v12gaGM97EKBImzXbR9dKSTGjqO3mKXCVbjBxGjAWv7ZzIppL",
"8zTLh4aBMH/ON+RiogrktpjUouLp7LCWkRxx/wHYcFjZEXTrY5TXIWxqD//cvejFT5TUSxUcIZ5Ig453Nbfu+SrHVySXTWrN4N6N",
"pFs9+JA+wf1OwcYcYXd6T4xxjcUoctJYYO3AR3PJ0wGTCbrrGCbY7j0AUFlnxFhaAEB4k6p6FaQLPlVFAqeGdtzaKRsfCKtK89iG",
"6aFxItD16YSj3mBJLjo8zo6AcO5JCE+5z+jtSA/I5R5FmKz0m3zKBSAFFKWEIQi+3ppo69mgPDu1WvRD/HoQJ/C1/3BAu7WjqjLt",
"9QLuqzMfkO5usknGh4oZ64T0WJD7Hq7WvufONPGhrrmh+7QGitdj8ULty2E4SGfWglH3etZZy5HZVAI+WF6ENs2+ItAl4Oq6NqRq",
"HoIgFPW0s56S9pQokI8ajWnGXpTAB55P9MOGAGKv72DEobCn261V4iXei0e49FtMSxWpQ3pddKBaSw/EhPlpjPaq9BCOOJU2dFSn",
"s3h+7FKDUeSlb6PlakPKozJEBpVhrGg5WPc8jEwvQeFfVsnA+5jgrLJwxzv62IyFMCWouSt9VuMqzVQHVM4p0iYrNfaoCCN6w/JO",
"pndeNXx6YnUNgxPsiJE9qTab2L7RiIGuesXQxw9REeuSEilCQgxocW935sw16pEhqnAdjXdZVecQL1nTpEomdA6LkAHHRplHiNvN",
"1bRTlCIsZya39CoQ4iV44H0YgwNcAF4qPawktSy2L02ZNVQntPajbUYt1GXrL1O2d1Tns6K1bdKU+tQZktvzGrGSj8Vjs3Qw9wTX",
"sdAmjHuwkweU91Nw+PIKE07L1UnOIFjyjlvp5xIH2COPw/DbI0YHAt15BMgT/qncOHxMUNO/uvctr9nTdKuypw3DKj7kT8nfieUC",
"arXMH37PUuieqXyw45mGTfxAB3MEhkVeROxJoXqAs7ztMIQb/ojvhSqnM62tA25NonJmRxJaxcUsQj568jy42+MGyZOwMr4iwzmc",
"xkmxIjw0hNKe+rSIQWd6gjLZuNJaeag9DTGNyJdy/WzCJJBQ497fS12RlY6TD8faPDWhbvlgiDEgi2pV1ERO1ypdWQNtClyQLUfC",
"Yx7WeuvBqcCw1/Fk9JyMKSCuaI/ce5gNXbiOqx17Gdv1WfqBGCLbETNvW+zvBQ49Dg8QVvRw6bhZcR6dbY3enYRTeJqO7BooplW8",
"5iWmo2Nnzc0C7aYLIo7TN2I5ldXl2E3VL5sKhe4BrCYib5ogfYZExUXhNbD6tNQ2viCGO5dUdZPGTCDSBbOWtwDxXI85UtmWcbyJ",
"eBoZvG9OAKPNTSqIwHugHZpcn04PR407c1VqNKBSiJdSuqoaAUtVMvbNFSbnhHnED+/ZSma3YFhKtGtaWIUZyXsUclYt344sNYzi",
"PpboTfKnw/0HA+UfjrKk7jqv3QmwycvTbe72JDgUTcgkBk18jizPT19TxxomI4RrNTmqLKckHKF80i7udnjc10bTyfGGay4p4xIJ",
"4B1Rt550hWL3zNvVTV5E7Hauksa7xRUDPt0VTMWKvhna5daePRQv9r57PLbAC52162lcOle5nQLEsqMpDhltDFY9OlXVWbjVGukB",
"U1hYj6kKHN7OGACRzr507i8Anjy0zLZhhvC7fTziBtm1aRvyU6v2Dr318JFgiRYYpNzpyOtqOY1HRgWmWwInke3ZRRymakP3CWIR",
"+rBPMkhwKcytnWnPnY8bvqnoKDo0dqG0t2nP46J3YbzDrnp3WYxhI0dwC+3b0bcfDtTFL25kyr0Kdjj28wgRtiXsjGRMF/Zuzcok",
"i0ec27vnBBk3HpdLFzeRSnLGaW489Tk5QT139T4AQBbj2SpNyJCpJIWW9IrSurPZlQXvI0vi/d12WX7Gksq4B/NVejwgLhDCOLa4",
"jMAcMIOkNApFHmuoXqRP3TULCJ5xqt0wyYf7XLUHeUGcOElvcB5Pls+rBR5ddDOmbJWYhmAlEn/KAnc2D2jvswkb5M+IVeSYuDSt",
"u438w+eCNYEyDPRbH8Wc7XCG5Cu99yRn8qL8LDtgGHVqtIqgH/BChIFcDEL0dPwnwVnDGUf88cOsa/l+6k7yuWvrhJCm7X4Hyyfq",
"nuGOYABdW8UjvPnA/vTgfMY5bqum1qfQ415KcWKKAvR+OcWlgRmymHWSu3AokYPEVoN0lvI6Q5rhY/PVXMnHeC5nlBYJWyafpAHo",
"BG5krlWX0ONmPsK4fJqeo87zLQzdsLfbIyQNhpoQ18lvr3MPoMzTYsMllrgnMWcaWgBcH2+gIbHDPOD2YHAqx0H0IQS0EM6QNvAb",
"r+bokZHBWUkxPQIFqCjtcFk8d1MclGuROEJk42Noteri4B5EKp1gar4IUqxbwutZOLLjRkPYQltUadBg6K6SKEwWmtypUgtOLDaf",
"jdt9mXqVVefetM9CowsiKPJ++Ogn9nkVVtFXUavLfMpwmEVPnHBHcQiVxd27lodHkvQzi94TjucOeIRN/ZKkPtlbdHxyZnY85yAK",
"JNfSKNTu3Gipj2XnZ8p2pKTbar7ZvHcFmTtSlowDmWnXiWf0ruWHK6rUVg0bRb7bmV1Ve7JW1zQRQFniXOQug25MNo6NXzO6nyGo",
"PXMDJpqJOg7uc74aCszsqxcMBclowgmvT42r93lLchnMB3uc4gnsX/vpMg0ij/O4pg1zgVIJDtYwa+WGGK6LUWB5fcZmK5oavYEG",
"SU9vAmKUmFpZmIwAaEcosAMYvNn1Ao5bQ3W4pX11C38Eq0rFyTuZWOcRKHmUKk9SKRdB+vRZuTqN+AOxUB/SI/h5tORqmMsQcTfH",
"ahqPvIQRGHaL2Tsmj73T7M4MqS7hLo1Ud3StBvvmruTryBgIVARGN2sGyic/G1DSOY974kYYZOyAaIh9IB7+yUCiNnCuJydHWoHg",
"gNohnQBykNNE6dnY6oQSWstS0H6Syok5GtdqMryjj+qGX2WGKfn1wlMnfuldbNGriZkldMIFPBRDW5bMgYtWHZMAg2uJDlE3TaPI",
"kkhuEM4xIBuTaNtrmN3WgY9kJBqU3YM/lymNgY0cGZBqeV0tsD1OHEhXRiWEva8YLWqlBJpHesTzxKRVTAW4AAGQI9RGRWBpcBVF",
"+WoTRM4QW0QI1ykynveF3qHVYXNjPAcLK72Y1QDVPM2ugfm91hRLjw5BfjLdk3FzM0ZsUq61XJqcLB1UzWeK+KdxLfR7F801eJNN",
"sxlEc2uSK42QO9mvNdRlQ9PGhSUMBA6ekkvnZq6iEPMO2/NJV8FpV8+3AwY1dl9pF4EvLcBxwUB2Te4CVFN3xx06hxjdYxP+RDEd",
"ee1n1+UsoLmJbbgTbiPwClTUGqvYLjPEdilfrBzQdblBr7Xtnogboc6R6AeBWj/FjTrfEsQYVrw9ZU4vTsXkyAYYVdNNFlsAYg+3",
"gQ5qZTzowLty6l5NzYKclovkcVdyWZnAPT/nDonQTFzTMIarej0CL/2cTm48Z21ntgA5SAV5eNEqOBAv0rLAGanoq5pYzyrZeAeI",
"XKxgrnugcLsLhPUdxUl2Hkz5wTW5ahqrct8h+ynufj2Wc1ibU2DC6LRuA+cqYU/tEHhuof4UuIlJ8KHQoR0V6XK4nmBWvTlBdWUV",
"q2/iB69x8agSbhtEvPX2ufcrB7WS82DvSc8+9tMgTOBtahoqm1WS6d2ZF+jWbDhHFCAKiKSpD9Yo2NUbeM6gquOKQ/SzUqxYMyky",
"Mh0iE2UJVSQ1TBlUAHhS6p7isxTQDUXLBFmSfRgyaX+CWIexUFMoxF5iJ15fJ50mTEDgq1WrXg+9W3Ha5Q3T2uCuD7Hz5B1PFims",
"flrVLoFV7jHWjImCVXHPIG/VdLKQ/qnJEsEWwuDIOLMWEh2DTLXps1tN/sQc2F7kKVpLKU3qc0Lq0uFWbFQmXVuJEpFiM+VwP5L+",
"Glb5wUDgRldXl/aKuFkAITTV2ChtW8pvHWKX1M1uuBSxCtZSEMlt0kN3nv7JfYpVG588uduJTTnujYw18JpZWHxdfk6I8ji5op7c",
"WLfu+qJPe6s5LLUzq30yaZQbSOna368T7Zethe9H/Mm0vG1YEwYfZgm6lUVFvF55IQrTJOlwh0vSYEljpwe/qX4dnal8IvKH2KhR",
"ejHBBiDjcdgWFag8fS6yzBEt4ioT2M2vOXoJIwMgSwmoD7iYVV6vyT2RD9HheR2v411AcmJjAGuvjCfScGBvvl1RJqWalu15vwwW",
"wPU55nJtGGLGHaWxjog76V0iqHYwx5C4+KPxCPYxmyoIWjLXRt2Q7G/8fZsucr0Shg6oZ9oQLHRSOw20+zFxN9i0wGo7QtxS6g9L",
"VZGblGv1xVX60mPrAZaWajaHhbUCaxEZUomLcVb719cmjnyG7HtCkBYYUEkbTzzeE01E0LsXWX8FTiXDT6wlnS6VSizCnVtdkCHO",
"1iNIW9ru5ehOkQcmHwnG4+TkGbAR1p9Cgw11BOuRsNko0n8K08hHADYrcM6c+wVtMFYcthnxWGpnn4V1ulcQtnbermqNK0/EY9/j",
"4cEMj93nLyYy1gCYAlvNnc/WYN9hD073YRwE7bRZUxRzYPlQAXRXJC3RJx88Hd7X0c7KDjaRDRBlqHtOenJbeJeneUDbJ/0ofIpU",
"Kv7Au/BtsozhMmmsNBfwPTmASuTCPYXaAx9rmNDdA0Q5DY12sr3DdzmhQtTFeXwePxvJyTHG+vYYEh1KHo1edUfYj6dR6DldtC7B",
"pqISpFV1P2Y9RXYSgo43KXkUI9FquZls3ZE9znvkFWDGU71tFctmOeJocdCj6COnKBsPcwbaUgsT9J1nGWpx2kWX3M0R0S7vmmmW",
"jZakvQA4YTgrhBSttRG0m0rRFuEn+zF3TNjBsFcX4LLSw333Ss09Rn4eGdPD88FBAC67O/FmaWn6rZJfX1dgQ/7e+0iBBlBsjIRI",
"gfF07BOxDq/zKQaOhdNprta7m0QRhx5+qZj38/LgyHuOMAUMj7cLwAo37twr23SlBMLJbT08Cyi5dY/TM4CTzMmdZGofQxd46v8l",
"7b12ZsXSbNFXSeUtZ+/Am6OqkvA28P4O7z1EAE9/+FdmVldXd28daS8ptICAaT4+M8ZPMEezobJdz9iHvthciE1oFvh8T1UL0Xei",
"bStjAY1eeX2h0ubgclABtP9YEIATtQUU5uo5Djm8uyNoQSSdQehkx1lLm76XkVFRnTxD0fGYiZhQcXRWey06oeKhzeXoQJ/4CCrG",
"ywFdteE5PEYML411i98Du8vd+9BjVLBAsyqYtabsPjINKkyf+gkc6ZvgtTFoPLJ3ZTpC+rJo6xEb3TqQ4Hqb24+x167kIx94KcLR",
"Ve/U+9hrqaTOHuD1pwDFLGlRf1hHIzu4g2d+FruvFId1XJQ91I7aNYX84BL4eoAdkQGcea8OPqoVerYPXMRMOSYKYFEHohYUVtEC",
"ZnRncEGVGwaxB1ge7UN5wOY97mXAjy+axkfM27oAhk/Wfh8/9y52W2xUAL+YZ42h6qmPIRw1JzrTPwH7bsvCpt6QFaZSz3eHzYyd",
"wr7LYI7dfmK+p/Q4Ldxr57C0+qd3siVqjCcpu6xjmWYd+jzRFW0qeaOctzT1uDeZUEo66Jmiicb3o5gYJKfqvDK9eaKvzE9PICST",
"2mvg7bWHM/NidbC8MZBQFYE5bx/j7bIEF6tcQ9Py+PR6TxCmsrVnH6pY1418IYDcKsDDCISPO7PORilHQX2lc2IboIatqiWorVC9",
"llwg57MR8HBo6QPH7JAnnjK2FF+6k0IrBfqoeIpu/dWKxCPgGSHp1+juDRCcu+ykb3iiPjNXrT/E+DRMiI9fZzu94nCndQdiXtRL",
"euE4+XrRchRSEnPwJovaT/yscwh2Is5PrUL9LBQdWyj20Y8cJnNvPEEzUQOHpcQsAPHaESZDULw3L31XRU2x+F6M7XW9wCR7xfvO",
"m1E1nuP5Ao6PAtwOcBQfoZI+bibSJUnF+Zw1Vg7N8/mlGq+DIl5M9NBCJIlaNsX8olAAl3FSLyvZv1ADesV5ySziVJHxLWHaMgoP",
"oPTUIFQ41/H0B4Kb+4KRm2okS86JlvmZsR8PShQgPkO5bvY7KKqkUJuN1rKAacONfhlLM1NDJ+Of/oVr8KUg+jKpGa5mAYIJbA3k",
"EYhLQsrF3us1XLT9CruX4kdUsLSh0+5NwsX+nQfkuAs/ZexJWHOEaTRgz+kGY8ctPBwYpD585Exs1yde5HXEdQSHec9m52LC2z8e",
"eqFGvbmPG0u2D0xwtDqDc6NLCinaDY58bn5QYPuOtabu8FTDChF56JaWH3zWa6AlSZmVRFnLjIlhS4Zvj+JN3Nz4StYJPpKuzbsP",
"8y0ILWY/g+WS+H0eXMlA/Sl99ZySmwOVHEUivieV+GzmJbK281tJdPeITPdpk8dm9l66zztRAVh/iS5s6kwEqO4TrhXFRZnhEUPx",
"uFUdzkr/bjlvhmRCyKPSaOrUqCdse2wGTHlzGRg3sZ9qZWbX2MlGLXFbKmIZFRLWHL1Lmw3LOPoezVHEdQvG7IGWgeSsnQP3eFhd",
"s2VkPpRTQs/TnaStkoj47igsMz8+xr6GPBlcee9GaRY+3rUOh7Ghr+/wedi7NHcjzRW8BIGT0y3EZenJaOfT7bKeTYQC+x3ZMdyO",
"RSEsDrJJ1Y30nR6urxLdD5mzVkTyUL14gWGx/tT22Ph5FgceqPtiF14V8FQ1fEG1oV4VBybUallb0Xane/YZuTsaP0IDS3PYd7LO",
"ymEX+umKnQ176d22a6RIEV1iqI9ar+31sKpF1+qFoibiKqsMehKUxucNaDeCsRgAaRNOe5GH1CPQTpiJLN55/24wZptppO+tyym+",
"3FDgc2I/NcfVlD0QEUVYjjX9po7f04qF0gY+vA3UdJ8SiFv4fJ51FLDFDWTg7u68AoOau0SEl7ynftYcmqkVEDLfo/PxJx/04MdR",
"jJ9fNpQ01BrCIM4zvLUFZziLZLC7I76BhWvXmXCfknVfLBzz36dICHNwFGJuToI/ou4h96dj906QPxCI+eaUmX7JZaCUUITTwh9X",
"R+iNAk2ePOQHCegN0WsGs3Y9BCotyj5U+OINr2xvqsZ7DGkahURMgrOmXW/Fg8q3LrP8SwpxSHoHMnB7epeonaEWPpoxFOP7fT9Y",
"yNEuK40+tfxsQwY6m/4bBk8ANx8zuMQLRu/FQsfSb/crg8LWDI/Xqoox7dmnC1ZuVUjiJOP9VzEd7gEh3rhLsZfN89vxP3qkOcBW",
"UUgcNPbUhT3xniLFz7RdTMLb6vozvJZjPu7zrtnY26ilfxDeV3S991mr8BdAZrjtvf5xSpQVZJzV5dTL+odJ+S1K2hjvDUjA6LvG",
"oGHGVg/WE1sbfUWefK3ociXLYXwcAQv2E4rRWPGS4ym/iQPU0MBC4rnMrKB6tU0KPEq+QTA9tLtVHXB7z0btgJ1Mv76Vp1RzJKRC",
"P36ozPZ1mcLQJw2om5/ZCQyXFDrYBqlPWg3IX3P0A1fPLXJnYSek8wdHuJ5S9oZKRfIrF4RA0Fv/GzwDxYTc81pGDjzmKeIdSi74",
"q6iPvU6z2LQVhE/xnHJsOPaHnomDjwige1CA0Hd/76QvS6O9WwXc4FQBHVyO55BT5u5kVm92WebmxltLKlyPyRKJ7sNKxSVnyu3e",
"nkF/d0w7L4MsBd545Lx9Mxl89QAtvrdxT/KoYS+8txsWW93mkqSI46mHqS0G99sjcRJep2CUdEi526XLPrxHww21LasIchyi7Nr9",
"+aZecunJ8B0nN4vFEhI+pWwWFs+99CCYp8zBEqloxn18vFZIDm+c0XY19TSpTEkc71XYVi1dfK7LoG2Q6JlLRz4R62aID1VRUq7V",
"zptYdtun1iTIxS+kcLWjv1X8C7DbS51g+GPHXWO2Nnu3H0nD/ChLH1yWB53qwmInisGQnqky0OT3esxm2iOGCY62Q0vXqr4WmyiI",
"SedD7i0zmISkqBWRzCLjUCOi1admNIPgCY5CPSzhMZTNZJHw+fndvyNoaKU/fISkZ19VZwh75UmWOVUyqhvuB96eErOieLt9uw3D",
"q1a9s85+xjQt8R25iGa1f6cm5mbcleP0ueNTluUVceXMa7Z/nj12+8R6XSviY1WbirxA7zxt7OoLWptszBLh3zvJfKW8e2pctztI",
"6LA5il1zmCT1dh/XWi3huC/5PicbozqOW9EZnnypEZJjWz20JXrH0dUdnPaAJbpt1tNgEBCxtTYAmUO8DtGPHIGvvf0GqG8iVW9A",
"dzCAtzWftHl3CTWTyywSnhcHX3NV4Niuyqflk4BTO2eHBk8p+KN7WqZYGRxuk7YZDd5Ll9uKck+GYt564G27E1a10yApGuF4e5sx",
"0kHT4+QZF8YDsp/BmFJZz3CJ44ym+ZXeVK/mkz7HOtWlF7mf8E2BIDeNHzNJCH1w9Wms4G87Ta3Y8DxqwQZkE+7PezEY2O+7fFVs",
"qkm7KiEJh9Bkyb9ojwljidm5tfFuCWoUyYUqdEuWk5gwwKiWwpdxlZh62fRyNnxTEypOGCgSzlqku4GAbzXgdQKoM6/45hVt7IUe",
"ynweiw447ePXmOb3kzdWNlw3naGQLvek5kl965mNzeNNjY4ZHmOR7mtxw15WT+PnFwqD/RrccGCFK60l3K1+3p7kWxnIZV+4MOvU",
"g/6pjrB/esz2XgzWMiJdM47rk3m9I8xo1TICl3LQOXzWWGHPPjpRKHYNZ5ajQ1P8A2ciKtbNKv5qfJXgmnSvi8e6UigZ9G4GKVlE",
"a9vpiUep383c2rCwdBttJvDDd6pITxngv2OsOerEuT5V/hZrGLomgksv2K9n5KlDuR9mHEwh4seb6WvwWksDA+MMgV1f3ewWGQdR",
"uNAtNpjstCgn+oo0Jem7xPuqygPcJ29g/ki8n1QP9EbeZCGYcSYi7sh2T4Hvu5hLmx03MGQOF689L/Nkn2CAHSKUccO69rnQ0RhV",
"pYT7ysQ5e2o+JJCOUF3Xd45YzfKFg/q7gMfB5DMbiYll6VlEdObZZg9i9FHVC0BzurruASFq7aULP3mS+KXhDa+KB3GZ3GBSKuhu",
"UENGws2KUh915qHjpKOjpTpUe74+MaQNc3690YTxktAdrP6eeW4ZH+Mk5HZE4E0m046JzkjEkoRk3mIm+CpdD2pI4dlo1QAG7gmM",
"gBhaxJx/Rvfue4UVElWScv9elOU95lf+oEQaU3sHymOnRRajXF0R0vuGyRCI74hGZNDFf+C8buk6V3wZxDs7mQ8ue3glval1EgWZ",
"3hMnZm4pXaoCFVwcN5wJmOvFZtkHZNkNG+ZexEpJW8a+zaDMsl4ln4sowWsn27NWNyhscNNlBbLnIJ7naJbsj5oqoKerIt+90wb2",
"riGmJT+3D4nCfnJnUyv4HsQs++KLRFongLLRp0ag8VKBqF9FGNjIpBdOwMPIZ3ECXRRsj+4D9kTmFFP14snbx3HnZcPWVaHGRALx",
"S+0zu51H2jEWc0S8qwtkvsylB64FJncIZvSl+AjPcOOYZRtgJHoh3YX55QBn4B2q+lwKtn6hv6mmNPF4UXGXnRaRgvpibyvmkkhy",
"cWN+60h9pRTDfEDaw3iNEUJ6YrGcjHMbF6F53MftjCiTD0lTesw3jvng4qynDQ5gNowm/disgwK5fEl5YrPV1SK34O6pzfQZuDUW",
"j6rUt0GpFtFgdIeWDzFAdcfywN7QZEzuRAHhKeIfGwbG7OrdykB9yQ/K5AWt1vEFjVDNgN4tcJj8zIr2BbAEQunMX4hPfy+tPr4d",
"+lC/vRV71gxYJB2GWT5TXYwq0uA6tabLDU+Ctc2z020AFf8xc18cHlr2Iamx9IhFFMUBdCDKFpcI5xb39rZ2RLgnSyBYsxNZM0M+",
"lKNcKEUGPoEWHHw+aYPPZnTB2aGShfNAOHZvZ1cZ2ixFgUGgnzOZhw0/oJC5FYzOKT0Ck5sweMMUDiLkM15+ee8n3+8/L+BSxdjb",
"95MYXaHJ4GHXXx+vUFv0AUnZvsV4qSXtu0qJpeq4GhuPJTY61/DlD6Li9z7RoZLO/vE4Esfy3OaMve9rWhPhQ9Xx6rekQVjz7BzS",
"sjcHRlHirMOH/vrSR7lK47MNl97BHgBKEbaccxTtEFXJioMy0MjdgXt63C0JJp/4P0870HEoFiolVG/5luzD93FdUVBKaF+D8AOw",
"+cCXsdk+lKcSyOtTtAjdXRmzs5RWHcKBYn8UUW0Gq8g2CIvIeMdGveymj0j+lOCQkJj5et18/8G+GUObMQzyjQX2Xv1wFVQ7z1fr",
"tR9EWCzkqzXN9HIGoSmFq9G2FP/W2rID6m6DaXm2jKmoFD9+EPdaA2/o49VInZ190G2t4X5d+oT3Gr2qaG+a3Zj6weJosZQSULZh",
"TcxTeoGaM7NgN3u99bWs3LI9ttfN2MT3GCNb386HLky2XbFmxvuSbyUTm3ox0GbBA6i2Ixl/Ip8zjXpwCMlAJybh1ocWFPaC95jq",
"73fg9E6X+4kws5WV61YhYx7MoWaWePg5aHKK25Pkz7f8YMCK9MYv+U0SEdV2LfW8mseRjz4XDyVtVY9A4tZXd+6Bg+a12DUfENvM",
"x5Pw5QJ5DkOpADe8KyvDheNl3xmJSx+6DTsz3dB8F8nfH2XgPhDmY8jyxVviqDm1PIO0dL9f1pIx5rTNEVtNnJuFk1Aw31LsFr/i",
"p4D1VNBjKBtplmZ76PYgdGNmmp64yyc8kHJaGmykIL6W5LRHv/EnGaOl1PoMNJ3IQyNlTNrn6n3MLP0+dnx68UZS3tIIQzxea4QM",
"XU42m2VQH4NjhTQqvLUHwYh64Rz2S11w2pOmG79cj0ua2nbWH2Wj2N+/lIzWiLkmKplEQvP+zqfl1Iq3oawNL0YFxMtd9kx+v5UH",
"r8qXdz6I+Rqt8fZcfzgXVwiITODUSItLsUhrfI0A5ca8rTqYGYMTNCfAWMmvMgkJ8zavmcViD65Lh8j692QE6MWfYMHa1cvUNRWf",
"eqeZRsV4ZhKqE2T5RJw9dN2nUVkvVJXWQ6GLcZ16wgxiAbhhtOxJECjuT+NmcmjyYhdh7BOht7/Fg1hcdqaOLHK7z7ss5JNwysQF",
"yi4ZWn0Zoyr3jli+3vjomrIHtu9eduAqVgzaABZS6BTHsaHW1WXODSgirYCfvxuGeKHT8LcsrAvkZcObjRGFsvtFc5eghNASbK2R",
"Z+O5gDjup/eRm75lIJ+F4LZGFE/lw2H1u0u/Kc2OCIPIWEz4EYnX25V1dU7vNwlYfWNcMwSVjGqTLurPWppqJTOeojSWT6whnaJp",
"6v4mvlQeYWXtjh8Z9b0udIFGbb9iB+Ms+la/OQZbDHEd6oeOXMQXorBBCrm22J6V6A0zZiTPyzpI0+ThxV4PFimWhTOIgas35g66",
"TRasQ/vEd6hjILsJLQ4UfMADcRGkaNPUBhNjyA1+7xbFbDIF5RQjwW8mfvKzegxkpbkf/awyw2h385iJeyksDFKytMPee8rnKv+Q",
"a7zXN51jvYrmrOxHybsbap2U/Yd/ag+xMEVrbuA6cuw6q6MvisHoA10yvQDJB+Ck5x009jaqVq/tYJHsri1aCq3kgfl9EL50fw1g",
"Bs1ggJJvJBfB+Dr973drPw5oTOONLFCzGI3Bq3JwU+dw+q44LbVon0UmW9W4OS5+EvWwksKDgwIM9yZBA1uNC7Mn7ErbHJb5Ay5U",
"FoKXNGtdVREH+ZR6KXpAQ6ar861obfuyVs9nurRhYOVyKSdp8h2Mk34Hw0ilG/jjWMbx5G66+PLaTTHBAJsNovolbCdG//4exP1s",
"CDSZYRidAYHqwNA6a4xCS6L3ZV51tuJzpK/5UG4ArCY9vENHXmKL0381cVV+fvetyBgHt+sXzYyN8KUW2AdqbYWn8N7U/h4gnTC/",
"U39zGgzKVlen9JdXqGk0t7EzkNDygTLWmMCtPGQMh7QklhlwcEx54G/szfY1J+33pTmPk4tnCMdzu89d6qtpidhgw+KdoD5pUyQu",
"w/bsDjVuzu6BtumgfDy74Dxi6Ske6GPAxJDEjuxRT0elSzF7J5M1Z8v7shRSoYwrcHbqvZiEn+duc0dyr2xF9z042SY8UmlfX+4p",
"Ir4S5/dYWtxTJ3PTyxAbAQYqJsjxQTOIPH1An4d2x3RBLusVL8u11tYqk1PEmjjHIblXMk+12kJrN6kv7y0O0Id20xGSGhTtzYck",
"9YmKdP0kHFbP4Ld67O1XklAfsn2Z0twA8hS0/VgafjuSx0deHYHyS6bQ+eQ24o0aa7VqE67EmvqB2pi+Rxeq51YmckutQ7oxXks/",
"vD9IaGytSSB8UZ5rl12pYrRXI8ia2/hz9sBvi2xUpbTcfWX81Jv4yFBhHvYgdYOW8mCFQ3PgebuCtsak0LNHozlP0IzPOcAJ7uj6",
"83DBzAiEjiGVL0ysRCQtHUDqBpjhB6JqShsAGl3+MA95gR7rXLO2QHTVWlVbfO15Dd5jfCXtvn41rG/TItZIHZpP8yODjgurDJQ+",
"aGUZu8Q+3sZmCCqoWrvyteyqgpLWCdF0yuPcg1EjMrWNNPCRPqD9WNVAm86H5Yu8M/DAis5Y+yUrdc3AZPGmV8IPjld/JYZB2y5B",
"ido5BncSJLZrqz4kuROQ51bdtgYxlEwdMF5HiTWbO+J2WpRsEYlZKk9UyQcFON64rO59vqRBPXiQFDfdfi/XkGOmyzWGXogQZnkd",
"RYV2zx6t4qw0PkuMZdLgd/O7+L3n36ESkW9XdKaMrRC+lhQWMGi8WvBG5L2IwIeStg/PaWJV0hX5Cz9VJC8JSEkrAjeZpGntdMbj",
"+0t1pQdFnRNqrfHzVkf8RIR7X59LAgVV8WpvptJlZyfS+Ga160gC7//xctLPi7lmqs1x5mxZGzTNdXn7Zx9ZcDQKYIP8C3GaCztU",
"0zevSenWJ9r6nat6fTrFTKQOjPJLXcIAQYs3KMi/C35RD/LvdGhKH7AdGFSriLNVODVaOl3/rcwv1gxSpgaODs6oyqB8fi7lVOfv",
"dEP8Qb3AAbZJx9vbsjdQxSoK1GBL5DDjpr/XSasz9Rhz5fJXSCyQsMUgL8CO5UHIBjqO8LgvT7jG8kGuU4QL6rnshbH8/GkHpQvd",
"meZYgVXDPaWkc+MHWoNrkWcG3XGKnjhnvTC60/Dg08u3jhlrnEX4PrrcK+BVQYHFCAq9gKZd2CNf4vusLUSJt31aQI6AWOiRVGkb",
"7iCrC3dor7282wNcXptbusbi9YyjB2LdgY43IhXuB9b3HfMaADE5vP2o7XlJT54gnY1YXLQbj3XR0DR7EnlE5LulGyOyUz/PJvXH",
"lIg1dPUh00ggbl0mHBmDKq/Wz7+HIxDEde1h+ZVq2E+aZBGEHsCFpBcMEkcn7EH0uQt3o/cYLpTuHop9JPvUYe8ufMJ5VLU2/kG9",
"+UXEWdOfQT+0zv2rPnDbZNSqbExKJTL+qS0qRcl+mBYsi4+7PaK89PDfAN1fYFyjCd4zZpU0Aad5+TsP4hI4pa3D+EunJNVxkD6X",
"VwYbRr93/EB5kTQKv80Oc1grMxapSDD0dFPDdZtRaaX4LNKbvdeXI77I73LuphrcBYY+SBSs75eRLKnBK5+3JlEF8pAkJ/Xa8tO9",
"Xo1kktgiMemt4wkFj6DmmllgdaspCUW61vq3k0WaP1RayofJ2zrNbU3xk0Pg4a0mlXxwCLSrjpRCkXW/YeDlUopeRXLNMXk3PeOF",
"CgtVqEE6LNeKuyH5jNa6FvreOcPAFGU2rjGPvd0SSeYpOjjYtInBh5zZCeITSoX0UfHlxMgHwBYTic4K5zYDRTyFvVpPiYZ89oGV",
"3dE+9HeafJmGydGafZT8qIPvRCcytdhFwnuNIDDlAUmJeoSbQ+easlGeuk/Wvj4Qt8DOWjDOCrvnxc1wszXjHJyQn15mHq4tIBRw",
"3AxQ7fhrFMIYCJhk0nj8rXmgL2fh8YQyMwYU9G5o1JpU+juvjyuAZHs9GEnnHAtjIN2QcxRnklDgsoD2KBlkoG58So7pP9RWKLRV",
"apzhVPev4QJ7ZLFW+3mSJ/I4aedN8PYe2KxsLhZGrjDxVUrKRBTVoXNPrJmbCEExaqkNUyib+m+elK3d274g4g8/I64czcAOR8/W",
"wkjXmSRlnRjlhKFwf8z/StoCy/rjDaMAikhJ6uH4bHGOR/r8CDHoKzznc5dUnjWQ6CFnIW58ZiVd3ImQz6qSEI9b2s+VdPUkXv1m",
"ZyH32pMELq2OT86hncIbVv2Fz2E/7+MeAnUZd0dCNt9QqUxb50FEluK05AeC9ksgd2GdqeswBdIFL5mZf1tEkTM4DQFzccPb2o0n",
"HRH6t05FFtnKrakaOjjCgoS4P8T+SWaybEzzKPYMJjPnQw7AoVFsUa7gBTq0tFOyg++ZrydpruoiALy++kXMC2SETylAe411+3dc",
"0xY4Arj+prCrAOae0bHYlfKc83b5C5ITylWYHJRTKYPLO8/iM9XuOMlThQUXkR06pYwRcKcs2a5polDWKmWecHCKWFmv0HKPfVah",
"HApR+CYvB5Qwt5G3Ehn9dAJKsYotbXkIg8VOVLUg7LZ/j7Zy6tlyiq9fJH0QgBzRzx6FFuC66BgwA/TPu/rTcHvCZFD8VcIujfAo",
"QSbjrb8Zgt7yab9v1zspDuyTqn8gdxg4hY1x94IZzRs5B/QbpZHWz18A9lo/sacHJdzjNUvb5/jCmIB30wUJIgq29edQsZh8v8Rd",
"3/p936hYW27NuAN86qY8p/RgIppdoDxcskZnm/e1wqjA63uturzYwGTnXew9Q35tIE9uwpG/7RXdsqhfiDVmdAR58Bs8YGjD9YGa",
"f1bfeuqGwoHxNxN2VSTrB6qZddAAoIPc6Zx3TgR6RWsE8Bvun7LdxVwEQrqtIO57dhD9bQe8olfFNXHAaH8mLEzvNNTuItryOfEe",
"97BCyeeWXblb5SVnTq6uMGBqD+7HDadXdSCVUM1ZK4GqdZ+aiFGNsiiKHqzVsuGThpwp4cxMbd5ld5tuBS3vQcesIeX2fGaHictq",
"xpuAjxx+uFUzQYn2vVE3Q/ZlnDCw4S8lqAolSLZt391x2pFWpj0JPtXEJdgdzcuvCZHJxkAH9EFYytAJ/BifAVhuW3i+VDwY2nyD",
"OGDnpbwjNiDlaDcIHGtpxkxHMnroxbK9vqwWbHcu8p8QojbO9mrrORZBcU3YX7lFPSgOZMyHBEMpM8/qyJzNxOW+BDvFUYFfHHaG",
"1JZwnHcFPQUfbJm5LROUGQJBMVn4PUvNypaT60+E4+oj1RL8wjbvPn25dTIG/BF/P25jAD0McwNJ8DSIoF1UMor5oB8OvnXwM1x5",
"9bJBP6t00f4QS9fm1xahXV7PwLtu04cEpm42jXBlIamby7y+EDm7w9K7fddT79jdFPA4z3Mt4pNUua+D0cf4VUAK6lPy7o82NXYK",
"DCAQVg/onAQIUymZs0Nn0qEIRPPEYnHhzYHYud8FJKF156EZytlYgVT4YO0bsaJqZUSg7mBpLiExQ2yZSopZY094r95wa4fAXgi2",
"p+K3driXk3NBDY7r1CsvfzmRGJwcct4TX1K5y+sgzJUDCAq7FDYIhgTgGRT4PvTxqz0lYxD4cU5T9DVrUW4qkOSHGNliL3Gkxt0T",
"YZgMcVzhSLdQoy2OEN+V7Et+LSAA2ifKeZC/H/eWPHWd/LD9HoB83dcMEioPC1eNk6bmUqveQ0/hn6whnVbpetbq5TSJUxGHL9hg",
"ee5hM8CTl11rIeX62K8uNKKXMXyE8wHmwG6DZPWzshCNcc7DCOY87EhmYsIQadCsuD3fa2213X+QdeT51wH+uQxuqBJPjvchFpL9",
"Xs+miX6IlJWDN/RZ3VhFIdBqzKwX2C7RL8vYugJfd5c8f1L8ZHgjs1DSQAD8ilK7MjWevRpFvrnf9pxUUeDTS4LQTKsw1SlE1b9i",
"/ogwsKuptAFsLwPB1gXniBK6nXV5L6P4CVU5eHr4OZbvebE7vr6U1SH6krvkb2MvP8rrnXirgviXUouM4fY2cXtNUI0VrQ7qO2m9",
"bMGqDI8fGoOQtUHm4FiPrl6EQr9V1LSk+aU2HbcA4i67GudeSKd4e9LzXC6SGUpjfmIBOI7CvrF6Ot8J9jnPzgOV1Z+VjSNnze7q",
"yZgO3B2q2K9qBc+MYiirOGQA5RSBL1AFOY2MDJmlCyMz7X8yHU8lmaTwruviMgTIcg28wh3B15e5NaFXn/+fgi7wjLvQFnfi3xUp",
"nQ9JO3wvkmvuAFgVg1Kg55uTPbDaJPLPi+bYWZ9AYoeHVmIt7DXq6gMvX5gqqDyB0TI6Cu/mEueOshU5UR8aQfjRMkpuf8rnLbyJ",
"Y5yk+JMc3lZYeoAMrf3Rn9wCOdDszLYsut1oRrTZW/FWc5UFA2Svei3NXgypkpPjGwuxsVMXvefvCLuUCk7wzHczdn5R70kCbdWN",
"wczrbfZdaRfBuVcwvSmZGl32oSyWY6j1R9pNUuUrZ2p8MQ1Yq4sebx5KdoLs/fbVnnuS7e1/aezqJPMjtZgH7+LdXbipWuDleFyR",
"eVPNBg+/3218YZAR9b7pdGN4zJof+slEMDRPe12lxlsPtUTp7U5zJBmakaZPK5NJEX3/HFQcZnrSF8e+wKksTLiKIrrEFruE8BG1",
"qkKxrQDomXSGX+CVoACJyZ2xFkX2uE7aNLPTFIpi8uBhB3CYIqWSo/0yuIg13/RTuCx+Sq0nihWx8dqOcXSMcmviuD7aOmem5HwE",
"XWz8H7zlin8uT/0E5j+xV7bu9L+AsUCMky5RFXmuxV5NM4v84jN7Lg8QZVUX+onlJzKlFAHZRDeGmB9GoJ8oKX/8pjce2r905aBi",
"8q41YkPCnvl+/C+5cswcb2lQHd2l3boYSx/WtbzVuC3H0uRwOgnIIC20+z1BjX6qaBQkkqawBBnw32CY1y8nZ61tpHbJtFfyxOcH",
"vbdM5XxLO23A3qmBtZtxJTyhJ4HYZZQuGO+9x9LjqiTDd15QbriZz4146NcZLDwePGAV2lL8XahZMyEipLjXDdM4GPiHq5EM2ANs",
"JS3rQ8DQ2W9J/CHuElR+xHWfPOGaKgp2EPJSp89r7QsF2OOyy3DfjU64ENOde9Gmmb6+9Hdxk9zQIOOpw3L2uoeJGhsmR8vXuL+w",
"2jsgtkoRk6SBX99ur/v9wUqgTnkatxUCj1M3dh9IVMJt83kvuibjVW9h6IKUWNSHCmC3tDExmL/0ZJsrBCHcD12bqvhykjo2vSx7",
"EHlWBcDjhdjCid0FdTyjcU6PA9Y8jdEVC21Ladekj2JuqwWTkQOI+WQd7GC6z6yj1g92GtV2dQcINuI8BKrWRiSkUNLE/fA5htE5",
"prtyCSc7DWDJgOxkAQKlPb0AQVEh7pQXFks9xMG2olFzW6izqbPpOCHBFvoIti77yNfYry9hYC/n3bnzz2/8vhnzlRhCkgC2ZOjH",
"Eg4yJkOewzb/hbgd53peVccscQqQhJYXP3Vgm5UWMo8PSlsOUw0RdrRUxSAU+uLxYbl6wb7c4fC8C/+1EnP0Rwg8ESDQzH9d1P0/",
"74cz1wx3rzYqCT5h4rmOGdrjR3Cnbl9QjSb6xPusPb1IWRKq9Yo7KkBea/vRNbWc/deLNhSi+dDd0t604fU1VwPG+2VsR590kurz",
"0mGonfsuHvL7KT+02DtKxt+uHuJybXnL+QUXht2x+jwnTOIGOyzdlcVXrV+HSYGAhyyYkB2Ucb9kMtvpgCUvJAzW3/QUTbZD5bsY",
"Dhthj+IGVe/xdvYYAHDSaK19bm9G9fmIpPGVK0W37hSotRdkqNLMJXY3KlT3VOBWtPT3sv4sp4cu5ugB4LqNcIREl4Bsq4QPp6E9",
"fpzePv/zECbsHyfA16INEtCGACDCcp8M2XJ2YixKGNnqUCJ7ncsQr5+tfu7xc624wEMDgono72EZ36FlhI4PmpQHrhP8Imm2pWdn",
"qxklePyyMNz1JS4qxi0nNAp8PiTtDHrTdGi9PoOOoJpfwdK6QxPfxEQws+cL7+WXPof439/jn33mRXV///23pN///jutqbTM/aXl",
"M/9TMmirf//tl7LQ33//V6U9dD5//4e5Np8fwbs+eeB7/ds2NnOx/u+/veZ/b+VH1e8PwaD5uUT/tfdno/9VOetfuyF/unHrZvst",
"f0aSTj/qt8/O/EfH/9LVj27RT/vTdyxW8Zc+0R8CR78EjJ4T/hBz+2tA6T7+9qMu9segvknfF8/2fs3PiP44858D/O/FEX/U7X7/",
"h/MM+7dm/O3b7PVvw/XbHw397fVHE38OLfmXTv/ob5qL0Xw4xD4Nfw3z/9zbj9zb7/8wnst+23+MMSfVj8zgb3828rdX8j9b/Dv+",
"H839NPtjst+msb/+92//aULXdKx/Tul//yY8Vfr/+S0ZH/vvv23FmG+/PQ3XzVj9cRf+6P+XUuVfY1h/SUD9D77zt19icH+aPKuL",
"rEun848RP9cVQ/oM7bdfx4v8H7/Zfx76Y/p58Wmy4rdyWn9DwMczru1vr189/5szZFNeOP20/1Pe6te3/7L5lwDnP8925/7PEPiz",
"mT+nMj12+tuPZu8/fjnYbz8KXsf8//5hop8L//b69e2/NP408CMI+M+mhWfn9186btn09Frsz7x/3GwatyMdmv1n3vuxjr+VSb8V",
"/xzFj7DWv1jq5/79/ttTHJ7tYyvWn61/b/U/jn+S/ih+6X4lTf6/fg3997+m9HkCe0/SZsyL8++//y/ov5UF+49B/Isx5u+/fPHP",
"8f01z79GNz/nfqc1/yus/mP/P482O9b1R/jvP75/bklWPPQ3L9a///6Hd/7R8K8Lk7l5WEZz/5ivLP9q7Wkj2/88ss1F3/9ynb//",
"/u/G/I9M8J+D/Wf0xVX8aYRfzvT33516+v7R9T9+Nv9zXP+bL/0PSebJVH8qpU1/GeKP2/3f5Jff/+GNP3qs/97P314/jvSX9/7l",
"s/8e8cNW/dnTr62Hof/0tSf7sf34/69E+XjpH0puf8i6DckT6j+XJPP8H/nyV7M/GnLF+t+FQro+SWCdvj8hPFT/lxJvFkd/f31+",
"9McExno+301ivpHIfFGVrSqNp1Gbt2mDp0lHYKaAr98R/yUtoSZDkdlSyQZz3o4quSYzuZ4yyb7/lHjznvaypx3waQ/M+Jp2no3s",
"/+5z/ynxxtK0TP//lnhjrIh+5sjS1h8Sb5b9cx7PPef+zPlp+rHBz79fEm+eTbM/Em+8Kz+kObKtK4tEmwHVerO9VhGU5pvzgYWq",
"znRI3/dtu1nnsmT54mmmevp9/2Hn/yLlRvM/fcs2//Qts8+H+8/n8T8SbfXTL89f8mX50guu6Df95X/myPEW/cD8L7ckw7yKyvPf",
"gFQjYRDIifiDgVjZrouwkhyh3LTUG1Ao5rPSqUMIpjgEZxm/TuFklwvM9154I06RUqFEDulKbjgwn95Il3Dqag64Gy8hFNiUZyww",
"c8tmeeEtqQd+H5/Y6Tgg5UvxYlFy4pXru7DTFQj6h+JX7fD6BvJnS4K25Xv0A+luoTjse38t2aJnDzVrCk6ebQ7oF3zuzVrQeLbs",
"aHin4m/oBEa/aFA2z/i56AaELfVVFO7UEFS2WWXFLQELviauHpYPn4VmoTayZT0wrnhvM2kuOrP5Vx5G0oAGqM6vtpKltaTqjTjU",
"UQVMchgYJWHiYiQsIrBile8bvgQk7w8QtPpr3/xUd5HIqh/z1j6s4E3M1FU56NoCPzCZ291d4e7Ktd8tH9sfDpNkINiG2CkpmrpQ",
"84B269rp3XZbAJhDfuFQ8kCBSKyMcY6JOcVo/M4PBqC2FxCl+LIwKYGewdToZjASV6WeJqYDxbDlzmvqk6HJry1308yAFTUb6d6d",
"x8vsSgsXE/lhQB6kR6furktSlNuJ8mnrUJ2vJOoNDop6RJKIVJU5lOaXVqCB2bWUReCojINC7RMSWfzFrK/RCDrj9hkG8U33qwDW",
"lRsv/sVT96GbXqBesIrDYZ3U4SYKEi/j/etNtpES3h7PY5eLJjeZhTGgF+KCZg/7AqkPmg3Wan+1i00Eu907GZHtoyIZpD1yphDL",
"Pfv0H0IVqe9rHkaR3rY2263xWxLIDRwdbHcwtZk/y//27ZxENnx1zcqOn93VAfBJW3X50F3D23Rj06GdKtB6jvs3nOWdrxocFhlA",
"n3z2kB3hjoMvBJK2HQmzbCLU2WrvcEJOCQJ3SMDRFVWXqM2TwiA9j2MmfIbk3pVcKjJIs4LtKYw+MB45ADSsfO/HhzgFSJ/5gmOj",
"AC1ddISvaJOBUPz9RNDro6DzLEjDkxWfJEXuGlWPZTsSlkL0Bru8zw5zMrKh6HcL8BKOEwWpZYaOatX33eVmNoFeWx7q12Aothzn",
"9wjN/EM2dfljfxItzWSTgKtlzDhAGoycTiLRMRIhyz+OI0wvdILx1n5OSMoHGmdccixzh5A+bLxL0/l4UL31V+JDWG8Jolg+KObl",
"BmfupTQMuZynMx60RV1bpxuMYPdmrpOWvyLVdyUP4lOn4DMLa1fFQw6StK+854N2/hqeIm20nimWp68X5CvwbgNofZVDCZSSbzSv",
"MI7TdTQUTnoyFUhoLZUYWVee3CluObHxXm5A3x1V5sdVIifbaRc0SoEtatKoka9L/DwEKWTyUIPGQxUv7YBwyVNVnPValxWFJskp",
"umyHU5e1zKJClvEWonThHb/d3bWRxrhn6zp9XxZfNuU50cMM3ymHTFfJtzJCWlZpWto8N03ed2/3vu3TlsOui9SlXU7TSgAibKbZ",
"oA2B8L8Vi/aHhMO4+y2ALobzqmwrDhA4DLc+27DzeXkaKjxJhJ56b0zBmaN5WZh5gWDgPflv1aBCOz3ttv06YeX3m9wsSZ0k7CU5",
"26gTYlk5PJh/uokPjCfyGnvC5M9xqzagOhoQmZXOaFSkxa6faO536KdlLsB53vgV00Uc4NR8a/HC2JYrFL9f0Ee7amgPfWHBPOfU",
"2btB7IWnT0bN30CDJziEJxSYaPxLd/yT3/jx1Q7nVlpvAy+94ui7VXbb4uTQ7onquU2TRht4EJTVnYetezm93jErY3gSXvrZpQOi",
"q3n9cEC3vHNkTBPffhGF+TUGR30PCDskjv6K55AIhMb/cm15+5WVv+rPpBTqwuI3O7218+qojgSdReE7GiA/xyGKAMBBOKUrXDKN",
"dY5H1kxg3ztd9WKdYyQwtr7+yqIk40ZeI+WIpolL6DT1ccahiwZ3a4NKmuuBMExzcT8k5SQgfLZPBmKqKv9+dog3EpkgatAg05I8",
"F4DwSd8PfMh3UUHzQ1Fs58pkWYmhJaB1wVzi0Rz0a0Nh9WGxPjqo5SZlQVCxDKCz9WFwCXDuZ5Y9fngUH68XZxUPBnpzxtW8qd01",
"binOpNF7tYB4zNFaamq156ZmEJ2qHltoGojLezIODNmIJnrKiea1Xb7/Ggc/Whzeg4wyd/SyeD0oM0kVPYThaVHQIVENO4tkTkK2",
"VoGluhsvMn9S486YjV/Ai1RuMDYwqUyhQr3RzJal3G3oIhY9YSoJjjjVDZFY74bm1aV22z5cLNpxzq9+zJApP3nN1t7w0FWByqqy",
"niVNwaCJfwTGUDPvKF2Eqzj0pjjybSytyt6zZR77lOmUHDYRn3Rf9wltB+UKitxLbgecXvRlH7Z0RsBskh/N11ORUtKaFZRlmZj5",
"zZnyWJnY49X9trLgPsBPkCLHuKT+25YYn2eV0Xy5nWjzQNkUHtAWQwcnCqqMTW/Ninj6fbrM4ikO6vCUbpdCJDUrgvlnQdsHQx0R",
"fWYykFjt65aLwMU75kMGo22b0UUqN3uRdDh8iG+xlpvl4+RxESU2gNZWCvq99ZogfV9ftLNakfH8bTQwKifpUrMWdq33F6OvRDFS",
"c52EQ6ENar3D8mXjKFQK554r/G0FQDvzXurodVa+qVxFbNXrqjtLe+pnfR5dCny+jI7ZmpaqUotJPL/mOM3fzxfLUzvFm/547+8k",
"cHMfA7zJhciyekCCMxvKIaszRE2H+hGNxb6WobSkdWV8+EBD1T6ug73tHQycWdJJli0+aGHMwBnaJqxNGSDjD63Eh3HxjlzTwpHP",
"ru9V9TdqVoUBA9UNeWm/NPYzKK8ZFzLt3+M7+1wGclFPdTKgE24CI/kRp4sh05iXpVN41kQ9841AYtsj6HchEHrXc22VIbGCJ8JO",
"/aaR2lahXzI+Wy+Jsm8+9hZFhstNxUwoNWjx54ETTbw5SCymc7U90PPefBywBgcnY52dSjcpGPYtiDHLr7ck1esxrgszqflQ7QsT",
"naK0YnOylI//vb3Iz6o0BSxyl9Y4PU9T52zPXpIrmVZ+ibFwrlkR81m5kdlMZUYvO+LoGUdpYu+MD410lp2kgMWVYIembt5QsKV2",
"E5pxYzmi3ljGJzT2nVhUtwZiwkzmV5JCT3wGSETJPU1cdkSBdHzZpC5qWBxuGjsOuu1Cgqlo17aZz4zPjo8ZvHV03zqt8270JFvV",
"j/qKhAfMjIbhV/anyp8s0Qd2UH9EchALdRTgwYcEJ2G7tm+ubrc+mtsSoEebn1KAJZAhqVTLUAe5r9W3nzkGnmkqR1MYpaRJJIPj",
"kvhZdNLna+ZEkoF+68fAMmgkgVDTVYndfFvRPZw2DoFj1SUHKmC+TfFL6t5yk62fw/reGL4m68c3VbJ1tjDDojEdXlwwIJ43h2O6",
"B62IaPScvZo3h+P4g/S+hKiKk83mfS4q0n3Oj/MPLgV6eFzp9xKaONzbw6t0o1c91ZlLxN/77XA3CNmSQdvHcql+Snqhbwtp+wHd",
"N4MOmknuieddwYEtV1Z301H2Z4sonvz42TtWKO4cBooRq6OaDlHL1aiA7YAVjGiFFCnEE+0FbxqKLQsBxvTZGYpPA5HyVO05ifsB",
"DUfrnNVI1LK2lQ1uLMNxF3RR0G3OB5dxVtxrsE1yjc/V4EO4ck67h+tdeK1xC1ykW98A8f7EO2BD9UGOvF4yl+vzkC3OWBXN9Pe5",
"VztFPxw/Vi1fDVkj4Uc6COh6MC8ISaJg9Hxuo0x2LKLzsPeXh0trs89s0fD5LLrwNTXR6d49a7JTG5V4j4i7el5G65R71Hpx4rSr",
"AXkc5Desua6aGfoQeOAfR/S24TkWP0jLfX2WI3mqaAgHWdxr+eod3K23X1fGu9eQv/feo0ApKQLDlx3idMgru2iI7/iHXIoFGYSl",
"OGp12iRpDX+efNAv6sEm6hTo/ZjxE3wyzEPEbRT37HxeNQfSufT/o+7NmlvH0gPBd/8K5K3MS9LkpUjtolLSUBK1i+QVqe1m1XSA",
"BEhCBAEIAEVSee+EH3o8doTD1S5nuybK7shxx3Q7wuOJnoiZDnvmoR/sf5J/oOsnzLecg4WE1sx0ZZXDeUXg4Kzf+falsLtw6+2r",
"E7t5cNJwFs+O9e7hwXn2YFyo9tza5LK6fdq3l667HypHx6urrcX51eyyfndzu9/a8QzHOlmqG+P7UfvDbWG8uthb7KrZ++pFEXOB",
"nl+c9q3jfsW43d9Z8e5Px/P72f7lXf/mw4fGkQ2s8MHpUtfS7X75/sbtn4DsDRz17Z1/fNmo+/3m2vvDcqG3AvzHib9a7QJv179d",
"rPQ7J6fbkz4wzMedNf9gt3dZPb/Rq4uF08rezk7BmG8YpnF+Opn0LvcvVKw1Us9uN5ru9lH1eLxSO76w6sAUf5g7XbEuPO1wtb/a",
"Pt8tN+32eNJeOGw4y63s9r2/qqnb9auCP+o3fPW60Vi8GGXfN5c+zLm39/q90/YLeyu7urvyYbk9ft+oNt4P296HI6t5tDopj+qL",
"Kpzj8Yrhbt+tNK526oP9y5u95uHcceew0v9wsLh8eXxr6aeTqum8r63Wri0Qr09V4/35uLtycTveO1gwe92j685Bbb6/dn41NDp2",
"d2Gi7vYWC8PjG/Ny+Uq37/2FZWdUt3fq98X3x5NLz74d6tfe5VrXvLo7vazV2uWW9f59Y1TTL/eBgOyuFNxVO9sFfsa6qq5UVdXZ",
"Kd9ove3trr79YVg4nNttHh/fFOoHBzsn2ePTux3//LZxX1ixhg3X2l6r3S2qx+/H2zvApGiLk4ujte05H2jmcu+24dwMrlZ69zf3",
"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"
].join("");
/*ALKAID_EMBED_END*/
