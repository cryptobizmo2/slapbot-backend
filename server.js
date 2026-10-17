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
const BUILD_ID = "2026-10-13 · owner-only · custody · V1.0";            // shown on the dashboard and the health page: it tells you which version is running
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

async function getMintCheck(address) {
  const cached = mintCache.get(address);
  if (cached && Date.now() - cached.ts < MINT_TTL) return cached.data;
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
    try {
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
      top1WalletPct: top1WalletPct !== null ? parseFloat(top1WalletPct.toFixed(2)) : null, topOwners,
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
  return {
    priceSol, price: priceSol * solUsd,
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
const PROVEN_V2 = { slots: 4, fastLane: 0, momentum: 1, momBuyers60: 10, momBuyShare: 65, momNetSol: 3, momRise2m: 20, momMaxMcap: 30000,
  tpPct: 60, tp1SellPct: 70, slPct: 20, trailPct: 20, trailAt5x: 12, trailAt10x: 8, maxHoldMin: 20, moonHoldMin: 120,
  dailyStopPct: 12, maxLossStreak: 3, pauseMin: 180, cashOutMcap: 80000, minProgress: 8, maxTop10Pct: 30, maxTop1Pct: 10, maxDevPct: 5,
  labFilter: 1, labMinLift: 1.2, labBoost: 1.5, gradOn: 1, gradMaxOpen: 2, gradSl: 12, copyOn: 0, learn: 1, cfgVersion: 2 };
/** Staged exits (V1.0): sell 25% of the original position at +20%, +35% and +60%; the last 25% rides a trailing stop. */
const MP_LADDER = [[20, 0.25], [35, 0.25], [60, 0.25]];
/**
 * V1.0: strict, bankroll-based rules for a realistic test. A $1,000 PAPER account (so 1% is $10 and fixed costs are tiny), 1% per trade,
 * 3 positions at most, a 3% daily loss limit, strict safety, and staged exits. The one deliberate difference from "stop for the day after
 * 3 losses": it cools off for 90 minutes instead, so the test still gathers data (raise pauseMin to 1440 for the real-money phase).
 */
const V10 = { startUsd: 1000, slots: 0, autoSlots: 0, riskPct: 1, maxBetPct: 2, maxOpen: 3, maxLossPct: 0, minTradeUsd: 1,
  dailyStopPct: 3, maxLossStreak: 3, pauseMin: 90, slPct: 15, ladderOn: 1, tpPct: 20, tp1SellPct: 25, trailPct: 20, trailAt5x: 12, trailAt10x: 8, maxHoldMin: 30, moonHoldMin: 120,
  cashOutMcap: 100000, fastLane: 0, momentum: 1, momWindowMin: 4, momBuyers60: 10, momBuyShare: 65, momNetSol: 3, momRise2m: 20, momMaxMcap: 30000,
  minProgress: 8, maxTop10Pct: 30, maxTop1Pct: 10, maxDevPct: 5, gradOn: 1, gradWindowMin: 15, gradMinLiq: 25000, gradMinLiqPct: 5, gradMinVol24: 50000, gradMaxCh5: 25, gradMaxImpact: 3, gradMaxOpen: 3,
  labFilter: 1, labMinLift: 1.2, copyOn: 0, learn: 1, cfgVersion: 2 };
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
    gridOn: 1, gridStartUsd: 50, gridMax: 2, gridLevels: 4, gridStepPct: 5, gridHoldMin: 180, gridMinLiq: 60000, gridFeePct: 0.3, gridSlipPct: 0.5,
    // AUTOPILOT: protects the account by itself (no one needs to be watching)
    autopilot: 1,         // 1 = on
    autoSlots: 1,         // 1 = fewer, bigger bets as the balance shrinks (fixed costs hurt small bets most)
    ddBrake1Pct: 25,      // down this % from the peak: switch to Defense settings
    ddBrake2Pct: 40,      // down this %: also pause new trades for 8 hours
    killAvgPct: -12,      // an entry type averaging worse than this % per trade...
    killMinTrades: 12,    // ...over at least this many trades in 24 h gets switched off (or tightened)
    cfgVersion: 2,
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
    for (const k of ["bank", "closed", "report", "skips", "events", "startedAt", "seen", "outcomes", "auto", "runs"]) if (d[k] != null) MP[k] = d[k];
    if (!MP.bank || !Number.isFinite(MP.bank.cash)) MP.bank = mpNewBank(MP.settings.startUsd);
    if (MP.bank.pauseWhy === "daily stop") { MP.bank.pausedUntil = 0; MP.bank.pauseWhy = null; MP.bank.dayPnl = 0; }   // the old daily stop misfired
  }
} catch (e) { log("error", `loading ALKAID: ${e.message}`); }
setInterval(() => {
  if (!MP_FILE) return;
  try { const tmp = MP_FILE + ".tmp";
    nodeFs.writeFileSync(tmp, JSON.stringify({ settings: MP.settings, bank: MP.bank, closed: MP.closed, report: MP.report, skips: MP.skips,
      events: MP.events, startedAt: MP.startedAt, seen: MP.seen, outcomes: MP.outcomes.slice(-600), auto: MP.auto, runs: MP.runs }));
    nodeFs.renameSync(tmp, MP_FILE); } catch (e) { log("error", `saving ALKAID: ${e.message}`); }
}, 2 * 60e3);

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
function mpBetSize(bank, S, openPositions, mult = 1, pctOverride = null, sol = 150) {
  let size;
  if (S.slots > 0 && pctOverride == null) {
    // each slot gets an equal share of ALL the money, and the bet is sized so fees + tips fit inside that share
    const inTrades = openPositions.reduce((a, p) => a + (p.costUsd || 0), 0);
    const share = (bank.cash + inTrades) / S.slots, fixed = (S.priorityFeeSol + S.jitoTipSol) * sol;
    size = ((share - fixed) / (1 + S.feePct / 100)) * mult;
  } else size = (bank.cash * (pctOverride ?? S.riskPct) * mult) / 100;
  const cap = (bank.cash * S.maxBetPct) / 100;
  if (S.slots <= 0 && cap > S.minTradeUsd) size = Math.min(size, cap);
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
const LAB_READY_AT = 300;                                     // finished launches needed before the lab may steer trading
try { if (LAB_FILE && nodeFs.existsSync(LAB_FILE)) { const d = JSON.parse(nodeFs.readFileSync(LAB_FILE, "utf8")); LAB.snaps = d.snaps || []; for (const [k, v] of d.devs || []) LAB.devs.set(k, v); } } catch {}
setInterval(() => { if (!LAB_FILE) return; try { const t = LAB_FILE + ".tmp";
  nodeFs.writeFileSync(t, JSON.stringify({ snaps: LAB.snaps.slice(-4000), devs: [...LAB.devs].slice(-20000) })); nodeFs.renameSync(t, LAB_FILE); } catch {} }, 2 * 60e3);

async function labSocial(uri) {                                // website / X / Telegram, read from the token's own metadata file
  if (!/^https:\/\//.test(uri || "")) return null;
  try {
    const j = await (await withTimeout(fetch(uri), 3500, "token meta")).json();
    const has = (x) => typeof x === "string" && x.trim().length > 3;
    return [has(j.twitter), has(j.telegram), has(j.website)].filter(Boolean).length;
  } catch { return null; }
}
/** Write down what this launch looked like. Safe to call more than once. */
function labSnap(ev, m, devPct) {
  const old = LAB.snaps.find((x) => x.mint === ev.mint); if (old) return old;
  const d = LAB.devs.get(ev.creator) || { l: 0, g: 0 }, nm = String(ev.name || ""), at = ev.launchedAt || Date.now();
  const s = { mint: ev.mint, sym: ev.symbol, name: ev.name, creator: ev.creator, at, hour: new Date(at).getUTCHours(),
    progress: +(+m.progress).toFixed(2), mcap: Math.round(m.mcap), top10: null, top1: null, devPct: devPct == null ? null : +devPct.toFixed(2),
    ...(() => { const fs = flowStats(FLOW.get(ev.mint)); return { fBuyers: fs.buyersTotal, fNet: fs.netTotal, fShare: fs.buyShare60 }; })(),
    dev24: (MP.creators.get(ev.creator) || []).length, devL: d.l, devG: d.g, social: null, nameLen: nm.length,
    emoji: /[^\x00-\x7F]/.test(nm + (ev.symbol || "")) ? 1 : 0, cp: 0, peak: Math.round(m.mcap), grad: false, trended: false, win: false, done: false };
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
      else if (c) mc = curveMarket(c, await getSolUsd(), 6).mcap;
      if (mc) s.peak = Math.max(s.peak || 0, Math.round(mc));
    } catch { continue; }
    if (LAB.trended.has(s.mint)) s.trended = true;
    if (s.grad || s.trended || s.peak >= 100000) s.win = true;
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
  const L = LAB.snaps.filter((s) => s.win || s.done), W = L.filter((s) => s.win).length, base = L.length ? W / L.length : 0, K = 20;
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
setInterval(() => { if (!PATH_FILE) return; try { const t = PATH_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(PATHS.list.slice(-4000))); nodeFs.renameSync(t, PATH_FILE); } catch {} }, 5 * 60e3);
function pathStart(ev, m) {
  if (PATHS.live.has(ev.mint) || PATHS.live.size >= 300 || !(m.price > 0)) return;
  let curve; try { curve = PublicKey.findProgramAddressSync([Buffer.from("bonding-curve"), new PublicKey(ev.mint).toBuffer()], PUMP_PROGRAM)[0]; } catch { return; }
  PATHS.live.set(ev.mint, { mint: ev.mint, curve, p0: m.price, mcap0: m.mcap || null, at: Date.now(), pts: [1], grad: false });
}
function pathEnd(x) {
  PATHS.live.delete(x.mint);
  PATHS.list.push({ mint: x.mint, at: x.at, mcap0: x.mcap0, pts: x.pts, grad: x.grad });
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
setInterval(() => { if (!EXP_FILE) return; try { const t = EXP_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(EXP.book)); nodeFs.renameSync(t, EXP_FILE); } catch {} }, 5 * 60e3);
function expOpen(pos) {
  const S = MP.settings;
  for (const e of EXP_SETS) EXP.open.push({ id: e.id, mint: pos.mint, sym: pos.symbol, entry: pos.entry, t0: Date.now(), left: 1, got: 0, sells: 0, moon: false, mh: 0, type: pos.entryType,
    rules: e.id === "mine" ? (pos.rules ? { ...S, ...pos.rules } : null) : { ...S, ...e.rules }, last: pos.entry, lastT: Date.now() });
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
      mpEvent(`Grid on ${g.sym} finished (${g.status}): ${g.pnl >= 0 ? "+" : "−"}$${Math.abs(g.pnl).toFixed(2)} over ${g.rounds} round${g.rounds === 1 ? "" : "s"}`);
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
setInterval(() => { if (!TOP_FILE) return; try { const t = TOP_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify({ tokens: [...TOP.tokens].slice(-1500), entries: TOP.entries.slice(0, 400) })); nodeFs.renameSync(t, TOP_FILE); } catch {} }, 10 * 60e3);
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
  if (opts.profile === "v10") Object.assign(S, V10); else if (opts.safe) Object.assign(S, PROVEN_V2);
  MP.closed = []; MP.positions = []; MP.evaluated = []; MP.skips = {}; MP.seen = 0; MP.startedAt = Date.now(); MP.watch.clear();
  MP.bank = mpNewBank(S.startUsd); MP.report = {}; MP.outcomes = []; MP.events = [];
  MP.auto = { log: [], typeAt: {}, eqPeak: 0, dd: 0, lastPause: 0, lastDefense: 0 };
  mpEvent(`Started fresh with $${S.startUsd}${opts.profile === "v10" ? " on the V1.0 rules (1% bets, 3 positions, 3% daily stop, staged exits)" : opts.safe ? " on the safe profile" : ""}`);
}
/** Make the risk settings stricter, never looser, and never touch how bets are sized. */
function mpTighten(S) {
  const lower = ["slPct", "trailPct", "maxHoldMin", "moonHoldMin", "dailyStopPct", "maxLossStreak", "maxTop10Pct", "maxTop1Pct", "maxDevPct", "momMaxMcap", "gradMaxOpen", "gradSl", "tpPct", "gradMaxCh5", "gradMaxImpact"];
  const higher = ["momBuyers60", "momBuyShare", "momNetSol", "momRise2m", "minProgress", "pauseMin", "labMinLift", "tp1SellPct", "gradMinLiq", "gradMinLiqPct", "gradMinVol24"];
  for (const k of lower) if (PROVEN_V2[k] != null && S[k] != null && !(S.ladderOn && k === "tpPct")) S[k] = Math.min(S[k], PROVEN_V2[k]);
  for (const k of higher) if (PROVEN_V2[k] != null && S[k] != null) S[k] = Math.max(S[k], PROVEN_V2[k]);
  S.fastLane = 0; S.momentum = 1; S.labFilter = 1;
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
  for (const type of ["launch shot", "graduate", "copy", "momentum", "at 90s"]) {
    const T = recent.filter((x) => mpEntryType(x) === type).slice(0, 25); if (T.length < S.killMinTrades) continue;
    const avg = T.reduce((a, x) => a + (x.pnlPct || 0), 0) / T.length, wr = (T.filter((x) => x.pnlUsd > 0).length / T.length) * 100;
    if (avg > S.killAvgPct || wr > 35 || now - (A.typeAt[type] || 0) < 6 * 3600e3) continue;
    const why = `${T.length} trades, average ${avg.toFixed(0)}%, ${Math.round(wr)}% wins`;
    if (type === "launch shot" && S.fastLane) { S.fastLane = 0; A.typeAt[type] = now; mpAuto(`switched OFF Launch Shot (${why})`, "kill"); }
    else if (type === "graduate" && S.gradOn) { S.gradOn = 0; A.typeAt[type] = now; mpAuto(`switched OFF Graduate entries (${why})`, "kill"); }
    else if (type === "copy" && S.copyOn) { S.copyOn = 0; A.typeAt[type] = now; mpAuto(`switched OFF Copy trading (${why})`, "kill"); }
    else if (type === "at 90s" && !S.momentum) { S.momentum = 1; A.typeAt[type] = now; mpAuto(`switched to Momentum entries (buying at 90 seconds: ${why})`, "kill"); }
    else if (type === "momentum") {
      S.momBuyers60 = Math.min(30, S.momBuyers60 + 3); S.momNetSol = Math.min(15, +(S.momNetSol + 1).toFixed(1)); S.momRise2m = Math.min(60, S.momRise2m + 5); A.typeAt[type] = now;
      mpAuto(`made Momentum entries stricter: now needs ${S.momBuyers60} buyers, ${S.momNetSol} SOL in, +${S.momRise2m}% (${why})`, "kill");
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
  const lines = [`📰 <b>ALKAID · last 24 hours</b>`,
    `Account <b>$${eq.toFixed(2)}</b> (started $${B.start.toFixed(2)}, ${eq >= B.start ? "+" : ""}${(((eq / B.start) - 1) * 100).toFixed(1)}%) · best so far $${(A.eqPeak || eq).toFixed(2)} · now ${A.dd || 0}% below it`,
    T.length ? `Trades <b>${T.length}</b> · ${W.length} won (${Math.round((W.length / T.length) * 100)}%) · <b>${money(pnl)}</b>` : `No trades closed in the last 24 hours.`];
  const rows = Object.entries(by).sort((a, b) => a[1].pnl - b[1].pnl).map(([k, r]) => `• ${k}: ${r.n} trades, ${r.w} won, ${money(r.pnl)}`); if (rows.length) lines.push("By way of entering:\n" + rows.join("\n"));
  lines.push(acts.length ? "🤖 Autopilot did:\n" + acts.slice(0, 5).map((x) => "• " + x.text).join("\n") : "🤖 Autopilot: nothing needed changing.");
  if (MP.runs[0]) lines.push("📚 " + mpRunsLine());
  lines.push(`Now: ${B.pausedUntil > now ? "⏸ paused (" + B.pauseWhy + ")" : "🟢 trading"} · ${S.momentum ? "momentum entries" : "buy at 90s"}${S.gradOn ? " + graduates" : ""}${S.fastLane ? " + launch shot" : ""} · stop −${S.slPct}% · ${S.slots} bets at a time · daily stop ${S.dailyStopPct}%`);
  return lines.join("\n\n");
}
/*AUTO_END*/

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
    return { mint, sol, tokens, isBuy, user, ts, priceSol: vSol / vTok };
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
  }
}
function mpOnTrade(tr) {
  const held = MP.positions.length ? MP.positions.find((x) => x.mint === tr.mint) : null;
  if (held) mpInstant(held, tr);
  const f = FLOW.get(tr.mint); if (!f) return;
  const t = Date.now(); if (t - f.t0 > 20 * 60e3) { FLOW.delete(tr.mint); return; }
  if (f.trades.length < 1500) f.trades.push({ t, b: tr.isBuy, sol: tr.sol, u: tr.user, p: tr.priceSol });
  if (tr.isBuy && f.buyers.size < 2000) f.buyers.add(tr.user);
  MP.feed.trades = (MP.feed.trades || 0) + 1;
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
  MP.feed.grads = (MP.feed.grads || 0) + 1;
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
  MP.skips[reason] = (MP.skips[reason] || 0) + 1;
  if (ev && ev.mint) mpTape(ev.mint, "skipped: " + reason);
  if (ev) { MP.evaluated.unshift({ ...ev, verdict: "skip", reason, at: Date.now() }); MP.evaluated = MP.evaluated.slice(0, 120); }
}

/** A new launch arrives: note the creator, queue it to be judged after the wait. */
function mpOnLaunch(ev) {
  MP.seen++; MP.feed.lastEventAt = Date.now();
  FLOW.set(ev.mint, { t0: Date.now(), trades: [], buyers: new Set() }); if (FLOW.size > 4000) FLOW.delete(FLOW.keys().next().value);
  GR.launches.push({ t: Date.now(), m: ev.mint }); GR.seen.set(ev.mint, Date.now());
  if (GR.launches.length > 120000) GR.launches.splice(0, GR.launches.length - 120000);
  MP.launchTimes.push(Date.now()); if (MP.launchTimes.length > 600) MP.launchTimes.splice(0, MP.launchTimes.length - 600);
  MP.tape.unshift({ mint: ev.mint, symbol: ev.symbol, name: ev.name, creator: ev.creator, at: Date.now(), status: "watching" });
  if (MP.tape.length > 60) MP.tape.length = 60;
  const c = MP.creators.get(ev.creator) || [];
  c.push(Date.now()); MP.creators.set(ev.creator, c.filter((t) => Date.now() - t < 24 * 3600e3));
  if (MP.creators.size > 50000) MP.creators.delete(MP.creators.keys().next().value);
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
  const skipT = (reason, extra) => {          // skip, and remember the price so we can see later if the skip was right
    mpSkip(reason, { ...ev, ...(extra || {}) });
    MP.outcomes.push({ mint: ev.mint, sym: ev.symbol, reason: reason.replace(/[\d.]+%/g, "N%").replace(/\d+ /g, "N "), p0: m.price, due: Date.now() + 30 * 60e3 });
    if (MP.outcomes.length > 800) MP.outcomes.splice(0, MP.outcomes.length - 800);
  };
  // every launch with real money in it gets watched for a creator dump, pass or skip
  let devAt = null; try { devAt = ((await balanceOf(ev.creator, ev.mint)) / 1e9) * 100; } catch {}
  labSnap(ev, m, devAt);                                        // the Winner Lab writes down what this launch looked like
  if (m.progress >= 1) pathStart(ev, m);                        // the Sweet Spot Finder records its price for 45 minutes
  if (m.progress >= 3 && m.progress < S.minProgress) getMintCheck(ev.mint).then((ck) => { if (ck && ck.found) labFeat(ev.mint, { top10: ck.top10WalletPct ?? null, top1: ck.top1WalletPct ?? null }); }).catch(() => {});
  if (m.progress >= 3) { rugWatch.push({ mint: ev.mint, sym: ev.symbol, creator: ev.creator, peakSol: Number(c.rSol) / 1e9, devAt, due: Date.now() + 30 * 60e3, round: 0 }); if (rugWatch.length > 2000) rugWatch.shift(); }
  if (m.progress < S.minProgress) return skipT(`weak demand (<${S.minProgress}% bonded)`, { progress: m.progress });
  // creator's bag and holder concentration, curve excluded
  const chk = await getMintCheck(ev.mint).catch(() => null);
  if (!chk || !chk.found) return mpSkip("couldn't check holders", ev);
  if (!chk.mintAuthorityRenounced || !chk.freezeAuthorityRenounced) return skipT("can print or freeze");
  const top10 = chk.top10WalletPct, top1 = chk.top1WalletPct;
  labFeat(ev.mint, { top10: top10 == null ? null : +top10.toFixed(1), top1: top1 == null ? null : +top1.toFixed(1) });
  if (top1 != null && top1 > S.maxTop1Pct) return skipT(`one wallet holds ${Math.round(top1)}%`);
  if (top10 != null && top10 > S.maxTop10Pct) return skipT(`top 10 hold ${Math.round(top10)}%`);
  const devPct = devAt;
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
  const sizeUsd = mpBetSize(MP.bank, S, MP.positions, mult, null, sol);
  if (!(sizeUsd > 0)) return mpSkip(`max loss ${S.maxLossPct}%: balance too small for a safe bet`, ev);
  const extraUsd = (S.priorityFeeSol + S.jitoTipSol) * sol, costUsd = sizeUsd * (1 + S.feePct / 100) + extraUsd;
  if (costUsd > MP.bank.cash) return mpSkip("trading balance too low (the vault is safe)", ev);
  MP.bank.cash -= costUsd;
  const entry = m.price * (1 + S.slippagePct / 100);                        // you pay a little above the quote
  const tokens = sizeUsd / entry;
  const pos = { mint: ev.mint, symbol: ev.symbol, name: ev.name, creator: ev.creator, entry, entrySol: sol, tokens, sizeUsd, costUsd,
                costSol: costUsd / sol, openedAt: Date.now(), progressAtBuy: m.progress, high: entry, last: entry, devPct, top10, top1,
                tokensLeft: tokens, realizedUsd: 0, phase: "full", boosts, devCheckedAt: 0, entryType: info.entryType || (info.momentum ? "momentum" : "at 90s"), mcapAtBuy: Math.round(m.mcap || 0),
                ...(info.rules ? { rules: info.rules } : {}), ...(info.extra || {}) };
  MP.positions.push(pos);
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
    let c; try { c = await readBondingCurve(mint); } catch {}                    // confirm the price straight from the chain
    if (!c || c.complete) { mpSkip(c && c.complete ? "graduated before momentum buy" : "couldn't read curve", w.ev); continue; }
    const m = curveMarket(c, sol, 6);
    mpOpen(w.ev, m, { ...w.info, labA: labAnalyze(), sol, momentum: `momentum: ${fs.buyers60} buyers/min, ${fs.buyShare60}% buys, +${fs.net60} SOL, +${fs.rise2m}% in 2m`,
      why: `MOMENTUM · ${fs.buyers60} buyers in 60s · ${fs.buyShare60}% buys · +${fs.net60} SOL in · +${fs.rise2m}% in 2m · $${(m.mcap / 1000).toFixed(1)}K` });
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
    const tok = p.tokensLeft * frac, exit = price * (1 - S.slippagePct / 100);
    const back = Math.max(0, tok * exit * (1 - S.feePct / 100) - (S.priorityFeeSol + S.jitoTipSol) * sol);
    p.tokensLeft -= tok; p.realizedUsd += back; MP.bank.cash += back;
    return back;
  };
  const close = (p, why) => {
    const cost = p.costUsd != null ? p.costUsd : p.costSol * sol;
    const pnlUsd = p.realizedUsd - cost;
    MP.closed.unshift({ ...p, exit: p.last, closedAt: Date.now(), why, pnlUsd: +pnlUsd.toFixed(2), pnlSol: +(pnlUsd / sol).toFixed(5), pnlPct: +((pnlUsd / cost) * 100).toFixed(1) });
    MP.closed = MP.closed.slice(0, 500);
    MP.positions = MP.positions.filter((x) => x !== p);
    log("alkaid", `PAPER CLOSED ${p.symbol} ${why} ${pnlUsd >= 0 ? "+" : ""}$${pnlUsd.toFixed(2)}`);
    if (typeof tgTradeClosed === "function") tgTradeClosed(p, why, pnlUsd);
    for (const msg of mpAfterClose(MP.bank, S, pnlUsd)) mpEvent(msg);
    if (S.autoSend && MP.bank.vault > 0) mpSendVault("auto: profit locked");
  };
  for (const p of MP.positions.slice()) {
    if (p.tokensLeft == null) { p.tokensLeft = p.tokens; p.realizedUsd = 0; p.phase = "full"; }
    const R = p.rules ? { ...S, ...p.rules } : S;                     // graduate and copy trades carry their own exit rules
    let price = null, graduated = false;
    try {
      const c = await readBondingCurve(p.mint);
      if (!c) { const dx = await mpDexPrice(p.mint); if (dx) { price = dx.price; p.mcapNow = dx.mcap; p.postGrad = true; } }   // never on a bonding curve: follow its pool
      else if (c && !c.complete) { const m = curveMarket(c, sol, 6); price = m.price; p.mcapNow = m.mcap; }
      else if (c && c.complete) {
        const dx = await mpDexPrice(p.mint);                              // graduated: keep following it on the trading pool
        if (dx) { price = dx.price; p.mcapNow = dx.mcap; p.postGrad = true; }
        else { price = p.last; graduated = true; }                         // no pool price yet: cash out at the last curve price
      }
    } catch {}
    if (price == null) continue;
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
    paused: B.pausedUntil > Date.now() ? { why: B.pauseWhy, until: B.pausedUntil } : null, nextBetUsd: +mpBetSize(B, MP.settings, MP.positions, 1, null, sol || 150).toFixed(2),
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
    graduate: gradPublic(), copy: copyPublic(), experiments: expPublic(), grid: gridPublic(), top100: topPublic(), autopilot: mpAutoPublic(),
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
  const pm = new Map(PATHS.list.map((p) => [p.mint, p]));
  const q = (v) => (v == null ? "" : /[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
  const head = ["mint", "symbol", "name", "launched_utc", "bonded_pct_90s", "mcap_90s", "top10_pct", "top1_pct", "creator_pct", "creator_launches_today",
    "creator_past_graduates", "social_links", "hour_utc", "name_len", "emoji", "graduated", "trended", "peak_mcap", "winner", "lab_score_x", "path_peak_x", "path_low_x", "path_minutes"];
  const lines = [head.join(",")];
  for (const s of LAB.snaps) {
    const p = pm.get(s.mint), pts = p ? p.pts : null;
    lines.push([s.mint, s.sym, s.name, new Date(s.at).toISOString(), s.progress, s.mcap, s.top10, s.top1, s.devPct, s.dev24, s.devG, s.social, s.hour, s.nameLen, s.emoji,
      s.grad ? 1 : 0, s.trended ? 1 : 0, s.peak, s.win ? 1 : s.done ? 0 : "", labLift(s).toFixed(2), pts ? Math.max(...pts).toFixed(3) : "", pts ? Math.min(...pts).toFixed(3) : "",
      pts ? ((pts.length - 1) * PATH_STEP / 60000).toFixed(1) : ""].map(q).join(","));
  }
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="the-cannon-data-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(lines.join("\n"));
});

/** Owner-only: change the rules (numbers are clamped to sane ranges) */
function mpApplySettings(b) {
  const S = MP.settings;
  const clamp = (k, lo, hi) => { if (b[k] == null) return; const v = Number(b[k]); if (Number.isFinite(v)) S[k] = Math.min(hi, Math.max(lo, v)); };
  clamp("startUsd", 1, 100000); clamp("slots", 0, 30); clamp("maxLossPct", 0, 100); clamp("riskPct", 1, 50); clamp("minTradeUsd", 0.1, 1000); clamp("vaultAtX", 1.2, 100); clamp("keepX", 0.2, 50);
  clamp("tp1SellPct", 10, 100); clamp("trailPct", 5, 90); clamp("moonHoldMin", 5, 2880); clamp("smartBoost", 1, 3); clamp("favorBoost", 1, 3);
  clamp("maxBetPct", 2, 50); clamp("devExit", 0, 1); clamp("gradOn", 0, 1); clamp("gradWindowMin", 5, 120); clamp("gradMinLiq", 5000, 5e6); clamp("gradMinMcap", 20000, 5e6); clamp("gradMaxMcap", 50000, 5e7); clamp("gradBuys5", 3, 1000); clamp("gradBuyShare", 40, 95);
  clamp("gradMinCh5", -20, 100); clamp("gradMaxCh5", 5, 500); clamp("gradMinCh1", -90, 100); clamp("gradMaxOpen", 1, 10); clamp("gradTp", 10, 500); clamp("gradTp1Sell", 10, 100); clamp("gradSl", 5, 60); clamp("gradTrail", 5, 60); clamp("gradHold", 5, 720);
  clamp("copyOn", 0, 1); clamp("copyTopN", 1, 100); clamp("copyMinUsd", 20, 100000); clamp("copyMinWallets", 1, 10); clamp("copyMaxOpen", 1, 10); clamp("copyTp", 10, 500); clamp("copyTp1Sell", 10, 100); clamp("copySl", 5, 60); clamp("copyTrail", 5, 60); clamp("copyHold", 5, 720);
  clamp("gridOn", 0, 1); clamp("gridStartUsd", 10, 100000); clamp("gridMax", 1, 6); clamp("gridLevels", 2, 8); clamp("gridStepPct", 1, 30); clamp("gridHoldMin", 20, 1440); clamp("gridMinLiq", 20000, 1e7); clamp("gridFeePct", 0, 3); clamp("gridSlipPct", 0, 5);
  clamp("ladderOn", 0, 1); clamp("gradMinLiqPct", 0, 100); clamp("gradMinVol24", 0, 1e8); clamp("gradMaxImpact", 0.5, 50); clamp("autopilot", 0, 1); clamp("autoSlots", 0, 1); clamp("ddBrake1Pct", 5, 90); clamp("ddBrake2Pct", 10, 95); clamp("killAvgPct", -90, -1); clamp("killMinTrades", 5, 100);
  clamp("momentum", 0, 1); clamp("momWindowMin", 1, 30); clamp("momBuyers60", 1, 200); clamp("momBuyShare", 30, 100); clamp("momNetSol", 0, 200); clamp("momRise2m", 0, 500); clamp("momMaxMcap", 6000, 1000000);
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
  if (b.profile === "v10") mpResetAll({ profile: "v10" });
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
  [{ text: "📊 Status", callback_data: "status" }, { text: "📈 Positions", callback_data: "positions" }],
  [{ text: "🔥 Hot launches", callback_data: "hot" }, { text: "🎓 Graduates", callback_data: "grads" }],
  [{ text: "📉 Why losing", callback_data: "why" }, { text: "🧭 Strategy", callback_data: "strategy" }],
  [{ text: "🏆 Top 100", callback_data: "top" }, { text: "🎯 Sweet spot", callback_data: "sweet" }],
  [{ text: "📰 Morning report", callback_data: "report" }, { text: "🔄 Fresh start", callback_data: "ask:fresh" }],
  [{ text: "🧾 Start the V1.0 test ($1,000 paper)", callback_data: "ask:v10" }],
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
  return `📊 <b>ALKAID</b> · paper money\nTotal <b>${tgMoney(total)}</b> (started ${tgMoney(B.start)}, ${total >= B.start ? "+" : ""}${(((total / B.start) - 1) * 100).toFixed(1)}%)\n` +
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
    ((r.flags || []).slice(0, 6).map((f) => `${lv[f.level] || "•"} ${tgEsc(f.text)}`).join("\n") || "No warning signs found.") + `\n\n<code>${tgEsc(addr)}</code>`;
  return { text, kb: [[{ text: "📈 Chart", url: `https://dexscreener.com/solana/${addr}` }, { text: "🔎 Full scan", url: `https://cryptobizmo2.github.io/SLAPBOT/?scan=${addr}` }]] };
}
async function tgAct(chat, what) {
  if (what === "pause") { MP.bank.pausedUntil = Date.now() + 24 * 3600e3; MP.bank.pauseWhy = "paused from Telegram"; mpEvent("Paused from Telegram: no new trades (open ones are still managed)"); return "⏸ Paused. No new trades; open trades are still managed. Tap Resume to continue."; }
  if (what === "resume") { MP.bank.pausedUntil = 0; MP.bank.pauseWhy = null; MP.bank.streak = 0; MP.on = true; mpConnect(); mpEvent("Resumed from Telegram"); return "▶ Trading again."; }
  if (what === "v10") { mpResetAll({ profile: "v10" }); return `🧾 <b>V1.0 test started.</b> A fresh <b>$${MP.settings.startUsd.toLocaleString()}</b> paper account: 1% per trade (about $${(MP.settings.startUsd * MP.settings.riskPct / 100).toFixed(0)}), at most ${MP.settings.maxOpen} positions, ${MP.settings.dailyStopPct}% daily loss limit, strict safety checks, staged exits (+20% / +35% / +60%, then a trailing stop). The old run was saved as a summary.`; }
  if (what === "fresh") { mpResetAll({ safe: true }); return `🔄 <b>Fresh start.</b> New paper account with <b>$${MP.settings.startUsd}</b> on the safe profile. The old run was saved as a summary (see 📰 Morning report).`; }
  if (MP_PRESETS[what]) { mpApplySettings(MP_PRESETS[what]); mpEvent(`${what[0].toUpperCase() + what.slice(1)} preset applied from Telegram`); return `✅ <b>${what[0].toUpperCase() + what.slice(1)}</b> is on. It applies to the next launch.`; }
  return "Unknown action.";
}
async function tgCallback(chat, data) {
  const views = { status: tgStatus, positions: tgPositions, hot: tgHot, grads: tgGrads, why: tgWhy, strategy: tgStrategy, top: tgTop, sweet: tgSweet, vault: tgVault, report: mpReportText };
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
      return tgSend(chat, "✅ <b>You're connected to ALKAID.</b>\nAlerts are on: every buy, sell, pause, and vault lock. Paste any Solana token address to scan it.", TG_MENU);
    }
  }
  if (!allowed) {                                                         // strangers get one polite line, at most every 10 minutes, and nothing else
    const last = TG.hello.get(chat) || 0; if (Date.now() - last < 600000) return; TG.hello.set(chat, Date.now()); if (TG.hello.size > 500) TG.hello.delete(TG.hello.keys().next().value);
    return tgSend(chat, /^\/start\b/i.test(text) ? "🔒 This bot is private. To connect your phone: open your ALKAID dashboard, go to Connections, tap Make a pairing code, then tap the green Open Telegram button it shows." : "🔒 This bot is private.");
  }
  const cmd = text.split(/[\s@]/)[0].toLowerCase(), arg = text.split(/\s+/)[1] || "";
  const views = { "/status": tgStatus, "/positions": tgPositions, "/hot": tgHot, "/graduates": tgGrads, "/grads": tgGrads, "/why": tgWhy, "/strategy": tgStrategy, "/top": tgTop, "/sweet": tgSweet, "/vault": tgVault, "/report": mpReportText };
  if (views[cmd]) return tgSend(chat, views[cmd](), TG_MENU);
  if (cmd === "/pause" || cmd === "/resume" || cmd === "/defense" || cmd === "/balanced" || cmd === "/offense" || cmd === "/fresh" || cmd === "/v10") return tgCallback(chat, "ask:" + cmd.slice(1));
  if (cmd === "/alerts") { TG.alerts = !/^off$/i.test(arg); CONN.tgAlerts = TG.alerts; saveConn(); return tgSend(chat, TG.alerts ? "🔔 Alerts are ON." : "🔕 Alerts are OFF.", TG_MENU); }
  const addr = SOL_ADDR.test(text) ? text : (cmd === "/lookup" || cmd === "/scan") && SOL_ADDR.test(arg) ? arg : null;
  if (addr) { await tgApi("sendChatAction", { chat_id: chat, action: "typing" }).catch(() => {}); const r = await tgLookup(addr); return tgSend(chat, r.text, r.kb); }
  return tgSend(chat, "Pick something, or paste a Solana token address to scan it:", TG_MENU);
}
/** The bot's name card and command menu, set automatically. Commands are shown only to paired phones; strangers see none. */
const TG_DESC = "ALKAID · private trading assistant.\n\nLive alerts, open positions, strategy reports and token safety scans for its owner.\n\nThis bot is private: it only answers phones paired from the owner's dashboard.";
const TG_SHORT = "ALKAID · private trading alerts and token safety scans.";
const TG_COMMANDS = [
  { command: "status", description: "Balance, today, open trades" }, { command: "positions", description: "Open trades with live profit or loss" },
  { command: "hot", description: "Hottest launches right now" }, { command: "graduates", description: "Recent graduations" },
  { command: "why", description: "Why it's winning or losing" }, { command: "strategy", description: "What the bot is doing" },
  { command: "top", description: "Top 100 trending" }, { command: "sweet", description: "Best-performing rules" },
  { command: "vault", description: "Vault and savings" }, { command: "report", description: "24-hour report" }, { command: "fresh", description: "New paper account on the safe profile" }, { command: "v10", description: "Start the V1.0 test ($1,000 paper)" }, { command: "pause", description: "Stop new trades" },
  { command: "resume", description: "Start trading again" }, { command: "defense", description: "Safer settings" },
  { command: "balanced", description: "Default settings" }, { command: "offense", description: "Bolder settings" },
  { command: "alerts", description: "Turn alerts on or off" }, { command: "scan", description: "Scan a token: /scan then the address" },
  { command: "menu", description: "Show the buttons" },
];
const tgCommandsFor = (chat) => tgApi("setMyCommands", { commands: TG_COMMANDS, scope: { type: "chat", chat_id: Number(chat) } }).catch(() => {});
async function tgProfile() {
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
function tgEvent(text) { if (/vault|paused|stopped|rug zone|sweet spot|moved|resumed|grid on|savings|started fresh|autopilot/i.test(text) && !/hit \+/.test(text)) tgBroadcast("ℹ️ " + tgEsc(text)); }
function tgGraduated(mint) { const p = MP.positions.find((x) => x.mint === mint); if (p) tgBroadcast(`🎓 <b>${tgEsc(p.symbol)} just graduated</b> (we hold it)\n<code>${mint}</code>`); }
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
    const sent = await Promise.all([...TG.chats].map((c) => tgApi("sendMessage", { chat_id: c, text: "✅ Test from ALKAID: Telegram is working. You'll get an alert here for every buy, sell, pause and vault lock." }).then(() => true).catch((e) => { TG.err = tgFail(e); return false; })));
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
  try { html = process.env.ALKAID_HTML ? nodeFs.readFileSync(process.env.ALKAID_HTML, "utf8") : Buffer.from(ALKAID_EMBED, "base64").toString("utf8"); }
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
    engine: { build: BUILD_ID, running: MP.on && MP.feed.connected, tradesRead: MP.feed.trades || 0, graduationsSeen: MP.feed.grads || 0, telegram: TG.on },   // details are owner-only (/api/mp/state)
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

app.listen(PORT, () => {
  log("init", `BIG MOUF SLAPBOT backend running on port ${PORT}`);
  if (ALLOWED_ORIGINS.includes("*")) log("warn", "ALLOWED_ORIGIN is * — any website can call this API. Set it to your site URL.");
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) log("warn", "SESSION_SECRET is short — use 32+ random characters.");
  if (OWNER_CODE && OWNER_CODE.length < 12) log("warn", "OWNER_CODE is under 12 characters, so owner sign-in is switched OFF.");
  log("init", `Exclusive: Gold Key = ${GOLD_MIN_HOLD} of ${GOLD_MINT} · Holder Key = $${GATE_MIN_USD} of ${GATE_MINT}`);
});

/*ALKAID_EMBED_BEGIN*/
const ALKAID_EMBED = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgaHR0cC1lcXVpdj0iQ29udGVudC1TZWN1cml0eS1Qb2xpY3kiIGNvbnRlbnQ9ImRlZmF1bHQtc3JjICdzZWxmJzsgc2NyaXB0LXNyYyAnc2VsZicgJ3Vuc2FmZS1pbmxpbmUnOyBzdHlsZS1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyBodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tOyBmb250LXNyYyBodHRwczovL2ZvbnRzLmdzdGF0aWMuY29tOyBpbWctc3JjICdzZWxmJyBkYXRhOjsgY29ubmVjdC1zcmMgJ3NlbGYnIGh0dHBzOi8vc2xhcGJvdC1iYWNrZW5kLXByb2R1Y3Rpb24udXAucmFpbHdheS5hcHA7IG9iamVjdC1zcmMgJ25vbmUnOyBiYXNlLXVyaSAnbm9uZSc7IGZvcm0tYWN0aW9uICdub25lJzsgdXBncmFkZS1pbnNlY3VyZS1yZXF1ZXN0cyI+CjxtZXRhIG5hbWU9InJlZmVycmVyIiBjb250ZW50PSJuby1yZWZlcnJlciI+CjxtZXRhIG5hbWU9InJvYm90cyIgY29udGVudD0ibm9pbmRleCwgbm9mb2xsb3ciPgo8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHZpZXdwb3J0LWZpdD1jb3ZlciI+Cjx0aXRsZT5BTEtBSUQ8L3RpdGxlPgo8bWV0YSBuYW1lPSJ0aGVtZS1jb2xvciIgY29udGVudD0iIzA3MDYwRCI+CjxsaW5rIHJlbD0icHJlY29ubmVjdCIgaHJlZj0iaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbSI+CjxsaW5rIHJlbD0icHJlY29ubmVjdCIgaHJlZj0iaHR0cHM6Ly9mb250cy5nc3RhdGljLmNvbSIgY3Jvc3NvcmlnaW4+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9U3BhY2UrR3JvdGVzazp3Z2h0QDUwMDs3MDAmZmFtaWx5PUpldEJyYWlucytNb25vOndnaHRANTAwOzcwMDs4MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQiPgo8c3R5bGU+Cjpyb290ey0tYmc6IzA0MDkxMjstLXBhbmVsOnJnYmEoOCwxNywzMiwuNzQpOy0tcGFuZWwyOnJnYmEoMTQsMjgsNTIsLjc4KTstLWxpbmU6cmdiYSg3NywyMjQsMTI1LC4yMCk7LS1saW5lMjpyZ2JhKDc3LDIyNCwxMjUsLjQyKTsKICAtLWluazojRUFGNEZGOy0tYXNoOiM5M0E5QzY7LS1kaW06IzVDNzM5MTstLXZpbzojM0ZEMDdBOy0tbWludDojNTVGMDhGOy0tZ29sZDojRjJDMTRFOy0tdXA6IzNEREM5NzstLWRvd246I0ZGNUE2RTsKICAtLWhlYWQ6J1NwYWNlIEdyb3Rlc2snLHN5c3RlbS11aSxzYW5zLXNlcmlmOy0tbW9ubzonSmV0QnJhaW5zIE1vbm8nLHVpLW1vbm9zcGFjZSxNZW5sbyxtb25vc3BhY2V9Cip7Ym94LXNpemluZzpib3JkZXItYm94O21hcmdpbjowO3BhZGRpbmc6MH0KaHRtbCxib2R5e2JhY2tncm91bmQ6dmFyKC0tYmcpO2NvbG9yOnZhcigtLWluayk7Zm9udC1mYW1pbHk6dmFyKC0taGVhZCk7LXdlYmtpdC10ZXh0LXNpemUtYWRqdXN0OjEwMCV9CmJvZHl7bWluLWhlaWdodDoxMDB2aDtiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudCg3MCUgNDUlIGF0IDg1JSAwJSxyZ2JhKDc3LDIyNCwxMjUsLjIwKSx0cmFuc3BhcmVudCA2NSUpLHJhZGlhbC1ncmFkaWVudCg2MCUgNDAlIGF0IDAlIDIwJSxyZ2JhKDYxLDI0MiwxNjMsLjEwKSx0cmFuc3BhcmVudCA2NSUpLHJhZGlhbC1ncmFkaWVudCg1MCUgMzUlIGF0IDUwJSAxMDAlLHJnYmEoNzcsMjI0LDEyNSwuMTApLHRyYW5zcGFyZW50IDcwJSksdmFyKC0tYmcpfQouYnJhbmRyb3d7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweH0KLmJyYW5kcm93IGltZ3t3aWR0aDo0NHB4O2hlaWdodDo0NHB4O2JvcmRlci1yYWRpdXM6NTAlO29iamVjdC1maXQ6Y292ZXI7Ym94LXNoYWRvdzowIDAgMCAxcHggcmdiYSg3NywyMjQsMTI1LC41KSwwIDAgMjJweCByZ2JhKDc3LDIyNCwxMjUsLjM1KX0KLmdhdGUgLmVtYmxlbXtkaXNwbGF5OmJsb2NrO3dpZHRoOm1pbig4NnZ3LDQ0MHB4KTthc3BlY3QtcmF0aW86MS8xO21hcmdpbjowIGF1dG87Ym9yZGVyLXJhZGl1czoyMnB4O2JveC1zaGFkb3c6MCAwIDAgMXB4IHJnYmEoNzcsMjI0LDEyNSwuNSksMCAyMHB4IDYwcHggLTEwcHggcmdiYSg3NywyMjQsMTI1LC41KSwwIDAgODBweCByZ2JhKDYxLDI0MiwxNjMsLjE0KX0KLmdhdGV7bWF4LXdpZHRoOjUyMHB4IWltcG9ydGFudH0KLnRva257Zm9udDo2MDAgMTJweCB2YXIoLS1oZWFkKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbi1sZWZ0OjZweH0KLmNhe2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweDttYXJnaW4tdG9wOjRweH0KLmNhIGNvZGV7Zm9udDo2MDAgMTAuNXB4IHZhcigtLW1vbm8pO2NvbG9yOiNCN0NDRTY7d29yZC1icmVhazpicmVhay1hbGw7LXdlYmtpdC11c2VyLXNlbGVjdDphbGw7dXNlci1zZWxlY3Q6YWxsfQouY2EgYnV0dG9ue2ZsZXg6bm9uZTtmb250OjgwMCAxMC41cHggdmFyKC0tbW9ubyk7cGFkZGluZzozcHggOHB4O2JvcmRlci1yYWRpdXM6N3B4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKTtjb2xvcjp2YXIoLS1pbmspO2N1cnNvcjpwb2ludGVyfQouY2EgYXtmbGV4Om5vbmU7Zm9udDo4MDAgMTAuNXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLW1pbnQpO3RleHQtZGVjb3JhdGlvbjpub25lfQphe2NvbG9yOmluaGVyaXR9YnV0dG9uLGlucHV0e2ZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0fQo6Zm9jdXMtdmlzaWJsZXtvdXRsaW5lOjJweCBzb2xpZCB2YXIoLS1taW50KTtvdXRsaW5lLW9mZnNldDoycHh9Ci53cmFwe21heC13aWR0aDoxMTAwcHg7bWFyZ2luOjAgYXV0bztwYWRkaW5nOjE0cHg7cG9zaXRpb246cmVsYXRpdmU7ei1pbmRleDoxfQovKiBBbGthaWQgd2F0ZXJtYXJrOiBzZWUtdGhyb3VnaCwgZmFkZXMgb3V0IGF0IHRoZSBlZGdlcywgc2l0cyBiZWhpbmQgZXZlcnl0aGluZywgY2FuJ3QgYmUgY2xpY2tlZCAqLwouYWxrLXdte3Bvc2l0aW9uOmZpeGVkO2xlZnQ6NTAlO3RvcDo1NCU7d2lkdGg6bWluKDk2dncsNzAwcHgpO2FzcGVjdC1yYXRpbzoxLzE7dHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO3otaW5kZXg6MDtwb2ludGVyLWV2ZW50czpub25lOwogIGJhY2tncm91bmQ6dXJsKCJkYXRhOmltYWdlL2pwZWc7YmFzZTY0LC85ai80QUFRU2taSlJnQUJBUUFBQVFBQkFBRC8yd0JEQUEwSkNnc0tDQTBMQ2dzT0RnMFBFeUFWRXhJU0V5Y2NIaGNnTGlreE1DNHBMU3d6T2tvK016WkdOeXd0UUZkQlJreE9VbE5TTWo1YVlWcFFZRXBSVWsvLzJ3QkRBUTRPRGhNUkV5WVZGU1pQTlMwMVQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMC8vd2dBUkNBSXdBakFEQVNJQUFoRUJBeEVCLzhRQUdnQUFBd0VCQVFFQUFBQUFBQUFBQUFBQUFBSURCQUVGQnYvRUFCZ0JBUUVCQVFFQUFBQUFBQUFBQUFBQUFBQUJBZ01FLzlvQURBTUJBQUlRQXhBQUFBSDVnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU9uQ3JtYzFDWlRSTlpuZUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQllpZWxyazhmVjZDcENvRDlqTkxyblJkSmxEVTJNTnk1T2wwbnc3azFYWHlUMTVIbWxvMmdBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFkMnBpMStwV1ROYnVaTGM4M0t2cTU4SFZ2THJIWWJjZ3VudXdaSldUeVRVaXpHcldkMDZXZkx5Tm5NdFRTUlpFeTdXWEFhTTlvQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT0pxMzc1blBmbm5wdXcrYXEwbGZRdU91eGpNOXhKVTR4NXpSMksrcWZVOC9UaHVYaHN5SEdJcnlqeUdXbkNTMzRaM2RDajV1bWpzMlNVZGd1TVpiUUFBQUFBQUFBQUFBQUFBQTUwQUFBQUFBOU5NM3RVV1piTGk4OWJSdHRYSnJzNkoxd1hqOEY0M1F3ZWo0cHpmazFycHo2Y0V5MHJRbWR1ZW5OYmxLaXJTRHVuQ2RGT2RCVG9JdEFnenFVN0NoYUZHTVJzeDJnQUFBQUFBQUFBQUFBQUFBQUFCMDl4SitnWkptdmtaaHJWSmRwM1ZDS2J1NHJsdUhSZWQ0Y3NyR0x6YndYVHNocVRubTdNTW11R25QbkZMNU5ldFplT3QxSFZsc3FkcEVwd0FEb28vU2ZLb0p4WjFXbVo0dmJQMHpjOVB6YTRBb0FBQUFBQUFCem9BQUFBZFBaUjlhNUpsOGVmMVY4dlp0a1k4WHM5UEMzdGdYMTVlWHFSMjBoTzJlaHBqbzh3eGRXeTZ0bWVpWXN6cko2R1habHp6anJ5YU5kR2hxeVdvTWk2WnN5VHJRWG5ad0x4Z282RGlPekNkcUNkV1pmVGtZemM5UHpLQUZBQUFBQUFBQUFBQTJwbzlMa3BsUEU5U2ErWUhiZFBwK0oyVDZKUEozcFdkMFBOeWUzSmZKdVoxOVczaVZUMmZHdmxGMTV0eTNqcTg5bFp2T1QwOHVqTm5FdFVLWFZJVlM2bEtrOWFyYks4V3p6VTZvMUs3T0s3a2NKektUWHB6bHBEMHJBdFRQY3dHbk5hQUFBQUFBQUFBQlgzcytpWlBEMFlsdjdubTNUelorejVCemo5V2ZXZVJ2UTh0VTl4UE0yMDJmYWkrVFAxc3k0aGxLZWhqM28zbGJ2T2t0T2lGMHJFb2p4UzlNK2hjcVdsZExQdks0M2FpVW9TSEVRYVp3RGppMGZPYzBSMUttZGxHcEdwczgrMnM4c0MwQUFBQUFBRGJqOTJTMmEzaXBQUm95TDZNNnVqWkcySjVzNjBreThxbHRjZm81SklkWmJxMjd5dUh0ejgvYWN5K2dobjJJeGd5T2hkSzhORVhtSU1ITkVpUnBhSTJ3cmZoemlSS3pRTzlValJDNnB4bXpuRHQ3YVJlQ3IzdmFWdVVDMldrTms5VHpLQUZBQUFBT20vd0JGT3pPUHpLVVhYalBRUmRQa2VvTk91WXBoOVRDalBtYVRUbDJ6bWNhVmJYVE10VldmS29WMitaeFBhejVBaGFQb0VIemJDSEZWYmNaRWVmQTBrWWxvekY2RGlkNHh4dTJtYXkxeG1NOWtqZGF1a0ZSRHQwSFNxU3ZsQzAyaXp4MkhsZ1dnQUFCc3grekpiRnM4Vk9iOHV4Y20yTVU0K3p6RDJEUGNob2wweG1uTWphOGVtWlNQYnJYSG9oZFoyMDVWYUhkUmlOdWNUMDVKWmkzWTlNc28yaWFZMnpscDFtSW15aGlyM05WVWR3YmpTT3l3em5UbHZub3RIWmRKbGVhOTZjQzZNUlRvUHpwVHZKb3BqOUx6YUFGQUMzcjRkc3pIeTlFMTBYU2ljdytqbnJSazV0anpQVDh5cTdvWDRqNXUya2hiTlpsRnNpemVEWFU3THhhWkthVXk2NFpsOWp5Nlp5NmFzQmVGNDFlRk94MithWnJ4cmNuWGpDZHRNNU5hbmJUYVlWK3FYeld5WFM5T3FDNkJzOVlDdXIwZENCbDZhc05kQjU0Rm9EbnFVV2N6NXRvK2lxNkc2bHJZWUc3UGttVXlNcTdiK2I2Q0xRZ05EWmpSM2c4UG11bHRzM2FpektLbWlNVHN0b2pZOUtpeHJ4WlhuVXp2U1k4SDlJek4zemlsTzV4Nzl6R2lLaWQyeTRKSTZ2ZWQ0VXRDUld1YnBwU0xoeHdSamgzVmsxbm1uZVdtalB0VFprMWVkSm9URzYxbjFpSnBZeUcxakMyN3BpMDZXU2EzRE8xbFRBelRYdFpkSTYwZ2Q3b3pMVW5SSmFFMEdUVDUvcHhoU2s2dDFvQ1diMHhNM2ZNQ3N0S3hlTzBoRURycHJIeTI0bWRxOFdTMjRSNVVxUlFKajhYblRnM1U0bDZTSXBsMzRLUFE4LzBvcjVtL0lGcVVTWGE5SjA1TXNaME5iZWVpYjE4L2k3WlplRnBjRjdhUG9wbnY2VVRMaDE1QzZ3M0dZYlFSMDloSkRSMmNrMHRNMFk5ZWN2V0NXNStWNWRQRytjMUl2QmVhQXpsSkhXUUt0SHFWN0ppZ25CaFJlcjFpZmFjRUhEbkhtYS9QOUR6Njc2UG4rakNxWVRjdVFUU2tRYmpFTDN2RXIyTlVqelJOWmxlVzgwWmtYZEdkVE91NE0yamtqWTNtM1M4YVZrd1gxTEpmejdjemhwNjBtSWpKZHhucE5iek5XZDF3VkxYVHJFdTE0TDBVWmVkRHZXVG5XN0l5cHdVWVZlOVVZUXB4UXB4WFhWNTNvK2RUZWg1L29RbUhmSm5OVFRiTXlOb1puR2JDTVp0REh6YUdSOUU2VHVmbDNvbnhyWlRzaXlLOUlsd20vZW9xTTBJN3RNODBwZm53MnkyUnZrOHlHdlBQWkNlaWZUdElvdDBxdVd6S0JQbE9Dc09MeW5CTzhFZnV1Mk9mbkhvOFR6K2VnTDU1dkREemVIbjg5Q2R1WHRaM1ZzTzNGclhkMkhiQTg4eWJ1Wm5IbFYweWQyTEdYdDFxWE84VTRBcXZ4VUg2Y29xRnVaK2xFZXBLd3FWTTZTYWVKV1RsWGhqbnVta3B6YVQzMTF5OUlhM2RjdE5hN0s3TG1vOGluSWhWTzlKOHJ3V2t3MHRsN002Vmt5SnpUTlpGZ200aTBKTFZTVlZ0ajJZcU51SFpENGR1UW9jYWs2NUN0emhSODZtNHhNbWxaTUV0REdOZGtGbFZMcHpzVVc2T2hMVkJ4NlEySktOQ1R2RWFTc3V5TldiUmpxN3JtYTFTbHlxUzBRVzFKSWFFejJSWjY0RXk3TG1yVlVPb3BaWmNXbkpnM09kT0RBdlFydEZJMDROMkdqVmwwRjVVaEpXY3FLaHA2WmU2VXFUY1VmaUVNdldwTEZJWExTUjNxc2d5MlhtZG5xc082bzBLZWNuTkdhcXJvaFdRa3kxb2cvRGljRnFuSFJHNHl5ck5oQmxPOEJHcEdnVHZKVjczaDNxQTNCaEMzYWdYV0VaVU5VYVNOT0xaam90RjExVGZrekR2S0xIdFVydGNyR3ZpUmpzeHFkaTBFdXhSZWQ2Y2ExWklMZkhhWFZGcnBUR2NLV0VhS0ZlbkVBVlNzTEhaem9MMnNodWM2TktpalBLMGtlYllzNTJPWFZPOEJPdHhaMFZEVXNXcnFDUjNqZHBXNzBySFJLSHkyamFkNEd0cFVtWVB3VnVkQmFjQkk5NVhhOFlmdlpTY25XMGtMcWtqb25MZXB5bDBQTmlkZVJMU3JyRnhYa2pJM0laS1Rybzhsb3RFSjFKbEo5b1RkUVYrY0xObnBNMmt6U1FiUk1tbzJ0TE4rck5sS3RHaEM5NTBMVHVSZU5US0JhQUZMNWRVaEswVVk0eXRGNFVPdFFxalNMSVUwNStkTFRxU0wycUpuZGt1Mm10U2V1Y1RSRmFUS3ZVa0ovVStWbmw1a3JTMTE3Snk2ck41VlZOV09aNmpGMzNxY0t6ZnFkNVNreXNOZVE1b3o4VitLMXZlQXZFb2dVazV4bFlheW9rMjdDM2dDZ0FYZ3lhQWVTRHB4VTV5aXMzSFRzK3pSZWRGRzdwazRWeHN0eExyQnJSQ1lYWE9qSE5VYVRDMVVrdjlCODE2ZU9Fdk4rcStZYWozcHZ1aWFzOVVwbjB5Wk9WbnJYTzhGYnJPa3FjU1RkQmRVeGhYWkc3ajNoYTNlQnp2VlZPc2xQMVdqUmwwNXg4OUoyZ0FBQUFhR2hhVHViVm1PMDR3ZDdNNHZlb3Q2eW1hUUZYVG1zU0pxaHdqeHRHdFpMM21yOXpzang2dWM2WjFXWjErM1B3ODhlNTA5UnZ6K2ZUOForYmo5VDVOdmtBYjczUmx0UkxNUWRwbXpLMU01UzY5VE5mT1c2OHJhSk1iV2xkSjA3YUkzVm5zalF6T3EwZ0NnQUFBQUY0TVhaR21adUl2ZVRzbEVtU0FwYjF1Mmt0anV5WmRhd3V0V2VhanB3VXRLcHhLVG1kYTlYT0VYbkxXM1lOOHpsSm90dVNwYkowcmRrcXdxclNGbzBlbFVIUjlPWHVjY2pzekxNRFdxNk1STTNoU1NzeWFicXVHa3dreTJnQUFBQUFBQUZLWjdKYlBTa21UdkdVNXpwMjcwbVVFbmJWSnF0RTUwNGRVYm5DbXJPa2RsZUV6cVZsbVk4QzY3dXc3czR3by9OYldpdVN0QzF2STFSVHZPZ2NZWHZlSFdsMHZUTTB6VFBwbVM0ZHV1ZE9vMnA4QnpuWjJnQ2dBQUFBQUFBQjNnWDdHaVVoYTBrK3hWWFZDbTRkam5SUmxhOVo5Rmtpc0tWbWNEODdiNkhtK3A1bWM2Tzg3TXJHNzYxeGNtbVNHdkpwdDdHMFlodXliYmNlM0RySDBlTFZLWnZYODYyTGRtMVRpc0tNSE84NFY0blR1NHlwTlJGT0JhQUFBQUFBQUFBQUFBNkJaNHNqUzBjaVBlY3J2S1hNMmxZR3VPY0cwWnRVbDluaU5NNzhlL3dBNDlieS9RelJObmtqeUkzVnJLU0hlWmJka1lYRjFaTkJtMll0eGcwYXJJbmxQSzZvUzZycDFoVzV3Zml2UzZxNTRJQ2dvV2dBQUFBQUFBQUFBQUFBQURvRm5pNldWYXlRbjNxcU1Wem9CenBCenFqTWpneXNuZW5jNWh6dk5hN3F6YXM1eXF5M1hYU3B4WGxYT2lxd2NPT3JBSFJlUHlrWm1oTi9jQ1VpSXB3TFFBQUFBQUFBQUFBQUFBQUFBQUFaUXIyVHBvU2J5SVhrS2Q1YUFSempLY2VkS084SXZ6cXpFdUJkZDJZOXVjWXVNdDEyMGRKR2JMYjFIUlc1MVJtNTBBY1I3MlJGenlEZ2x2ZUFvQUFBQUFBQWNPZ0FBQUFIT2dBQUFBQUFBQXp5NlVyQnBMelN5U0xjSkszRm02c2RPOEhaSG1JZ05OdHhicGpDckxkTnB6YVV5cjNsMjAzVTZjYXV2ZWtTMFpzeWFzdk9XOVhnb0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFkNEZDZlVla3VtanVma2xFYXhGZElaNlVhVEdXVzFkdVhYbkdGYTl1cDBvOVl1YTJYSG9ybU5IY1FVbWN0N3hlSGVBb0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFEZFFLRStvNHZUdmVkS05Fa3YzT0YwbUhWQzBPY0dFNFB4UlFBQUFBQUFBQUFBQUFBQUFBQUFBUC9FQUM0UUFBSUJBd0lHQVFNRkFRRUJBUUFBQUFFQ0FBTVFFUkl4QkJNZ0lTSXlNeU13UVJSQVEwUlFORUlrWVAvYUFBZ0JBUUFCQlFML0FQUzRNNWJ6a1ZaK25yVDlQV25JcXpsdVA5dGFidEJ3cndjTlRFMFVGbXBST2M4NTFTY3g1ekhuTWVjMnBPZlZuNmg1ekVNeHd4bklvbUhoS2thbTZmNlMwMmFMdzBDSXN5ZW5VczFyT1lzNWl6bUxOYXpVc3lPamFDdlVFTFVuaG9JMGFrNmY1cWNPelJhS0owR29naHJ3MW1NTHNZcStOcUM1cVJoa1dYZGdWT296V1pyRXlMaDJFT2g0MUUvNU5QaDJhTFNSSWJOV1JZM0VNWVdKdGd6VE5IZXY0aFJrNlpUWENWamhRY2gxdytJUkc4a0V4TVd5Uk5jemZJTWFuL2kwcUxWSWxGRWhoSUVmaVFJOVJuc0ZncHpSTk14S1lsUTZtcGl4N1NzY3ZSUGhVMmgycHcrTFRFeE1URmcwRFg3Tkdwa2Y0S3FXbExoZ3Q2bkVnUm5aempNRk9CSnA2YXAwVTRvN0lQSW5Fd1hhajJjMzJOUVppOU9KaXdPSURiT0lWVjR5bFQrOXBVV3FGRVduYXJXVkpVcXM4eG1MVGdTWW1PbFJLNXl3M0VYc2xZK1BEZk1kOTQvdEczWHVwOFQxNHNEZlBaNmVQM2xEaDh6R0FTQUt2RTVzcVppcEFKanF4RzhReHlhZGpLcHkzRC85RXArcjdSb2g3dUl2MmNUYUEyREZZMU1OKzVBektIRDZiVkhWQWFuT1p1R2FBYVNySjlrVGlHOFpUSGFuN0UyNFg1MjlrOXJIYWJnaUEvWnhNQVFOWUhCS2lzTnYyd0dUUW9oQksxWVU0ekZqZ3hYWklPSURUbEk0ME9rRlZvS3FtYjlBaDJxdGw0SXZwV1BqT0UrZDkxczQ3MlNHZm5veE1Uc0lXQWhiTndiYlFnVndSZy9zd01taFJGTVNyVjB4dUdjZ1Vqa0xpTlNEUnFiTEFTc1RpWjlPcERTbU1RT3dncVJlOEVxTmhZdnRES3A4NXduejFQWVJkbjlZMjRPRENJTW1hWmdXMUNGNFd2aTJuTXhpMjBJRmRmMlc4b1VkQWxhcm9GT3JvWkt5UEQzbW14R1k5QVJnVnNsZGhGcUk4Tk1Rb1JLVzUyNGhyVTVUSGxtR0NjSjg5VDJpWE5sMmlqc1NCTmNMUXRtK0xBWm5ZUXdtWm04QklMcnprL1k4TlJ0VnFhSTJjMnAxblNKV1IrZ3FESG96R0xKV1pZdFpUTUNFNWpIVVlteTlrcW54SHFKd2Z6MVBhVlBrajcyWGVGakMwSnZpd1VtZGhNelZNM1hKc3JGR3JvR1g3L0QwdFJqdUthOFA1SGlxZlNsWmxpVmxhMkxNZ2FOVEl1cnNzTmJLUWJpSHRLcHl5YnpoUG5xZTYrem42Z2o3VDh3dkNiNHNGSm5ZVE9ZVENiNEFFeG9VOWpLYjZHcjA5RGZkUk5iS3VoU1FCVnFhMm91YWJkbUZSTkQ5R01SS3JMRXFxMWlMUFRCaklSMFU5Nlk4aVlUS1h2S2U3ZTFMNUR1dHowWW1JRkpuaUlUTXpQUjZXcENaaDdsVGFrUTZ1cFJ2dVVLZWhaeE5USkF5VlFZb05pVmsxcmZFSGVZN1JhakxGcXExc1RFYW1EQ0NMVXgyVDFxbkNHVWZraWVyKzFMNUl0bTNPeHRpQlNaZ0NFNW1adjBLQ1prSlpWTE0wYTR0VUhPcGZiNGVucWFWbjBLd0lOTVFTb0RFYld0U21OUnBrQzVIYTYxV1dMVlZyRVFpTlRpanNSaVZqNXhMYkIrNEZoQnMyMHhGUW1ZVVFrbWFwbTY5MWlKcUxOZ1dVYUVQWVhBTnFUOHQrSXA2SCt5QmswMTBKbVBVTFZPSVhVdE5zRVcrT29Sa1pOTnZCNHlsVEtZeWg2VnFzc1dvcld4RUhrWXh5WWZHaUY4eWZyRHVpK2huOGEyQ2t6Q2lFa3d0aUU1NlUrTlZ6SGJ0YW1uY25KUGMzUGlxbXlmVnBmWjRaTGNTK0JLRFpWMTB0UmJJakRVdEpwV1hJRVYrMmdHVWZrUFd0UmxpMUZhMVZzSkZYVWF4ODZmZGgzcjA5OWsvOEg0eFl3c0JDeFBXaS9UY3hVWnBvUllHN3ZHNkZFWTVNRVZpcmNVdmwxZ1pLRFNwT0E1MU1xOWtPbHF5NmtVNlNyWkVxREJVNmhVWFNZREVxRFZXVFMwQzZnYmFlaGFoV1ZIMTJvRENzY3NuYWpTK1JUaDZoaVEyMVlCWW00N3pHTEFac0YwZ2ZIcVVSbkxXVDZhSG9FYnNMTGFuOVNsMThPdVduRU4yVVpLeHhocURaV291bHFUNlRaZnB1dzFDN3NWY3FHZ3lDUXJxOU1yYlVERFQ3WXVveWFuaFRqK05DbDhrZnVxN3R2RFlLVE5LckM4RTBnUXhWd1NkSi9odFNYVVdiVVQzTngyQjZVYlEvRXBwcTlWSmRLUjIxTWdnbFlSRHBhcXVwWlNmSWpycVdtMm9WRnZVOVprTkY3SExVMndsU01wRUJLRU9yUnFVS0djTWs0Z3hSbHVJUGVsOGtIZWxQeGlDZ3htaEVqVmJCWm5FV0wzSmZ0RDhNM2plQ3NlaFJITU1GeFkvVTRYcHBqTHlzMkVIY3FJSTR5a3BObGFxNFlIU1EyUkc4VzNoQUIwd1lLTXBFL0dvNGJ6VGVDckdwOWlJbFJrZ1pYaUhBcW5MMEI1MVRtcFMrU1VvZXhYYW5oUTlhRTVnVW1kbG5rNTJqSEFtTW5TRWhKYWN2RVhTb1BRSjZnMkYvd0F5Z2NWSFhTL1J3NHRYYkxKQmRxTENVenBkMTFMS1RZTU1UeFpobVowa01EUEpabFkzWW8ybG5YUzI4OGtJZEtrZW1SWktwRnFQYW5LWHlSUGFwN0tZelpzRXhDOFNtWGpzRkNEQ2s5MTdEWDJDWW5NQ3hBYWoxRGt0MEtJeHlaanI0b1pQUlRHRTJCM1dDQllGbTBxY3ByVlY3eW0yUkhHUWphaFVGZ3hFOFRDTXJCNTA1dkNzU295VFNsUU1wV3plUERvdW8wZmtBeTBxYlJVSmhJV2R6S2RHVmFtSW8xRnpGWFVUaGpyQ3pOdmpwazlDaU4yV2VNeEN2Vjc4SmRmYllWRGltQVNVb3p4RTF3MVlheXcxNGF6UXN4c0RnZzVFUGcyOFlZTmgyTlFZWlcwbXFMYndpYkZhb01hak9JbEFTajhsUDVXSGw3VThLc1p5WXFGaWxJTEsxVEZ2UllQQ25la3NKeWR6ZlhOUm1abVptb3pWTzF2ek9HOXoyTnFJODVXUGNWRldHdERWYUVrOVdscG9hVXdSYmNVNDY1Rng1SktSMURHazNJbkQ1MTF6bXJUR21qU3p6RjdWS205T05uVlRwRXhRRmxhcml5RHU1eWFTNWFvMm8yVUZtZkVib3g5ak16TTJwblRVNGthYTlxRnFwODVnelEwNVpuTG5MRTBDWUZ0NXkzbWlZU2VNSnphcGpObE9scXE5eDJOVHpUb285Z2U3VmZHbFM5NC9kRTlnUHE0bGFycHUzaW83bHZCTDA4S3R1MHdKcG1rOUdKaVltSmk0OVp4WGU5TDFqYnIwQlNaeTJtaFo0VE0xdENacldHcUlheG5NZVpObDcyNUZRZ0E2RDJsSnNGMTBOYytQRFVWelY0aVV2ZjhBSzk2Y1B0VnJhYm9NQW5KcExHeXgwbm96TlJtcVptYlpOdkdZbWs5UTJsVHZ3dGs5VHNLYnRCVHhNSlBHYXpDekdhaE9ZczVzMXNZU2V2R1pRcHNDRFRweHVJQWpjUm1Gc21mSlRWV01GQnB5VVdWM0JIRENWdTlTbVBNanZUamRtRERITEJuTE1DbkxtZmsxRGdOTlluYU5rbjdPYjVNelBHWUUwekJCZzc4TEJ1UFYvVmR0U3ptQ2N5YTJtZWhXRVpjZEtxV25MUlp6VVdOV2N3a215b3pRY094bklwck9aU1NIaVREV3FHYndVSE1SZVduNXBqeXhFOW5USkttMm96WE1xWnBFMFRCdnFtUk1kT0lLWmh4OWtibVVlNlFiL2gvWHAwOUtOcGpKTkpta3phRmliQkdNRkthS1ltdW1zTmN3MVhNM2dvdVlLRTBVMW5OUlp6NFhZd0NJUElpMm96WE5TbWFWTUtUU2JaTTFUSU13SnBtTDZUTkJtaWFnSVdKNk1USFNOenZ3L3RGM2piV0NrekNpYThUVzAxTk5iVFcwMXZOVFFPNG5OZUI2aG1XbXJFTldHb1pxYnBCS3ptUERVWTlBRVVTbW5kMHhERE1YMUdaUFYzbVptWUV4TVRFeE1URXhNVEV4YkUwekVVUnQrSCtVN3J2RE1wRmVqT1pSTTFVSnFvVFZSbXFqTlZHYXFNMVVacW96VlNqTlR3WGFhb0RQT0UxUk9hODVyem12T2JVbk9xVG0xSnpha05Sak9ZMER0QTV3SE1WektWWEVxMU13dVlXTUx0TmJZMW1hMm5NYWN4cHJhYTJtdHByYWFtbm5POHpNek1UaUhWZjFiejlYVW42dXBQMWRTZnE2ay9WdlAxYno5VzgvVlBQMVR4dUlZem1reC9iaC9tTzY3eHR0VSttWm9RemttRlhIUm43R1ROWm1zR1lRemx3b3dzRHBQTm1wR21oVE9XWnBZUVFSRzdsb1laeTNNNWN3Z2hZVFhmUTAwQ2VJbXFhdWdIRTVyVG52T2JtRmUzUmdtYURNTFBHYW8vdHcvd0F6YmplR0J6T1pOWW1SQXhFMVptS1ptaFp5bWhCSFZtZUpuTE1La1d5UkJVSW5OQm4wek9YQ2pDQ0NvMEZXZG1BbFAySjdyM1kxQWtOV0Z5YmFHbWllQW5NbW8zQ3Nab25pSm5veE5MUlN3SlhJMGllSW1xYWpiTXpBZTcrM0QvS2R4dU5wK1ppWW5lYW1tdWFoTXpXMHlETUpPWERUWWRJY3pVcG1sVE9YT1diTDJRVlRPWXBtbEdqTHBsS0hzMU0rY1NWRDVMVHlQcExPYUpyeVhFQXpCU2Fjb0NmVEUxd3NUMGlteG5MbUVFMVltbzJ6TXpQU1BadmFoN1dYYUgyRFRJNmNURTd6VVpyRTFDWm1venhqQlJGQlk4ckViRmhtTXhNVWFqVWFVMXllVUpVVlVoNzAwUGsrOVAzaTlrM05Yc01URmgzSDVETmc1c21tY29HTXBVaFZuak5SbVRNek16Ty8yTXhPN25lbDYyWGFZWFZvQmhwa1RUTzh5WnFtUjA0bUlvT0llaFJITnZSQU5SUmNDcFUwV3A5MUVmMXArOGJzdFAzcUh1SnZiYU4xaXh6MTVtWm1kNWlhVE5NcDR6QjI0ZXlXcVRVWUhtdk04VE5JaHB6Uk5Nd1ozbWJLdVNZeDZSMlV4QjNZNU5KWlVxYUp2YW51ZmJkS2Z1dmRxaGxPSHVlZ1FqQkVQU0xFWU51OXNUVE5FMGdUS3pWQzFrK09QMm9XU3orb21tYlRVWnJnYWFvU3VDMWdMYlJqMDhzNGMyUGlLYTVMdG9GbFNGZ0krNnluN3I3dnVPeWVMUXJqcFBjV05NNHVMYmk0YWExbXN3bVptZWphaks5MTNoOVJmVE1RRE0yakhOaFpmRUh0MEpUTFR3V05uSmlqRTltTGN0YzVpcVduaWtMRTIzVVJQWWRqSDJnYVlCbTF4Q0lJdW9US1BHcGxiaXhzUjBFWTZxa1VaYXFjMUxpMnpkR3dZOW9MS013bkpzaU01OEVoTFBOV0lkZ01scDZEdXhDZ1F2TzVLVWNROXl1MFgyaSt6N29JUmJWTk45eE16SWFBdFRuZzhaR1NDRzJ4aHZ1T2hCbDNPV3BiOUM3Ujk3aUdIdllXTU13WnBWSVhacDJFSnpZd2RnRGlhWVd4TXhLUmFaU2xHY3ZZZHJMdkZoM1gwek1ac0RpZG1oR0xOY05pYWN4YWhVYVVlWU50N2Zpd01ZZENkbG0xTG9TeDdyZjhNYkFXSFlHZmxxdHFmdkF1WmpNRTNPUXNKZ0JKQ0trYXFUWVRFNWJhY1FibVp3c1Bxb3lXVW8weFlOT3h2aVlJbEw1TExWeER2RFkzM0Y2bmlrcTlJc0pzWUlUWVdFTVBSVDN3Qk1aalBrUW13U2E4WFVhalV4cUcxSmtxMCtJb2Nza1hFZTN5MCtrR0VSVzdZd0tRSE5QVnRZM05rR3A2amFuVGNuSjZWczl2d1QwbnBwenhweG1MRVdDNW1RSVRub1h3UWR5dTFPb1VaSFdzbkVVQ2hJc3U3V1JpclZWSFNSaUEyVmlwVFN6dU1QaTR0djFDTDQwb2UxUHFXd241WTJGdGgwQVptakFEZlRzbTJrSkdZdDBBR0tNbHprMHZrRzRuREt4ZXN5clRhd2dVR25hbVJobEs5QWFGSS9acFQ5M2J5MDVoWHBQZnBVYW1ySHlIY3VjdDFpejJGaDBwVExRdXFUSk0vaGlxV21RbE82MG5hWXBwQzVhREFXVWZsL05Da2FqRXBScDFhcHFOTk14RjdRaTVNOFRDcHVHS2toYWlrRUZQYXBNelhtRk5VSXdibnRZaTFQd3B6WmZzS2JMM21PNHNZYktwWTRTbkdkbk8xdjRsWHN6NWpla0ZBNHpUU016TllRN3lqOHY1VjZkT2pWcW1vMDRNS1RpbE5OS2FhVTR6VFlidHZOamtHYUxBK0FmSTBZSitXeXNWT3RXRDB5c0ZoZGFlcDZ6Wk1ZL2FGbUdSTnJMM21nTEdxRzJiQVFoYWFNeFlnRnB5d0p6ZE1KeWN6TUc4YTFINVptLzlmTTFUVkR0RTlvZHd4blkyMVFBVEJFcHRwTlJRMVJ4M3VqbFQ0UEtpbFRONElQcFVwc1B0Q3luQkl3WVRGY3FOK2hWTFRVRm1obm1pbWtOUTJ5Sms5TGJTaDh0eFA2eHUzckV0K2JkNW13WXpzWS9zR0ZSV1VxZWcxQ1V0U1RMVkgxdEQ5d0d3OGczYXdtYmhlMmwzSDAwalZHYTJSTWs5WDQvOHloOHZSL1d1MjBIcDE1c0NSQVJrZUlaTzNTcWwycXNGRVAzaFpocldHNlU0WFVSbUxXek4rbkVGaDZpZm1oODM0djhBMXJ0dFAvUC9BSmhtSm5wemJPSXRUQllkSitoVC9ZQ3dPQ3l6ODhyRTFLa0pKT1pucUFncHpTRmxWZThFY1lvSGVoOHE3MXQwVXNXY1V4bjZFb2pBckR1KzBiL25QcFF4eXVla1hrVnBWcG1tMHoxN1RJTTAyUUNrckVrL3NRYksySVRwRXoxaFl0T2VDVG15cWNMVEhNb3hkNjMvQUN0dncveXJIQloyT2luUDRaVU9sRU91ayt5N3YvenR0UytDQ1Z6cW9kakNMWit4VFVhYWptbzBQN0lHeXRpT3VPb0tZS2VKclJZYWpHMUVaYjZMR2p5RWJpVTBWWnhQL08yMUg1Vmp0aVUyN3V1ay93QUZJZHlhUklOSVNydW01LzVtOXFYd1JGTEhpZkNuTXpJbUxaNk1TbFQ4YWxRMUcvYWcyVnNSa3hjSVROS3JEVWhPZWpVRnBXcVZGcWNQQzFOcVgwNVQwYTBsUTJWZ1YvaVlnSlluTk5aa2NuODBXUUlGNGVjNmxTRHVYYm96MENKVEFGV29haC9iZzJWdE0wQnBsVmhjbjdvbFA1QjYzL2h1ZGg2d1E5ZUppMlp2RnByUkR1MVJ2M0lOZ2NRaGFreGcvWkZ4RStSZlcvOEFCZHRqc2JHNDZzUlVaMnluRGdrc2YzZWI2ZzBaTlAzVStWZlcvd0RYdTJ6WE8vWGlMUzdQVzdmNEtzVm5pMEl4OXRmZGZXLzllNWgzdCtla0NKVExITk9sSHFOVVArRG00ZWFRWVJqcUYvd3ZyZjhBcjNPMC9OakJiRVJDMHhUcHlwWFovd0RKRG1ZVXdxUjBDNDJYMHY4QTE3dDhkeGRLVHRQbzA0OWQySCtSbm9Ec0pyVXpTcGpVMmd1TjE5Yi9BTmU1UGhiZUpRcUdjdWtzNXlwR2RuL3pjOUlZaWM0elZUTTAwek9WT1c0SExhYUROSm1QL24wTk9XODVMemt6UlNFMVVWbjZob3pzM1JtWi93QTdNejFaTTF2T2JVbk9xVG5WSnpxazVqeko2dTB6L3FabVptZHZzOXBtWm1mM24vL0VBQ1FSQUFJQkJBRUVBd0VCQUFBQUFBQUFBQUVSQUJBZ01FQUNJVEZCVUFNU0V5SXkvOW9BQ0FFREFRRS9BZlh1UEM5ZDBXKzZMMEt3K2ZSK1lOaDRoMzNsYVA4QVVPb1lNUnFwNWcwamE2RDBTZ1BYT1k2QVlUQmVlODdaVFFZemVZWURtTkJwck12WEhFYkhSOVk0TkUzdU83cEhIUHZBZEp3bU9PT09pdk01eHpoQmdKTVpqTVpqTUJNRmlpc1dFaWZuQkJnUWlzV0ZXTzlRWE94ZTBjR1F4NmJvc3lvOWdtRDVJRFVXT2VZdEYwN1dHbk1UNHpSMk9uWXg1Qlk0c0NQSXcveUorazQ4bWNIYVBJWXFpN3pGT1Urc1Z4SFdDaWcxZk5PV0ZRYXdoNzBOVERGQWRjd2lDQ3BxWVk0QnVuMFozWFlhY3ZRbW5LcjMxRkZvL3dEL3hBQWZFUUFDQWdJQkJRQUFBQUFBQUFBQUFBQUJFUUJRTUVBZ0VDRmdjSUQvMmdBSUFRSUJBVDhCK1JCNzdjY2NCMDN3ZlJjekRPeWd3dmtOSWlLQVlWc3EvZVozenhLamQ0b1lvc0tnMXo0RUtjMFpvelJtaldsLy84UUFPaEFBQVFJRUF3VUZCd1FCQkFNQUFBQUFBUUFSQWhBaE1SSWdVU0l3UVdGeEF6SkFnWkV6UWxCU2txR3hFeU55Z21KRFUyREJZOUhoLzlvQUNBRUJBQVkvQXY4QWszY2k5RjdPTDBYczRsN09KZXppOUZXR0wwK04waEtxUUZ0Ums5RjNINnJaN09FTGdQSmQ1ZDRydkZkNHJ2bGQ1VkVKOGx0ZGpBcXdSUTlDdG50VzZyWnd4ZEN0cUVqNGxaYlJWQm11RmZMZFh5VVYzNnJiN0x6aFg3WGFlUlZZZmhyOEZxcVVuZFVFcmxHS0tkYkN1V3U0dXRxRmpxRThKZjRTNW9GWnp6bmQraXBSVkw1R1FnRStzZ2NqN3JhQzJmZzJwazVMTFlEcXB6NGtUTnRKZE1qYnphVksvQWFKNDc2TGxKb0s4MDVPNWFmUk9xWFRaWDN1aFZmSDdOOVphbFYzVHB0SjlaUWRVNmZ3VFJWQ2NWSGpNVVZrd3NuS2FDZzEzcnpBMFRhS0RxaU03YjdGMmZwNHJGSDZTZUwwVzNFd1R3bkVGdFE3dHRaOUU1bEQxOE00VHcwai9QaUhpdkxXSk9UTFpMSnUwaFR3RlUreXJWYUtsZHoxVGF5ZzY1MjhCUmFkcCtVeDhLNXZMREJXTXA4VGxWRTZwd1Z0aFVWSlhWUW5rVGtBMFhTVUhWSHd0Si8rUWZmd21LSzhtSGUvQ2U2dlZWblZiTkZXVzFXVkpNdXF3NUNUT0ZIZDBwdU5jcmhZNGUrTGp3V0tLVENzUnNxM25xRm9jbFZzcXN0UXRKa3pmVk5xb3Vrb1VaRnM5OXhybXBKd3YxWUxjUjRCeXVTY285b2F4TEdNdW9XaHlWVkt6b1V6VnlBYUxvb3Vrb0VVRkYxelV6NjV0cjBsaDRtOCtSdXFkMDIzekpnbktkUHc0cnFteTFXb1hQZGt5OGpKNVE5ZDVxcTV2OHZ4TEdlSDVUbkorbEh4c2pDZDYvR1dFU1pmcHhjRnpHVnZSUExVTFE1S1pIMVRheUV1c2h1dm16MHV0bStzbUNZV0diR08vRGZlUEtseXF6eFEzQ2RQVnVTZTQxeVJOeU9UVUxUSlNUYUp0SlBwSUJBN25WVnl4Y3A0WWJhNnoveWkvR2QrSEZVN3BxTjB5WlZXSkR0QW1uL2pFbVZGOHAreVlpVVE1YnR6TWY1SUJCRUtJcDBlcy84QXRhcXVlTmNsaGg3czNpc0xwemxhWjdQM2hXSGRZakxDSkdBcGszR1RMQ2JoUEpqVWFMWXJ5VGEwM2ZXVUtiUlBvSkVLTHF1aWg5ZDVFWXJMVGxvcUJiVVQ4b1UzWnc0ZnlzT2wrcWJKWGhrRVE0SVJ3OTJQY2dJa3B6SjFpQ2NKeExHTGhPdVV4anZxanBLbDUwemtvbE9oSnZQYzF5UEg1QkdLTXN0bUYrY1MyakxGeE5zemV1V0xzdU40ZHc4c09URHBKalBEd05rMlI5VnNlaWRPVnlWRnRqekNlR295TW1FZ0VKQTVxTGFQa0V3b0piVXJQRm92bWoxUk45cWRiRE0rWVJhSnhhS3U1Sm1Dbm14dUoxdUU4NFRMYXZxc0VYRk5kYk5DcXFoVzFRenhGTWdFQWhsb3EwVmJxbEpPYUJOQ0UraWQyQTRwb2JmbVVQV2VEMXpOcG41OW51RzF5R1RhTHFuVHl4anpsVk9tTTJXSVhDcGROMmdUd1ZFOUNpRVUraUtFaUo0b2xTVkZxVlJZWWFsTUpNRnRWT2tuak9IOHJHQjBkT2NyK200WTJpb2pEcGxlWFRMU3NtazNDZUErVXFMYSt5Y1ZoVGloMFhKY2l1VXRsTkZRcmxLdFpSUlNFaGwydlJNSllJUE5ZcFl2Uk5CUlBHY0svYkRjK01xV0ZzM0xjdzlvUGVHWjgxYUtvZnBKNU54bHprODYwV0hpSk54R1N0UW5ndXF5QVRJSnBBeWV3V3pKNGxoaGt5WlhhRUxZSG5OdmVpdm02eTAzRVE0d0Y4M1dWWlVDckUwcUNWVEp3bmsvQTVYVkxKMWpISEpSWWUwVHcyUUNKUVFtNXJrd3czeWN6a3h4V0gzVG5MUlh5WFZSbE1IekRNQXFmWldsVTVyU3JQQ2NyY1JMQVV4eXR3UjVKL05Ca0pHVlZSWVlieWMyRXEyeU1FSUliUS9kTjRDRTgxRm50TytidXFzY0t2RVYzZlVxdzlKVU0zVGppblFqRjhzVVVtOGtKUGthRzgybGgxeVA3eCswN0xpcmhXM3NFZXNPNm9DVlZoMUtySDZCV0pWSVlWZFZWMVpVQ3Zsc3NFWVl5YmdWeXlkVUVBaFhKQ1UwTjU0dlNXSXA5NVlMaXI3bUE2RnNyaUdpckZDUE5kNG5vRlNEMUtvQU9nVlNWZVZwVk80YzBDb3FLejlVNWx6Q3BDVlZndHFML3BBUWxFb3F5c3laRlZWREprd2szREk1MzFncks2b1JPTWFGNWhHVjVXVjhyRVVUaW9PV2dXM0dPZ1d4REtwbFNFcXBBVzNFdGtlaW9QVmQ3MGxadXErKzdvYzlNejJHcFd1NzdVY3QvcURjSjRhd3F5c3JKbmxRS3BDclZVQ29GZVZtNnFzWG9xajFLcDlsUUsrYTA3NzJwQVd5UE1xcGZlUkQvSFBSVkw5RnNnQlhWMWRYVnlybFVpS3VxT3RxSlhLLzlEUFNWVG10OEM4c3RZUHV2Wkg2bDdNL1V2WlJmVXZZeGZVdlpSZlV2WlJmVXZZeGVxOWpGOVM5akY5UzlqRjZyMk1YcXRuc3lEMVZaWFZJMXhYZVYxM2wzbDNsM2wzbGRHdDBGZFhWMDZLdXJxNnVpcnE2dXJxNnVycTh1OWtZWWZSZTc2TDNmUmU3NkwzZlJlNzZMM2ZwWHUvU3ZkK2xlNzlLdEQ5S3REOUtab2ZTUVJ5VkFQa3F3ZWhWSW1XeVFWVUhmVmxRcTA3S3JMaUZRaFZHZXlyRjZLM3FxWk5PcXZLbVdrci9BR1cwQVFzVU5SbHNxMFZTckxoSUk1YWlkQ3F3Z3J1a2RGU1AxVks5RlVacWdGWFpVcXJaTm9MUlVJVnR3QXRPbVN5cVZaVXlXVlN1SlZLWlhZclpUc3hWWWx4S29BcjV2TGMzbGFkMVdFTGlGU0lLMmFveXVaYlFWTWdvOGlaUEZFdGVxb3E1Tm9yVlVBVjh0bFdJTGlWUWJvSW9ubGxPNXZrb3ExNnJ1K2lvNllCMXRSUWhVTHp2SnA4MDh4a2JJMG1jejJuOGxzeHduN0ppcWtydStxb3czd1JYYUhsbExxaEc5Yzd4aGVSR1ZrTXorR3FaeDVSTFJjQ3VJVkQ0RjlKT3FYemlST1p2QlZPV0l5SE03dWhWV2xUSmg5VTJYRndUU1lTWVhudFVUUStBeENvek42WktoVUVxNWh6TW9ZZEJsTzh4Y2VHWGxxdGdZanFWaWlOWlBKaGVYSlV2cnVHblRPOEsyaGhPb1QzR295NHZYZUNIUUlJK0E1Wk5rTDV6OWs4UllMWlRTWmMxcXExbmlqVDdxcXBOcE9xME9xNi9kZkpGOWx0RGZBSWxFNlozM1RDVEM1VzNVL0tGaEZCb0ZxVlhJL0ZQRW1FNlZLcjRCNThscytpYThPaFd3V1B5bE1SV1RicUtPWFh3RDhUTm9SaEdUa2poRnA4NVVXM2ZSTUtESmlhbWU3Smpsb3F5clF5RTJpR0lLa245ZHpERDV5RU9tNGJQVzJZOUZXK2l4UmxnbUZCcGtlS2dUUVVtQUUwTmhTVE4xQ2NkM1A4QTVRL2NiaG9xaFBEdFFxRnRiYjRCRXJvbjNENTJHYUxEZGxYYWkwVG1iMkNwbHhjVFFUY0w4aE9PN21jTEZEM1lzdFowVUpGQzlrUkZtYk9ZdU1WSmRkeXliTDF6YlJZZmNxUEFHbkYwVzNmNWN0a3lwWVdVUFdidzBaSEY2WklqeEJuZ2lzZnNxNUdOUXNVTlJNZFUwVzBGKzN0RFJQRGxmSzJxd2kwTzh4Ymw3RFVwdXo5U25LUFdWRnNYSnZrZHFhbGZPZnNtNGFCSFcwb2VzdVdxNUp6a1BNWkF0RnJPaUJGSXRFeFFSNVJTMnIvTUU5T3FyazVaRDJua0pQdThKNDUyQVcxdFJaQjFXS0tnL0tZVUdpaEVuaklnSE5iRUxuV0piUmZMRDFrQ0xKekk0MjgxYUJlNHZjVU9GdkxOdEJiTlpGTkhVYThRZ1JXSFZSalY1MFRSaE9LdzZpYlRBV0VXaDN6NVg3VDZVd29OQXFxazRjVll0RTVUQUw5Mkp1UVg3VU9IbnhUblBEMVJ5RCtXNXJWVVByS3RWc3ppd1hleWZYSlFxbXhGOWlxaHBjNVl2ZWl0NERsT2w5Y3pRZXFHRWNGdG5FZEFtaDJSeTNVUFZSWlA3Wklla2p1ZEU2YU8vd0F5cmx3bTAzUGNDZndESE84VkIrVlFZWUY4NSt5cmJTV3VjVGg2cUxJUDVaSWVtOTBURVlvVThOWWN6QzYvU2dzTDgvQk9MaVRUeFIwSE5VR0k2bFZNcWJveWg2cUxJUDVaSWVrZ2p2WGh0bGIvQUZJdnQ0TndzY012M0RoL0svYmg4eXFsOTA2RVdzaXV6T3NvZXMyQ3d3ZXFIOHBHTThFSXRWRDBsNXJxVkVTQVdYc2dtdzRTbU82MmdxVmwrckZmM1FuUGhkaGdOZDNVcllDRUtNUEVUN0tVUFZGQUJOQjVtUS9sSVFCWWRGRDBsNXFGUnpnajNuNnZhMjRjMDU4TnlUaTJlcXBWWGFUNkxhaUsyWXk2NUdzdXpsRDFSWFZNVnlRL2tzV2ljdXRsM3k5cEpoZFE5bnUvMU8xN241VmZJZUk1TEZEYkp0RmJJVmNqQTFuQzUyNFpRQ0kyQy84QXFERDdvend4TCt5WVRyZVFoZXNvaEVicnZmZGZ0UXVVOFY5MStwMjNkNERWVnR3SGkzaFZLNzhLTEovYklPbmdNZmExaTRRcDR2R1VWS1JKanZnb3NuOXNrUFJEZTRZUTYyZHJ0TmRFNXY0OW8vVmFqZXdxTElQNVpJT205eFJuQkFzSFpEREQrZmdkS0ZWM2NLaXlmMnlRZE4zc2p6WCs1SDlrOFIrQzdWUXRnK1NydW9zbjlza1A4ZHpzaDErNUZpaStVSnU3RG9QaE5hcWhaVkc0aXlmMnlROU03c3cxS3FmMUQ5azNkR2crRzBLMm9mUmJNWHFyWlk4bjlzZ25SZDF1cS9jN1IrVUsvYTdNRG1WdEYvaVZDdG9BcXNKSFJVamJxcVJRbEdsMTNTckZjVTNIRXJGZDBydXFzVUk4MXRkcDZLa0JpNnJaRU1QUmJVUlB4cTY3eFhlWGVYZVhlSzc1Vnovd2Evd0QvOFFBS3hBQUFnRURCQUVEQXdVQkFRQUFBQUFBQUFFUklURkJFRkZoY1lHUm9iRWcwZkF3UU1IaDhWQmcvOW9BQ0FFQkFBRS9JZjhBMHFaWk5pZlpua0p0amY1eC9uRFRjenNGMncwMWRmOEFhdXNIdnZaN0VDQldqOWd2aXNSVzhBZTVQOTQvMHovWElyZXFKV1ovUEFkL3VsQXdvTzkrQ2tPV1NIdkhML3BXYjFFSlp2SGloRXpkenE0VjNBMFg5WVorWDJPNzBPejBPYjJPSVQyVDFPbnFtN2tQZ1V4UzJxTE5KOUJ2d04rbzNYL01TYnNXdEc3QnpRbUZDUTQwZEZMb2I1NnFMKytXSnBkSXVIckU5cVZ1ZEtrTzB5aUZzaEwxRnlHbkJVUk5jU0JpWGxpelFKd25XZXR0bzJlaUFRVUpmY2FhY05SL3gwbTdJVytRWXBweXZzR2J2cFRxZ3RGZTRmeTdzVkU0VGltaVhZeXN4YUFpcDd5L3dSNlYyem13bU9TSkFMSG1yaVN0YUdMTUZ1UWtkdEUyblJqUmlia3l2SzJHbW5EL0FPSTJvcUs3d2hYYm1kdlFadTRwZ0p1eVNVamRqYXMrTUZXTmVnbFFsS0ZZcnR2QjdLR1VTTFcxQlR0aWVPNFdWZXdoUTE5NG5TUXRERERNTkRGUVErTkpnY0VKNUVFMFArQ3doRElPeC9KaEpKSkxKRGFTbHVFc3M5d1N4TUV4TllUWEl4SXNFRUVEVTBKaEwyODZSQlVIRktpSTM3RkdwTE1adWJOQkpUVzRsRk5FM05sTWdRR3BHMzBRTU1Sc05DWG9tYWhhQmdDZnZySWhaYndMSVQ1TktMNFVNYTZZV0VKbW9iZ3RYRnBRUVFRUlBnUnY0TVdTZ2tqM1FRUjNGam1Gc1RCYmhJN0NLTzQ5QjRFZlNLcWxmVEEwTVJGaUVUblJLNGY4QXhmTy91MHBjSW82UHk2RWlFcEpnYW1RbGRqcFQrb1pWamJoS1JzaUVFZlFneXEyVldNYTJSS3RpS2VGR2htQUhjR21Hd3N6MkpMVXlEaTZFeWthSDlEcjZHaGlyRzdvNHBiWVd2eWZ1YkdoQ0VTWmVQdUozSldkWk1kRHNleUVWQzRDbE1IS1RENUV2bzZXc1N4TTRSUVpOVVpBVW9idFVRVDJNbDFidm9WRWg0N0RWMFdjUEJVd2hPdnVSRWkvUm16S1pBNHdYR1RFTXR3TG9OTm1tb2EvYk9pUWxLbkZQSFk5MklZb3l5Mkg5NXRpaW1CNUxRcWhkcERzQjlSNVNBcFl2WVVCejJFMVV5SFk5Vk1ONmttOEtpTHNXRWhJWjVhQ0RrREVKZkdKbUh1UVQzMGRIQTkvSVdTMzBJYndURVhrWmdCNGJrU0dKaWNpYmFXaG9vMkVCakVRMSswWkFoQVh2U2VPU1JqUmZBS0FtM2tUaTVNV2tGb285eTBxYmp5VW53T1dUbENqbUU4VVk5WHlObXltYms3RWJCQllWUWxUMjNHTElRa2NLQ1p1RUN1S1QzQTBNZVliQ1QwRm9RRDFGb0xBdDdFcXlHb3ZSY2pSYXB2UHdoajQwU2tVQ0JOMDNHa0pTeE9STnRLY05FNlVKQWFhY05RMSt5U2JRcmlrVk1FVGxsZTZ3OTBGSzhsTVVOakVTUlVOMWFxMkZjUllvT1ZxYkRTRmdscHl2VW90SDNFTUpycGpXd3VTcHdOSElVRlVXeXJHSmRraXpaVlk0N0NvODF5OUh2ejNXalZYTkIyTE9DM1JwNjBHcUVmSXVqOEliWUJlOHNab2lSYVcyVzNJNW5zTTNkaVVUbVJNSVRJYUZ4TWVTL1pVSS9BMlFGc29WdGU2ZGFKUEF6TWNER2s3ald4T0JUQ1NoNnI2QnRRa2FVT2VCbDNjK1JzYzUzTDUwU09kV01TRUZrM0lJRjNDdmRxOTlIdXozeEFpU2R4TXBNU0pibDFBaDdOeE9IdU9LdEFsV0dPNzFXL1N3VzNkaU9aelliTzdHaXRVYlBWV09Fd3BFNVFvWGtRanE4VC9BR0dERWpDU29nOCtKYmtIU3BIUlVnbzc2UVJwVDU0R1E2bmdZNjNHeXNOWUZWQTl3YTdhYk1ucURVMFNVUWxCSUNwUFFlVWJ1SWVPNDl3TEtOMmoxQXl6b1Nlb2gwWVROc01kM3FnbEJXVmJkMkV1ZnpZYlhNU3JESHE1cTUyMFB5Vjl1b3ZpbWtoRE91dTM2emtJSVI1aHFaQ1ZSbTJ3dGlZcjZCcUM2cEI3c01DUkJCRlJzMEpCVDU0R1VlWTJNWnNEUlVZaDdtSGxmUWt6Rk5ObFZrU1oyVE52Yzk1SHNJcFpNSWFXYjNLdWdQVzkyTmIwR2l6all2a21tcWtLQlhVcWJ1d2x5K2JESGNPTmhzNzZ3MjRWeHBYd3diYmN0MUZxVnlyVnVISnRrdDFZMVF3UFJndFhkbUpKaHI5UktYQ0VTN3JhVlNvcjhzcEE1TllZMlN6b3hPd0s1QkdoSHovaUJWOEV5aGIzd01wajZHTkpqMkQzRmNvTDZ0TGdvZmNqVEJxa0ZQYVNJS1piaWpzT2sxNFl4c0YxSXNTM0toc0VwRUs2cmJ1d3VXNXNNdWRocmdjaHJTUmdra3RZYUVOT2YyNktWNWpxbTNybmthWENJTER5dE9ybm12MUt3c2h2eHNVM1pJWVVsVUpoUUxnb1B2WWxDaU04RzlCRXNOd3NRUUtVMDFkQ1creHBQNTVHdEpLVFBBek9TMlk0ZHh1Qkx1aittUW9pZzJpWGdHUzU3Y2lkQkxjNC9zcERTeVVON0R6QVdldGRMeXdxbTdzTG0rYkZ3ZjBORlliTzVKSWt0eFJUMTBadEpYYnNoTExxK1g5TmFuaDlBNExXc2F3U1FtU2ljQ0p2MHFPVWhBSmRqUkp1eFpPQW5SQ0xaYXFWdFppVUY3Q3ZmMU1RNXNrK21qK1RaajMzMkpJa3lEYzVPSU5EV2tsSW1Wc3pPdzltTWUwb1pzcXNiNUdTRDNjbVJPUTArRHNNRW5sWjF3U2N4UVhyY0tqTjBROWZZWlBVb3J0WVZsWHpZcURXOWhGbFJ2MHZoZkkrdDBTN0U0YWU3M2VrRlNscjhTSHV6RGFsMmR3NnZVU2QvRW9XL1JrY0ZGcEFacXZSVnA0R3ZmQlYxdnZvdGpqMmo2TXV0RGxENTM4YkRxWGZKZjhBc29YazlTRUdob2FHdGFaZGJNNFI3RW5jMGFSeFpveWtTeUY2L0dnNFAzQ1BEcjVMaFNqZHYrQTFTWnFNM2QyT1VmMWdrS1UwcWZJMkVvNElML3RiNE54dXozTEtjcitvZUhGeW1xM0RZQzBld3E5bFRIVkxscWpTaTh3d2xXb256K2hFSWhUdGlMYVNHdXVNbmZrZXBjQ2xYMThEVTRCQzgyakVjNXloQ1V5VzI0UkF4eDZVTzIvbmNhMWVkR3RKN0hqY1JwdzFESUtsTlhRMFJwVG01WEpJVVVTMG1Yd2MyTXJQelRUUkQ1SUZUZGg2dGJqTzAyMFpzNXFqYUVtMk5MbGRsbzJ6R1JwS2k5UlNQdlA5Q3RwU1NvVWQ0Tjl1ejJMMHZnYkU4Qys4YUZKZHpwWVNXUDBhOWgxWkExWTBxeXo5Q3FpeUd5TkZkNnZRRnNTZk5TUmIvQkxyR0RhUit6MWVWaVRvZEhYUkRpa1FsVTdNcU4yZnQzR1RTNkZDeHVWQlYzRlpsb2U2RlJRTUx3VzRoc3JyVmkweXgxc2kwN21sOTlOa3BFYUVZdWg5TGVON01ITlE4U0ViY0lWUlU5allRMHk3YmV4REhLeVlMN2pjc05zMG1laWRLclJXYkt6WllXeUhvWVd0MktwdUxkaml2cG1TNDVKa0tac3o2bGNnZVMxWFpITmoxbER3RWJoa3I2dXFqSzNBeWhaVmlpN0prbnpJalJKNFJrZERUaDk1TnlLV0NkVGdzUFlnUy9DT1lXQ1dSRkxUbXdRVjkwSldxTmNxNFJWVzV5YzJNbThnK1o4RHVWaTJFNmpxckpOd2piNEx4K1J5NGM2TERndVBhay9rSVpCK3JFbHQzUHNrUjNJQkUwUmx2Mlk2bENOMmVpVW9SU0xlL3dCcEFveXhXMGUyaFVqYjVmU2JkRjdMMitxT1NPRlpGSlhvRURCbzVCZ1JYVjZDdkt3Y2xNQ291ZEpxQktSWlRHQ3J0RTRoRFc2L0tEU2VJZDlpcTRkbXJIdytDTE1zY01wK2FJdWFOeFNybHVKY3ZnUEM5aGhSeXRtV3JyR08vQjBLaE54RG9ORDVud080MVFTVmJHQVJwbDdJYTZVOURMaTB1M3NSODQ3RmhkdU5KcjVSc1F1MHZ5Uk51aUpJWE9LWk1yd1g4c2VLZWtpbFJOc3ZBbEVZcEpNc2E3QzdsNk9nc3VSZHF3WWYwTFMwWGhpUXgxbEgwMzlOQlhBU3BZV1FrM1JGV1dIQkNUYXpKUExBeXJydEVsTllZNENGeUpxcU9VV2REMyt3YVRQSm02Zlp3RjRNU21ycW92QVd1NnhSWWR4T1V4UTNuSy9mY2gwS0ZTSFZ5eFpqOGd1NVBuZkE3ang2UWtkeUNyR2NFS3RFSXFldXdwUVVXTUQrWFk5WklrbXU3ZEVraEsrN29KcUZGM2k3OGxGQ2JaZmdkSjJWZjZIemhzVEh0ZzB1TmhhWFpPeTBXVVE2c2w5T0VKdE5OWFFxeHZlK21MNUprMklkdnNMRnlxdzUzMG9WNWRoRTNtOUQ5UktLVklZYk1aWDFudnBWRlpZcU9jbU1Kam1VMmliS2U2dDZFcFE2cWF5dEs1eXFuczBKcERhS0owR09hSXlRMGhJMDVZME1qUXFTZkwrQmtTN1lxRlFXOENXWGF4SEYyK1NXeEI5b0VybnkxZ3BObGxtTjZiRGtvTFlhVkZoRTk5WC9BRU5tNWJsNmVDZUNJbHlMUnZHaGgzK0l1UlBhSU8xZEJyUkMyMDhZSFgwTEtGaGJVSnp3S1RReEthZXhMTFBSUlk4bjhLVkJHemI4SDlpTTVTOEYwV1R1UFVDVkpwWStRY0lkR3lSTWFOY0ZXdVZSRXA1STJyRngwSnc1RXNoek5ERXNDYTNKV215dy93QTVTOFEzdm55Q0JoS2hrU3RGL2IreHBRcFpDcWJzcTJjbnRvc3QzVi93aVpjbDEvbU42cXFpY2U3Q0dNZlZ1V3h1b0ltQlJkamhiNVkydVd4UFRBV0FmNENyTUVFaDNHbHF6MEpJbmRVMW1RZWtGc1U5RFk5UXptQzZEODZ5U0pOMlRKTWhPd1RzcWFOU0o1R2FtNHRDVktQUml6OHhhSlpiZGhzMjhpd25JMW94dEt5V2pnRkI0RXhBeUhrZHVQY1dFZmdkVUV6SjFLallKSVF1VGs5dEovN1FaUXFWaTVVY1kxU0ZTM1FaSkhOdXl4OEJhTlNTSWYxU3lRdEYxaG5DQWhPRzUxVzc0TWt6RlJQeUU3QXN6UWx5RWNPRUpWa2hKQ1dDbm9Uc2wzUXBzUE1rVitvb0pXMC9JYkQ2RDVFcW9lK3NJSXNRTTBKZENLdzF4RmhPVU1UOEN3emM4dG5zNGhYUkNtZ3NIa05DOGlJVGtVRlF1TGs5dEZWd3JqSlN1M3V4SEFpQzB2VXg2eWNzUzRhVGlFL0JIOVp6b2NBYWN2R3NFQ0dwSWg2ZTM5TFN3VTZsY3hhQ1F0UFk4UjlnaUlMSGtaQ2ZLY0VWWmVKK1NWUk5MaWdqTDFHdjdERFptQUliaTNYYlpJd2h0d2xMRklKRnczVWFabEZwRWtWbUVpc3JhVEFuSjVDZkp3VlZIK2NvaWdQbFBKWmVCVWZRbEx1UlBOZXhNNlZ6MTkya0tTZGxFOUM0MEVEcGdra3NzNURvSkNHNTBjeEt6OFJHeENPUFdiRmVtTk5YVFgwSXZMVHRscW9VYUhmQTlsUGRnZjhBeXA4RVYvQ1BrbGNuNDRJQ3k2THlRM1JEM0d4N0JpUXZCbG5xTmtrL1FtYUVteWYwbDA4aWF5ZUMvRXZjbVhkaFJqMEU5bnAxRlk4RHQzdUZ3NzFFK1JKNEszSEEzV29QaEV2NEdKcGsyTXdvbUZUUkE2aitRYWJReGlsSE93dUxDc3VoUlV4aUZKQnFFeTVVNVVlU2VZMjM5U1pLSWVHU3pvU3RFakxPVFBCMnJwbXk2N1J5SGtWWVRoNmRTTkZnOXNNVUl5eUw3QjRrMk44SU4yd2JPN0oxUVZVMlZkRVpPd21NZ2pSbERtTElnUlk4aGxTNkQwdVU4SHpSU1hMZmcrM0Z5eVg1U1prbDRFTjh0bTFXOUJNcHROcXFDN01SR1pIc3NVQmtpaENlUFFzUTU5U1dVWkNKL3dEUWJZYVkwWFQwbGlZa3VpRHVMRWtpZ3FIVjZnaERxb1V2dTZGU1NTZGlXUzlpZExaY3pzczlMWXJPaHhKSk9rTVRab1FscFVncUUxNm9JS3paWjdjTTVCelBRaDN6N1FpazBiWTB2S053dmNWN2Zad1lINFJodmt1TCtLRld5MlhMMmgvVGhHSlVudHdOblpYWmRhTnRLbXdWM05SMEdyUHFjL1FPNDkwTzA5bWJQcUdqR2tXUk9aeVJQYWhMRFEyV05KWW1WUzl6aDl4Yk03azNhL3hvTzVjM0pKS0thc05Fc2tsRnN2bGU4YjZDMFFKRENFa1diTnZ2SnBDWHFYb3VjY3M1ZXBjM29EbG1YZkxHOVFsZVd5SzNQSXFaU1VnelplbzNYYktrY0VQWWpnZlM3VEVyUHNYSitDc3VjWEVyY2lWSksyZzEwU1pXMEZxSU9xQjdsYThITHAzSUlJSUpRVDdFSGMyTkVoTVRKa3llbVpJaDdFZGlXQnNybVRSdDhzVU5xVVFPU28rb0NGMkJxUTQ5a0YrZ1FER0pBQVArcEozYjdjaGdwY2tsblhSL29vWlR3cWNnNVp5am1ISTFrZzV0S25rRXBwc1VMSW55S0FNYko4akdhYjdFMjZoVmlWT3dkQllOcmFia1NoYUh5em5uT09Sb09ZTGxIZERsNkJwdWRTWXRxZ3Q1SEQ2SndlaWNYb25CNlorQlRoOUE0ZlNPSDBqajlJL3lSZFBUQ1VsQk9GV2g3Qm52dFJncHIxSVJjRitHUjN4MlIvQ3JMYUNYdXlYdVM5eVc1TDNaTDNaTDNaSXhyUklzeElNVFBhTUduVEhzZk5Db1RqaXVqNUVMZU1SNUl4dkJVYXJqMkhjZ3d4RXRTYXcyaFZFMHQzUTQzdU9ZNVlUdzhJYk95THN6Q0ZrWHNFRi9TamludGxPenFnMkcyODZ6cUlFdXo5amhlZ2xSMUtDK2ZsWGVrazZLeVkzQzdFZVhvbGJPK3lVMFNlTkQyRFBkYVNzV2lQSWdKK1lFektMa3J5ZmFxREk3QWIvNGtEd2t2S1M3QyttV3JPRDg0aUxUZGlTNUM1TVZGYVBRdDA5cVNMTDhHTjg3dWhkbmdacXphRU15YjZhNkp0MDN1TU00eEhrWmMxNEtvczNVc2lYVVR1aThzeVVGVzkySjJ6dWdsWDhLTzkyNUhDejBvTncyM2Q2V1JpaTJqOGlEaVhUV0dTNDlTaFpia2dsSXVKdWxnaXNlS2tZZ29zaHR5MGh2cFkwN0xoOGd1YURVREVFaHJzY1Ntd2l2RE9ZVDhpVERFalB6VXpQN0RiajN5RHYrNkNLWnRicW85SUUyckNhaHVVSzBUZFIyUGFNV29ZdGFkY2NDanNmZWlNNUhUSHNxeWhvbGVTc1dnRGRiUndlMGdrZmlncE1TY0pWT0NYS1JvVUxIVkRBSklkZWFNWTBJYU5valZtUTQyeGR2b2NGamVDaTA5eksrQWhacnlOK1k2TDNJTEpFbmhFdmNnZ2dXVWFhblpQb3JsalNqc0VaazVpbWtFRFhZNHRpYTJDVmRTYjBvVE1paGRIUnhPcVJwN3g3RjRTMmFKUW0yUkwwUzNMOUVLdDdsRUNiVm1PcW14ZmFDbTR5U09HalRGS1RuYnNQRnNJRUxiM01od1RXOGpWTjNJL0kyVWk5Q2xxZWR4cUlNd2lLMmlQTTEyZFJBOFE2dmNnRERIVk1qWklwdFBzUmZBUTJYYmZZMFdTSnhSSWg1WkJHa0VVS0RUU25udUtQcG1iS3hHWmk0SWtpbk9seVdsSzMxYUlFbFpsU0tZNUc0VWpTNmlaT2t6TUMwWGtkV01CWlJQOEkyMjVicU1JME1ybHNPNFJIa2QzYndlT1NRczhWU2FPeUdnb2cwSnlrV1ZFUmREbzlKSkhycEVwVml1NUFsOUVORXRFaE13UVZoQ1N0WVdsWTNhV3IwMHViZ2d2VWVyTmhaRUUzbDdoTllZeFhVRERZZ0pVVHR4R2xDbUVxdDdEVFpRbFpFblgwM3cwc25rdG9tR29Ta2YwamJhWG8wZHlsaE9od1dKRWhLMGtpN3FmeEI1V0lUZ3V0SEZBR0Z6OUxDNXM3bEE5T2RHNHBCSWhpZGljVG1FRUZrMlBha2hqdTJ5U253dEtIeWF2V05GbFhzeXBEVEZCcGhJRW1WcGM4RzhDVW1taHJzZ2RTSmFPbUgrakFHOVlGVmxHRTU2MENxNFE2U1ZXRi81QWJiY3QxMGJkb2JaWWxnaGNDVU1lNkdoQnZrTjZSby9VbE5iN2pLcnJkYTMwdXNpWmRGVmVkWTdJMWJTT1lncmpVb3FtUjJHVUtqN0hnaERYY2NDV2lSRUlzdVRTaldIalFrbzQraTB4UWJJYXhDb0pIR2k1MFRrUHd4b1NQMzBnUnpSTGRxSkNkSGh5bmhGVks3VEJVeUpQd0tRUUJiTkx1VlJVM094MnR6K05jZEY3RFJVc2pWUjFmWlNtaDZkUjFzRS9ZYWJROUxqUXlKemhqRStkeXRqMjAxSDJoVlpocUlhMHFYT2xZSXphSVVaSjJpUWxvMFVrUkxrNm5UVlhHbFNLNDFNdHZvYWtTN0NDRytpU3hVSkZiS3NxRC9BTUc1YytnNnNoREgvQkYrTm5EN2tCQ2JiZUVORWhJM2VSNFR5S0FQZ1UzM0VxR1daVTR0dGdlN0NWRlZpMGxvc0R5N21WTWhGc2R4S2VLakNaT1NNVGFFalVCNWVuVlhHa2xDT0dqNDBmeU1xT25raEczN2o3RHlJTnVTaGlRSngwN2pWQ2FZWTloSTBRcmVVUkQweHA2L001TVpRN1pKRzVjL1E4NkZwM0MxUWIwR2xPaVFoS1drc2pKTGF2eXg4RTBJYndJVjk1RDVZdFNsaHRIVDdTR05MU0s0MHVTN2QyWEd1QW5kVnFjWlloSUlXdzJkekZ3dHlKQ20ycThZR3FqREpaSGRpM2ZnYVdaUXpGZ05MQnFCb201Y1p5VzRuQW4zQzBkUmRycDJJVnozYlhKaGp4UTYzbTM0WkZMeVREMFZIc0ozR3BxTENJSEpFNU1hSlNleWxwTSs3L1MxVEFzdkZSYTJHRFROcDdjY0RRaWNoN21VN1hmYjB0Y0p2MjBZa3R4dVkzVkhOSkxZa3V0a05QaXlYQ3J1R3NnU1N5cHZPd0svQXJTNHFnYWxsblo2S1JjeEpEblNoRUtXbWtzc2ZMeUozSHNMREVOVktCYkJxSEJUUk96STd4SHIyUFI4RWs0ZDEweGszcWpFNlZyZCtKTGlUb2hXZGpJaFVUWnlWMUYyTkRSaDlMVkU1UThNYW4wVkdiUkplaXB1YkZ4cGNzYWZveGQ1eWY0VkZFdGs4OUZJK0VSQ2oxTm5TbEw4ektjRU44c25SOTFOd2htd0dIUElub1pFeVJFYkkyNE5aN2FEVlJvU3FHd0pqdTQ2L2hnZENZSlR1TlFKeFlsb3lsT3hIQzRkdWh2T2JzNDcyR0dVN2hkOUZ4T0dOU3BaMjBTczZKNUxwRWJZcXJOaUJiM2FvbW16OVQwMFNVbDZlbGhNeFZFb0VtM0N1T0ZGaGU0K0I2cFM2Q3VJbTludEVZUG9GMlNCbHNWdDBVd3BHMng2U281Wmk2N3NZMHR5L29yZndsV1NnVjJYRUt6Nm9lS2RoZFExbnNSRDBHbDZJVjVDVFcvTGpnYTBsbEdNYUVxTVZMcmJTY05CU1RHNFBvY2pRMHhzdnZxd3hVVDhkbHV6c2RHSXVqNG5oZzBidSt1MFBTTFRmSWs2bU5SSTBYaytBM0NIcXhxQ1dUeFhzRk1nMFhMcnVXNzBXcjE5UzZyMlA1R0ZjV1Nzdm9hVGFhRU5XbDJMNmQwRW5xYVNpSlFYTWpqS2RGdTBOQ1hNTDU2RWFQTS9uM1lZNmhNeDlGS1ArSG9nVW5MdDJMTHpYVDJJamd5NGVPbUtKdHR4N2tpZFNMcksxVmRLRzVYMGFsYUllaGNoTUxCQWxBNmhVK3REeWl6TmpOeHVXSm9tWFpEYzFaTXVSMUlNTXkya0lJSmY1VUpNanJsaWhRNVZlejBiUW5id2lUbE1EK285VnNJZEJDdnZIUUxiRXRrUWgycXZvNFdkRkZZVVZSTGpaYVdXNDZPNld4RTZLRVdqc3hhRE1qbFJzTlhGTGRDU2xVYnJXWVBER21LMXNZMUlhYXdlN1JVdWN2REV5c0pIVG42ait4S1FmUlovWWZFa01zTlpFNGNpU3BkWXdaTktvdTlGT2JKMFg2TUQwZ2pzQnNvUFFxdURZckliQTZJcjVNU1U5TENLaWZTV0JwWFZZMjI2bHVaL2dUVTdPL1FnUmNJYndKSW14OGxDZmcvSjEwTlphSlZpNHAxUWw2QnRmRlpiSjRkTFltU0MwSW9QekVjUHNPSDJDcTltNURMZWlsTGhYMks1RXorU0ljcXNHbXJsQTJjaWtMMkFTZGt4MFE4eVQzMWtETk1WS0hLRmt5Y0ZkQm9hVkt6OWpMVHV0SEljK3dwTzNJU2x3VE9GWmZwUFF0VXBlNnZwWnkvZ2JoQ1NrdUZwN0wvME1LTkdSbG9YeVd4UXRHTnBKRkF0Yml1L3NNREpZK2xOOEYyaUMzbVFvUnlWREpCdDdzYUliUGdvUjZieGFRcmRmNUd4SWo1dnhyTVdudXRFa083TDVaVU9SY3hzSEtlektxS0dKbGRSREhlSWJTczdwMll3TTcvSjBGWDBTYnVXR1JYanMvaEJXQjJHV1RoOEc0YVRoOEZwTlRMdCttME1WVWRBN2t1L0RrbVcyeVJqMVNtOGtWay9Wa3BXcTl5K2ppbGxkdXlJdVRQMjdDU1dTQitKbnNqeExiKy9SbzVHemdqVmlVc1I3TVkvR1I2c08veG9ray9LNTB6YVgwUVNsSmxDVE5ORXIxWEp0MUR1Y1hVZm53dFY5eEdzck5XZjBTSWpwUzA0MFVweWhicWRWL1lZOTdZV3lGVWVYK3RjMnd5VE5aMDNPeUt0VjFXenYwS0ZHYjI4aS9GUVFRM1JSRU45YmpWYXIySGNXSTBzSjZadUMrajJZeCtNNm9mdWZnZXY0M09sTE0zNFFoMFFuTmlDSktxekk1cHAwbXpHWlhld3pxSng5aUtWemJkL1VvTHFGRm01M2FQQ2o5VlVHa3M1RWR4TGZTaGFuUkFzVCszSTJuMEY5QnZlTzJQYW5samJ1YzYySjJKUkpkcDdESzRjRDBWOEg4ajBSOG40SHIrZHpvNklNdmdTTGg1YUpUNEdRUkZuQkxLSlFuc1pVTE4zcEtaTzRGMGYwSkVJbGl2SFNZVS9ydEFuSTRoVDJNcllodUNxeE9rcFhhL29GdkR2Wk9uTnV5Q0hPMURzalNTUnJKaEl5VmtSS1cwV3B4SlFhTXFhL1hQSHlWcWVxeHV5UFdQQ3JQZFBnWWkxcUVVRFlKK2Jka1N4WXNGQ0JISkJsY0ZlNTZFV011MERUNjI0MEpseVRKR2tFdEV5SnRwVGcva0NIVEx3NEVpRnN2OEE3alcyVzlHNWY3SWs3cDNROU1XTUxrN2pFdGthdG9sc1l4ckkzTFpEZTBITEtnTnQzWjMvQUtHV2VhRlA1NDBtZ3pWOFBrNWtmQWlBcFBZWFo4ejRLdHdpYTNaSU5ld2I4KzRrcU4rSEpZY1RwOGpOS1Zja2xWeVJZWTFhSmtUT2tFRlVTZENrV216TGpiNDF0bzM3UXNIVnJvdnFYeUxWdUNXeG9Va3hTNUhZWit3cGloc2lUaElha2VGL2c2TG1LUTdmQk9Rc0FUaHlNb1YrVUxBOEFlZlI4ajFhVnhCY0psa3VzZkkrQ3JhM3lMMmZZOXFtM1lrSzhOVTBiWGY4bHppaDhyNEZjU2x5MWgxUHkwU0oxa2t2UWVhSUV5SlQrdzY2TUxWZ2xrSjVRbDRGbzMrMkxWcVd1amVQeEpLc3hoaGs3SWhvaGNzZTBzMnlTcEJSRTJ2b21kZkp2cGJTbG5BNlloczNlbWVRMEx4K1JEYWh6b3h0amtkRjdmQXR2bDVqVkNwVUZyWk5BVlc4bDJlN0ZGMTJKVmZ4OEU5V2NqbzZXSVpVa1RLcjFJVHNOQ2JHVHVXZmVTSmJRbGl5MGIvY0RHcGJLSHRySzJNWkwwS2RNTFpGU0NQclQwdXV0SHZUMmkrUjZJeDdmQTlWZ1NRSmh6c1dHQWlSVmVrRk5IQXJvU2xDVlNESDRkU2NVdjRHTi91aHJ5ME0vd0FGc2JSRU1qOUJsMmlMajN4N0ZmSTlFT3o4V0hyK1p5VUtMQkZ3aDZMRldkVlozVXVJVkVud0pvb1o4QTh2bHNza2IvZElUb2xJK3NrTXFYYitnOWNvVHFKNmg3TmZJOUVQOEhBOUVMK0RjdkhxS3d4SHVkK21xb2wwUlAzQTdzUW4zUTg2R3h2OTRtSjZXUzJ4RlhyakdoSUkrbDIxZWoxT1QyYStSNkl3L05oNklxWDQzWThzTzRoM0dCWCtocjRSZTF5c2gyN1hzaXNVL2pSdi9nTFZRaE93dmZJR05DUXlOWHBacXN0ajJhK1I2SXgvTmg2SXV2eFVkOVMwV0ZSUDBNNGZ6d01SS3FQQnJOLzhKTVQxaFFzT1JaYzJaODhJZ2RoM0xOYmlQYXI1SG9qSDgySG9qOFRuVnVtaGlaVG5qQThoc29RTDZMcTMvd0FaQk9kZHBEK1NqSGVxQk90YTRxSkZ5QmpqNFh5UFJHUDVzUFJFNk5oaUxJUnRpSEJ2UVRiZ01vT3hqNnZ3eHEzQTMveVV3bW45RnpFTENQS1BuS1A0S0NlWjg0SlJyNE1mOWFmNHdwcmVnYndTYmtlQ1Q3UW5XOU1YRzdZMmoxOGJ4Nml2azVEVlJid1BrdytpSFkyZi9ObURtUStwSXN5OGlWOTg1cCtSSDVFTnhOOS9WRys3dlAweEZ5ZXhQRkNmK21tM09hSWJNbmNVM1JIUkRJWkRJWkhLS2JDZHhEWTRwRXQvM24vLzJnQU1Bd0VBQWdBREFBQUFFQUFBQUFBQUFBQUFBQUFBQUFBUkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFDdXlOWktNQ0JUZ3lBQUFBQUFBQUFBQUFBQUFBQUFBQUFRMGVKaC83dkNtUFFpdTNqQUFBQUFBQUFBQUFBQUFBQUFDNVN3enMzOWxLOURobG9wN3Y3aUFBQUFBQUFBQUNBQUFEYmEwNnptbXJnanhGRXAxaXFxdXBnaUFBQUFBQUFBQUFBQ1FZdHJybUdwRXB5dnNXVWxuc3Jpc1N6aFFBQUFBQUlBQUZUVW5NNnQwUDRHb0tFOGhNdjlodWc5aWdvZ1FBQUFBQUFCYWV4ZVZkZTNxM1lxWlZEcDFLc3ZkVHFxbnVxaUFBQUFBQkRPbzJlanZvWUJtdzUyNzc2bGliUXlRUlVTajgwZ0FBQUFEdkJtOFFYVUxKRUFMRlF6NkJwZDB3WnpEeitzWmN1UUFBQkZGeTExaGRGVi9ucFVKd2ZvR0s3eTdyeFllaDhZVzZpQUFDbFBvdzRJRmFhY0d1cG9iajhydHZaU1FuU0hnMXQxVWlRQUd5dHdTdHV4d2JIaXU0a3R1ZXJ1dzhwb1FKTnpzcVoxMGdBREdwaU9sdDZ5ZWhyNXBqZmV1aCt2OEE5eUJFY2NZSTZhWm9CRWRzZlBZSVBSay9PT0tjdkptd3RmdnQrYVdZNWtueVJXNEZJNzhwUXkyRDF0ZVJPOXdiY3Q4ZFBlNnE3WW5tMmJxWllZRklyVTJaZW5jRVBKWjZqN2hEZ0F1YUx1Zk1QMXhnN2IwMDRGcG01MjVKb1Q1bG9QWmxxQzAyTlJJN3BlOXUyb0ZKcEtndTNaTURXKzFqaXBxczY1QmN4Tk1pNmdLb01kTUo3bnljYVQ0bTVxR3UrWXRlZHIzckxzVmV2UW41M01wbGphT0ZJN3VjazRsVXQ2cVNqUFZaQnRaMXBNN0tWeUF2S29wSFVJK3ZlMGFjNkVDKzkybnJWNjNHYjBkS05MblNyYmFaWjRYSDM1L1EvVzNhQURzNVA0RlhsZ1BNcU05ckg2MmpiYmFvcUNwWnY0VmErTEtBQ3Y4QStCWmJadzBCeXZ5bnlpVXlBVldXZkJVWGhhUHpLRGRBQVZEL0FLaGdkQW9DeTB2bFNLZjV2RHFibUhpOGlXWmlkdGlBQUVCL2c0ckFjRnJwWW5KMFJQOEE3dWZEa2pZQ0ZPU2RZNlVBQUFBQjlhaGRuS1VBbWJaTi9ubVVYYVZJN3dJN0RXK3FxQUFBQUFDMU50Sy9UNnBkSGFRd3RQak14cnFJSzdOTnFPdmtBQUFBQUJCeWxibXVNVWJiVTY3RjJWN0ljMEZidjdiSjI4QUFBQUFBQUJEd0tFa0VrY3NHck9PTHBjTWRjUnBackg1SUFBQUFBQUFBQUJCQU90VTB1NEtDSjNjNHFXNWErc1dhZGVBQUFBQUFBQUFBQUFBWDI4RWFwblpSeTJlaXRPZVByTWZVQUFBQUFRQUFBZ0FBQUJDRHJNdDlPUG1vRDkxcC9tNHV6Z0FBQUFBQUFBQUFBQUFBQUFCQld6ZThKTHdSdDN2T09BRUFBQUFBQUFBQUFBQUFBQUFBQUFBQkREWDFCZWpzZ1ZtQ0FBQUFBQUFBQUFBRC84UUFJQkVBQXdBREFRQURBUUVCQUFBQUFBQUFBQUVSRUNFeElEQkJVV0ZBY2YvYUFBZ0JBd0VCUHhEL0FBVXFML3Rnb3JJUWhDR3l2L09iZ3h0aUVSckRlTGpSQ1l2K04vZzJ4WVh3eXJndlV3bjg3Y0c2SVdGOExveWw2K0dGbnl0dzJ4S0c4VHdoakVlSUlZdlV3dmliaDFuTUV6VEdtdUYvY2R3OE1lTVhtWXBjcC9BM0RvdFBESVVUSlQrQkllVUhRdjNLV0tYS1owNThEVVQ3SHNUdzNDNFRMZkQ3T2lEOEN4U21rWENHSkRGNllTT3JEUW1YU3BvZmJSTVFvM1dMUFJQWWl0NWd0VVRiNlZDV1lMeTlpMGpqSGx4dyt4NGhCandrVFF2RFFUVWpac3loK1dFR1BhRTZzTVQraFZCV0U2TEZIdGo3aFlXc3REYjZLUDhBQktlbG5vWE1JNHg0UXBvWVNjeFNVU1B2QzZRNWw0Sy9RbVY0WGZGS1FnaDRXaC9aQzhYOVBxK1Z2RDJLRHVZVDArQ0lhS2lsR3lqMkxmbDhIclJSY0xvU0hsaTBVcGZTd1EyVTNqV0VpR2hXS2owUU4zZ3cyR0UvM0N4UllwU3JOS0lXRXpVVWEreElKTWFLYkd2MGJEZjZRNDJ5S09ZbUpyRy9EZy80Ui9aUzR1RU0wY0czZy80UCtEL2t2OEU2K0NVU1M4d2FEdUMyN3VsVEJlbWhCbjh6K0ovRS9pVThHZDJMb3lYSlA0UkVSR2RFTjRuNE5Nb0pLSk5GQ1dabHFqTFRncGlNUWtGMFl2RXdoc28wUXRteDdHa2JHdDRwc1NwQlllaEl5NGpJSjQreERQczJVdmlpSjRnMW9hSUxoUE13bjRwVFo5aUg0bVhqZy95VSs0N2lmQlM0TDluUlB4UEN3eGVHZjNEYjZMdzRVcGNYd3hqYTRMMWZoaS9QU1NRM0dKdHZORzRhS2JJeWhSOEdlSmhzbUowTkdMV3ZTeXgvdnBvaGJlQ2R3eHJvZjRLNk5hMkppb2Fqb25od05KckFxT2kzNFhsby9HYjlqWjhFRm9qZlRtR3RDUTN2QUpzUlg0TmhCY0Z3bzlrYU9zbEt3dnN2aWF4VTBmMFFiL0JQMGhNTVEwRUVFaEtQb1JDRU9wRGZUdzc0SzBvL2k1bDBTSjRaZGpFRjJJZWJtRG9wYWVlL0N4YTE2cFd0bHlVNGhCcjZGYkJ0bzRIK1N5MzVoMFMrSm92MC9Fd2ExMHViTkJyWWxvUVNwTmliT0JzK0VrVHhmbGFMTzR2bHJRK2lIMkliMkxFODlFdm1aSndUOVBvanNRK2k4dGt2ZjhUUnRFZVN3UStpelRvbC9rZzBUOE5sR0tqcENhTlhEYklRbitpRUlRUVFURStiLzhRQUlSRUFBd0FDQXdFQkFRQURBQUFBQUFBQUFBRVJFQ0FoTVVBd1FWRlFZWEgvMmdBSUFRSUJBVDhRL3dBZlM2ek5MNTdpRXkzaTZURjhiZUo4RnRNWHdkaytGTDZ1ZDJNL1JDOGp6Y2RrM1haK2k5VnhOVXVSL0pmSjhpUXhFSHdYRnk4ZnBDY2lGdXRGczlHSnRkblovQk0zQzAvZDBYd05md1Q1M2Z3WW1kaVh4WXNmbWlmNE5jbktGOUc4SmZONVdqUStoTW12NzhHY2k4YlF0TDhaODN2Zmd4bFB3dmdlMTJXV3hzYkV4UGVsS3RMbDZYRUUwVlpwemh0REREeEV4TmIvQVBEa3BjWExLTmlsTGduY0pyTXJYNllvV3pHeUt5c3JLeE5sWERJUWhDSWlKdkJwNE9oQVZKc3lDWWhDWmVzSnBjc2lHTllKSFpCWVluY3dueXU4MWE0SGhiVHlzTFNhZGFPaUhZdkRUc1MxcGZnMGRDZlBoU1dFOUdOOEZDZHd4UFJ2a1E2Rng0R3pzNktMRFkvNE54aWNZbUpqNEZpbloweFlKL1pzU09qc1dHaEliNUlTRlluemhGR2RZaFdpL3BmbXlFSC9BS0VpYUlhNUVFRWh3MmFFL3dBSU1jUHE2eVltbjZmdVN3OW1oVmVTNFIrNGVhUG9hRS9PeHJDRDdFdUJpSU5ER3hMMVBDT3doaTg4Mlk4ZGhEN0Z0UEZNWFI0N0NIM3RQTkRrbzhkaEVMaWV5RUlJVHdmL3hBQXJFQUVBQWdFREF3TUVBZ01CQVFBQUFBQUJBQkVoTVVGUllYR0JrYUd4RU1IUjhPSHhJREJBVUdELzJnQUlBUUVBQVQ4US93RHBLbnR1Q3oybUpmZFJnMms2V3MrWDlSbnRTajdUVkE3bGYrMVhVanVsSHF5cFRPOXZhYXp4cUIrVXJMSGxXRjVvMGF2MmpoZU1FZnM5Q2lMNnpNVFZLUkJvejl3Wlpqa2E1NjZkaWFxenZjSHJOVno5ZHd5Nk1WK2pINjZpdGV1bi9vZ3JRWml3S1grc2F3YU5YUzY5dGZpYWVMbXEvTExXQWROWXJVTHJFcmIxblRNWVlPNStsSVhZOWhpR2pUdW5DeTZ3aTNkNWdmWTdpUTFEaXhOVHpLNkVUdkhyWHJLbHdkQ1pUVWI3bHZTWllWYmRQckxoOGdIcWYrWTdSVmhObHV2SHEvRnlzVXg3WVBYWDRoYUJ3Q3IrN0V1VnNRY3N2N0w0UDlJT3hIcS9zVFRoL1RXYXRJQjQ2UXZWRmJvWmx6Q3VvRVhldEQxcWJxRnRhUjVqQk5ONHNJeU5NcUFOTjJsTnVzWXQwMGVab0hyUVdoZUppRVR0bWFTbnRIdWVrVG1ZdDN1Q2M2dGNNVWRBOFE2VWpVVC9BTWQya1dIZ3Q2STl0M3hEbEliV0R0bzliaU50V28wRnJRYXVrc1JUMnlQWFNXZ2Z6cWwyRjFYS1V5QVJXc2UrcWFScVNqTmIvcmJNQkEvU2FDNkoyL2srMFZscXZCS04yWCsrWU9Eak0rOFpZTkdIRVVVdkhUcHI5bUgxdDQ5Tnhac2tRMHpOT1ZjUy9TN21KcjQ3YWZTMUlQUmxYSFNNa3dwZVpxUmtDSnFQL2hnclJyRk9QV01keCsyc0ZORDJjSHB1N3NRdHE5WXJFZFVxZW1tWjROV0lFemJSNklDWWlXYkNNN0w3VFhLSVBaZThyZFFKVmo2eDNQNElaK2kxMEJwR3JyNlJOQXpBVWRDN25WOTVlbHhpUzdldURzeXNaN0NXdG94bVpXY0N6OTdmRXVpdGZ0TGpTZHpCZHZTRDI2TW8yOHpZWm1YS25ETU92bHBNUDhRU3NhNmsxdzFvTlNXRE9VMVAvQkhxVmFLTHQ2Y3djdjVMSjNiZGoxbGhwWmhRZGlLekV5bFZMOExIOUkzbDVidGVoMk5vOFVXNDJoZmFDQ3dDYVJseks4UGlZYlE0ajVsemNHc0YxVmRQTFg4ZUk1d1FnT2tjMFVMOGZ6VXNab0s3eTZ6U2pkbUFBelhMTnlDbUprMU1KQUhEZ2NRamxFWTVheWRtWDJyZncraVJOb3h5SHBMTVlZczFabUd2eEIrRjVtSmNGWFRabG8wNXRtWUZuWjJmKzdFS1BBTzUrMnNCMlVVdlYyNEo3L0VUYkI3Mm5kMm14M280OEVxZ1ZqdE9mUWdlQWRJUnRWY3dCblhxelIrWit0cGZZb2pVdlgzZ1hDelB1N2Z2U1ZpMkRQZEtvNnhnQ3RDSHVoRHNhKzlTak92eElIT0gwcGl3TVhyMFlWTFpjdGtNWnhaZ3NlNkVtYlQ0L2JsNU0yeDFpQVRES2lNZlNWK2tRL3hMVGF1U1dkWXZKTmNSOEhTSG85T0pwT2dnODlrdlJmczI3LzhBV2dBcTZFWXBkVXJYOXQvUzVwVlVHaCtYckFKNVNOUk5HZ2RIWTRJcTV5c2N1OWNUT2loOTRCZ0FiY3pCeGZyTU9rcEVxTmJGOXBTNWNRcnVLWFMrZjkrWnFxdTJYOFdHc1dYM2xXT2hMdnErOHdyVEQ4eXp4QUVGczF1eWRVdS9EL055aE92eGh3WUwxbE5TckhsZmFVaDFNTVZrNGRPalBYNk1yc25mMUpYOXhCMTlaL1pDU1dDM0VCQVIzK2x3UXJWYU1BbkpuZU8wUkZ4WC9RQkczNGdRRUxUZnJ3T204dTVYUS9IU2FyTHBmcDVoRU4yQVgvSjFaWUJzaXN4cUVielprOE1jcGMyTmYzTVZtKzhERjZITXFuQktEVnFaWDNLalc3ZlFNRWIybzh3b1p1RVpHQzArMFVzNnJzUDUrbWdVeTlJS1RZWDhmelV5Tm9NRzVXV2ZXRy8zYU1YbVFxTHdhOWY1bHdtaVppTGFpcUNsVzBVQVhtbWUrOFJKeEF6Nm1HWTIrdHhJNHl6RHBFNlNyZFVjdWtjeGw0TUVESWVGd1FXTmtQVWlPQ0JYdDlrY3Npa2RUL21FSGErMEV1bVJlb2M4RVRkaXJuTzhvTUM2UFUvaWFqSmwrT2hIb0pEaWRhQU5ueExmL2VIcHQ0bE1WdUduNUkrdFBKV2VrcDYzblZLS3g2TUhtQlVEbzRqd3ZFUWE0bDlQWE1GNWRXSUU2NU8yMzVsWE4raEVDazVaU3EyNWwvQVVuWXkrOWVrd1J6VTlqTEhlSmRaK3FZSzc3TEt6azlwcHJvdUFHd2E5WmlDL3Fud2o3eWxZUUhNV09zcmNabmNxWGNOSW1HOGgybXlDc0doRHdaWnBnODVZdFkrWFdJclZXSTlKV21BYklSWWl4TnBwb3ZZUDc2UnNDcVIxSC9rTkhsbHdSbEo2blhnMmpsZXE4emdPaHIzdlhwREF5WXFyZWp2S3RrNkpDNFBKQmxQVGZ1WXkydTA2U3FoYnFvbUdnclRmU08wdDY2RHVTMlJQRGgvRXI2RzhNQXBwNC9LSmFUcU14V0hZR2FKd2J2QnZFMGxxaDdCOUZWaXd6RHBXT3hMdlUxYzcrN0tKZUFIZmVaSm42RGlDdTgra2QxTDhQODNNaHU3SXVzRkY1SnhDT2UyOFROYmZTdlE3cDFib0UwUTdzRTJ6a3dta1Y4dUQ4ekduc2hNTU5Pa1c0dlFRQnpFUSt3QWIyZzh3UzJHclZEMmhIcnVRYTVGaWFrWURsUm9IOS9hak5TS1IxUDhBaU1tcWFBaGxDWlE5M3B4enJGWjFIT2RZYkFROUhQZmljbDVhbnpBYURiOWVqdktjVTRkb3kzNnhwOVlUVUltbzZ3YkRiV1dKMmVETGVlRHMrWUFLaWJNSks3dkxqMVM5UXZmSm1Vdmh5SDNtZHQ1WkV2M3BwNk0wN3JoNE5aWU4wZWJhS1lrMzBnTkY2OXdmcEttaXN1c2V5Y2x2bUNIOS9FUHJJWWJuNmgyOTRib21IREVVV28xRFplR0VvdWNuMjlvRGJqV1VZRGJMTkRWN2o2NkViZ0J6cStzR3JidjM3d0tsbzRNUzRMUkNNdVdhRVBVQU5VMEhtR2xPc2xEeHY1aU42V213UnpHV0dhOW9Zc3c3a1lraXhJMklQQnQ1UDNwS3IvZzNnbVVOQmJ2SDU5SlkyNWZtT0F0ME9hNi9pSjc4WGNXWExUSktSQVBEMmRvUUJkMzY5SGVZUUdOT2tVQzE5SFVpTTVEd2tkQVRaemNRWDgyTldGd2txb0VMeUgzbGFkQjBlR0FpVUd3WWxxcWg2QitzVnptT2h0OUZlWmV4bXBqWXkrOWVrcmpXcndaWVMwQzZPbEQ4L1IrbjBZUFdUSnFVcUJoUnNtSTFIUnpBcFE1T1VXSlVsb2E4dzcwQnd6UmR1REJBRU45ZHB3NXhGZ0xwTjZBeGlFcUtHclVQTU5qMXNCNDNqTjZXbkI0aGxadmFPNWZFYzZ5b2RaZ3VnYXdManpIRHJZNU9HZEdJdlcvNEVQZVZwb2MvdThLQTZOQndUTUF1T2R4RGZkd2Nla2M0WUp6ekF6RDZCWjBnNHFXN3AyWWozSi9EQUNnTXRMMmU4QXVpUFdLQVg1ang2d0RKSERUaDYvU21HZTZKbThiSWJLM2k0blV4bTJoa2JRZStyN3pDOUJUdnZMS0xwbmd2N1RWQnRJRzk4eCtyK1pabVFYdkFWNlQxWXJaeXM3TXlIZDlHS05OWlFpYW1TQmt6YnJ0RTdaaXpWeEZjc0RRUUJBRHFsRHpOaTZvbytOWHpHaHVEd0IwTnB5ajRpZHI0bFNwbFlGWlllN3dlN0RMS2V0VXR3YmZlK0lnazMxSUlsOHgyNzJka0JuVXBaeHgvdUtCUzgxOFFnQ3pVYzhkaVZCUlo0ajVXSEhFL01JRTM0b29xOVVJNERWYTVQOEFMMEVPOGVwUnNrQkZVMzlPek1BdGJ0ZWp2QVZURURjY0xBVkgzK21nc1Y2Zys4SlVkSmE3Q015WGIyalA0bGc3QzB4RVhLVjh6Skg5cG15WFdJdlQxY2ZlTnFSU3dVM2Y1cGZjMUgxWmFoZGJpd1JOc3hMbHFxWWNPVWFObHk0blpBMGF3cHBEVnFIbWJOMXhSN0dyNWk0MlZwc0hiaUhobDEybXRzY0VxWUdBQU5tZ05ZaDRQVTd1WDRqTlNtMVhMQVFGVXhqYU94cTlvNlFpeDNlWTZmUUZSZk0xeHJJVHAvUDhBc1lBVldnSVR5V1crWDdIbU9kSW12dk05RHNSeUhsaU02WlM4ZGU4V3BXZnJnWHJjZFhTQnNPRWg5QmcyMW9QMDd3RmJRQk85L2lPR3NVRHFqcDJZMkpkcjlsZ3RWaWJ0dXpDeUFPWUpxZlpqbGVibUxpVmRadUJ2c2djN0dYN1RFTldIamVXVUlyUFNvdmNTRmxRVy93QkVQeXpONEZ4ODZMUGIrcG1FczFaZm1MVU5FdVZPd2U4UGdqMGhOQkROUzJGSUFkV29lWm9RRHVLUGpWOHhDN3Rob0hZMmhzWlB0SEpEVVl2QkdGSTZFZTdGUm1LTFE2Zm42UnpCUHRhbDllTHV0L0o5cW5DUnI5Q1dFbUEzSmtSRkVic2hVaFRTZXQrOWY5bXA1dmNHNzl2TXNxZ0FBT0RZbVdmYmVXTVdHcEdXaks1UmhvYXh4Wk10bXppWTdid25EeEUrNmFCdjFOeUFVV296OWp3OUdOWXdzTklJOVlYZ0NIR2FUd3FLUnNZV3d6RlAyZUdVSS9wTllNQXY1Z09SdzZ3dExuZTVuYjA4b0xCazJKVkxpZTdyN3N4QnhWNWYwbDNCcFdpZWVoNzFOdzk1WlJYeU9VcnlyNWl0TDNhOVphMGRScGdwVEZiOHk0NFo4TXNLMVVHU25lYmptRnFRZFdvZVpzZFc0UStOWHpNcFlHaG9kZ2FRcmRIY3ZvSHRBTXBGVzQwUHV4OXBUU3NyR0RsWmRDWUtxL0IwZXMybnpBdFl3T2Q3MStMNW5kTm9OM2VWRXhtT3NGQzJGZ1ltbzl3S2FoenROSzQvMWFwQ3dBbEFMME5qNytZejFIYndONVlKb1BFRGdnejRHSEd6OXBXVTMxYnN6RUNEZ29UcHlmcCsvRTBDZlpCV1hvbW9PRTBUdk1IajE5SjNlM2FLQUxOSnFjbkpIcG1JY3FkbW41UGVaZm8wUnMrZ2tWUGN1dk13aDFacjVnRkI5WlFVck9KWlIyWjRNeXRVNVQzaVA2c3BvTzBvR2wxMmFTM1ozK0VIOHl1RHI3Z3pyUnA5eUNtR2plTGZ4Q0lORGZuZUhHWTlNRis1S3dMMWZ2ZVZ1TFVvOVlJOHpJanJpajQxZk1kTEd3cWpzTkNZNVc2VERMUnhMbHdPWmJ0RldQS0g5ZUl5cGVwZG5nNWVrZUJ1Mmw1NWpkNDRpUzNFM1h1RXBYYnVZN0JhdXRnMkRwVXkydzRKVURFREdhUjBqUk94c2ZmMGxHRmpDcHFGanZ6K3VZaWtTazFIYi9TYjJBdnh4NWZ2RlZ1OHJyTFZacDJkaUY2ek1aUlE4T3N2R3l3OG16RGQ5bnMyWWNjY3pEaUpoNGRtS2NPQ25WSmhQRm5xUkpCUVBSZTdWZG9LMWpMcGZ3Nm5wQXBHQ3ZrUG1vNWgxTmY4QWFPMHFieWt0WCtoRGF1L1ZQM2doUWNKVDJsd1hrOUc4VzJKYUtTbkFaZlpodUtFQngrNGx3NGcrSDNsYzNaYUhnWjIwczhQOHhwTm4yeWhyYnIyblEvdlI5akVLYzRtQTVaZ0JjMG90MElJMDlqU081VU9EU1h2OUQ2R1paRnBRMURWaTRQekZoQUNzQUQ5M2QxamxndGRBN3JpQ3NmRDI4ckhwY3NLSnhUNW1uaW9ZWlFXWHpONzFwNjh4dzNIV0NvRVd6V0d4WXU1MDh4dzZqYkM2UlFzWkdySGZwQnowR3R0eC9vUTNkcUVZcG9ENDlENW1FQnl6TGNsdlRwS2RXUmlhdGp5Y201TW9RM2ZLbVY1V1RrNGlXWTlzWHBkZnRRRmYwbjRtZkVPanQwWlp1b3gwNlJSQVJwTWliUzk2RkE5ajVhd3ZVakZXYzA4UFNKWkF0S3pyY0hrZVlxY0dvNmtjc2pGTlVUWGNkelVsUGFNYVNtNkRpMGhCbzh3aTZEV3ZqZjd4T0ZFZkVZaVVnbDhsdnUrMHpYdjhNNG1hUG5FU3VLdE85aFZTeE95QVIyRFIwemYzZ3d3RXRja1h6UTRKZjB0bUd3UXloZThydTZTcmwwakdwYUVDTFZkVnY0aFJMWllZZXQ0K1h2SDdxK3lRS1Z3OUNLMXRlczc3RHpjYk1Yb0hCNDBQRVZ3WU9DWldWZjBPZkRRNndibmlaUmFzQ0xTNW5IMWxGcC9nRHg4ckVyMW1SVW9zbDVoTStPeDVOVDk1aUlvbEp0L21GWGV0MlAwSWl0NVZtdlYvRGpBU25SaldWc0tNSG1XeXQwRHVvd0pubnNsODJmSDZhU3E1am5DRmIzTDFaYlRzOGZ2U0FnYTZQREF1Q3FhZThJcVI0bDVJYVN4Nm04RnptdFcwN3RuVFh2TmRFOWVrSERJc3ZTUytEcHRUdVJBR0RvbVl0MjUwK1RlSmxWdVJ1bUlrMEpydjFUUWhRSHdTczlweGhCNWNwODM0WTJKT1krY1UrcCtadzRNclNhYWtHWEljSDBacDA1MmpuT1g2WEZKdlZlN3ZBUUt1Z0dXRStBdUR1L1lpVU5GWUFLcnNTckhtVTJkZjQrdkVFclRhNWZweTY2Y1RLbWNXdVg1aWtxOGNmUUxhaDBRYXNacTBZNGpRbUVRQ2FRdXZZakNwMnVkbjU4UjZiYlZ5c045c3JTSlFITUdnazVWeDZtNUNTeDNuWFgzK2Y4QUlLQUxXYVV6OW44MzZSUU9BTHRqSzhnY0cweDN6RGdPWmllMlh6SHYrSFpNSjNqUE1GVFZCemJtekZSWE1CRGpNK0diSVlIZnZBVk5OS0h2TEFVeHp0REptSlhwZFgwSDdzTEFqU04zQjdSd3BOZTNmdnIzZ085TjUyUFozR1g3Wnh2Y2hpK0RlZjNQeEZEZUR6MlpkSmJYaDdrSG9KczEvaUFLRkRwa0ptaFRraWxRSHE3c3R0WTlBWUppL1RIdHZLVzZvNzZRL3U1UVpkNTFiWSs1TlpIMHdxRjNCb1FoWURneWxPMVZzdHY4UWRORXFyV0NMQm9wbnNOL2lHZHRDaHZ1UDJKU0VOSExnZHBhL2ZCdm9ic00wZHFqZjZHaGlKd3VGWVBqd0Q4L1JSMW1iRXNFNjdlR3IxN1RFb0NLaTJhc2RRQzEwNndLWkxSZWR6OXZFVnF3NHZuNlZZa1c2SjBsMXZZTy93RGZiL0p5bW56R2dOTUE3R2t0a3BhZHQ1UTk1VUVITjhTaXBvdndsS3VaTXZJdmMybHVPOEJ0eVRYclhyMGhmSWFCNWkxNWxRTWFFM09ZSmlnZXBNS0kvdW01TWxSN3VQSnI1UXM2dFNMM1ZaclRkWTRJQUlIV1Zyc3h5azF6cm5kNmZtRE55Mjdlb2NSaFEwUWU1OTVsR0RrR0xtbXI4Zm4rSlNpMmM4bmFJS1VnNVVvSEk1aUhVK3AwZTBIbXJ6Mzd6SE5NWGlPMUxGZkxnK1dXNjdGVHhENmZ5VFY3c3VSb2crbjl6ckFpdExiTXFBV3daVUpiR0hxejVmeEg3VjlPSTJtQTFHanVZR3NyaU1PeHYzZlNEVEZXcWhMTzZlN3dkSXdOaFFtL1BsS2k1VndSUlJtQUxWdkRMSStpSG9mQm50SFJhRkFvRGdJSXd1V0l2c2ZsVXN1MEN4cjI3WXcra2UwRmJWZDJXdHZRaXBiTW8zanYzL1VyTDRQZEpRVnUvUUtBWlZNM2hBNnd4cTQzVE9rMTBYL3hVOGdXZDlEN3l6RlN4VEE5Vzh2c3cxMVFncUJlY3k3emZUV2VONG1pckNtWVZCamxjTU5LVWxSYnZMNk1NdHNCZ3ZBa1ZySzFYSkNXdEdrdWlzMFNvcDRTdzkvd3FJZ1lOUENINWltRFVxYlBjSFU3UHJCc0ZDM2tZUW5BZSswNERsWER1UUs2VTk0ellHNDZQY2dCc1EvbDltQXRPbGFkemFCNmpraEpZZWk2bm5lTlRJcmJDNUZoNkQ4c1ZSYXJjL2E2cHFkMlh6WmJlWmxPQXdPSWF4TlBBUUtBVldnRFdiR0c1azd1M2JXWUFEUUJROFFMYWMzN1JkUUpnZmlCZ0FwMDduN2Vzc3RCdEwzQ241SHhMa0pxUzlmN0NpVXdsMFJaZFB5cUF0dHBybm5UdzlZY0Z1MjBlVlhnMWc0RU9wMVRsNnJtVmgwMVFZZ2FUSlZwRUFETHBEejhQaDU4dVk5R0ZncGlGUk13aVdReTNoaUpVbG5lR2hqcjBHdjcwL3dCV2lVQU1xL0JnKzhTcG96R2F1VmJDQW96bVhwVHJIZDBNb0MzaXBXSHZtcFJtcm9LaUtPU0FvWFdwZEJ5ZEdEbVp5K3k1bGJ4VGFudEh4QlBid09zd0lhVHF6ckZsT3Y1aURFK2gydSt6eDZUS1dVeXpjQjk1cVV4alBnZmhnb0t0VTlJNnZEdVEyM1ZFS2s5ekoyWWdMVmRIeWZjbC9QRGg3TVhPWnhnUTkzTExIcFpMb0FYQitqbERkWWdMaVZaaEl3elMvbVVIVXdBb25tN0c4b1VtaGJuNTJPaEVFTE9nVFI3aER0dzBlMkVwVzBaNEExaHFEUlhnMkp2c2F2QktLa0N3dFRvYnNyK3JsN2JlR2VzWktUS3JheTdhM1pwbkY3bHRuZDE3VnpNK2F0SU9kWUdKdE41YWpVVlJvcU9tNTg2ZXNCZUttNE5TdFI1Qy9lSjdaMk15YVJSbWo5Qnd3NlF5T1I5eHI5LzhLanczQW9kaCt2TXFRNVI0Yi9FcFRXc0dGbHU2K1lNYXhzYjkyb0hTdXJ2NHFPQ0dOMFBoRW14NktMZnpKb1krbjVSSEJjTGlkcUl4a2ZYcEhSd21uRTc2RWJubEtQRHpMSFJFeEZZT2hDS01VSTdTMHVGby9FUFlIdzhSODZEQTVONE9Ta0NQWmdvMnFTSHhiaWJURXhnYUl5NHNjY2VUN3l1dDJjNURvN3pPUlFEVDJKa2U0RjkzNEpjWFg0TW9nYy9CbFgyV3p6Rm8xVEJjODREcDhmMGlxejM2ZmFVSnFkV1dJSEt5bGttQTloMW04QlRzLzFQTC9FVTYxV0E0ejZRaTZ3ZnBzZGJiYy9zZWd4OUt4RzdFc2VJSTBRaHRBWlRvTC9URXNDUFZnZXRNcTZqNGhmaFJndHc2NWhmUWVxaTZWbkNSWmtiT2tLRlpnaUhyMk44MWo3eDlSQ3ZIMUZ5V0NYOC9hSmRYTUMrNE12R1grSU5RNWFuckhXMlhselFUMkU5M2FHcGYxTlNYWWhvSmJBTzdBd0N0alpsNDk0VndUVkJGOFBhQWdGT3AwWlpPQkdERlA0SjNpVlRWVk5JNDlHNTk1clh2cjFncUVhU0diMFRVaHBwTjhJckRDOWd1aDdzTTQzUWZFSldVdnFzSHhEa1FYYm9NVEdnbFhQTTY1d2dYb254TEdxRklnQlVDYUZRYjhDSDZ6SE9yQ1lMcFVkMngrN0RHVWJadGVXYlpaVTdTMUdCZ2NHeDlibFRBUWdCd1UwWCtnNkV2cnVNQVFqYUhFYk9ZbnFNcE5SL3hDMFdHOW1VN0k5Sm95MzBZcUJ1UkFXcXI3YVFSQ3FIem42K0hYdlIrWXQwbmE3WG9RdG9MTkE5Q2JBTzdGNkwzbG9zZWFJQU5WZVdHTVhUU0I0bHJRSmVwbjBYQUxSOHNQdlV4K0xFL1lud0JmbmNOQnJsUFlVUWFsRWJLajMxaXJLcnZNaHJZTUdYRzJBYzlvQlZhd25NY21rc1liR0dpY2JuaUt5NEtyR29mVzNJTElhR2doNEZ2ek54S2ZLeGxEZjJQNmd6cHppdTBVd29iWHJLczRQeW11Y1llc3dBSWJoQUFtUVRpZnZNVlZWdFlFQXROQnpDRExyVHl2alR4QkdveDZFWFpOanpHcm5XSDBRODZKdlRsN3VoNWlaNlRSWUhVTVUxSjNKRmRPNUJsM1hkMnZtWmF3NXlJbE5JanduMFJ1RVUyajFwM3hmSk9oSGdaVEZZNnFsNHhNeGJBOXorL3JtK2FQYS92TWhpdjNLc3dzRXdtTjVXOFFyZERHOFdlR0ZXQlUwaC9qTlpZek9UM2hvaHYvMFI3SDNnL1Q5MjMzTThVekI2RUJrenFvNXBleFlESHBSUG5sbVhwWU9oVVo5Y2JneDFaUzZrQ0ZKb0JiTFJMcEZObVJQNk43eEZFcEdrZ3F1em5aajB1NTI4UWdsWnJERnVPWTd0dmVLL2lBVkxTL1lMajlRTGVZblVGOWVrYXBiNzhvTW5hNHNidXZpQWFKajRZQ3ZhS0Q5NWlsYTJ1N0tseGdjOXpmdytlMHpob1lJQ0dDL0hFV1dMV3UzYU5XaTlvSzlJRWxySlpadEZMYXF1c05FWG1CY3U1QnVvOFlpdFJQZUs0UFZCM1hwS2NXVGhMaStzZVF0N1N6NEtNVjBmQkk4RHRHSStzRmZRSlVBd2VGY3VhWXo0VFA4QUgwQzJEdUZmdDlwMDZVWGRsSjZuRVAyblRMNkJobk1jRDdsOW9hOHJ1ejdVaDdjMGZWdGdHSDRYWHBINWRRZW5ZSDVnZm5ZdWZTUWo4TkF2bVBYR0Z1VktaZEVjQmJLNGdVWVFjTjRpVVBOVzMxZ3llNXZ4RlJGYk5CNlIySGJyb2czK3hGREgrYitZbmJ6RFNyMW1WSjZ0dlFpZTFON0ErN0ExWERzTVVFdGNhQTkzUHdUQWRGVHhHTGc3bytVSWczQWFSWXV4VnlvYlhmckdtTERXdE5NeTZXZVNHTSttTlB2RHpYTkdCdXdSREJSd1B6R0JhaHRNN2F1alY3ekUybmFBWUM5TU1VTnhHd0g3YzNsbVdJaktnUUtoY1hlQzZsUW90SHBjcjFUeVZEbDZHZDQ3a3UzQ1RRaW1mdk5QaVdqUFVmbGx2NkgxSmF2UTZ2dkdGWUVHc2ZRODhSN2ZUSU9zeER1OTFsRkcrUGVJRVZWdXh4VSs3NGdmd1VYb082czRnNkFUWFo3dHlodE11YWhHVnVYb2RRZnN5dm01WHU4SnM5SUhpVytpc3hVdE5hME83dE14V2J0dnJERUhxSnJORDFpZnFETG1WSjVNUFdhSkx6WjdRRUpKdFlmdXd0Rnp2WStTeDVUR3luc2d0S1cyRDJuS3Z5eWpicHVoOTh6UEFDNk9oN2U4cFl5cmJFYUp0UjBoaWxzc1daZ1M0Y2VzdmNnVWp2TGRXbk9VcFdMSDBoajVubERTOUpqbzRlcFUxcUhhb0crNFUrODAwZU1TNEJvcEE0Y2swa25JQjZNUlZJa0VhbHdIRXMzSURSVW8raDE5NGIrTGpkMTdWRHNhdm4wbEJsakVEdVFHNnZNTmhIdVRvUFdkWWtzWFVqU2h3dWtGRjFTRENYb3UxL1RPR0o4RDRsRkRkSUs4NWgzUzNFekxPcktGc0UwUm1Md1JGMGx1WXEwWkkxVDdKc3pXSmRESzRObjUyZ21pZUdQOHVpNjdHMWxIaVk2M1E0SGd4T2tHdWp5bEhxeEw0a3RlMEN0Ym9IME0rODV2TjczMVlvUUhWcjdURkNPTUh0RG52akxDQnBPN1BsbUFGaDFML2RxWlVIcjlvcUM2UFFSNnh6ekR0Z3RNcllVTXQyamlDV3cyYXhya0s4cHZBdXlKNjNzdVlPQjdvTFJ2cExJQ1dScTdDcHIxemt6S1J4aUhLOTh3emtyc3o3akZlOFEybnNianZEMm1wTHZMaFZTNDRnSUNub2h3UFQrWTVubXlFOWd6RERxdGdmVFFlYm5EOExYWDRsK0pacVNsdkVNVnRIa1FDSFRGREpOaTR1ZTRuYWtqTkhzelk4VEl1djJZNVJPSmRpdDZOSmwzL1N2UjZYUEdhRk82NWlybCtoUDZvZ01UNmZTLzVKZUxiWE9zdXkrb253elZvY2xIcmNiQUt5WGZRWmhxeHNnUFRMSFVma0ErdXNWdGI1U3N3ZExneEVXekJPNzBuV2Vrdnk5SmllVldjVE1GdThrMEExb3dpT2dydWJkNHJvNkRtT3FtQ3JiaUlLYjFxRll3cmd0dUlpdFN0dUpvamZUck1TN0dyR01EZFhVQ0ZORjFpQjFYazdWQUNoUHZGdFY5STJyYlY2UzNFdHhMY1BwTFh2NlEwaXpjTHhObkh1UzdjUFJnOWtaUnQ3UlFNNlU2VTZIMEZjVGdnTTVZVTNET2tacHBJeTRhTU5QeEhpNEh0RFQ0WDVud011SVNTd3Y0bVgvYld6RUxNNy94REZWTmdlbFJXOTJYNGgvTXZ4UDc5K0ovZnZ4UDdIK0ovYnZ4UDdKK0ovZGZ4UDNyN1NrS05rbmhKb2hUcXpsQ0I3b2ZhTHNIcFpmaVpSUTV3ZTBiZm9HVFFpQkFxM2VrNnoyanlaZExSQlVhOUE1dUNBM0dzR2MzbUJWeUlkQ0JObDFXaHhVdWkxR2RDVk9pWGdRMDBYblpCaE9KS3d0UzI2UkIxQUZlSlFYVWJNR3VrYUYwMHdIb2hPdStxWXA5TGxOOEZhRWVDV2xxTHUvdWw3cDZIN3MzeWE1YmlOazk0VzJJUi9yUlJYbFlSNWx6OURvdWwvaHRFQVAyajdSVFZmMjRtRC9iOUpYWVdwajFKcVZ3Ui9xYlQzejVud1FjUml4cVcrMFFLL3BmSlRLR1I1czl2eW1XU2RueDVMajhLTittcys0eEVkUTdzNnoxblhlczZqMW45eFA3aVA4QU1SWEsrWUw2eWpOTTBtcXA1ajF0UGJFS0lmWVB2ckRudjZZWnlUb2JmaURXVGxnOXBXc3JtTFZaTG1iUzZnVFFwZTArcEVsdXprRDN6QnZHdVh2TWdNNXF6MW5VbGFTbHFPSzVscHNwMStsazF2eEFhTWRGN3loa2ZRSzljRVMycndmb1ZCMEJPRCtaY1VlWXFpNnVkSUMwRmVETTFWWjNSOG9DdTduTjdzZGdybTcySTFWZzRGSW5wMW1xSitnSTVQREZaQlBXTTJKNGZpSDZCOFJ6N05TcjdpR0dFdE83ajBYMzBqaCtwYnROY25pRmRrZFUzcjI3ajZ6Rlh4TVF6dTM1VFVPQW42VGllNmZNVkRzeFdPMzJoWDEvRVcxQWRKVHErR0ZhdTRtZ3BOQUxqUjZNYVBVN3ZVcUludXR0ZXN5Z25SL2ROVHpRNFJwYnFWL2d5M2JMcEt1T3FCYjFJUHlmR1o2eXBmSFU1OUlwUk81RUdveldrNlhITGFYa3d3d3c3RDNheDFzbjlLZnpGWjZEay9IdkFMNnNGbnFSZk1IRFV3S080bEhrVndhUkRTbEl6Q2JSUit3bGhZZWRIdEFmWkVhdnREcXZ0Q3RydnI3eG1WVjNiWlpIcFlpVXMrb3dxMUhsL2RNMGZhNzNaZVNqL1pSaUdLcU9BRDJqelZGN2htYW9QZGdMb0wyaW51SSsyWmxqdEM5V2tYV0c2UHZyTXVWV0Z3VGc3cERaWDJNcnpSMUJaNmtyRU9nMjQ2a0lYcHBmY08zYWZHOERSTTZ0RXhWNHUvbUUwMGNEWHhIcStZanJhSTJGZ0RRV0pvKzBPTHdudEZhY3JOS1hKMEptSGVHcWNTNHpFTGhFN2todi9hR2pCMmdkR096T005NGpJUFpnNENuR0QzajZ5UXQ3UlhVZEVFZFFHeGRlOHZBRG92YUNta3BpWEdFTFNTM0RnYy9NeGdIbzE3YVJQanhxOTQ2VzdPU0FGeFJyY3NDeHJpWFc3UmFVMzhzdDFFdlpwSWlBRjZUNzZ3eVhmZDluOHpHbHRHcTlwNkxFWERYWjVoSUt5MHVIZW5uVm0wZ3p3VWQzK0JpY2FnaXdDTEw5T2JjRXJWSWIvQ01UR200QWZhREd3Y2ZtRW9wU2syR1dKTDRXcmllY1FGWURxMU5EK0g3c0RBam1yWUJUSnhGWDZpdUZ2UWhGM1c2VVFPZlF4dDdRMWgrMUlBUUhxbUFWcmJDb3FyU3ZLeDFBajFtS2FCM2l2RHRNdFZnS1BvNnpKOHgrcE81cEhXT2k5WXZpam9kRWhyVmRMNWdjQWU4RjJuZUZocEh0S2psT01SRFJ3UE0zTU9zMGI3SUpvZ05RZk9JMVZWeXFsaFRMZ2Y1UXR6M2R6MmJoMTlNSHlRQ3c2QmF4RGJKL1pEM2o0YzR2YXpNc2hMeGNzQ05MRjZaR2h0SzFZSmI0UDNFMm9EVTJPRHhHQlRFQjIxQnJxYlBjeTdtMEQ5bWQ0WWdyWUNvam1XR3JOSW00SVhoU2xsWTk3d01IM2lXVFB5b3hqVk9qZ0tsU3lOTm9sUTNPYS9XS3daSE14QWhvWEdMWFk3N3kxMVZnWVIyQlR1TTFaZWY4RDNqNUpacDRuYUxIOHNPZWMyK3hLRmRnWkxuenhacUFpWldzVXd1M3FLYWtyM2hocEFoQmttQVpKc0wwaEJtMzRsZzVVZlRhZXQvVlhoek5SaEVtYVJDekpLbmdMcDlHcHJBZFdMc1hPRlNyV254QTd2aGcyNmR5QzZGOHlwVmtCMUJseHBYYWJqSXh2czBmYzlpR3pjR25XS3lzckVOR1dqTE5Td2dCWjBQdkZsS0UrWTJQSDNuTVZiaEFyTVBHTE1IeVk2VXB0VjFsZ3U3N2tRSGNaUWh1R2Q0MTRZeHRjYm15dk9GZUtqMVdmTzcvQUN5dzdLL2pNbzAzcWQ0aXMyZzRHdThxWWdEYmJtRVdXalBibU9rbXVRd0dYNWltS0Q0aTNtRURjT3pGZVZNTVowWUVDNDBhb2VZanZLVlFNNENXdDJDNmpOOFNwOXdoVzF2YlNvdDU1aXRkVGZiNjZEcGNOTzhzSFV1bU9qQUJvZFo2S3c0aWVwcXA5cDhBS0gybW42RmRQb3pXUWRTSWFTM3BOUUtlWTZ4OVlRUTd3Sm0xTjBTQ2pBcURZbHZHalQ4eGhENkN6UXN6RzIwSmozcWQzWWpWRGRQcXlxRGxsaGhSZytUSENLcmF1LzBaU25DR3Z5M0xucUVaaExuRlBTQWFSRERuRzhyamt3S3VOZytjdnhFU3ZMTkVSV2F5enJSS1lRMnlPaDlwY2JOUjZUSlVMQWdmU29ZWmdMaUJRM2lIU0xmeU9WdzVsWUk3d2VaWi9FdjFYNkl2YU8xajdNWG1Pb1Rsd1JBOXF1ZWdKY1c2WWwwOVVEKytZNlJiZXV2SDExRFRKQnhPMEQ2bjhTdjVZek9TWlpFNnpYMis4UmhqM2lqa09nMTdRVDNXajZrVUp0Z1JHT1VCOVdKV1ZWNW1RM1pTMEFyZEFid2hvTGR2bmgyUG1MVzQ1ZTB6WWxRSUtOcXI4blhpM2xhRGFCTElyUVJXTW01dTdzWVVZSmhvc3dmSmp0eW0xZDV2RkE1c24yRzNkbGNtOFpMM2Q1VUhjcVhDZDVpUFg0alVieTVQY1lpallWTGhyZDE5ajRtbmE0dGY1aGRFL2N2aURCUnNsaDY4VEk0aEtSZ1grU1VNTk9GcUQxK00xSXNpU3BVMDZNenBIeUY5eDVtWUlkUnJ0QndsRWlyQTg2TW9DcFhBcUowQjBKcWkrWWswWEZPa3l5M1dJUmliVXQ0RTNJcTlSZTcvQUY5YUNEaVYzcmtlTXpqQ0lPMFpxdEVjbmtoWU1ReExZWXQzbUZOR0Q2V3R0SUZTaFZhSmRqZjdDRHpOamxqcks1YXdNd2hRZDBmcXVlaG1POFJOYzkzejZUQk16SmtYRHgyaXRYZVhPOVowY3NGS212dERnQ2pBN2RXTVhWTnE3eTJvQnppSDVlaE1GOWc1OE51K3NkZGgxemxsSTV4T2FPcWFRWGlIVDYvRXAyWFM0bG5kMWlJTWRLUEJBZFRhWmtlNUJybGI3dnhLZzAvTUYxTVN3V2F6eTB4TXIySGlWSkVrelZ2a09wdVFMUU4rcWE3bnBEU0VPVmI1MmVqRWhpTEdhSjFOU0NnTlZvY1BQbjVpdlBFeEpTdCtzR0xNc1EwT3NacXljeXJabnpBQnhwQWx4UnUxRGN0b2U3S04zRncyRFlxZVBxNk1xZVVZQzlMekZYM1ZENlZpV3dtU05XQ1lacjhQcGh0b0tZS2hxdER0MzdkMk94QndHZzRJamJUOVAwaUJpRnV3T1YwRHZOMkhzVTd6cjRVZDRZTGdZMERnUHRGRGk0WEw4N0hRbFdhNm94bkY2dkJ2TVlOWW9PRGFDYlFXbkhlVVlaTEdzeVp3emozZC9IcktzV2hSUlFkamFDZ3JNcjRBdTIwd2RWaUhFemZlWXdlOThRWjk1ZndxM2lYRTRJUmREaStKYVVpTmlqSzFpUE9qK0pqc3ZyMThjekk4SmpNMUs5WlJOelI0ZG9XS09FMWhZcmNqU1FMaWNGaDdQdVMzMWh0UXZobkxWb052bTE5eDJobGpTMXFEa1RDUzVycEwxbWptWDJ5d29ja3ZzeXp5RVYxd2x1dG1EVEZDTC9KSm9ZR0Y0bGVxSE1zRFFmdVRoNUs3YVFHb241Um1XcTIvNFl6ak11VUMyNTdtSmxDYk11Ymc1WFI4UlZXKzBDMm9OWHJFSUtxZzVoTnNaTS9TalNZNitZQjA5QXRaazYzWldld2RpM3RHUUp3NnQxNWVyT21EOXVyN2Q1Zkl1c3EyWEJsaU10NVhiSDBPUE1zT1UwY2RXSWJnZm94NWpreWFoMTd1ODFsNGlkbkpVRmlCcldoM1prUFJrR0JNM3ZMaTFyR3Jwb3NPYnY4QUVGZDVtYnBIM1B4T3ZET3Frb2xTcklPakFPWEVkYVRBWFp3d05pMDNOVDh6S0QwVXVXeXlodmp1anZEdkREeFVQYW1rVnI4UFVpTmV3T2hEZEhjOTRtQkdvMzRjUFVnR1VkeDdMMmFZN2pGQ21vOE9zR1RycStIanpDaTBiM2dKeTBpS3AxaWpIcU5FNlNvR1RtZktCTEFiTWZLVjUzOUpvWWpibXlPeC9qUlIzeE5iU21HdnRieDRPbUlUZUxnMHY0bHpYUTErbUMyck5wcXVoWFMzZnhBdVBCQUFXcGR0YXdNSWxKcFBVZTJrdGd0UDRCVFdWaUU1MHZITExBNU5yUnU3QjArWjU4TVRZd2NuQVFzZDBtZkJ0RjNMNjVoaHFiQkM2K3Vaazd6OWRYdTd5czJ0UUlyaWtnMWlSTmFwd3NXYlNoTDFudW1MTFpYNGdaZzllWUp3ZE9rZDRBOVBTVGliNjd5OHRYRzF2TlEwNW1pQzQyZnhOK0xGUDVpT3RTVm81aXh5QS91c1pDcThqcVBaM2phVGNQVVNmQ1dqQzhBaG9ucUhiVHBIaXByeVZONE1mUmo3SUVRYkUxcHFRaU40ckhybzdReDlEMkFUcGM4N3BBUURWMGhLTVp1LytOUm1RTjh3TXVqaEk2R3pCaHRtVmo0RVZWdWE1b1Fqcmtlcmc4eFdxUHRMMTdiRXZNUG9WWUtsWWRxbkhGc2NIZDlpSTdWNGhucFBIWFR2RnBodGlhdks3dlgwcVZ2VU9xNjhSMmpRY3hWYzZ6QnV1bG5vRVF0Nnc2L050RnFydkJZZEZtRHJDdEZSVGhyNU5zeEZCeVV5a2lMVDJkdUdJTDBaTTI0ZnpFR1puMExDNnowQlVvblVlN0R2MytIYVd3ZzlHSitUSStSazVJaXRTdGhMMzJsZ091RDFJWWQvcWVwYlB0R0JsZERWd04zVTlZNjJoYVpPenY4QU1GSTYvVWFiZzB1WjZyTkVkemlheXM3WEpEVzVVZ1VjY1FaV2tHZ05Kb3VXdHlQUTEvRTZpcU94QWRzV1kyckZmK1Z0SjFKdk85emFEaXlMVWJ2eE5MME1RS0FoQ2pTQVN0WUNNRlh1Y3VaYmpwditJODE5QWpBQ0tPd1FSbFVNRXNXQ2FGdCtyZDZHT2VJdFh1bmJwMDdSQ29rb2ROL0VaeXhBZ2luUzdITDBnaTNScGw5b2tVbTYvVUk4SHJkRS9ROHNBQXRLQ1VWY1hIcG5vSnd3dVFxVm5WK1RyRVJyUHdHV0lLZ0U5SWl2T1lSMTZleTlIbzlJUWprSG51K3o3VjlRTHIwbVRoOXBid2RVMHhaaitFTUwwNW1UWlZPTEU0VGNtTENaVHZidHV6NnhpTEphWjF4amVWOWxqb05HSjlLTU1FSllhdHQyL0JnMFJ3TUk3UUJFeXVCWTZ4UjBmU1VTM1RLV2JjM2gzWThUQmFKN2Y1K0Ztc0dpaHgwWVNoU3M5SnRtcjdFcVZzNnNKcnRyMC9sOFF1cG9UQXkydXJ6OUFsYUhkZER2QnRqTEx0MmRoM3hLTCtCMDNkbGZZYWFScnI1N0VxTVY3cWpHNkQ4eXRVMTRTdlh0MjE3UWlzb1VDZzREYjZWS2lJRkZvWUwwbGY4QWJRdWgxbFYwQjJtL25MNWxSNStTT21jekpVY3gySGl1T3R4M3FMdUhHSzBTeGxROTRWTDBYcnNmZW8waGlDb05GZnFiUFJpbW5Tc1pMT3NTVkRFcUs5b3VudWJkdEltSHlZWVh3TnZpWVRvZ2Rrdjd3Y3o5WnlSa0NxeE01VTdoazdkSUZnR1IwZXRHdmNnM2daSitxZFluMHdWR2UzM2s1L01IQk1NYTdUU0twckgwZHVzWnRjOTk1Uzg1YUJ3djgxVFpLeTlwZENha0JqQUd1aEpZTEw4dmlCaUczMXc1ZUlpV3p2TlV1dGlLME9pQXRoOER6YnZRZ3VzSXBaWGsyZVlvSld5bDMrWTB6V2EzYVQ3eExaV3hRV2pRY3JzUnV6YnFjSG8xMTE3UnFxMnhsWmpPbjZ0VDVaWDNRMnNmblY4VkxKZGtROGZkaXZHaWNtcjdlV09XV2RoQWJUbVV5MlZWcDBPc05LR0lHcis3T215RFFjRXl4dHRHNFV5OTRDSDdlNFNxMllRYkJ5eWpKeGF0dlNhaWVJOUlzT25xUUlZaEJ1aGpjNFRjbGE3dDJLK0haem80amd5cFJTVEJQMnNneW0zelExN2o2eEFVaU5pTkpDNEIwd251YWZLTWJ6bnJ2Ry92aUxHQnFKQnRNSFZITWFtM1BTQ0RubDZPazA3dEpWaDVQb1FQdEhYZC9lSXF0cXEvNm93d0RISlo2eEluQThPMGRuU05NQlZiUU5ESzRJaWo4ODdzdWFQZWFUZVdSYXpXZ2Nyc1FWUnNIM3QzMk84T0RJYUtnZEF3VFl2R09EdTd5d0s0cUkxVjZBKzhyRnR3OEErK2tjUkcyYm5WZDM5S2pGamQ2MytJSlVGZUFsUW9aSDJHcGdHcUxaczhmbmNIcURRZERzYUV5VVM0c0hySGdoUGJvVmwweWE0dUQycVlIc08vTVpZMmdhRGlMVVYxZzZGWGUxeGtscGtZaThpOUE1T1BvRmgxanRIQlV5d1BVekM4aUR3eDBDdmJmTTBaRzVvbmlJMEVZaURiOWVIN1Jld0ZCN0R1ZEgyaU9DZG01MGVIb3hxdlR6bVI3bnZLZm9NT054aDB0TkRxdXh0NHgwaGpSSm1Pend3SmE1TWhFSGlBajFvUExtQWhDWUVkb1p6RWh5czlHN05LM3EyWGRpQ04yRVBGbitrYWJodGI3ZHBsQTFnRnhoKzh1c2t4MGYwL2xEczMyaXBTd0xaMXhCcSsvRHZucEtDQTQwTzY2cjFZTk0reWJ2WVJwUzV1WHV3aUlGV2dDMVpTQUN5MXBacTNjZmRHcHB2d2NkRHBDS0ZzTGlncWdHVG85dk5SRlZ1NWVYQjRpWmIxUzE4emZyZUNhVGhEM1NHc09RUlIwdlJGazZQaEtWWGlONHJabzIvMk1hY1M1dWVrVHA2UzRxdFlydlVabU9JN2JyRmZReEJBSWVtNDdPc1ZPSjlMMGRIMmdwb2g0U0ZGTWMzVDZ4STZvc1QvQURHVzRnOVlzQnJEcVI4a0xLY3JlcjM1clh2TVFGQlE0ZHoxdU9HWENQa0Y0VEljSnZCQlRON202TzdvNGdzWWRoVk15amZHYzlmNFJBVzBQbVdKZ0tQYy9la1psbmcvMW5DbnRFV0UxY0hFSGlXNW10L0FSU0RLM2M3QkRjOXhCMDQ3NndIUjdqanl6NWNHUEJGVXFxdTc5RllRQzNVUEt4ZnRzVTVTbkEyZTcwMGlKTXhkaTFmeERNVWQvQjMvQUF1S2FwalNYdnFZQzNVMzIzQitaaE5IU0c3Nk9DQ252bVdkQjlEcDVYNkI4STh5NHN4ZjNOc1dmbzFURDlHcjZDamhJWlNLbzhzQ05vRnAwRG1JNUp0MGdJWVczNWF3R1ZMN084V0lMRHJreE5DbFVXdXpYZmJPdmVIQ01MUlk4anVSaExoWFNXZHJkVnZTUEhTRG1JYWFSTXFWNyt2Nm1Pd1k5SUlMVzZhc3kreGcvd0JselRnam1VWnFHVzU0bGtsQnBIYVZCZDhneFhRYkJvZlFMbFk3Z0hvUHU0Z0VadDVVSGxPcjE5SUd3SmJ1QitXWXRiNEdqeCtZQXZCeU5Fdzl1YlQrVXhDcmdhUUVxTmFvS3RIME04cW5vMUt1T0dHTVRJNWZBZkNMbU9acmxQME5NM3h1Yno5M3ErbldEaURoRzR3WEJVdWI0aUd2UnZNR2NCS1hOZTV0Q3lqM0drdXl4czVJSlEzM0JBelBmVXFreXNzblZiUDZ3dFhsWVV2Z2JQc3h4TCtoSG1YREZvL011RFBZL3JqOTBqTUoxZGY5cXRjRVZ2Qm9HRWxZc1dEWitZNjBTd2NNdmVFSE1JTlJVVVBYZDJScXJTcW9jVWZ2NlMrUFhRMk94b1JvTEFPV0NicjlNUksyN29FQ0thbUxkRXNTME9ac2N3Sm4rM0ovRUp5TW9hUkRmWnlzblI4SlM4SXdpQnpIOURqTmJFbFd3L3Q1UzR0TnR6Ryt3UFUveEdoVUErOFlBR0dXTU9ZWWcwNFpvby9tTnYzQkZLMFVBKzFCTkc0M21PZUdJZ0FsTEFjSTZrc0NscVhCOTV2OVdVeGE0Q0xDTmRQUjcvdTBYUFdJOW9SVmJmOEFkYTFsQVNEa3llOEhwNWNqOFNxQlRRQzFoaGt5TEoyL0tLWVFjSGhORDNpZGgxUzJPb1l1QjduV1VyYXQ2L1JVUUdZdHdST1hMU0tqVmRrSDl4OHd0RGxLRkY3ZXBLcWVsUFEvekNNR0FRTGNjdzBybnRrT3p2OEFIRzIrSFk1bUhaaThBTjE2UVpoZHdXY3YyTm9OTHJlMksyYVJJL2MreDVob05qbnYvVW9sTUFpRGhqVlJlc1ZQa2ZRL21DMzR0Q3RBeGtsRkdnOGZqTEptMkF2dFdHVkJOWkJvT1NVTVF6aDNnYWcwOFIzT3NUR2NFYzdNZHB1TWtBTVMrSmNqTkxrN0w1SW1BOVlkeVgydWhEWTlXYjlVc1dPMW5WMm1ZME52K0JqRXNRVFNOcDZKTnlQaHRTT2J3cnA0aTFWS3U3dkJOTXNkMVJDS2dNQnJySFFSTXd4UXNqZ0I1ekdvVzdSa1g3RWRYTm1idm4zK0pXR1FwN1pQdVFVdzRuUzNxSWVyZzRQTXNUd2hhZWo4Y0c3S0pYQUx5dlNLSEp5Tlh5bXh3YmQ0M1lxdldWVGZwU1VFTFZvT1dIbkFMWnYrc0Q5TkxQdVM0UDFsS0YxZ09QS0hXeEg2bitKODM0SmVmZUNsUUlpYk1vSFhRakdwbjNJN1FlR0NhWWlKTUpxZFlGZGVzY2VkWlIxMGpmTlVRZXBBdXVHQ2lOaE55TndMNWorUWZ1a2NQTGdOQndSWmJnMC80dHB6TE84UnBhT0NFVnB1SFJoUE1DVkEzWEhRWFVaMGw0dDJxaUNVb2I2ZXJlT3NqMHo4c1FSbnB3OS80TFpRYWFyTEJVTGxqelZ3ZUtEU2JYcWV0eW9HbzNBNkFVblp0R0x5MDlFWlA5NHhlOGt2dGx0NmVlOG8yem5iOGQ0b2grbFlHZ0RpK1g0MTlJclM3aXA4UmtnQ2pJZkVUN0JISkhxNGp0TjM3a3pEWUhvSVh3ZkJDb2x0QTBQM2FGSVVWN0JWK3F4Szd3Q2pEaDBqb2R1U0lsdGtXYXpBYW5EQjJjVjZvdEd4N1NyaFZlM1BMTEpQZVQ0T256TVNoVUdrbG0yZjhaaGxtSHo5RVNER1hSaGkyL1hub1lrRGRsdlJwR2F0QWVBT3N5dDZ0SDhFNnZhVzR2YVpRY29jUTZiWHIrSVlsY3B5R3EybzBmc3djek5Ud05RRlZwRGlHT3I4UkNrVVV1THhVRkM0Qkw0eWoyZzZNSWVVWXBiY0oxKzBDQzdBck5IQ0dkUXpWMnV2MlBFY3hJT0NaQzk2L01WUk41Q05seVpNV3gzR0FTMmxORkVJRU9Eb29xVkFxOSs2NThFc09HMTRpMlJtTUdheWx3MHphSjFhTWRaOE1jYVNDSzFJTnNyYm1FN1F6cExzVnhPQncwRDBpMU9QL2xHdEpncGc0dVgzSmFtaVJ5Lzkvd0JKUXlseVVnMVBFWmF4cExPcks4UURpVjlLcDcvUzZselgwdW05eVRXanhIVS82YmhOVTMraC9VNFRmTCtocjV0N3NKWGRZZG5MTkNPZ2RZa3FvcHRtcG5kcUY5cU9kNG13SHZFcGJnbHF0ZXNzT1M0VXhkbldDQ0ZOQVp1Q3hQbjdrT2VPR3c0Q0tvN3Avd0Era3pVd1JNTXVzQ0NYVGNHTFJRYkpIUlVyNlZLK2lhUEU2dzB4VjlPcFBNWHJ4RFhid1czSHhJTXcxK2daK3Y0emZLZ1pJYTYvM3A0cEZuMXhBMU5JdTRmYVlrTFVzMFpaeVlJVU5HQ0YzVDRFUlhYbVhOQmJBRDExUXgxZENJbTRxbnhuWDk2UjhMTGR5SXFLL3dEVlU1OVlXeVFjaWFrSzJEWWdOYlpvZjNFb1RFcjYxOU5wdFlOSjlQd1NndkRQTkdmcHVNMVN2b0hxZmpOYjlOUkxTNSs1SGljVFNkVzRIMGNMK0k3YWdVclk1aFE0TFRYVTlrdkZCamlCdXM4NXRNc1N0YXI3WVIyVC9sbDIrbEVzL3dDeW50TFRXL29rM3Rhckl4TGFjblI3UzJKZG9xcmxmV29NdW4wSEF4WXZoanF5cC9DNC93QnJaRm1ETlVUMTN4K3ZXUTVPaGI2RXRBNEl1a3k3MGNBSmxlQmJtM29TelQySUNtVEVBc09vNlN2UFhYRjVQMWpOZ045MzdzdWwyalE3RGFkWlNSVi83aFRUNlFqM2c5Y3hTazlZZVlEUTN2cUV0QjdFYWFaNnl2b2N2V09zQ21JMVNQcE5Zc1JxcCs4NFRWQ2E0bnF2ajlPODFFRmNUN2t5WGVMbFhhQ2hNMktyOUlLSE15MzlJd0hBNVphYWJyUjlvN2RWdVlPN01DUnhnbm5tWEZDY1AvaEtkU0M2ZW04R1hUWTBtOHdtNDlYckViOVAvV1ordzIzUFNOdEhNRzdVbUNuendzM2pqNG1mbFQ5SndtcjYzM254bXVieldSVW0rSHVtckJ5dkxLSFI2dzVtYlRDd1o3RUdBYnkvZG1hZ3YwQTlYZVhGTkVLbGQ5L3BkU21Ldi9pb2E1ZzZFZStzNmJ6MUppVTZISkJWRUxyaVpRYXk3UHlqOUZ6WW82UXA0bCtTRkxFM21rNUpnWFQ0SnFoTmNYMTN4ano5Rm1NenNRL2ZNVkN5bk8wcHVnZEF1WDYzSzAvTWJnUzJMZldCcWl1djNWalE4YWZTNE1LOVAvSkFVNUp1bGQvb2ZSNzA1anl2TENidU9iQ1ZtMU8wWGdCdFZiZ0R4QXNIUnVGMThWcFRxUG5QeUVpQkZZcVpyQyswZEkvbk5jSG9qTi9ZRW93QTZrZlZzdDk1b2ZOR3NmRU84c0xIRjZBNGVrN1Q1bFZyZzVZaHBjWURiai96UmFGSUxRREJkMDd3enBUMmxKckwrdnQ5SW1qaEFYM2EvRUEzZWlkY2RoTUZWMkErMDFrZWM5OWhNOGZVRjBuSUR2RXQzc3hIWUVLVzFYLzB4NktvTFlZUHFIWmwzSHVRdkxMUlhtZEk5WjBwMEoydldZYWg1bU9zYXQ3Mklub251eFd3aStxbC93RFgvOWs9IikgY2VudGVyL2NvbnRhaW4gbm8tcmVwZWF0O29wYWNpdHk6LjI4O21peC1ibGVuZC1tb2RlOnNjcmVlbjsKICAtd2Via2l0LW1hc2staW1hZ2U6cmFkaWFsLWdyYWRpZW50KGVsbGlwc2UgNjAlIDYyJSBhdCA1MCUgNTIlLCMwMDAgNDAlLHRyYW5zcGFyZW50IDc4JSk7bWFzay1pbWFnZTpyYWRpYWwtZ3JhZGllbnQoZWxsaXBzZSA2MCUgNjIlIGF0IDUwJSA1MiUsIzAwMCA0MCUsdHJhbnNwYXJlbnQgNzglKX0KLmNpY29ue3dpZHRoOjIycHg7aGVpZ2h0OjIycHg7Ym9yZGVyLXJhZGl1czo1MCU7b2JqZWN0LWZpdDpjb3Zlcjt2ZXJ0aWNhbC1hbGlnbjotNnB4O21hcmdpbi1yaWdodDo2cHg7Ym94LXNoYWRvdzowIDAgMCAxcHggcmdiYSg3NywyMjQsMTI1LC41KX0KLnVwe2NvbG9yOnZhcigtLXVwKX0uZG93bntjb2xvcjp2YXIoLS1kb3duKX0uYXNoe2NvbG9yOnZhcigtLWFzaCl9CgpoZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDtmbGV4LXdyYXA6d3JhcDtwYWRkaW5nOjZweCAwIDE2cHh9Ci5sb2dve2ZvbnQtc2l6ZToyOHB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzotLjAyZW19Ci5sb2dvIHNwYW57YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsI0Q2RkZFNCwjNERGRjhGIDQ1JSwjMkVFMDZDKTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0O2JhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50fQouYmFkZ2V7Zm9udDo4MDAgMTFweCB2YXIoLS1tb25vKTtsZXR0ZXItc3BhY2luZzouMDhlbTtwYWRkaW5nOjVweCAxMHB4O2JvcmRlci1yYWRpdXM6OTk5cHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMil9Ci5iYWRnZS5wYXBlcntjb2xvcjp2YXIoLS1nb2xkKTtib3JkZXItY29sb3I6cmdiYSgyNDIsMTkzLDc4LC41KTtiYWNrZ3JvdW5kOnJnYmEoMjQyLDE5Myw3OCwuMDgpfQouZmVlZHtkaXNwbGF5OmlubGluZS1mbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4O2ZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKX0KLmZlZWQgaXt3aWR0aDo4cHg7aGVpZ2h0OjhweDtib3JkZXItcmFkaXVzOjUwJTtiYWNrZ3JvdW5kOnZhcigtLWRpbSl9Ci5mZWVkLm9uIGl7YmFja2dyb3VuZDp2YXIoLS1taW50KTtib3gtc2hhZG93OjAgMCAxMHB4IHZhcigtLW1pbnQpO2FuaW1hdGlvbjpiIDEuNHMgaW5maW5pdGV9CkBrZXlmcmFtZXMgYns1MCV7b3BhY2l0eTouMzV9fQouc3B7ZmxleDoxfQouYnRue2Rpc3BsYXk6aW5saW5lLWZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Z2FwOjZweDtmb250OjcwMCAxM3B4IHZhcigtLWhlYWQpO3BhZGRpbmc6MTBweCAxNnB4O2JvcmRlci1yYWRpdXM6MTJweDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtiYWNrZ3JvdW5kOnZhcigtLXBhbmVsMik7Y3Vyc29yOnBvaW50ZXI7dGV4dC1kZWNvcmF0aW9uOm5vbmV9Ci5idG4ucHJpe2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjNUNGMDhGLCMxRkE1NTUpO2JvcmRlci1jb2xvcjp0cmFuc3BhcmVudDtjb2xvcjojMDMxMDFGfQouYnRuLm1pbnR7YmFja2dyb3VuZDp2YXIoLS1taW50KTtjb2xvcjojMDQxNDBEO2JvcmRlci1jb2xvcjp0cmFuc3BhcmVudH0KLmJ0bi53YXJue2JvcmRlci1jb2xvcjpyZ2JhKDI1NSw5MCwxMTAsLjUpO2NvbG9yOiNGRkIzQkR9CgouYmFua3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmciAxZnI7Z2FwOjEwcHg7bWFyZ2luLWJvdHRvbToxMHB4fQpAbWVkaWEobWluLXdpZHRoOjc2MHB4KXsuYmFua3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6MS40ZnIgMWZyIDFmciAxZnIgMWZyfX0KLmJre2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjE0cHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTgwZGVnLHJnYmEoMTYsMzIsNTgsLjgwKSxyZ2JhKDgsMTcsMzIsLjgwKSl9Ci5iay5tYWlue2dyaWQtY29sdW1uOjEvLTE7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoNzcsMjI0LDEyNSwuMjYpLHJnYmEoNjEsMjQyLDE2MywuMTIpKSxyZ2JhKDgsMTcsMzIsLjkpfQpAbWVkaWEobWluLXdpZHRoOjc2MHB4KXsuYmsubWFpbntncmlkLWNvbHVtbjphdXRvfX0KLmJrLnZhdWx0e2JvcmRlci1jb2xvcjpyZ2JhKDYxLDI0MiwxNjMsLjUpO2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZyxyZ2JhKDYxLDI0MiwxNjMsLjEyKSxyZ2JhKDgsMTcsMzIsLjkyKSl9Ci5iayBzbWFsbHtkaXNwbGF5OmJsb2NrO2ZvbnQ6NzAwIDEwLjVweCB2YXIoLS1tb25vKTtsZXR0ZXItc3BhY2luZzouMDVlbTtjb2xvcjp2YXIoLS1hc2gpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmJrIGJ7ZGlzcGxheTpibG9jaztmb250OjgwMCAyNHB4IHZhcigtLW1vbm8pO21hcmdpbi10b3A6NnB4O2ZvbnQtdmFyaWFudC1udW1lcmljOnRhYnVsYXItbnVtc30KLmJrLm1haW4gYntmb250LXNpemU6MzJweH0KLmJrIGVte2ZvbnQtc3R5bGU6bm9ybWFsO2ZvbnQ6NjAwIDExLjVweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpfQoucGlsbHtkaXNwbGF5OmlubGluZS1ibG9jaztmb250OjgwMCAxMXB4IHZhcigtLW1vbm8pO3BhZGRpbmc6M3B4IDlweDtib3JkZXItcmFkaXVzOjk5OXB4fQoucGlsbC5vbntiYWNrZ3JvdW5kOnJnYmEoNzgsMjQwLDE4MSwuMTQpO2NvbG9yOnZhcigtLW1pbnQpfS5waWxsLm9mZntiYWNrZ3JvdW5kOnJnYmEoMjU1LDkwLDExMCwuMTQpO2NvbG9yOiNGRkIzQkR9Ci5jYXJkc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLDFmcik7Z2FwOjEwcHh9CkBtZWRpYShtaW4td2lkdGg6NzYwcHgpey5jYXJkc3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDYsMWZyKX19Ci5jYXJke2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZyx2YXIoLS1wYW5lbDIpLHZhcigtLXBhbmVsKSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzoxNHB4fQouY2FyZCBzbWFsbHtkaXNwbGF5OmJsb2NrO2ZvbnQ6NzAwIDEwLjVweCB2YXIoLS1tb25vKTtsZXR0ZXItc3BhY2luZzouMDZlbTtjb2xvcjp2YXIoLS1hc2gpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmNhcmQgYntkaXNwbGF5OmJsb2NrO2ZvbnQ6ODAwIDIycHggdmFyKC0tbW9ubyk7bWFyZ2luLXRvcDo2cHg7Zm9udC12YXJpYW50LW51bWVyaWM6dGFidWxhci1udW1zfQouY2FyZCBlbXtmb250LXN0eWxlOm5vcm1hbDtmb250OjUwMCAxMXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWRpbSl9CgouZ3JpZHtkaXNwbGF5OmdyaWQ7Z2FwOjEycHg7bWFyZ2luLXRvcDoxMnB4fQpAbWVkaWEobWluLXdpZHRoOjkwMHB4KXsuZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MS4yNWZyIDFmcn19Ci5wYW5lbHtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxODBkZWcsdmFyKC0tcGFuZWwyKSx2YXIoLS1wYW5lbCkpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxOHB4O292ZXJmbG93OmhpZGRlbn0KLnBoe2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7cGFkZGluZzoxMnB4IDE0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSk7Zm9udC13ZWlnaHQ6NzAwfQoucGggc3Bhbntmb250OjUwMCAxMXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCl9Ci5wYntwYWRkaW5nOjEwcHggMTRweH0KLnJvd3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmciBhdXRvO2dhcDo4cHg7YWxpZ24taXRlbXM6Y2VudGVyO3BhZGRpbmc6OXB4IDA7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgcmdiYSgxNjcsMTM5LDI1MCwuMDgpO2ZvbnQ6NTAwIDEyLjVweCB2YXIoLS1tb25vKX0KLnJvdzpsYXN0LWNoaWxke2JvcmRlci1ib3R0b206MH0KLnJvdyAuc3tmb250OjcwMCAxNHB4IHZhcigtLWhlYWQpfQoucm93IC5zIGF7dGV4dC1kZWNvcmF0aW9uOnVuZGVybGluZTt0ZXh0LXVuZGVybGluZS1vZmZzZXQ6M3B4fQoucm93IHNtYWxse2Rpc3BsYXk6YmxvY2s7Y29sb3I6dmFyKC0tYXNoKTtmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjJweH0KLnJvdyAucnt0ZXh0LWFsaWduOnJpZ2h0O2ZvbnQtd2VpZ2h0OjgwMH0KLnRhZ3tkaXNwbGF5OmlubGluZS1ibG9jaztmb250OjgwMCAxMC41cHggdmFyKC0tbW9ubyk7cGFkZGluZzoycHggOHB4O2JvcmRlci1yYWRpdXM6OTk5cHg7bWFyZ2luLWxlZnQ6NnB4O3ZlcnRpY2FsLWFsaWduOjFweH0KLnRhZy5idXl7YmFja2dyb3VuZDpyZ2JhKDc4LDI0MCwxODEsLjE0KTtjb2xvcjp2YXIoLS1taW50KX0udGFnLnNraXB7YmFja2dyb3VuZDpyZ2JhKDE1NCwxNDcsMTgxLC4xMik7Y29sb3I6dmFyKC0tYXNoKX0KLmJhcntoZWlnaHQ6OHB4O2JvcmRlci1yYWRpdXM6OTk5cHg7YmFja2dyb3VuZDpyZ2JhKDE2NywxMzksMjUwLC4xMik7b3ZlcmZsb3c6aGlkZGVuO21hcmdpbi10b3A6NHB4fQouYmFyIGl7ZGlzcGxheTpibG9jaztoZWlnaHQ6MTAwJTtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS12aW8pLHZhcigtLW1pbnQpKX0KLmVtcHR5e2NvbG9yOnZhcigtLWRpbSk7Zm9udDo1MDAgMTJweCB2YXIoLS1tb25vKTtwYWRkaW5nOjE0cHggMDt0ZXh0LWFsaWduOmNlbnRlcn0KCi5zZXR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dhcDoxMHB4fQouc2V0IGxhYmVse2ZvbnQ6NzAwIDExcHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTtsZXR0ZXItc3BhY2luZzouMDNlbX0KLnNldCBpbnB1dHtkaXNwbGF5OmJsb2NrO3dpZHRoOjEwMCU7bWFyZ2luLXRvcDo0cHg7YmFja2dyb3VuZDojMEIwQTE0O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjlweCAxMHB4O2ZvbnQ6NzAwIDE0cHggdmFyKC0tbW9ubyl9Ci5ub3Rle2ZvbnQ6NTAwIDExLjVweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1kaW0pO21hcmdpbi10b3A6MTBweDtsaW5lLWhlaWdodDoxLjU1fQoKLmdhdGV7bWF4LXdpZHRoOjQyMHB4O21hcmdpbjoxMnZoIGF1dG87dGV4dC1hbGlnbjpjZW50ZXJ9Ci5nYXRlIGgxe2ZvbnQtc2l6ZTo0NHB4O2xldHRlci1zcGFjaW5nOi0uMDNlbX0KLmdhdGUgaW5wdXR7d2lkdGg6MTAwJTttYXJnaW46MThweCAwIDEwcHg7YmFja2dyb3VuZDojMEIwQTE0O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEzcHggMTRweDtmb250OjcwMCAxNnB4IHZhcigtLW1vbm8pO3RleHQtYWxpZ246Y2VudGVyfQoub3J7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweDtjb2xvcjp2YXIoLS1kaW0pO2ZvbnQ6NjAwIDExcHggdmFyKC0tbW9ubyk7bWFyZ2luOjIycHggMCA0cHh9Ci5vcjo6YmVmb3JlLC5vcjo6YWZ0ZXJ7Y29udGVudDoiIjtmbGV4OjE7aGVpZ2h0OjFweDtiYWNrZ3JvdW5kOnZhcigtLWxpbmUyKX0KLnB3e3Bvc2l0aW9uOnJlbGF0aXZlO21hcmdpbjoxMnB4IDAgMTBweH0KLnB3IGlucHV0e21hcmdpbjowIWltcG9ydGFudDtwYWRkaW5nLXJpZ2h0Ojc0cHghaW1wb3J0YW50fQoucHcgYnV0dG9ue3Bvc2l0aW9uOmFic29sdXRlO3JpZ2h0OjZweDt0b3A6NTAlO3RyYW5zZm9ybTp0cmFuc2xhdGVZKC01MCUpO2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjdweCAxMHB4O2ZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y3Vyc29yOnBvaW50ZXJ9Ci5yZW17ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2dhcDo4cHg7Zm9udDo2MDAgMTNweCB2YXIoLS1oZWFkKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjo0cHggMCAxNHB4fQoucmVtIGlucHV0e3dpZHRoOjE4cHg7aGVpZ2h0OjE4cHg7YWNjZW50LWNvbG9yOnZhcigtLW1pbnQpfQoudmh7cG9zaXRpb246YWJzb2x1dGU7d2lkdGg6MXB4O2hlaWdodDoxcHg7b3BhY2l0eTowO3BvaW50ZXItZXZlbnRzOm5vbmV9Ci5tc2d7bWluLWhlaWdodDoxLjRlbTtmb250OjcwMCAxM3B4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWRvd24pO21hcmdpbi10b3A6OHB4fQpmb290ZXJ7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tZGltKTtmb250OjUwMCAxMXB4IHZhcigtLW1vbm8pO3BhZGRpbmc6MjRweCAwIDQwcHh9Ci5jaGlwe2ZsZXg6MCAwIGF1dG87Zm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtwYWRkaW5nOjhweCAxMnB4O2JvcmRlci1yYWRpdXM6OTk5cHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMik7YmFja2dyb3VuZDpyZ2JhKDgsMTcsMzIsLjgpO2NvbG9yOnZhcigtLWluayk7dGV4dC1kZWNvcmF0aW9uOm5vbmU7d2hpdGUtc3BhY2U6bm93cmFwfQojanVtcHtkaXNwbGF5OmZsZXg7Z2FwOjhweDtvdmVyZmxvdy14OmF1dG87cGFkZGluZzo0cHggMCAxMnB4Oy13ZWJraXQtb3ZlcmZsb3ctc2Nyb2xsaW5nOnRvdWNoO3Njcm9sbGJhci13aWR0aDpub25lfSNqdW1wOjotd2Via2l0LXNjcm9sbGJhcntkaXNwbGF5Om5vbmV9CiN0YXBle21heC1oZWlnaHQ6MzMwcHg7b3ZlcmZsb3cteTphdXRvfQojYnVpbGRUYWd7Zm9udDo2MDAgMTFweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1kaW0pO21hcmdpbjoycHggMCA4cHh9Ci50YWcud2F0Y2h7YmFja2dyb3VuZDpyZ2JhKDI0MiwxOTMsNzgsLjE0KTtjb2xvcjp2YXIoLS1nb2xkKX0KW2hpZGRlbl17ZGlzcGxheTpub25lIWltcG9ydGFudH0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KPGRpdiBjbGFzcz0iYWxrLXdtIiBhcmlhLWhpZGRlbj0idHJ1ZSI+PC9kaXY+CjxkaXYgY2xhc3M9IndyYXAiPgoKICA8c2VjdGlvbiBjbGFzcz0iZ2F0ZSIgaWQ9ImdhdGUiPgogICAgPGltZyBjbGFzcz0iZW1ibGVtIiBzcmM9ImRhdGE6aW1hZ2UvanBlZztiYXNlNjQsLzlqLzRBQVFTa1pKUmdBQkFRQUFBUUFCQUFELzJ3QkRBQVlFQkFVRUJBWUZCUVVHQmdZSENRNEpDUWdJQ1JJTkRRb09GUklXRmhVU0ZCUVhHaUVjRnhnZkdSUVVIU2NkSHlJakpTVWxGaHdwTENna0t5RWtKU1QvMndCREFRWUdCZ2tJQ1JFSkNSRWtHQlFZSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDVC93Z0FSQ0FLQUFvQURBU0lBQWhFQkF4RUIvOFFBR3dBQUFnTUJBUUVBQUFBQUFBQUFBQUFBQUFRQ0F3VUJCZ2YveEFBWkFRRUJBUUVCQVFBQUFBQUFBQUFBQUFBQUFRSURCQVgvMmdBTUF3RUFBaEFERUFBQUFmbFFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQWRPQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUhUZy90U2VXczl3NHo0M1IzS0pGYjR4Um1TRUkxTzVCWnJ4eVlTNjlXWHcwS2srVzI1YjdwNUdQdTZycnhKNnZHWE5POHRBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQWVSRm4xZXhuUG10bHVMQlQzTGpRNTU3TnV2V3BlVjViNlNoV21HYVVwMnZ0c3VUT1JtZXI4cXZacGwxb1RqbUp0V1lFamM1bHNTT1A1YzAwa3FneTF2VVUzWG5SMUswQVVBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUxpbDcwM29jNHc5b3BtSlF3Zk8yK3F4TWF5NzVCMXd5THRxMHg1NjgwajViMEdJcnpWanNqdUJ1ZVJUMGlmSFV3eVZyU2RzSDZ5dXhjVkt2UWlaODJheXhqT2lhNW5OU054cjZaeXU5VmJqRjFOMEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFIYnZaek9KN0ZtT2VmSzhueUZ2b3ZNME9YYWJXdStaTHI4MFZreHlTa3RCZDJDcWVhdFUxYnQvUVIxcGpQOG52U2t6ZlE0RzJac1cwN3FxY2tyYmV2Wkk3eVhJanlmQ3FwamxKd2RyV2h4V3MwaEpxUmxTMlJpODM4YTZwQXRBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQURUYjl6TUt0U3lNNGU4ZmxMYTJNUGJTNStpNU5tbXl6c2xYYklrT1NnSE9zaDVQMG5pbHIzY2pidGZZZ3ZuR003bGEzUGxuYUdleGJwWSt6bDc2OFJjVzFwMWVHaEpuc0pOWFVqaEhPU0VoeWNTRUxRVnJicnRsY2pjTXRKOWtYUTlCUmJqQVhRQUFBQUFBQUFBQUFBQUFBQUFBQjBQVDIrc3p6aUhqSmw3eWRidXVtd3o1eW1UY2xIWVN0N0x6MDlOekVkSFk4NlFBSnN3RTg3Z01LM2IrcXJxeU5ZMno1bVpVM3ZQZW01OE1Zc1dYZVZsZHZ0azEyR3RwNjJRN1hWMzB5enNKSFk5bkZZeE9rNU9WRkhJSXE2cFIwazhrSyswalpNdCtmMzdiZk5nWFFBQUFBQUFBQUFBQUFBQUFBZDlWVDYvUE95dVBqSm5RWndQVlcrZjA5dFZFc3pidVh3RVBlNEYxVHY4QWlvbnVNekozNW5MdjNFeXJXd2RwV2NmWDhtbVJ3dXU5blZ5ZG5PS2ZLN2VGTTg5VjVqMVhQaGlJNkNHdHY2R1JxNjZaOVRhV3RyZGxDNjFLaTZaU2Y2MWJYSmRZY1d6MVJwV3NhNTIyNHJzNnlpbHpWTWtZUlZYUVp6cmtmODc2R3UzQ0F1Z0FBQUFBQUFBQUFBQUEya3ZvV2NYUk1DWVE4NTlDOEZkMG5KNjFxZXA4SjNPUHBsWGpmUnpMVVdLalA4LzZ1RjE0UTlYZ1hVZDN6SEU5NUx3MnpNNzNpOXJDV3ZRUTJycDlzb3p6d3BLTTV6VDZ2eWZxY2NNclBlVXU5Q1JUWmZsNm1kdjBWVU1LNjIyNWx1bzRpb3FNcTg0MEU3aUYzVzBVYXVwa25WU3FOS3dGT05MbkgreXM1cTQxaHpNOWQ1aTZvQVVBQUFBQUFBQUFBbkgxTW10bzhWenhVOFRPelhYM2VhaDYyWStZVzZtYzFIbHhWSExiODV1OUw0L2tuMENyeXUzVEZEMUpoWW5zbDdyeUhkakx1b2RPRTk3STM1TlBFMlBNVENMMmRwU0s2MlRxQzlNcTAwVnIwTTQxbGJ6ZlhNWHZyMTBpdGF1c3VGdFYzV095Sk9YMEpaVlN2RjY4U1RnU0lNc0pISzRiV3RYWjhrcEl2SVczVFc1aU1NNHZQU2VidWdCUUFBQUFBQUE2UCsveTlQUExuaTluQlhPOURsZWh1cloyWjB6dGVLOXFwTWVaN3NKaWZMbzNjNFhXOCtPVHlVTjlYdDd5TWozZFhsdHhMRnRLaGZONS9yazdwUGNUMW1VL0tibm40N281cjlVN0dScnFpdTBrT0syVXlQdG91VEtGTGltdG9TWWV1czk1cWhKMDBxdzB2VnlTNnhiUnpqUGhaWmRVNlZ1UFU2dW10TnVYb1NMVkU3dU1iT0YxMWZVM3ZNdGJTZVNBdXdBQUFBQUFOako5M012VXo4MU1ZbnEvRzdkM2xlbFd6VTliUGxrbVR1NTBVeW1kRHpXYzYyZlBVbU1qWVhaempCcGNwNitoU3RxQ3I4c2dQYm5rdzl2WDV2YWtidXFyVHorZEtWMWE0emlHbEsvUEx1cXZDM09NeVZNNXpETGRWMGJ1MWRkQlhrcWVMSWpKRHZPaHBvYk9PV2E4WnNrZWF0bHVYb1hRdFVTdFgzMW4wNmN1cGZFNnE0cm9hR1pZeVpuc1BIM1FBb0FBQUIwMlBZWmIrZVVQQjd1SGRPTDdTaStpOHBwMnpNTjN3L3FyWGNuVmpNMzQwdGFQTFdFVWUzZkxhZU9DSyt3bmVsS1RHOXZyNVhtaWhiVFc0d1pJeFJLN2ZraUYxUG9LWTh4clpodjVPZ2hDdXpnN0Judlp1aUtXVTlSelBoVzBjSExWTFhFemtKdUlyWXhkbkVOWmU3bjU0Vlp0ZDNLczFkOUdNdS9PdW9TNU5vajJkckZUV1lsVnNMN2VNcXNTYVNOZTRua2dMc0FBQUgwUFV6TzFYUEZtUE9PSTdWMjlWZmN6NW4xM2t0b3lKYnZtMTluekQyNUUyTzVvN2oraHlwaFJ0YVl4QjNMemg0VllVSjR1K25VOXJsMHN4a0MzSzd0OG5tL2FaN3Rua25NcjBEU1BGSFRPMU14MFRlWDZkcWExWlBQYU8xZ1d0NWl0aTFOMzFGL2FiWkp2NWtNY0pPSlB5WmtlMzc2UTFMTXVxMVNkNkhlMW5kSmRnVVN1cExMT1NEcEV2Mk1nUlZiMDNtYm9BVUFMUGJlVzlibkhmSCtrOGhUT3docGw5a0xaUFB3OVhtVzZYbWRPK1o4ejZUemx0MTZhdWZKRXREUGVUUFlubFk1N05WTjJlYXlPZ3IwNzg2bnJhMW04NHlydWVzNUpsTWErTGRibEdGYWxIcGZQZWdqemVubmFOdWRkVEkwRU5UTGswNjBsYlp4WlpXUEZkVkVyM2NvdlFhVGhwNm1HZWJNWjB6bTVmaWJ0cU9ZeWpydE9YSkxHVmVqVjJlMGxKUnk4dWlYSkljNkV1ODZiZmxQU1pSbmdYUUhUMFd3bTFubGxZRDhMdG5RYmFtYTlUUHBUZnE4d3FlaVc4NnFydWREdDFxN0hrL1FvMW42Rk1qbUt3ek00OWk4N2REaXZjNVhIc3JmVFh6TlBPa1lwcWNYTjJsRTYwc1YzWWt5SmF2bTFadllWRVpTWld6TGZraUdqSFBXOWQ3MDFaMWMvTWt0WlpZcjFFbm9yNGoyWWx6amx1aWt4bWxNbzJYWGE1ZEw5SEtVSEdNeVpxU3krajFNTEVxTDRMR2NKSE5iRzNEeW9GMFhVdnllbmpKS2M4dlQ4eVhlMnRuZExxYkxWV0hyRXplYTl4aFM5Qk13SHRKaVRzR3huSTBtS1RQenZRNGNoeUhicGxUbW9ZMjFoYVNvenZYSE9LdElzdHAwVytnOGI2ZkN6bmZ3OWZMRWRqSjJUTWF6dEpjamNZMjlXT1NlWWtKUTFMdU9YWThqbU0vbW5leDZUOUNuMlpYejlPQ3FTWTVhblc1V0xjYjRxb3h3bzdad2gwNFQ3VUROeUZ3eHU0ZWl6NS9qNkYyYk9OdlRPcm12WlV6a2FDdXRkUllrM01xRHNrUzYvTVZuR3NZbm1WSnV3OC9STDZLbnpWWnZMWXZMclNYVkYwcDArbVk4NjE3Tkk4cWp2NEYxdTR0ejBtZjNnckxPZnZ6T1YxSDBremkwMXNRbHJacnN6blBSTmEwK280ZXQ5aWR1N3Iyc2RPNzZsWWpYcnhrek91TEUrcWl1elE2YUVrSnN1OVZtVzhyRmxEdlNnYWpTL0dCVitNMGxmWmRMUXFOVHovcFBOMm5vL08ra2t2enRISm1kVmpHck4yakRwTjJuRkRVcFE3REVJZG1XMTdXczR6SVRqdnBEbG5McUpjN2JuYTBrWTlOSHg4VTNNOVorM1A3NkpxWjh4NmlHYkpxdGVQcVQxMlVwcDV6Z2UycHF4eXdIMTlQR01pYmRNV1pYb0ZPdlZDM2ltK3JVYy91dHRJTlhMbm1qWFMxbktWY0VlcGRYS1pWTHNaSmtKU1NrTVp4WDEraVpRN3ptK2xuYWVOTWRvN1YxaXdqVVYrS3pUZFRXejVyMC9tTFplazg3NkdMZk8rZ3cwV2x5eUlkYVp6alBaWlhtZXg0U0FkQzZrclFYWHZtYkl4dnR6NmRidXV1TTNOYlc5QzNEakp1b29TSjFUNWF4cFpGMmM3MXZtdVp4dnI1TTg0YzdXMXg0M2FkWG91ZnkvTksra3hKY3VseFB0OVBzMUsrM2ZRcFI1cnBjdE9PdFE3MHRuYXNETVYrazY1MkM5bHZJbk9vbk5xSERITmNZNnEvYmlTb3M1YlRCcnFwZGRoYXZ5K3ExaXR4SzYyL01lbTh6clZub1BQN3BjcXpWbm5UcFZjemh1Q1NtZWUzM3o0ZWdNQ1VicGg5czNEQ0kzSTRzTGJLb0w5ZlMvZGp5dDFWMW1aWUZ2Q0VvTEQzYzdwb2RvZW1VNVBVek5WdE5XYzZqT1F6dzgzb1BVK0Qxc2ZJMi9OU3o1c1dndDErdFpHcTd0M1hISTYybVNUMXBrVkxXQ3U2SytYY3JsdEZJN1NvREZsRG1jK2t0d2JPUGkyb1k2NjcvUEs4MXIxZlBLQytxNzVQaStzUExzcHNvTFF1M2NweExmWGE4MTZUemV0MmJlRnRsK2Uva0k4eGgyTHQzK2ZzazNJWmQ3TE5YWkdmSGFpWTVxd013YVd0akNjVjVLdXRiS2JXalBscGNGVzExMDFqRjZhQ2R1ckppczZNTTVpN2xLVFBvMThmYzU4Nm5jblJ4eHBoWHhkS3hQQjZkZC9Mb2MzMVFwMlk2M210ZFR0MEk1WXJpOG1LUmpwOE01aTFVdHJoMEpSN0pMdldaRm1tMTVpN1BkQmEyTmQxZkpTRnJsRkVGWWhTWFdndGZTbXg1djBmbkR1eGphdzNtNktjaXJTTnRyUEtabmE3dWlrNytFTGE0amx1WHlOaTdEbW10U3Jja1V0RzIzRGl3UlRQVFZtUnJHWjF2Vno0S0V0YXJQT09XZWprODlvWFltY1Y2MmZkSlE0b3hKUTdtYUtVUVcwdGJFRldMcWdzcXQwTXh5dFhHOFMreHhGZmkyYzBHY2M4UWFucmFqTGl4MjlXQTlTbkVZaXVXM1E1MGpHZlZybE1TSjNpeWp6Zyt1Mm5NNjNudlFlZnROSE9jdDFLNTh6aUVzV3k2MGxSNHk0N1BVeHBhcXFyejVVTWNXNE14cVlXcVU5RkswNzgyU3ZzWkxQaDJ6dWl0RVZsWHB0UldxMzAwS29lYW1Zbk9YV3BUY2huTDNKVXBScTVHb1pHeGxPS2hiVGJhMVJHNG9acExWNzUwRnlyaTBuTzhEbmVBNzFkaEU0dnAzUktWWlp5a1c2TWJVcDQ3Y1pjdEdJbmJOY3Y0cjAxVUhrazBzSGF4V2kraWR1MTJ1VXhsWGRGcHAwZUtyZlRSV3F6Z3ZTYVZGZWFseS9MV3JiaStTeU1rMmFsNXdVbDI5S2J0U09PYWVjMHAwN01UdFdIdEtuQlRrWmFEU2VsWG5KcDVzN0pMWXhDTmxIU3hpR2NhS25IaEtWdEJmWEd5MjFPNlpUZW96SjJqVll4eHdlTTA2NlJaV3RMWXk3ZFVkN0lVWWhUZGJFY3kxbGlnVlcyRUpMSHRreUxWVHlMU1gwVVNRbEc2TzhGMWIwWFppbFovT2hqc1oyeGhid3Jha3NVTEF2WGE3VW03Q2laNHJaWG1VVDA3NW11YVJNMjhSN3ZwUTBzNXJhNzY5QlV6ZXVPb0w2UWk3dllVaURpemNpOXRWOUt3c21yT2E4cU1LNmk5UXVUakZzV2VWUlpWMVF1VmtmbWpMT05UcTlXZWEwZHlwVXE3TzYyTHo3cmZGV0MxYXl2cXN4ZzJpRnNacnpwSkpQb3ZKbWFHZTR1UUJkQUJkcVkrbk0zSXVSbWFaVnp1dTJWM0VjNjlRTG9OTDFpaHRtS2Rpa210TE1xeGhxMUY4V3JzYXRWVzJNdldyS21DNjd4V3NsTjF1THFNd21lWEZrelJMVmU1OFBOTXlqZWl0MVhkOUs1Vk8yMTFtak1wMTJWRk03YXRiWnFYdXJ2TEp3cjNtbk01N25LTTRhclp6VTJER3VraEt1WFR0R2NxVktHcUxTOWF3dXF1WExKeHRIVU5QR1M2dHZJVUF1Z0FIa2JVMDdLdTV5bGJPdTIza2tpb2l3dGt5MUxhcEt6TUtaUlVsR1ozV3p0ZlBKUm12T3pMaXVyZlRxOTkxMVEycFRiZlhIc25iYTlYT0dFWVhZNWJYMGY1TnJjdkRkNXY2NzRXVHljSEYrMzBhSEZtZDdTbENTN21HL0xQTExseUhUdmJWeWRzV3FvU00ycndtZHBaVFQ1OE9aRy9qNjB2eVhOOW8yMVRKVGoxWTlJMjBkdVhMeXUwN2RUcUpIS25OWjVsOUZvQW9BQUJvWElQek55TGRVelVqUGwzMXJra2xmR3RPTFdVNWtlOW1jY2Rxenp0c3kzNWpMaEtXdXJuTkxHemkzUGxIZlhnTTYwdkxibm5HSnFkUXh6NW9JYWN6UmZSNkhqNTlmZXQrZVo4V1NvekhmMFZicklkT2trTmpMcU94amMxdWRHd3ByYUF4VGRkZlFsSTR1MDdubGkyUm5kZWhSYXc4Y1hFbldMdkROQkxmU1hPV0wybnRtdFFybk5WYkloUGFwUlNsaW1LcWdYUUFBQUFIZERPdVI2Nm1VemxzTTByTzJ1MUlyVzF5UnJaZHptRGVkVm5Nb1NxMXFXZ2pzVE9jNHFvaitjMjlkNG1ob0o2MHhCR2hXWnFNcEdxZFdNWGEyVHNjK0xQMEw1blBIbHV4WVJ2ZmY5VDVwekhsMks4c1kwL0Irazh0djBxZDViNlBjMnZaUmRXMlZ6SzFtclJIU1hobkdpa3RxNXhQUDJjeVlSbHptKzJ4Wmh6emprdGFpTTBhVTMwbDNrTjdsV3pzbE9GZlV0dWV3dmFBS0FBQUFBZDREMTJlOU10b3paWlhoR2xybXpoVzR3K24yTlNyNTI2N2JOck9IYysxdVl4ZFN6TTMxMDg2TkMzMDBkVUpGU1pWY2tpczZqbkRHdmo2L1BpbW95cGRFNnJEMGVGdWVmNThPY3FqMTlEaTl5OXNHMUhydUNyS210Y3RoSzI3bFZjTU1KMkkzVlZmTWFWMmNyamp5amV5cnRVN3pmV1RpQm5QcFBPeEVMYSs3Nk5Qc2Vkamt1TDJ3QXVnQUFBQUFBQUFaVzZtall0WkpibDdlYkl0YnlGc2lNaWVoYzFublZ4ZFpXMUlWM1RWSzhyWXk2QVFpU2xDUk4xUnFTU2I2ZU9mZGpIMnM4czFWeExYVW5DWjZMeis5aGMrQzhiZWRmUmNzNG1jZnozcnFDTHFsdGtMT1YzdGZaWjEyQlhaeUJiYXBZajdPVlBPR2M3VFZGQU43T2dHNnRaSWtxRjFDZ0xvQUFBQUFBQUFBQUFKdUlYSTA0bDNPYWF0Mm9ydFFycStxbUNzVmNrUmxMZ0ZZcHhyVVRNMFdiSm1YblhkRE9jTmltM1d2UitiOWI1UGx4cjI4VGRuTzN6dm9jWFhUbW1ZTjF0NVQrZG5GM3BjdGJXb0pidUdRM2NuYXR4ZEhNMDd2UnM4dlhNZXM4bDZmUFRCazB2dnRaMWF4WnhueUtwVGpYWlZDT1JYbEVYdWJ5SytlbEczbEhZWFFBb0FBQUFBQUFBQUFBQUJmZWl3akR1ZktaVjVyNVM5NzNoM2tKRVRTWkV0TkZBMmM1T0piNlBHY3ppLzFmaU52SEhBTnJCMTA5dDQvd0JYNTNQUE4yRVdCdFJuQ3V0VE43cU5Tekg1ekRXY3JUcmZvdk51ckxkcTQrdk00bXRrYld0NC9OTmlaSWVuK2ZUTXJFWmI3TTBjdHRYbmZVVGt0SXVqMlpSSm5mT2ViSUlVbGJRQmFBQUFBQUFBQUFBQUFBQUFkNERGcWR5TXZaMHBsZVd4UVJubGNWcFRzcmF5MElTa1F3dnpySktFRFp6NnJNelhWVDZ6YXdpM2puUE1jUzF2cmFjN3JXVmJ5c2M2K0IwNnpsYlJKZmRCVll1SlN0MTdmUHptYmFPU3V1d3VsYXR4Z0tMT3dMSXhEanJlaEpkNW1NYUtTdTZBRkFBQUFBQUFBQUFBQUFBQUFBQUFBdnVTc1JwN09sTTNxT015WlJiRzJQUVhoME9jbHdLYnFVc3RvdlhrNFNTYkZESFBqRkRRUXV1VGpKclp5TnJHeHhwRHZUdTVRekRPSUxXVmI2ZGpaWGJ5MkhTdTZxMDZTRG5RT0Z6cUlhem1CSm9ZcEMyVlBJdEFGb0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFCSmhYcU45b3RrMFlKV3pNT1AxMGtXUmFqMERsVjlKQmhWbFRweEw3cU9ZNU1JdklFcFFtdTloN3VIejQwaDNyMzBJVGhqQ1VKUjY5cDFXMEZzSjExT3lNb2tTdktyOWdaa3BqVW5lY3F1cDFjRkFGQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBbkFHWktXSXhlcktaMDRaOWt6S0xzMXphMzFMcFZpaTBzNTNoSWhibm13ZytoSVcxMkw2REIzc0hueHA3eVhYdS9Bam5DbGM0ZE8xcTkxUlpDZWtJc2FzRVlqZ1ZEQy9PVzloQ0s5NENnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFIYktnWjZyWWx4Q3lSbHJMN002TnVSSWRVYVlUSFkwSlNLb2JuSk1XZXhLTGNIMXVibmw1K1czenAzeXVhL0V3bkgxN3B3eElMdjVhaFFkZ3N1VlF0bkFGQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU84Q3lkQWpYVkpEQlZKSkIwQ1JKdzcwaWRJaVM1YkU3RTcyRWF0RjRyZkdvWHZBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQS8vRUFETVFBQUlDQWdFREFnUUdBd0VBQVFVQUFBRUNBQU1FRVJJUUV5RUZNUlFnSWpJVkl5UXdNelJBUVZBMUpRWkNRMFJ3LzlvQUNBRUJBQUVGQXY4QStmcWpQSy9TOHV5SjZEZEY5R3hsZ3dmUzBuYjlNU2QzQ1dmRjBDZkhWejQrdWZHNDVuZndHaEhwTHc0WHBMdytqWXp4di9wL0psdnBtWlRDQ1A4QXQ2M0s4SzZ5VitqUk1URXBuZjR3M1dHSFo2R2EvYUJLeE03SnJuNG1YaFQwdklqZWlMWkwvVHNySC82MWVQWlpLZlNESzhXaW1CaUllcjJJa2JNb1dIMUZJM3FCaHozaHpMWlM5K1EvdytUR3B5Vkh4TmsrS3NueGJUNHFESlF6dlZtYjM4bGVma1ZScnNiSmorbUk4dHg3S2Y4QW8wNGxsN1Vla0pYRkMxejM2T3lKTFBVYUZqK3FPWStUYlpOOU1LanV2azJkeTBMdWRzejA2cnRVczRSVE1pcmhkd25HVWdXVkVFSHpOa1FYc0lNaUMxRzYrMFhLZVBqNDkwdHhMS3YrYlJpVzN0aitrVjFRYVJZZkF1OVNwcmwzcWR6eG5aejVnUXdVbUxSRFRHSHd1SEtxL0hiakx3WDFGOUNodTVUbDF6VTR5dHUzWm1WY1dVQWpoT0U0elJnY3JGdmdkVzZyYVZqVjFYeXpIZXYvQUpLVk5aTVgwYmpGQzFyTExGcVcvd0JYQWwyVGJlZmVDc21MajdpNDBGQUU3UUU0eWl2dVcrcDI4N0ZYazZyb1k2Y3JTM0k1Vm5jdTlPZmRkcTgwSFJ4cHgrZFFoNE5xY1lWaFdGSVVua1JiU0l0b2JxcmtSNks3WlpVMVovNGdCYVlYcGo1RW9vcXhRWXpCRnlQVndKYmM5emEzRW9KaVkwV2tDY0pycHFNSW9GVk5qbXg4ZGRuVXBYalZlL2JxQ3M3WWJkdTcybGk4YkphUEdNMzE1S2ZWV2RqcnFhbkdGWm94YkNzV3dIcUhCRnVINC80VmRUV0hEOUtTb2I4VEs5VHJvbCtWWmtON3hNY21WNDBXb0NjSnJVMU5UWFN1dmszcVZ1cXpNWmRLSTQ0RDFCdkhwQzZ6Yk5jbGJrbVFQRWJ5b09pdzdpQThHK2JVS3dyTkVSYk5RTnZvcmxZMWRlVkxLbXFiL1B4TUd6SmZHeEs4UVM2NUtGeS9WSHZudks2QzhxeGRSYXdKeG1wcWFtdXVqQjlLNTluTy9XeldOREhITzB0eWJJYnVYZWwvK2lmTXhXMnJEa3NCaDhOanR0YjAwMVRmc2Ftb1ZubFl0blVXSmF1VGlOai9BT2RnZW5Oa0dwRXBUY3pNK3ZGbVJkYmU0R3pUaXl1a0NCSnJYeWUzVHhQZUttemsyOXV0dk1wRzNXVS9UVFkvYnFIaWVqamVlL2l5azhiVDcycnhzbHYzVlB4ZXhlUUkwUWVRL1kxQ0pyVUhJUUVIcFRrY0psWVBGZjhBS0EzUFQvVE81QUFCTTMxYmhPNGVWWHFWZGkvaDJOa0JzYkp4cFhtT3NUTHBhRFJHdmwxRkUrMVBVcllaaXJCTEJ4WE5md3g4ZWpEOWRmOEFjcDNBM0pjZ2ZUTFB0aU55U3hZcDRuNXRibkV6Z1RPMkJEWXF4cmkwVnlDcmN1bVBrTlFjckNWMC93QWpXNTZiNmJ5NkUrUFVQVXU3MHF4eThzb2VvcTdJYVBWM1dLY1hOaituR2R1eWxseTdSRnphekZzUjRUUE1IbUxMRDV2czd0aGxDNlRIVGxhVHlONzg3ZmVlaUQ5ZmtmZWg4MUhha2JIdEQ1RW9QaytZeXhUc2RBcE03VTRDRmRRdW9qM3hyQ2VuR2FnOFJYMzB4NzJ4M3pNTkxhLzhmMDMwN2xOd3NGRDJXZXB2YjZQUzYvaHowbEsrSTQ3bDNwd2VXVlBVUjROSHFkdGNxemFNZ1BoMXRMTWF4SnhpMjJKRnlZRmcra1psbmJ4ekZHMlQyeC9wcXRidDFONEN6MFFmcjhuK1QvZExhTXVHckkzaGdlSmpDQlNXRkFnVUxOYmhaRmpYR1BkR2N0MEEzQW11bXAySXdYU25YVEh5V3gzenNSV1QvRjlOOVBOcDlvVE0vUDhBaUd4UFViTWFZL3FGT1IwYWdUV3BxUFVyakk5TzFHQlF5ak91cGxQcU5Wa2FwTEkySVkxWldZejg2N2ZFOVFzNVdtVUQ2eEcraGMxL0RlU3M5RC92NVg4c3JnT3hlTnJMUGVWSGFTcFBKMHNiSUVlMHRHdkVMRnVtdHdKMUZNNUJPajJBUXVURWZmVEV5V3huOVF3aFYvaWVuWVJ5TEFBcXoxRE5OM3lZL3FOMUV4ODZuSTZjSjdRK1pianBhTDhGNit0T1RiUWFmVTBhQjFzV29MVTlsbkZXWXVUTVpmR09uTzBuazE3ODdiZ08wczlEL3ZaZjhzNEQ0V3N4dkkvMi9sWlNkUDdIdkVSMzFHdWhPK3FwQU9uWkluSUowYTBDRnllb2cyT21Ia3FrejhNNGx2OEFnNDJPYjNxckdQWE03STdycmgxcmkzVm1xeWE2NC9xRjFFb3o2YnVockU4aUVTN0ZTMlhZejFkVXNhczFlcFRNeVVlbnBXdWx4MTQxMnYyNnZhTjV4UlBReit2eXY1djkzZlRVaDBaYU5QMU5xNmE4bUU5UXNDZ2RCUnFjd2tNTm9FWmkzVktlUW1KU0hOeE5ySzIrbU02WmROMUwwV2Z2cXBkc0hHR1BWTS9NK0dUbVErTGtESnA5VXhPNm1vQk5UVTEweDg2MmlVWnRWM1FyRDRqTHVYNFlhUFcxZnkxams2UWpndWUzaHAvK2tKZ1d0VGRlM0swVEw5a080UE11SDB4dnVoT3owQTNBdlFZNWdjSkNZYlFJV0xkTmRFckFGdHhzaUt6dGJxdGJHNGhUbys4OXBhbjRwaS92K21ZZTR6Uys4VVZYV3RkWlJWek5ESEJ2KzRaK0wyTFJOVFUxRjRrRk9KMUtjMjZtVlo5ZDNRcENzYXNHVzRjWlNoNll3ODQ2OHJTM001VDg3dmVKNXdoTWNmbDNlSEV6ZjVGTXJNYnlQYVdRblFudkFrRVhITURoT2hmVUxGdXU1cndLbG9XeXhyR21Ndnc5WHRHUEk2aU5ycGozTmpXK3E0cWo5N0RvTjFvVVZyUFVjbnYyS3ZJNDZhajFDMnYwL0oydVRVTDZ1SlJ0VFUxTlFyenB2K21jdWxPWGJWS2MycTdvVWpEVXNyVmhiaWtRekhYU1k0NDEyUDI2bU1FcmZqanhSeHJ5UjVVeSt3MjJmN3FhR1dqVEViQjhrSkFzWEdJbklWOURZQkMyK2dyNTlVWGtUeHhZemx6TVhINzlsMW5kZTAvSWpkUFQ3VnNYSW9iSHUvYkEyZlQ2T3hWUFU4cnQxNVdJMlBNYlcwR2dQRXlhMnJhbTBYVjVDTWhXcW5KajFOVzJ1bEIwK1NoN1JXYTYxWmxsVXF6SzdlaFNFU3loYklxOFE0NExudnBEQkxod3FSUzdNMjduL01vV04wZGUzYnZhM0RhemhGeFNKeVd1R05ZQkM1TTNOOU1BYnlqSzZtdFozVEVYb0JzdVBocVdQRmZrNEJhZ2R6Mm1XUGo4TDl2MC9IN3RrZTBWVjIybTJ5dldkZ2tGR3hiZTZrMUt2MGVSNEl5RTdOdGVadFd4Z3k2bkdaQTU0aEVJbXByclRtV1ZTckxxdDZGSlZYdTF6eU9aWnp1bU5YM2JXSXR6OE5melZPODNHT3hoaldTbjFWVnJ6c3VibGRXWVJ1TGpFUVdLblJyVldOWVcrYkE4Wk5kVFdzMXk0OWMxSzZMTGpqVjlnRTdqTnpib1pUWHlPUS9JMXQwd01qNGUvd0JReFBoTW45bFJ5YkVwRk5NOVV5TnRQVHIrMWQ2bGo4WHg3T3hZQ0NKazFDNnJEeU80bVZUM1U5aWpsRzd0VjhzeDJyaWZWaE1JUk5RaWErU25Nc3FsV1hYYjBzczRJVHVWRGsrSFgycUZZODhVY2E4VThzckdPcmxHcnFUOWVNT09WS204d3hybFdQYXovT0JNQ25sWTdqaHhaMlhBY0RsaTFSSHR6SHZzRHRZMmdPcWpaL2pxWTdQdEZPeExCOGY2Yit6NmRSM0xTWmRiMktYWXUxRld3QVZOUkdaaTJJYTN3Y2liNlpDbWkydHhZTXlqZ1lES2NocXBpaXJJUzFDalJLZThyRFIxQW5LRmRmSlZtUFhNakxGdGNwVXRabnNLOGNUSS9MeGNIK3dyY0xMbjdZVTZhd2xUdUtmTDVBV1Bjei9JdGJQQ0FPaUlXaEFFcG8yTVRuazJOOEtrT1pZQVRQTEUvcGNjblE5ejBQbVVwczNXY2pOU3M2TXdNbjRiSjlTeHZoY3I1L2VZVlhhcG5xZCsyUWNqVXN5azQyK24zY0xmVWFadlJ4cnU5WEdBWVl6SEh1Y0J4WW5iYnBndHEvdXFaZFFhNGpGR2F1dktTN0ZhbUViZ3VJbnc2Mmg2MlQ1ZlRhZHoxQ3psWlduTi9VMzhZUDhBWVB1MzVtTlB1cTlvSTUyM1N2RnNlSHNVeDdXc0lCSkZLckhNcXBWQThwc2F3YjFDU2VtSFVvRmp0WTlqY2owSjFFV1dmbDEySHl2UStKN2laSStOOUwrZkRxN2x1Z0k3aXRMSEx0anJFOERMVGRRT2lqRElwdHFOVDQ5dllzREFqMkdUVjNGeHIrOVhsVjhoclhUSE9yc2thdnF0YW9tbExwaTJjV3N5Yk1lNDBWWklzcmFzK1ZOZWFHallxdXJZN0NNcEVSU3pjT3hUZS9PekFYZCtlMjc4SCt3ZmZGODFId2FUNFlReGFyTEpYNmV4aE9QankzSWUzb2xCYWNscmlBOGFOdmF6cldYc0xIR09xdWxOWnRzeVhFc2JpQU9vOG1wUUpZNWFHTDdkRVBUMHUwTGRrMG5IditiMHl2aXM5U3QwcWprYWwwQkhYbXN3TE5ObjBjbG1EZjU5NXVQdkh0M3NYVjhTVktsRHhmTVQ2cHZ4M0Z2bG8rS3gxSjJtWWxvdHdqR1NKWTlMVjVkZDBlaVlsTmE1T2Zad1dlbXJxdXh1ZG1EL0FEbjN4RHF6SVhqYlVkTlo0bUxpcVZ0eUtxcGZtTlpON2xkVFdrTFhWT2IzT0YrcTV4Ty9xdHBXaldzNVdtaVYwV1doQjhKajcwUHVQUStUV3N2UEVOMEhYMk1CNG4xZFJhUGxSZVRWRGhWTXUzdTIwTDVRUllKY3ZHMVc0bFhGaVpOWGFzOXBqM2QydU9vWmNaeWhkZHJ6YXVLdGRzN2xsUTRWWFRpVVp0cTJQZDJyY3F2dDJjUllLN2JjVWg2TTZYWWoxUXJxVTVObEVxeUtyNTZpKzFnL0l3Smcvd0JnKzlSNHZtTDVXYURTL05MUXNXbnZFeHdrc3U4VlVQa0c2eGFRaTltb3R5TklneCtNZks4VTQ5bDgvVFk4b0w1SnR0TjFscmJnNkV5dFl2NWFzZWc5eDhnOXBqajRyMDc1Y0t2bllmZkpmdDBIM3BIaFovb0lXaHdxN1JiNlRja3czNHpMcjdsWmxOdlpkVHNUSXJPcWJPN1hlbklBeXZKWlExZGRzN3JLTFIzSy9jVW40aW5SUmhwdzlXcFQ2ZzljZkhxeUZ0cGF0djhBYnV6eEY1dDZrM0d1WVA4QVlQdkxmek1jU3h6cVYwRjUzRXBCc0xURndDOHk4bGFoajE5eDhtemt5Z3NiVDJaWFRia0g4akhsMlZaZEVVMk5ra1VJNzhWNjY1R3RKZSt5ZG1kbHB3MThxKzg5TXQ3V1puMGZENWZ5ZW5Kb1QxRjRvMmF5QkZCTXJwbGRVK2xJY3FwWmRaM3VtVlYyMk13N3V1L2hycGVuRmdZREJjZEExbzl0ZlpldCsxWm1WOGxCZ0lZUFh1QXZTMVdYWGV0MkFSR0dwNmV2TEk5UmZsZlRTTEtjSCt3RjVXV0oyN0tEeXE5b2lOY3kwMTBpNjh1VVJyR3hzSVZ6TXplMlBlTnFpc25jeDA3VmFtbFpia3ZiTjlNUWZEVkV3bmszUW5jclNiN1ZXb3RwUWQxRE5LME5jS2ZJZmZaQjlaSGRIeVl5OGFoNzVyODdzZkdlMDE0UXJtNmtueEJFZktqWjFLeHZVWWMrMHhzaTF1bktibE4zZFNXb0xFeHJaWXZKZGNHM0FZZk10SGVvM01PemNzck5ObTlRSGxDdTQ5Y3B5ck1jNm96aGlZclk3WE56dXFYamdZQi9VVi8yTXRkV1k1K280NEwyWGhGWnk4eDhSclRWanBVTTNNN2ZUR1hqTFg1SEhxNzFtWGFDZXVMUWNpMiszdTJXdEIwSmcwSWNqVUxFbmtaM0RPNEp5QmdkaE82WnlRd3JEN2U2dy9uK2pkYWh0d09LazhWbzRGdmprVUhQalp0cGpXdS9YZnlhWXdWV0dZOWRpUHVHWERSUmc0eUt0Z2RjZCtMMzFkcXdOeE53K0t4Z2RnSFVCNVFpTWswVUlzWVlNeWw3V0poY2hrQWxMTW9iV3B0UGw3VUJTeHhzS0tBb3pjenRkRVEyUGU0VlpXUGhzY25aNnN2d3VPemNRSU9oQjNvelIrZmtaek01UVBFTytucGY1a1BqcmlMeXNKbVUycUNmTzV1YVl3Vk9aOE04R0cwR0lJTVZJS0t4QWdFMTBTaTE1OExhSjJLNXh4eE5JSjd5NU8yL1F5d2ZFWTh3cnUyK1hUMkxvRHFBNzZNdTU2aTNieHNOT2VUNmsrcXNNZm5rZWY1TWVXL1hSZzBxVjFxWnVaMnV0Szl1cXh1Wnc2TzYrWGIzSDY0TllXT3hkdkU0Vnp0TE95MEtzT3VweEU0Q2NKd25FelIrU2svV2ZCOU9zN2VablY5ckw2WUErb3pPUDBLTmxLbGdRQ0FmSVBNR0plUjhOcWNNZFp5cEUrSlpZMXRqenhEZFdzYk9xRWIxR0hPdE1ON3RGTytobUpieHN5cWUxWUluNnZHSGd3SFVEYm1PdlBJOVZiZDNwZGYxK3BOeXZ3eU84ZGJ4dk5kaThiS2ZxcTlOL2p6YzN0VDM2VTFkeDhpM2NSZWJQK1JReDJldmVhZDlwM3AzRk0ySnFjbVdGeVorWE9GWm5hTU5UajV0VGlJRjBYOTBiaS9yUzZ5K21FTkxNNCthaHNxUENWdThHSmRPeldzL1RDZDFGbnhWMEpMUXNxdzVGWWh6QUljeDRjbXd3dVdtL2x4T0J0cjlLZG1xd2FjZVpOZUhaTXJnYXlKalhkbXpPcTFCMFFNVGgwMkljcCs1a2VuVjhjYTg5eTNFQjd6NzVZcCtyTFhWbU1mUEt5cFczdnByc1ZFN09NaVZ5eTBXMkFWbU5qaUxTdk96anorVUdBelpuS2NoMEd4TzQwMnBtcXpPMERPelpDQ09oaiswOVUrdkg2WW8vTGpLdHVRcVl0Y0YvR05mYTgxRFlpdzVLQ2ZHUTVka056dDA3SlZEQ1p2NU5SVUxHcjAxMmxhNDJHTFBXZ0paNm83UjhxMnpwc2lKeXNPUFRhYWEvUzFuYndzZVA2cFNvZjFPMXVqZnA4WUNZcXIzR1VicStsOHhmQUpXRElNK0lRemhTOFNwYTN1RHRQSW5ub0hJZ3VJbmVCaEN0RFdmazFOVHpOa1FNSngyVDRPNXVibXgxRnRnbmRuS3N4dGNKa2ZYNlIwbzhWem1xMm5LV0hMYUhJc01MRXpjMzAwWnJwVmUxSnNyU3lzaWFtdWlWczhXdkhybjRndFlmTXVlRWs5RlIzaVlGeGllbVZpY01DaU42cldnZjFPNHg3N2JJSlhpM1d5djBzeXZBb3FtYTQ3YXJNUUh1V0llWEh5UUhWc1ZJMkswYXRsNmNtRUZ6VHZxWitVOE5JaHBhRUVkUTVFNWd6UU0xMDNBMHJYdUhzMDFSN3pPTTFQTTNPVThkUE04emNIbXFMOVhwRVg3cXY0NWI5M1hVV3RtZ3hYbmFZVHRXenNYVDRhMmZEV3lwYjZYZkRhK0RCeUorSDVNUHArVExLYjluSHRFV3F4eXVFOFhFcUVEWTFVYjFDSE90alhXV2RLcUxMNG5wMFhCeDBIZHBvaitvcEQ2amFZYjNlRHpFV1VWZlc5ZW95eDUzR0UrSWFmRUF6YVBEU2tOQkVLNk01TUozVEJkUG9hZG9UdG1FRWRGRzRLMWdxV0JhYTQyUTdDZVpzemM4VFc1d25FOVBNMzByL2ptTDU5UGlmZlgvSExoNTFBSWxEdkFLS29jdTNYY3NNNVBPVHprODVQT1R6YlRiQ2Q2MHdXV01lRjAwaytLRlVzeldlSElzTUxPM1RVMU9KbW9HWllMN2hHdGQ1bzdBM05UaVFVV1VwczQyT1NiNk9Fc0VjZVNQQkVJTy84QVhKaE9iZE5UVTFOVFU4aWN6QlpQcE00Q2NETlRoTzNPMloyNTI1d25DZHVjVE5OT003VU5aRTE1VmRKTUR6anl2NzAreU0xZkZXd1JLcmZUVmpYK25XVGw2WE9mcFU1K2x6bjZYT2ZwYzUrbHpuNlpPNTZYTzU2Wk81NlpEYjZaR3luRTc4RmdhZlhPV1VJY3JJV2ZHM3o0NitmSDVFK1B5SitJWkUvRU1tZmlHVFB4REpqNWQxa0dYYnpYSXNBK0lzSStKY3NtUStxTWhnMkpsOXVaZVVXTmw3eDhpemZ4RGdOa1BvNVZoWTNQeCtLdEErTHVueGQwK0x1bnhWcytKdG54TnMrSXNuZnNpdmMwL05tNXlFNXhMR0JIcmwwL0hiWitPMno4ZXVuNDdkUHgyNmZqdDAvSExwK09XejhjdG40NWJQeHV5UDZ3NUg0Z2VUWGQ4VDAvK09KOXlmWksyU2RyRmVmQjFHSDArNFExM1Z6dU9KM0duY2FkeHAzV25kYWQxNTNYbmRlR3hqQ3hNSTZCeUlMMmd5cHVteUhHUXc0cnhrSzlhWHJTQjhZdzAwUERoaWZDMnJQSWdNVXhHMU1lMDg3TFl4alF4VWF5ZkNXUVk5UWpMVXNacW94MmVpMXM4K0dNN1ZZbk5ValhrenVHYjMwR29sbGF4Y3FzVDR5dWQvSGVXMGxCTnpjM056Y0FZd1kxaG5aUVQ4a1JHRENlbi9aRSs2djdJYlJXeTNvWUdCbnRCa1dpZDFXaHF4V253U21OZzNwQ3BYOWphVHRLME5OaXpYUU1WZ3lIaTVtcHZIc2h4YXpHeExSQ0NzMlZpNUZpeE13UVpTTk8zVThzcTdVRFRIWWR3djVMUk1ldmlleFZMTTBSc3FOZFladUpXN3dZalRzVkxPN1ZYSHlTME5yR2IzMDBUQmoyVGdpd2tkZHpjM0tyMnFKcVc4YU1GRmpUNGZVNDBMTzRvbmZzaEpQVFlsSjJzd1A0WXZ2WDlreVB1VlFaMm9PNElMN0JCbENDOURPUU1ERlQ4VFpDOVRRMDR6VDRNbVBqV3A4bXBxTGE2UVpXNStuc253b2FOak9zTmJEb0daWXVUWUpWZTFpNng3STJHaGpZbG9oQkVWMldQOWRRYVluSTJ1VzVLT1p5N2VLOG9sZGxzR0JaUGhLbGc3U20zSVlRM3VZV0ptaVlLTEdnd3JEUGg2a25PbEkyUTBMRnZsQk1WTFhncVFEdDByQmFpVDRoNHpzM1RZbk1UdVRreG10elV4LzRwaS9UaHdTcjdaaysxZlRVMU9NS0NjSUdzV2ZFTkJrTEJhcG52QTdKTyt4bjVEdzQ5WmpZZDBkR1RycWNpSW1VUkJlclRqUzB0YW9SUVhhNXhUV1BKQXRTTGZhSWx3dkJIRnFUdXYybU1RYjlpWTMzNWg4NGEvVmRuTnM1TnBoWm1pbmliQUxheDcwL0RtRzZoSTJjWTE3UDAwZW9SbWd3N1lNZXRaK25TZC9VYTJ4dW01ekU3azVOUEptcHFhNmE2VmVNV1YvVDZiMHBQMHpKSDVZNUNkeGhPOU82czVBL0pxY1p3bWlKM0xCQmtHQzlEQTZucDNySmRaM0RTcU0yOE91VzNjeEs2dVVzYlEzTVpPQzJQemJFcDVGYTFtVmZYampIcy9PeVBGbU8wdSttekUvbWJmTEg4VlhOeXR4aHh4eWRzRjNDczFLWDRtNU9MQXpRWUZlUFNuTGF0ZTdpV1M1YXcxTm5DTmRZWjd6WW5NUTJUbXhua3pqT00xTmZKeUU1VGxObWUySkgrbjB6cFFlbG4ySzFSSGFxYU5pTkRRWWFqTkVUbTRuZE03b25OZmw0aVYwZHhqeEV1Yng4aWpremZTckhacVR1UGtXeW12bTFOZkFaV1NLQXhMTXA0dGsrVm9iVDVNeGZOcDl4OU5Nc1BieDREcWZjQ09tKzZudEZNY2IrVVFIWTBER1FxMnBxYTY3RTVDYzVzbWVaeE03UmdvTTRJSnlRUy94WE0zNmNQcFFmTUk1RHpCYXdpWDZJeUdNN2lOT0ZiUTRwaG9ocG5hTTRFVDZoQTdiNmNleXJ0eERmTFN2bTU5bUlvcXE4dTJMVndHUmxDaFdZdWVuMzQ2blV0K3F2Ri9sKzVzaHRMV3ZPektiZlVIVSs3b3AwYmxnZ093Um8vSW5RcjNGSFFzUWZxTTRtY0RCU1lNY21ER21xbG5kVVEzTkMrNXlpZ3MrWWZ6UjVQcVovTTZWSFJnUGxoeHMxdUdxZVJCY3dndkVWNTMzbmNReTJ5cFkxeFBSRjEwcEhCZHhtNUhycVYwUGMzOGRaTzVTbkpyN09SeEtObkl2R09yTVdNcnJlMHJWWFRPNzNUN0VIZE9LZFdxZnpzZ3pHKzRXcnRxQVlkZ3oybnYwVTdVamlRWUsrNDlsRDB0cnFPbTVhc1dNdTU3UmJ0UmJhZEc4UTNPWVduT2NqMDFPTXhWNVpOemNyY1plVjJjM1BKNkw3cWRpWkEvTlhvUnVOVkNOZEtsZlJPZ1c1R0lOOUtxKzQxamN6WTI0M1ZLMnNZWTFXUEh1ZTFiMjIyb2Z5VXFUdU5aY3VNak1YT3R4Y1hqTE1nS3JPWGxKMDlvMDRPbHgvNVI0ZXh1VDBqVlpPeXJsWUdXME5TVjZibnZCNExqa29nOGlyS1pGK0dweUk5VEllaUhvRHFGZTIwZGZrS2JYb0ZnSFhDSEhwZ2o4eGp5YnJXZnBtUU4xcDhqRHhYWENaYTNtQWJJR3VqZmxxN2FCOENBUmNNVmo0c2ljVnFodVlxZk1vWFViOHgrUXhrWml4cnh5NDdpVUI3aTBTdHJEZmpmRDFEeEx2YjNGSDhwOXpIK2lyL2RsTThyRnVJaFZMSXlsT3FIUnNYaVZPb0x0UTFiQzVuSUhFRm9LOUI5U3pYY1VRL2FScm9JamNUYW1pSUI4bjhlRkYvTHd2a29QUWpraWZMN0IyNHIwUmRkSy95bGcrb255YXNKbVU1TmVQT0xQRGR4RXNNVWN6WXdWVjFRb1Y3bUMxMVI3eVQ3ekd3bnVuT2pDR1RhMlEwOTZ4S3Y1RDl5cnliSU1RYmF4K01LaG9WMUFTc1M2R3JjOXVuM3BQOUt4VThrdWpLOUxES3J5SmJnc3FwOUpkZEgyaitaL3NqbDFFSDExK3pmNjZhM000NmFaaDRVL0pXZEdLZkxyMjdlcUNNZkx0eU1RZEtrNXN6OG1kcFJqUFpWM0tNYVczdmMxZWhXekZ6QUNBWWc0cnZ6MnRGN3ZERXRLNm10TmVMVGpDN09acHVFYkFFOGlhbFgzTjkxSStxMDdlZ2ZYY2ZxQk0yRENrOW9ybFp5RmtaTlJUTEI1RTBSQks3U3N5S3hUYlhlOUxkNmpKbDJLNlV4VG9zT0JIc3krT2lOeGExZEhvSmlwenlMSDdsbEs4cmNwK2QzeUR3VVBpWGphZzlmWmJHOFJSc3pXeTMwcXphNk5jN0owSGpEQUpQQktvS0RjQW0ySUx6a0s0ems5S2NUWU9XdFNzeGN3VnN5cE1QRGJLdHp2UzN3eVVnUEV0N3EvQWU1eHhxUDc0UzFXdFluYmZlcDRhRmRkRnNJbWcwMTQvMmF5aTlubDB6djV1aVgyVmdlZWcrc0RveTY2QXo3bC8ySUl2NU9GS1BvVDVxVzZBYzFIUkk3UW5aaWpRaWZscWZFWTcrVUp2RTV6dDE0c3R1YTF0Y1ZaK2xkTFdUbFRSSHRhdzc2QVRJL0pwVDN3Y3BzTElVMVpkSHFQcDV4V1pZUk5UVVh4VTN1RExoOFpqbWJuS2VHNkE2aXVETEZsTjdVbnRKa0RrTEpucnF6NVBjUi9xQWpleDhHQTZqRFVFQUxIUFljNWtIdDFmTWgwZjlLZEc5ZU5rKzFiRzMwUmZFclhsQzNJc2R3L0lvOGRsN3NmNGhjYUV5dFN6c1NZbGJXTXdycWoyTXcrVEVBU001ZGdDSTVtQm52aXVyVlpsUHFIcHpZck9zUFIvQ3dUR3ZORm1aUUtuMTE1UmF5L1JXTUVWaUoza3lKbjF2V09IUDVGTU1VOFNWNE43eHhzUUdmNlR6TU1hak1XYWxlVDNQenMrZXMrSVIzS1U4eXh1aWpmUURjYU1kUS9KVlNXSnFyb09iYTlsZnQwdy9GdFdOeVcyNGErUUNBVEkvS1dXK0tmZFVFOUhXM25uUFVtTlpEQVBKQUxabEFveU9tS3d2cnNScXoxQklJTmVSRnFhaTkxNE5CN3RhOWVQd3B2bGlmVlpXMVo2RHowSDFnZEhYb0lQZkwvVDBUZmJwL1lyYlhSRzR0WXZiZGpzZ2JnSFFmUVBhZThNMU5TdkVGQ3ZtSFE4ek44R0FFeXF0Y1NtNjE3VzYwNDl0N0xoMFVTeThPdU9nUXNka1M4ZnAxOGowN0FiSkxQVmgwNTJhK1ZZZk00UUxva2Vjbjh4U09tL05saDRsSzNqMU1ueVY1R2x5OFl2TlFUN2tpWlI0cWdkYk1mUTFCNGg2TjlZRU1JMFpnVkF2ZGFickZISnNoK1Rmc0F4RHNUWGVwaURvcXdua1dPeTNqcFJodmNPL1RpeG1lMXZDVGU1bW45UlRRMXA3eVVCbTFpOUtNQys4Qk1QR2xtWmJhc1gzYzY2TEwvNi9wdUY4WGE3VllWR2RudmwyRnA2YmlMbVhmZ1ZVL0FxcCtCVlEraFZUSlR0Mm1KNWEzM2lzeVQ4cDQyT3c2cmN5Vi9sWmNhdHFtdWNvbVFvVzZBNmxlYjVmR3J2RG9VS1FpSzNBc09CRUkzQWhMWm1zYkhnUGJUOXF0dGRFYmcxOVhGaEI1akdNZFJSSzZiTDJBeDhhWDViM1FMQy9pSU50YlFEYmJrbGh1T1N3VDAxZ3ZleHNhWFgyNUJodDFLMkxFUzczRVdaSDllcklmRXR6ZlViTXh5MittRTdZdEg0OWtUOGV5SitQWkVQcjJSTDdEWThwRzNjN1puS3dXVnZDaEFERlQzRmFHamxGSDBDVlpBWmN6SElvWWM2dXF1eUVaYVpJdHducURyNGluWTh3VERVTExiRGJZQnlOcmNtL2JSdWxaRHFSd2I3RjNOOGoySzY2cmNvdW9VdE9RU2IzMFZTeHBTdkdzeWIzdnRTcDdUOENsRStORlFaMmN3MlR5MDFFOE5MZktpTEwvNjEzM2JtNEpYL0FPWXhuS2NwVDlWemU4eGg1bGgrcUs3MW52SzNUMmd0bmFSNFZaQ01ocTZLa3J5UzRLbjVLY3F5aGwrSHkxUGd3L1VLRU56NTl5am9Ud1g5eFRBZGoyanF0b0o1RjJnbXl4OExDNVBXbWg3aWIwb0dKVmJaWjJNWEhqNTltcDdRMnp5M3lmN1lhSkc2eEZtUi9WdSs3b3NyL3dETWJyaS8yRzk1VDRyai9lT2hFMU9aRUJCNkxjd25KYkZLdWhmSXJ5eGJTOVRINU45QkI0SUE5TnhZSXpjais3VzNTcCtEWkZmYjYvWU90VkExMnI4cFF1TGpTM0x0dEE4dzhWaHVudjhBSVdnNkh5RjhxZmRaa2YxYnZ1NkxLLzhBelc5ejB4djV6MDlxVis0UUNCb09tb1ZuTWljZ2VpMnNzQnJzQ00xYTNZL0ZmbXdLRkF5TDJ5Ylk1L2ZFVnQ5S25EQzJzMU1vaDhucGpZalI4bWxHdHlMTCtoWlZoc1l6WHljcG90R1hqRjZEK0tyeTFnMHl6SS9yWC9kMEVyLzgxdmZwakQ4OCs4c09ndnNCRDlxcnVFYWdlYkJobW9WbjFDQmgwV3hrbGVVVmx0UjM4bUZpbkt0ejhzWE5DZUkvd0ZPb0RzUWF5YTJVMXdBa3JnRlFMNmNlV1dQYTI1M0FKc21hK1RsTkZvbEJNVEcwQWlhNEd0NG4yV0tFOUx1SDFKTWordFY0ai9majQ3WkRYWks0eW8vL0FNZVpUWDNyYlF0eTRvL1VNSWk3YksvbysyUDZVaXZkWm1ZbFRWNW5wMWt6ZlMwTmJMcm9IMU43bXVoRThpY3Vpc1ZQTlhobzhhbEdPMTltYmNtUFYwSjJmOEZXbnZBZFFkdktueFhhaFl0Q1FJWG52TmRmYWNweEppVUV5dkZoZWltVVh0Y2Uvd0RxdlVNZmlaVjkyU1AvQUlPM3lxVEoxOE1wbGRUWDNYM0pSWDVKVCtpWmdnVnBqNUg2a3B3em1sQSt2Sy9vV2VLdlNQNThuK2RKNlZsTXQyYlVsV1UxVUs2bnRBODVibXVuR2FnUFFFaVZidmU2eGZUS2owWTcvd0FSRzZLeFVzb3lWTEhwcnJ2VTVHQlNaWGprd1k2VmhzdXRKWmtXV3pjU2xseDA5S3lXaVlUMmVuc3VpbmhzNGNmUjIvaVV5OXYwKzVkZUthMTFsMWEwVi9vY1N6WFVzMVA0ZmRHNUtOeWlaUDhBUXU5L1NmN0dSL09rOU5xSnpQVm1CekE1RTVnd29HaFhYVGxCb3pVTTFDc3JEV055VDBtcG1MR0Uvd0NNcmRGWXFYclhMSDJtYkFuSW1MV1dsZUlUUHlhSTJhMFp5eDVUY3dxdTViazVUcmF1YmtDZW0rcFdyaytzWS9ZeTVsYzcvVFBoTWppTUxJRXlBVXIzTFB2cXM3YlhvTGEwUDZMRlRVc3Zabjd0a3hyanp2WGhaWDRyeVBPQy9tejByK2U3QXlXdXA5THluamRqMG5HdGMyUHVjcHVCelBwTVpOZE9abTVxTFcxcm50K2tWc3hab1Qva0J1aXNWSkNaWWNNcFdvdEZ4d2crSXFTV1pMMlRjOHpVNHpVcXlHbzY4cGtaOXVXa0hxRnEwL0VNeE5yYnlHNVYyMm10aWQ5S2IzcWc4NGJaRGR2b2crdTIwMlQvQVBIOFF6Z1NqSWJHUDRyYlB4WEo0MldGeUpvVGpPQm5tY29HbXdad21waTFXNUQyWFZlbUl6RmpDZjhBS0RkQjRpdWw4dmV5a2xpM1RVMTg1NkwwRUh1LzNXL3haUDNkVi9vbnJqajg3L2RuZ2UwV0gySFJvQkJQQW52TmFtb1ZFMFo3VEN3ck13MzV0ZU5YMEovekZiclhrRGpkaThJSnI5cGVuKzVaTFA0OG43K2dpajlBZXVML0FEZ2JlMC9VM3RHOWgwOXpOelUzMTFDTlRIOU9BVEw5Uk55emNKL3pnMDN2cFZjMVJOVldUQ0NwL1pIdkQwUGxMZjRzcjcrZ2lmOEFudDF4UE9SV1ByYy9VZWp4WVRCTlRjOFRjMUZVdEthSHVZL0RlbXpJeWJjcDRUQ2YrQURBM1QyaTVBY1BRVjZFZktZZXA5b3YyMm44dksvazZDSi81emRjUCt3dnREN3gvdUVNSHlLdTRLeHRjRVZya2VwbmgwSi80Z2FlL1JMR3JQS3ErUFE5YzFOZGY5SDVhNFRNcitUb0luL25OMXcvN0RlSzUvdWU3ZjYvKzdvcWt3S0pYZzJNcitvVVlndHRlNTV1RS84QUdEUUhmV3U5NjUzS2JZMk80bXByb2VpbngwVDdtKzdLL2s2Q1YvOEFuTjBFeFA3Ri9nUWRCN21MQUpXbktMZ01xblB4OFVYWkZ1UTNRbWIvQU9UeWdQVkxHU0RLVjUyYTdZK1BZa0loaSszVi9mSy9sNkNWL3dEbk4xeGpxN0lPM21wcjZWaEc1VDZYbFhUNGJDeEkzcXBWWHNlMXVoTTMvd0EwUE4vSW1SWlhQaTFlZHJFdGd3SEFhaXhJZWg4cmwveTlCSy8vQURXNnFQTm5saktzVEp0ZzlJdEE3UHAyUEQ2b3RjdHk3Ny9rSjFPWC9SNUdjaDhvWXJFemIwZzlRSm5ldzNuNkpvYWFIbndJTS9EM2c5T3MydU8zd240YTgvRHdKOE5qclAwS1Q0akJXZmlYQ1A2amxQR1l0OHZJUXNUL0FOYm1aekhUWDdHNXY5alJuZ1Rtc0xuL0FMbXlKM0RPWW5OWnRaNG1weE0wWm96Um1wNG0xbkpaM0ozRE4vOEFBLy9FQUNjUkFBSUNBUVFDQXdFQUF3RUJBQUFBQUFBQkFoRVFFaUFoTVFNd0UwRlJRQVFpWVRKUS85b0FDQUVEQVFFL0FmOEE2MW1vMU01eFdlUzJhaS82M0lzbzBta29yQ0tLS0t6Zjg3bGhSS3haWWhpSHZyRi94dDBOMktKVkY3bU9XbENscVZpOVNmOEFBNUhZb2w3a1BFMlFmc1Q5MHBDUlZGWnJhOGVYb2oxc1hwVDlrcENReXl5elNjb3ZZOGVaOEhqL0FQSkVXMnQ2ZnFreWlMd3lpeFBGRkNXV2VmbzhmUkJuM2xMTjcwL1EzV0VxR1hlR1hpeFBMd3lVYk5QQkZjSDFzdmFzSmVwc1E4ZEM4aWVPblJXS0xMSGhvZUtvaUl2WStDeE8vWkppR2Q1MDJXNGtwZE1XeXRpSkQ2eld5Y3VEczFmZ20zdVcxOWl3aDRaMmVTSDJRbCs3YXdoZERXR0xaSmsrUlFPaUs5VEZsaTV5K0NYS0ljbzVRczJNZldIdVpLTmovRG9YT1h0V1pFUjR2WXlpcUk3YUhsQ1cyUlg0YUJMMExZaThVVUllR2RsVmhadWp0NHZOaXpwd3MxNnFLMldXV1dMTDJJaXh2RFlsdXNzdjBzUXl5ODFtaWkvb3NXV3h1a0o4RFpZc3Nzdlp4c3N2S0plaFo1Tkp3alVjczBzNFJPZGptZklSa0xONHJZeE1zc3M0S3doNFpxTlRMTlROUmJFNUNiMnV6U3pTaWZCNXY4aHAwZUR6YWlERUpiMmEwZklqV2pXaldmSWhTUkYySWtTVmtvMmZHZkV6NG1mQ3o0V0x4TVMzMmhua1I1L0ZQVnFpZjQzaWtuYklSRUo3NUQ4WC9CZUpId3hQZ1I4RVQ0WWtmR2tRVkNIaWpTYVNuaTkzQnBPaXpTaVVhSlFGQWpCc1VVaThWaTl2WWt5alNhY29lK2pTVml4U0tLd3hvYTRLSEU2UlcxeVluaWpUNkVQRll2YmUrc3BEOVNleXk4VUlXNnR6a2E3NkY3V2EydXhTOXkzZGxtdjhLc1VkdGwrbHhLTmY2Sit0bjN0ZU5BMFhSRjNteXhzZm1WMEtZc1NsU0ZMWkpqNUlxMGFQd1c5Ykg2SmxOaTRMeklYQjV2SGZLUEI1dnBrWlpYRHJaSkRUUjQzeDdsM3RzY3I2UHNzVHQ4Q1dHenNsMmVhVkVZNjVXUmRHc2hJY2JJNFpkUGtaRkNkZGlrbUordGwzaHNzMHQ5aUhWbFdSNHl4SW4yZVR4T2NpUGpVVWVSU2I0TkhrUEJHYWYreDlDeTFZMVJCbzdOSDRhdnBrWlg2K3NTallsaC84RkhuRkZZWWp5ZGlRMGVOY2lpVnlNV3hvK01pLzNEalpHR24ySjVkaVc1bjJUN1JFa2p4OTQrOEl2WlE0RWZ6M01UM3RpZGQ0aWVYdEVEc2l1U1hQUXV4dmtsMGFPQ0RhZFBkUXhMMk5GN3BmaUpxUkYyaUpOY29naGtlQkprVnlOY2t1alVxSWN1eXY1R2hQYlF4STBvWkRvWkhIMklhTkNFdHQvd0FMUmRkK2lSRG9aRHZIMkwwVi9IWDRhdDBpSFJJOGZlUHZkWlg4dEZGZmhmNlhtUkRvWjQrM2hML2JObC8yYVNtY2paRjBPU1BHK1RWaTNpdjc2elJSWDhmL3hBQWdFUUFDQVFRQ0F3RUFBQUFBQUFBQUFBQUFBUkVDRUJJZ01FQWhNVUZRLzlvQUNBRUNBUUUvQWYxNUoza251VGVDTjQ3YzJqZGQyYlJ3dHdKejIyN1J4TXBmYWI1YWhkbHZtcktmUWhkWjJYTFdVK2hQdXp3d1FSMnZRcXJmU040MFF0WGIzeVBhQ1dodjd4UGdidEl1bDdLcVNsOUJzWWxhT1o2ZWhpOUhybmE1bnd4WmM3dEg0MGRoWGVxL0daSkpQVWZBdHB0RHRWVVpHWXF1U2QzZVNTU1NUeWVUenRER2lvVXRubE1wRndNeU1rWklreU1pVUp6WmpRMFltQmdZR0Jqd1NNcUtLblN5cXAxTXBRdUJqcE1URXdNVEVWSlNvczd3UnhSZkVxcE1SVWlwRWp4YU9DQ0NDT09DTkoxZG9JdEdzazNqOXlTZWZJbnF5WkVDV3M2TFpvZ3lFK25pUVNKNlNTWkNxdTJKNk8wRUM2Ykl0TjNaaUtYZGFNZ3A2azM5aVZtejJNclBrRkxneUtXUUt6SnNpWUo1NUpJWWgyVjJJcUdZM3AxZGs3WWtsTDVXaUxNalpGUWtOQ1FxU1BJOVdqRVRzNlJLT2RrYi9SaUdLMzNnYUYycWhXVnZ0NEYyMk1SQTBLeUVSWmtpN3NFV1F4YXgxNDRXSVpUZGR5ZG1JWlRiNzNvMVlobE52djRFRVdZaGxPc2ZoUVFSMC8vRUFFWVFBQUVDQXdRR0JnY0dCUU1FQXdFQUFBRUFBZ01SSVJBU01WRWdJakpCWVhFRUUxS0JrYUVqTUROQ1luS3hRRkNDa3NIUkZFTlRjK0Uwb3ZBa1k1UHhCVlJ3Zy8vYUFBZ0JBUUFHUHdML0FQUDVOYVR5QzlpUjgxRjZTTENaNXIwblN6M0JWNjUvZXFkRUx1WlZPZ1ErOVU2REE4Ri9vK2orQy8wZlIvQlY2QkE4RnJmL0FCN081VjZLOXZJcWtTTXhlaTZjMzhRWG8zd29uSXJXZ1A3cXFScDkrYk11YW5FZitpOW1ISGpWYWpRQXNWdjlUdTBLRWprcVJYZDZsSGdRb281S3NKOEE1dFUraTlLWkU0R2kxNExwWmlvKzlxTlU0bE9kRlJzL0phZ0RlV2hyT0E3MXRUNUtqWEwyZmlzR2p1VzE1SzQxL0ZlMUNuMWdLMmxpUEJZTlZXckFyYTBLRlVpVEdSWHA0QUI3VFZQbzhZTzRPV3V3ajd4azFwbndVNHpxNUNwWG8yM2VPKzJibkJ2TlVtN2t0UnJXK2FxOTF0NXcxVzFUamErSnZmcWhBbk94d3RkRFBNSWkzRlZDL2ZRazdXSEZhdm8zTENZekgzYmRhMGs1QlRqR3ZaYWYxVnlHQXh1UXNtZk5hdXVlQzFaTUhCVGNTVHgwWlN4VXQ1MEdRK3lQTk5aM3Bya0gyZzVLK05PcXgwT3k1WmpQN3BvRmVqNnZ3KzkvaFhJVEF3WkRmWmVlNE5IRlNndG54SzlJOG5Rd3N3c203WkNETXFtMFR3RlNyeFJLY3pLcUkwSkhkUlNQcWN0RFYxQ3RZZmNzZ3J4b3p0SEJlakd0MmppcXE4NGhvVW9BbjhUbGVlNHVObFZocFNVenZyM0l1TzlUc2U3dGFvVGlwQVRLOHJENDJBcTcybFBOY2ZVVTBicjZoWG9WUmw5eHlBVjZQVTlqOTF1a1BBV1hXYTcvQUNVM3VudzNDeXF3OVRJZTlUdTBHTTdJODBHZDZoY1QraURzMEhJT3lzSVV3cWI4UFgwWFlpZlZYWENYM0JJTldyVi9hL2F5L0VjR2hYV2FqUE0yNExNK29xdm1SQXdiUzBUd0ZTaVNpb1BBcHdSSGVpTFNydVNubXJ2cityamlZN1dTbml6Y2Z0MTQwYU1Ua3JrTVNIbWJDTnVKbGtyMFFtYWtxb1Q5VkpPZmxob09kMnRVSnpsTlF1ZG5EUUJRS2twcWZxNktjcVczWGk5RE81ZGRCMW9mMCsyZFpFbzNQOWtHdEFhMFlBYnJERDZPYTczcTl2VnpwVUlIaUZlNlBFN2xTOUxoVUxYYmU0aFkzVDhTbUs4YmEwVkJiTkU5eWJESE0yVHNhenNqelRXZDVzaGMvd0JMUVZQTFFCOVhSVlBjc05ITnU4TCtJNk5WdnZOeSsxZGJGMmZyd1FBb0JnQnVWYUROZFZCTW9lODlxMnVHYW0wa0hncFJSZjRqRlVrVDRGZWpkUGdWN3pDcXllcXRMRnF1QnN5dGx1YW5QenRFOEJVb2s0bE9kM1dRZWFOaEhlcGFCYjM2ZU5sYUtsZWF4OEZ3MGEyWG05NHpYOFQwYkQzMjVmYU9zaTBiL3dBb2hRQURBWklra0JvelhWdzV0Z0RFNXJVSllWcjFHYXBaTm1xVkp3c2s3MGc0NHE3TVQ3TGxxNnF3bU14WnRUNXJXSGZaZXlSemRTd0N4N3M5Vk9kYkM1cDNPd1djN0NnYlFBcWxVRm1NK1NwcXJNNmV1Ym84MUpyZS9lcEd5ODN2R2EvaXVqN0IyaGw5bTZ4K3FBZzBDUUc3SlRKa0JpcmpLUXg1cTdpM0pTRHJyc2pacTBXc0pMQlNMWnFjUHdVbkNSc2xPODNJcXVvN2lwa2Q0V3FacVJFbEk0dFYzSlhPelpPeGpNaFZOWjMyd2s3bmFDcDVXQTJjckM1YXhseldxSjhTdGR5MVZVejBwdk4zNnJVRXVPOVZ0clptdzRoQ1BCckJmNWZaQWR5dU53R0ZoaHcvWmpFOXJRbE84M0lyRzY3STJVb3EwczFoTlRiVVc2anU1ZWtGM2p1V0ljRmVBcGtuUkhjMWVPSnJaTkFic1NwNzA0OXdVR1hFV1FrN25aQ08rYmlpTzlFS1Z2T3lUZFVLYmlxS3R0Ylp2MVI1clVFdU8reWxkRUJ3bFoxTVdzSitQQlN4WTZyVDlpbEtpdURIZkt6K0VnbXJxT1A2SXdmUGlpdzd0R1JONXVSVXAzWFpHeWxGV25HejlWbU03WnNjV3FVVnZlRUdzZE85YUU1K2VxRTUzQ3lGOHpoWkNUdWRuUng4SitxRm5QUW1UM0tsTk9jUTNCNXIwYmJ2RTRxZGxiU1NiclJpYkRFaWV6WlU4ZUNMM1lyalovQnh2d095Umh2RWlQc0FhRUhiemgrOWwxdTI3eVY0R3VLRHhqdjVyclc3UXgwNVR2TnlLbE82N0kyMVZWTVVLcjQ2SXNZeklUVFdkOW4vQVBUOUxPc2Jpd1RUanhzZ2ovdGhjMENwNWVxbkVOd2VhOUdMdkhlcXFtamZpekRNaGk1Wk5HRFJnRUd0RXlVT2pzTXd6YU9idENhNndmNmlIajhYMkRySGltK3d2ZHUzSXZkaVZYQmY5dCtLNEtZMlRvM1hqdnlVckpUdnR5S2xPNGNqWlNpcUZWVFpUZ3BFU3RKVFFjTjZubW5IY0tXUk9EeFk0OW95UnNBeVkzNldTNzFKU1U5S2NROVh3MytDOUcyNzhSeFUxVFJtVmZqWSs3RHo1cTg2enJ6dHVvemh4MGhFYjNoTjZWQjluRThqNjRVbWd3YnQrWnNrM1liZ3BJSzU0YzBZRDl0cUxOKzVYVG8zdDdLSGttU3BOZ3RrRGVHUlVpYnJzamJWU0lVMjRXdmZucWhPZGxiR0c0M2JHRGhQeFFOaGNjYkJaejBaeEQxWTh6M0wwVFpmRWNiS1ZWYkpNcWN0RFdrNk4yZHpQOHFaSkpPK3lwa3dWY2NncjBwQVVBeUN1NlR1aVJkaUpod0tkRGRpUFdTQ3ZiOTFuVk4yblk4azBuQWhYYktJZEloN1RjVUhOM294V1NyaURXYTlFZXJpZGh4b2VSVjE3UzA1RzJSMlhhcFVHWXFBVytCMFpUdk55S2xPNjdJMlVvcWhWc1l6SVY1cHJNNjJ3MmJ6cmxOYm1aSU5HK2FuWURuWVdJRmNyWnhUMVk4ejNMMFRidnhHcmxWVXJvdytkZ2EwVEp3VnlFYjBUZkVHN2wrOXNrSUEyaldKKzJsZTM3ckpoRHBBOXJEby93QlpOVW9OeWM5MkFSZTdFcTZkcHRGa1FwNzk5dlZuMmI4Q3BGRmRYR0hXdy9NY2lyOEIzV055OTRkMXNLSjhSbnA1aklyRzZjalpSTkJ3eEtMczA3aFN4cmQyOUFicndhcDlnRW9ESUo3ZUtsbGUraUl5cW10ek1rOC9FajRxU25GUFY4TjY5RTI3OFJ4c3owMjkvd0JGSnZlY2tXUXNYQ3I5NXRreHBjakhpQUdSazBabFRPSjM2SVZNTUJiWFlkUnljMzNUVnZMMVFBM29jZnBaMUkzVlBPd0E3TDZMclFLT3hRZDd1OVhoV3dqZnVWeDIyekZjVkpBdEpCekM5TUxyL3dDbzBmVUtlTFRnNFlGUlc5bHpYZnA2bkdZeUt5UEd4enNyTHVkRStNVUR2bk5SSEhlWktlYzBSbW9oL3dDMjRxV2FIdzYzaG81K3B2WU5hRE05eWt3WFlXWGJQRmJ5U3B4bk1nTitNMThGcU1kR09iNk44RUdYZ0dkbG9rMUFNMkdVYXJ1ajhUL3BvNXhZSG1QVlROam4rQ0pOU3VhbHZDMXVSNW90TzVkUzd1VXJCMGhuNGtIREFxK01EYlRBNGc0RlIyUTlSN203Si9Rb2h3a1J1c04wNjQzWnFSRWpaSVk1YU9Nd3JyYVoyTkRjWnE0T1ZsS1hxK0tiM3E5a1U0eW5lYmRzdk4zaTNpc2RDWUZNeXFHZG5ETlNDNnlJYnNNZWZKT0RCZGh0WWVUYUxXTG9zc0dzb0IzcVVFTmd0K0Q5MVBhUEd5NS9NaUN2QnFtcDJ5V1Ezb3V3eUZzckE0N0pvNU9hTmsxYjZuaWJCQ0dEY2VkczgxYzNPK3FFVWQ2bU55bjcyL2haZElvVVlEalE3SlJCM3E3bGJ6QlhWUndYTkZBNzNtcThKT1ljSERCQnd4Q0RqM0ZUeGJuWktLT3NiNWhUZ3Z2Y0RpcWpSTVU4Z3BkNmEzTXlUV2pBbE41RkZBOExCd3ROdUYwWmxmMVhlU3FlNVNBbVZyMVBaQzRJUkk4NUhaYU1YZjRRaWRKcDJZUXkvUUtMZzFvaHVrMGJ0QjBlSU5Wdm53UmU2cEtsb2htOTFUcHRpNHhJRkR5OVFGSVlDaWM4N2tTY1RhSFpGVENubUVXbFh0MjlUSE95YmR0dFFwN3hpcnd4RnJVN3hWTURpMDRGVGdiVytHZjB6WFZuQTRjMFd1RjVocU0xZmd1QVYxd2twdFYyTzJmeEJYbVNjTXdxTEpCb3hORUdEa25PNHFmWkUxTElJY2pZNXVSVWtSYnF0SlUzbVhKYXVzVmpTeTg3VmI5VmRZUDNLdnU3bHFzdjhDaTZmV3hkN3pnM2xtaTZjM0hlVjBoM3dTODdRMENhRUZtd3pmbWM5S2JzQmlpNDRuVE1KK3hGRjFQaEgzVHAzN0JERyt0b1JabllZWjMxQzZ3ZTdaMVRqeXRFVnV3N0ZUR0MzRUZTSUlPUlFka1pwcmhnUkx3c0J5b3ZTRzVFL3FaOC93QjFNYmJNbGVobTY5ZFgwaHN1S3ZRdFlaTGlwdE1sS0tMaHpXNXdRZExnRTdnTEh2ek1rNTJaUTVINldTekNLRmw1elpuaXBiWExCUzNXYW81OEYyM1puQlNiTWs3MTFURFgzbnFRdzNLNDBTRy9pcEhGQnJRWEU1SjBLWWM1emhNakNsaExXMEdKM0s5L01mUnZBYnpaTzJWZ2g3OFhjL1VUR0lVSHBiZjVna2Vla0FtanZzYzd3MFR4cWc0WWhCMjRvamR1czQ3N0MwNzBZTHNSaFpkT3N6c3VXcTY2Y25mdXJoR0cwMXdvVnFHNDdzdTM5NnVSQVd6b1pvdE9JWHd1eFY0Ykx2cXVLcFZ1UlZkV0lxMWJuWnFtbVJYWWVnTXpPempkbjQyRGtVVTA4VURZQzdCWFJoa01GV3ljWEhzaFhSS1haR0M0WnJxb1A0bktaMm40OGxORjV3YjVxLzBsM1Z6ckwzajNLNUJiMWJQTTh5dFVVR0xqUUJmMTMrRGY4cS9GUG9tQ2NoZ0FpNC8rbGQwVEVPN0RpVk00K3BqUVBlWnJ0MHZKVVRqM0RTMWdlYW5EOUlQTkdFNmhGWktlOFdUM2IxTVdDSTNhWWc1VFVsSTZ6Y2lwd1hWUHVPWFZ4VzNtOWwySVFpYjIwZFlZYjlvSzZjUlpOcXV4ZFlacS9CY0I5Rkp3a2JCZU01VVFibVpKckIvd1dEa1ViSjk5bDJ5OGRWdVpVb2RPTzhxUVY1K0M2bUQza0tidGh0U2p4eFVoaVUyR3ozTi9GRWdFNXVQN3IrdS8vYVAzV3M2Z3dBd0NraDBadTZyK2VXbUdDb2I5VklCVlZOR1ZqWjRPMVNva1BkT21pWGNMR3M3OUdnV3M1b1dxSE84bFdHMFMzNzdPZG5WSHV0bjdqdkt5ZHNuanJHRFBFZDZGMGtzZUpPQjNJdFFlaEhiM3FZdG13eVZ5T0FKK0NuRDFobFkwOW1xdTlrS0s4azZncHpRNUZCdVpUbTVGRnE1S1RSTXFicFJIZjdSKzZ4bXBCVGRpdXFoSFczbkt5NWxqelUwWTU1TlY1NE1SL1ozS1JPcU1HaWdGdjhTN2FOSVk0NXFaMGk3M2pRZnZaS1FrcWlTb1JvenNtTVYwZnBJL21Ocm9peDNncUFyV2szbXFUZHlXcTFvODFyeGZOVU0rUVdxeFVrRldJNVkyVVhIZllXbGRXN0Zxa3J1Z0grODJoc01GM2NpendVeG9adHlLb1pQODA4dTM0SjdzeWp4QmNtOGltL01wNW9qTkZ6alRJWXE0MEFESVdWd1ZBakRoblczbkt3eGNxTjVxV1NEVUdOMlcwMEx1RGNTY2dwZ1NZMFhXRElLNk5DcTFLY1ZNbFk2RkhLb0JXOEtoMERuQmRvQkFaQk9PU0xva2p6VWcrbVRWcXRXNExXZWRQQXJaS251MzJTUWlOeENCM0s4TVJvU09EcUZFZUNEaGlGMXJOcHVsTVVYV1BPdGNuWTRaQU5RdWllS0JOQ0ROVFRTaElxaW05U0M2dUh0N3psWUdOeEtBWmdLQ3k5NzdzTkVRZjVrVFdmd0c0S2YyREZFV1I0QndlelE4ckR4cG9ZRmJKc3E1WW16WkN3dDFJYjNjbXJXdU0rWnkxdWtEOERaclppUDVtU054bHdaVHM0SFF2KzgyeTZkbHlwc3UwWkRmUkJnM21TWU4wNXByTjVNMDNXbCtxeG54UTVXVDRUVTVXZFhEMjg4cmJ4Mm4rUXNudVZObkFjdEE5SmlDYldiSTdUa1hPTXlhbFZFMWc0Y2lxUlBFS2tqeUtxMCt2aDhhS0szNHJaOTlqUjMyWUxEUm9wOVU0RGpSYThXRTN2bjlGV0pFZjhyWkxWZ1QrZDAxcUJqUGxhdGFJNDk5bFhoVW1WcXM4VmpKVk05Q1c1eXBnYWl5NmRvSzZjUm9NNGF5YXpzaFBma0pLV1FUWmlhb0pJaklwdzRxWGNpTWwxY1BiM25LMnV5S2tyTDlsSlhCdFA4QXBvME5Od3lXNVZGbUlzb1NxZ0h1VldlQlZIT0hNS2ptSHZXeWZVQ3hyc2pOWHUyMEcwOHJPNjNVWTUzSUxXYUdmTzRCYTNTR2ZnQmNzSXorOEJha0NFUG0xbElQdS9MUlZKUE5WSUMybFJoVkFBdHNxcEowcnJ5NEE3d0pyV2UwTnpHOVRrUG1jdG1iczIwVW5QQU82d08zYjBJemQrTnVvMHU1SXZpTUxaMEUwOTNGQTlvM2s1MmFFblNSbWIzRlN6Q0J6VGh3VCtyYnRISEpWbmJkT09MdjJVMWVpRUJYamdzck5aMTF1Y3BvM0podTZlbml0eXdXTmxGalBtcXNIZFJlOFBOVWlONzZMWm55VlJLMEd6b3NYTnNyZSt3aDVOM2d0V0E1M3p2L0FHWG80Y0puSmlyRmQ0MlZjRnZLbzN4VzRLcmpZSG5aTzlVMDVBRXFjUTNBcGlwVW1VNUxEeEtxODJ5QUpQQlhJekMzbXRhSzZYQUxXdWZpTjVTaGh6dVZGcXRhMnlYWmJLd1RtdFdjdUtCWEpURkZVQXFvL1ZZRHVWNmM1WUJaNkdObGZWVkMxYThGS1N4c3cwTm9yV1l3OXkyQ09SUWxaQ1BaZEszeHNjWEtnSlZBRnRLcG5wME5EaURnVjFzSEQzbTluL0dqcWp2WHBvdDc0WWY3cVVDQ0dMYVZUT3pWYVR5VlFHZk1WcnhISDVRcWhoK1l6VW9iRDNVQzFRMWkxNGpqMzJhc04wczFyeEdONVZRY0E5NUdab2cwRUU0bXlnUm5qWkkxekMzaFVJS3EwMlVLckpWQzNkMUZRK0twSXFvMEtoVU9qZGEwazhGNmFKWHNNcVZLRTBRaHd4OGRQZlpoWWJJbzdMN0FtNmRBU3FoM2dxUTNlQzltL3dBRjdOL2d2WnY4RjdOL2dnNWpIekh3cnJJTUp6VDcwUExsd1hzbkwyVGw3Rnl1dWEvZ0Y3Si81VkpySEh1V3NXTTVsVmM1M0tpb3huZlZVbWZJTFZrMWF6eWJOUnMrSzE0ekI4dFZNaHovQUpqSUtuVk0rVVZWQTU1NHFrbXJXY1RhSnFsdTBWV1JXUzkwODF2Q29RVld6RTI3bGlWdUtxTEpUQVh0R0wycmZOVkppbklVQ3VpVEdkbHRQV3VzNlVPK3dKdkt3Y3JhQ21ad1ZaeFhjS0JYV0hxMjVNb3R0M2l0cDNpdHAzaXRvK0syajRyRStLeFBpc1NxdUo1cVFFK1FXdGNaODBsVjE3a0pMVnAzelZienVhcFJWSk5tQ3dXRmxDUXR0eTFuRTgxTGViWmJ3cG9MVkV5alMwbkt5U21zU3NUNnJkNjdCVVdGanJPbEQ0YkFtOHJCZUUrU3JEai9BSndxd0kwK0xsclEray9tQzluMGo4d1hzK2tmbUM5bjBqOHdYcytrZm1DOW4wajh3WHMra2ZtQzlsMGo4d1hzdWtmbUM5bDBqOHdYc28vNTE3S1ArWlNHendvc2xpcVJaYzFSMTdrVlZ4QzIxdHJiVzJWdHJiVzJ0cEM4N0JCMDZqZ2lKK1NiWEJGMDhWSzk1SUdlQ3ZVS2M3QWxiU0J2WUp3bmlwVDhrWFRFendVcG9DYTJsdExhVzB0cGJTMmx0TFZ2RmF6dzFiUk5tRm5zb0g1VjdLQitSZXpnZmtYczRINUY3T0IrUmV6Z2ZrWHM0SDVGN09CK1Jlemdma1hzNEg1RjdLQitSZXk2UCtSZXg2UC9BT05UNm5vLy9qVGpKbzVXZEorU3dJY3JDSFF3N21xdGlNNVZXckhiMzBXcnJjcXFSQnN4V0t4V0t4VzB0cGJTeFdOdENWbXF6V3kzdW90VnhITlVrN2tWckF0dE4rR0hMWVl0aVh5bGFzVDh3V3plK1dxcm9DcXgwTlJwZHlXdGRaOHhWWHVkeUVsc043MXNoVUVyZFZwSzFuTmIzckZ6dkpVRGZxdCtoV2E5bUR6Qy93QlBESy8wc0h6VW5kSERlTERWWDJtK3crOE5PZ1ZhTFdpRHVXRG5KMG15czZSOGxnUXNxTWJLR3lWOGtaR3ExNFREeW92Zlo1clVqc1BPaW5jbU13cWcrb3EwamkxYWtRSG5SYkp0b1ZXcXJOVmEyZkNpbTJJUnpDb0Evd0NVcW9rcUxHZk5WYjRLcEhKeTJaZktVQ0hURmduTlV3c0JpUGRNaWQxb1ZJVE9iNnJiSjVLZ1cxWnF0SldzNXJlK2FxWE84bHF0YU82YTNubVZrc2JLQllTNXFzU2Z5cWpkS21CeEJ3S3ZRTytIdkhMTllLalN0ZDdRc1hPV3JESGVzWmNsVTJ2czZTZmhzQ0ZnNVdZcWpsVUtvV0twVlVKSEpWZGUrWVRXdkFiK0V5VkhQWnpFMTZPSkRmM3FyRHBVY1ZydGFWZ1dsYXJnYk1MS0VxdFZVVTQxVXJyUWVCa3BzaUVmTUZRWHZsVWlDRk1GSGxPd1hRTzlhMktEYzZJeTVDelVZNTNJTFhMR2N5cXVjN3lVbU5aUHhVcWxaTEd5amJOYUozTFZaUG1xYXZKVk9qUWVTcERCN2w2V0V3Y25TVlhFOGxxUTY1a3FraHlDcTRtekd6RFFpV2RKUERSYWRPaFdLcUZoSmJWbXE1dzcxckJqK1lWWVJiOHBXckdsd2VGTnJROGZDWnJXYVJvWnJFcW9CNUxHWE5TWUo4VUdqRXE0MDRVL3pacWtyV2FDaTF3N2lpRnlzYk5Vd1U4aE5OYW5QSUJ1amZtcnRUMzBXWEpWTTFNS25PelcxVHhXcUNWcWdOVlNUbzBCS3FMdk5hOFlmaFZHT2NmaUsxR01iM0xhT2hUMUxqWkdPWjBSelZMTm15aDA2R3lvc29SWnRrODFnMGNncFBmY0djcHFqWWtVOFRkQ3VpSERZUGhGbFZLenJEaWFDeWF3VjBOQmVmSlZPMHVhSXNHcUhJekV1Q2M3TXlSVjdNL1JUejBKS1l3T2pja3g3Y250bXRlQzZHYzRidjNYbzMzaHlrdGxoNGtMYmtPR2hoNjV2RTJENG5hTHVGVlZoSHlsVWlEdm9zUEMzZlpVQllGWTZWMEdYRmF0R3E2Ty9Sa3BaMlM4VklmK2haSlNGWG55VXlabEFvRkJOS0d0Sll6VE9WNndESnVsTDFWVkk2V05tR2xWM2dxTlVOdmZaMGRuZm9rWmhVc3BOcXhEK1lXc3dqa1ZSNC9GUlRsNGFPT2hjOTQ3ZjdhYzdabkYxVHlzbXBEYlJKTXliZTZ6elFwTlVFcHAzZ210eks1NmQveDlWTDNoaHg5VFZZelZHTEVCVk03QU15cFpDeGpPeTNTSTQyVXR5V3E1VnJ6VldTNUZZazhKS2xMSjJkYWZ3S1pVOUc2eHBjYlp1MlFwZUttVklWZmtwa3pKc2swVFUzU2U3eUNNek5TUnNCK0pBSXV5Q0xIZWFtdzl5a1JMUmtWS3lVdzJlOHE2OXBhZEdhbXI0d09QQTJjYktnT1crZVVscXM4VmpMa3FuU2J3VGp4VFJ4VC9BQTBwNTF0cXFLdGt5YUtaVTlESm9xVGtzSkRjTWxkOGRBTmEwa25jRi8xRDlZZnkyWStLdU1iMWNMSnVIZXBXWGY4QWs3SkRhVXlacWluR3A4QXhWeG9rT3lGVzF3czcxUlR6TnNqWDZxWTFob3pHNjNxNGpSRWg5aDM2S2ZSbjYzOUorUGNkNkxYTklJM0cyVmxjRGlydm5uWlBRbU5PSkV5RmhkMlFpYzlJT3kwNURjcGFFdDY2b2ZpUEZjZEM5MGwvVkRjMzNqM0xxK2pNNnNHbE5wM2V2U1ZkMlIrcUpKb01CdXN2K0NrRm05RWt6VjV4dU56SzlIVDR2ZUtwUUtUUk5ObnR1c0IwWmNMSmpmWlZURk9LcUtaNkZNRGhaY2UyK3o2SzlDTjRaYndya2R2V3M0N1E3MWU2TTdyUGg5NGFOMzNocy90cGNOUGpFTmtSM2FwcHViNnpyUGVPeCs5azdPc2lFUW9mYWR2NVpxWFJXU1A5VisxM1pMcklqcEErOGQ2dXdoZEdlODJCcWtGSWNncjN2SEFJN3p2Szdic3pnRk9jelpXZ1VoVjJRVjkzSURSS0FRUVFDcFpSU0sxUEMyVnN3WkZhK28vdGJ1OURFSEVFS1hTbVRQOEFWYnRkK2E2eUc0Um9mYWJ1NTVhRjhkOWt0RGlORURNcGtJWU1iWkNoZDU5UVI2aWRsZGtWS241S1NMeElON1JvQXZSanJvbmJjTlVjZ3J6M0Z4NHAwUWljaUFGTW1kbDZWTEo3eXA0NUJYb3hyMlFyb29NZ3FxVFJOWDQ3cTVLN0QxRytmcUo1QzAyVjBLMVZLaXk5bm9YVHJOM3RLYzBZYmxlWTR0UEJlbGIxVCsyd1U3d3IxSE43VGFnMmNONmx1M2NiSjcvVWNHVlRuNWxOQ1BDbnFHdjd0R1doSUxxeDM4U3VOaldseHV0d0dWdk9KK2lrS2xhK3M3czdsMXNaM1Z3OEp5eDRBTGdzZ3RYeDMyOVpGTnhuRlhlanRsOFJVeVptd3ZBbzNHenEyOTV5WGFZY0hhQmtNYkNiRENpMEx0bDJSUmFhRVk2VXhSU05KcXFuU0xDTy9MOWw2TXo0YjdQd3QrbHJtdGRJT29SbmJjMys3Ynd0bGxiUEpPZjcwU2dzZkV5R25Ld3N6MEo3dEc5N3pzTEo2TEprQnQ4eko3bGNoQWlkSjd5dlRDL0UzUTh1YW00elgxV3JaUWQ1V3FPc2YyamdwdU16b042UHYybjg4ckppclR0RE5ibnNjcGlyRGdmVWRmOEF6WWRJbkVaNkZMS0txdkxWN3h1S3ZkSG83K24reTlMajJ0NlpsMWJhOTJuMW0vQjFrdEpyQmk0cHNGdURCWTJIblUrcXZEQjFiWmFFenNqRlRVdDJqTStDZ3lrQnJFbmNLcTcwZXJ0OFRmM1pXQUFUT1NxcnJSTXJHKzdoZ3Bic3RFeDNDa1BBWm5jaVNaa29FNzBEd1ZLdE9MVlRYWTVURldIQTZBRm9maU40ekNCWldFL1dZZUdoVkc2SnlzdTRpeWk5TlIzOVFmcW9KeGFZWUU5eFdwK1hTekc5Y01ScHY2UTdCaUxqaVY1b24xVXQ3Y0VOR1FWMFlEelhIUkdxWEU3TFJ2VTR4NnlKMkdtZzVsUUdZQzVldWpERlU4YkwzWmFUNUxySHU2dUgyanY1SXc0TGJqUE4zUFRiQUh1MWQ4MWtEa2ZxaFlYTnBDOTdpbjlkc21rczlBQTRUVDJEWkJweXRQUlgrOVZoeWQvbEVPYklqUFFtRElyWGt4L2EzSG1tM3hLdmtpM0l5dGhFR2wwVEJ3SzlHZXBpZGtuVlBJcTVHQmh2N1NrNFMwYmgvRGJPMlNaMGZmaTZ3bmU3MWMwWllIRFJudk5rOUFSZWxHNWt6M2lpMkdPckJ4elBNcVpvRXhtVU50a2dGRmZGQWMramJtWE5UZWY4YUYyR3h6aXYrb2kzbmRpSFh6VnlIRFpEWmtOL2VuUmpoRHc1N3Jlai9LZnFwS1pwREdKVXpxc2J1VjQ0Ymhsb3czYjdzajNhQW5XZFROVU53OGNGWFE2dDR2dzhzdVMvaUlXdXh3bWMyODdZYk8zQnA0MmRXOGRaRDdKM2NsS0VldFovVGR0RGtyN05abjA1Mnpzdjd4dFdTdE1aK3hEcW5QTzlBS1F3SHJMdnZOdzBKbkFLYWxiZW95SDJuWUtYUjIzbi93QlIzNktaSmM0cnRIeXNjTXBEeVZOMkpPQVVvRzF2aWZ0a2dNM2syM3BYV2R0MUF0L1NYOEtOVnlZWXpzTW9MWlc5RytVL1ZTbkpyYXVVenFzYXBtamR3eXN1RnhiU2RGN1YvZ3ZhUFh0SHIyajA5ZzNHVmdRRmxGckM0Y3dwaldIQzFqMk9rNXBJWHV3b3YrMTM3SzY4U0kzTG9yaHVaUHpUcFlHb3Q5SlU5b2JYK1ZlZ2tUeS81Z3BPRWlGS3lhcHNuQzBDU1owVnVPTDdDN2VjUFd6VjV1RHJBQXJvd0ZrMUpqWi9vcXlqUC8yajkxVTBVM21ROHlwQ2dzSE5QalJqY2gzakxOM0pYR2k1REdEUll4amF5YXI4ZDRncytKZWdoZFk3dHhQMlU0ank3aFpSR2VqMGI1VDlVMkpETWlBRk4xQU1HamRhN3BMTm9PdVZXRVB3WDh2d1g4djhxL2wvbFRuSEVtZHBRa3RiVU9lNVR4R1lVd1pMWGIzaFRobThudFBPd1Era0MremNmZWFvRG1tK3k2UmVITk5POXVxZENZTWlnenBUWjVSRzRoZGF3aUpDN2JmMVY0YjdMaDM0Y0NycHhzZDBxSnNzdzVvdmRpYkpEQWVzbFlZYmtXbWk0bnl0YTZNNlU2M0J0SDlsMWJRR1ErdzJ6VnFjemJJQ2FiZmsrTFBaM041cHozdW5OU1kwdVUrbFJRMzRHMWNwZEdoQ0g4UnFWZWU0dU9ac29xMkRSNk9maFAxWGNOQ0ovZGI5TkJnNDJ6MEpzTWxydGtjMnFoQlUxcjZ5MUhkMWtFdFBhYkxPcUloYXJuQ1JobjlGSWlvMGIwTjB2MVJhSlFZaDkzM1NlR1NsWlBlTVUyR3plaDBhRnNRL00yY1Q2K2FFVExFS2R1YXJVNWFGTUJpVGdGZGdZNzRtODhza0hOWVRKZW1lWXJoN3JQM1YyRUJCYjhHUGpaV2kxUXFuMVBSdmxQMVhjTkNKL2NiOU5Cbk8xeHNPaFJWVkxLNndWMEdYQTJONitqai9BRFIrcWs0Y2lNRDZpWVY3K2RGdytFV3ord2NGZWJzbkMzaWRDL0VtR2JzM2NsZFkwUTRJOEYvOWgvOEF0VjBtNjNzdG9MTmQzY0ZxQzc5VlhUYWN3amIwYjVUOVYzRFFpZjNHL1RRWnowcDZOS0t0VlR6c2xpTWlwSFVYVnZiMXNFN3N1SVhXUXpmaFo1YzlNOUxqMGhzdytJb3hIZjhBcXlYMkl3MzdKUmFWTTREUTZ5S0d0Wm05VGFESGYybjRlQzEzRThOMW1heUhEMVE0RlM0VzlGK1EvVmZoSDAwSW45eHYwMEdjN1doUE9UZExIUTRXMEt4dTU1RlhtZ1hlR2pMQmpkcDJTRUtGU0N6Wkdkay9zblZ1MnhnVmNORklDYXZkSWVJTGVPUGd2K25oVjdjU3BWNTdpNDhiTS9VemxndXFwaFdsVTVwM1dQSElxRkVBQXdySzNvM3lINnAzNGZvanpVaFFDcmprRjFVQUFjWlY1cUovY2I5TEF3YjA2QzNjS2Zvb2ZPd0tIUWVDZDhSQVQ1dGFkWGVPS0xUQUJsVFlDaytCTGpkWFg5R041dU1yYXFtaGpiTnBrdlNON3dyelRlSEN3UTJDcFg4SDBmQWJic3o5bm1nWHp2REc3dlV1anM2cmo3eW1UTTIxOVRWMHprRVpORFdEeks2ejNSVHVUSW93Y0pHeVdZa29IZCtxQnM2TjhoK3FkK0g2SnpSSWJ5NDRBSVFZT0dQUGlwcC85d2ZTeDhkM0lLODczMHdqQnhuYkQ3bERHWkpUdmwvVUovTTJkUjdyc09hZXdVR0k5VFJWc3BpbXN1WDNPd2xpdW9oT25IZHR2eSswekN2TTlvTVJuNnFieUdqaXZSdHZjVGd0WjFNaFpjWnQ3NjcxUU0vT0VZRVVEckJoV2RnT1JVSnVVcmVqL0tmcWp5YjlGMWNNU21abmlwWVBHQ2tjVS84QXVENklBWWxDRkNMUUJtWkxhaGZuVFp5TDJWb2JDVkQ3azBaTlR2bC9VS0o4eHNZZXpVcDNBQVdWQzFkR3VHZ0dOYk1sU2JKM1NuakhzSWsxSisxVEN2TXBFM2pOU05OS3B2SEpxOUdBejZxYmpNMnpsTzdWU2h1SUF5WHRuK0thSXNSem11cFhjaVJzdjFoWkJheHBjWk53VWpDY3ZaRlFHdXhEVDlVZVRmb25jMU1Mcm1ZNytJVC9BTzRQb2pHTzZnUkljUXR0M2lwT00wY3NRaW9ZK1ZPNW84djFUeUlMcFhpaDZPN3hjVWEzb3J2TkZ6alU2RmFyR1dsMWNNRnppcm9rL3BUaGoyRVhPTXlkL3dCc21NVnViRitxdWtTSXNtOGdjMTZOdDQ1bFZkVElhVW1nVjBHTmlYZFd4akJkazJpd2FzQW9IeS9xcVNPcTM2VzZzazg0ZWtIMFhWaVFGclZVQ2xqSVpsSnRoY3lVNWIxc1F2QlNEbXQ1QlhuRWs1blRvc0xlcWh0bVNqQ2dTZjBnN1Q4bE1tWlAyOE5pVWNNQ3BYUTBaaFR4OWNiWVB5L3FoOG8rbWcvKzRQcG9NNTJBSW4xVlZYUXBTR01YbmN2NGZvWDRvbTgvY1hWeFJlWjlGZmg2N00vc01INWYxUStWdjAwSC93Qnh2MDBHYzBQVlZWRnh0bWZCZnhIVFhkWEM3Tzl5Nm1DM3FvSXdhTi8zSlJYb1dxL3NxVGhYMThENVQ5VVBsYjlOQ0ovY2I5TkNIelI0ZXBvRm5iVEROWElMUzQ1NUtaOVAwbkxjMVg0anBueUgzUGRqQ2ZGWG9adk45YVZCK1g5VitGdjAwSW45eHYwMElmekp4OVhRSWU4VHVDNnpwa1RxbWJtNzExUFJXOVRDOHo5MWFwV3RxT3pYYWJ3OVhKQVpMOExmcG9SUDdqZnBvUS9tdE9uUUt0VGtGZmpFUUlYRlhPaE1tN2ZGY3I4UnhjN2o5MjBQY1ZyQzQ3TlRicmpnc3ZVQ3o4TGZwb1JQN2pmcG9RK2FsYlhSa3hoZVZmNlRFYkFaNXFYUTRVM2YxSHE5RWVYZmVPcVNwUldBOFY2S0ozRlZiMytvL0MzNmFFVCs0MzZIUVllT2diT0syTGd6ZFJlbmpHSzdzc1JiMFdFeUMzUGVyejNGeDQvZU5kSFZlVjZXRTEzRlVpT2huaXB3M3NmeUsxb1o4TFF2d3QrbWhFL3VOK2gwOVNFN3dYcG9zT0dPSld2RmZIT1RWTG8zUjRjUGlWNlNJNDhQdmZKVTBKZ3lXM1BtdlNRbVBXdEFMZmxWSHhHcW5TbTk2cDBpRVZ0dy9GWXcvRk9nNnN5NE9uTmUwaGp2VmVrUVIzclc2VzN1WHRZaitRVk9qdWVmaUs5RkFoTVh0U09WRnJFbm5vVldmM3pqOWp4VkI5LzdLM2hZcmFDM2FPSzJndHBiMWg5eGYvL0VBQ3NRQUFJQkF3TURCUUFEQUFNQkFBQUFBQUFCRVNFeFFWRmhjUkNCa2FHeHdkSHdJT0h4TUVCUVlQL2FBQWdCQVFBQlB5SC9BTzBqK2NmL0FBanlWNlNFUENlb01WN2d4ZDVzdEYwTkM5UlY5bndPa1Z2ZTBpdDRwL2xUSXZZUDZ6SGxqZjhBWjZ2OWZnOU8wUXNwUjhMTUp0VWg2RFdCdG82ZisybWFFcFpiNCswcEo5TGI3RlpTclAyQ2dqVHkvb3ZFUmtWYmRHblVld2FQQlE3b2ZLSTJFVXQ0WjJIK29NcGVib0w3RnBXSlhrU29XVmprbEhyb3NTcmlQOUJmK3RBekpQTG9oK0d0SCtOUmJFbmI4WWxoQitYS25XNUNXRVZQVlRGazdTUlc3NWFRaGd1UXpZUmlzRndoVDZjTm03SklXVW1oSWhydjNTUDhBTE96c0o0VG83TXVpQllCUGNoWTU0WjRJeUp1WnFGTFp6WjZRbFlyZm5FTzQzbkhuLzBFcHNMamxzSkxJQkJmbU95RmNMaHFueUcyMHR5TlpFa0kzUVVXbDBRdko5eUFvem0wd3ZRYk9wWFV2b3JOM2hFYVdWRU1FaEl0enRLcitDem5CZVdVZG1STGE2NktER1BXMDFIdHVxQ1FSTTg3MU5ON0dVZ1JuL09pY3BscDZvVVVxem9WT3J4aGtrM0Qvd0RORWxzWUtpQlMvd0JEK2h4UmpFODZqclM0Nm1Fa3MyRjNQeHZKS3AvSytUZkFEU1ZEQXhra0lZdUJlTlg3dTNvTzhDYTJKYndKamJhZnFaR2Q3emRwVmZCYWxNVVpFandPWTVRK0JxTERvM3VTb2Vob2I2RE1CYm0wY3IwTFoyUHA2bHJjclJsZWplUlhZMkgvQUpMcEoxWEZoVUh2S0YzUDR6eTBWNWE5eDMzR1FkVDh0Mi9CS05oeDRLakhtWkpNTGdLeU5Dc2tMeEJMNFIvcUFaRUpEMHFvdGY0VWg3YmpjczBLbUVTTnNHNHBPQko3RWh2VWhjSC9BSURHNXFjRU5DQkp1SnlvTkNwMkRBVWE2M0wxNVdMOUtMZGFNcXZGd3lEUWI0Zi9BSXJTQ1hvTjRFcS9vTjNzaTk2eU9yalFveTRIVk4zYmNJbmZTVHNodDFJWW1EZFFoRWR2TXV3a1dGQkhraGY0alpVazk1YXpHZkF2blBKTjZCTENvMktqSWJmSS9nZ3U4UXVXU3RNZUJxNW9uVU9XaDFJWFpPZ29Vcmh3UU5pbHR5R0ZidVM3dWk1M0d1ajhodnlQUWFxR3JVZlVsemNQMExsckVZVm4xTGlmbklpSEgvaFN0YUNFaDZQNWZBNUlsQ2dvVUkySDNuWDlZazRWMG82T1dUN2FMT0JDVFlqM1FoS3REM0xQVm5hdUJMc09KK1FYVVM5eHFGVnNoRTgxYjJ5U3RDY0ZvZzFTcFIwZDhUbFZrS1Y3aFNMeSs0VkZLSWFuTlErU2ZqQk1UZkVQUmNWVUxtd1NLMjdaRllhNngrUkE5UGcwS0d1T3RRNmhpcmI2RHRRWnkwQ3lhYXVBN1Nudi93Q0FqUGE2VTFlaUxUUjFqYmJUemN2UjIwSWFEblY3RTlPM0M5VmpiWXFVUXR5SW9xMVpiTndYK1VJNitoeS90RGpKTGRGQW1VczBFVDlhRnhrbGhQcWNsQ2lEU2dqTGUxSWRuemtteWRKZ2JnK0JpYjFWUk03dFI3ZlJ4UFFXNnFRWUZpTERKUEtwY0cwQlRuaXpKMDZNalNoeWlKM0kza2M3ZUdNMVNhQktxc3Zib3BhQXlETEtzLzhBZFJScTdWdDluc0ptV3VidXJIRGRrSTJNNmNpVVpoS2hKYkRvbVRrQ1Z1d29RNmJDWCtnbEd5STJPNkcwS3M4eE50Q1VJaUV6UVdnc2tmRVp0TGN0a0h0cVVmNEszYnEzeVA0TlpVb1hJeVI2S0lrTy93Qm1YMjVEVGM0ZkRLS2lZdldvbnVKR29STmxyUGdrY2tNZ1hRaENGU2VzRnVqVTNxUG9KdFVPdHloSktHTTB3TnlwTTlYSDdUL3RzYUVwYkh0VlhmSnZUZHZnb2Qxc3Y3RTRYY1hGSGJvY2ZZazFycGwxRVJSdEY4RksvSnlsOG83b1pKUkVkZ3lObVp3SFFhbDdpVjNKYXcwM2Y4aTJMZGp2VnlWWVMzWkxVTjZnNmZuOXVYRitxRGx3cHMyYkVyZktySWtjL3dCUllFbk85d2tPdHlJdkJKdDNma2tTOSt3VWlwMjJGWW55OW05MFZXT2d3eVgvQUNUV0lXeVRLSkhZWENwYTBUOHZwVndDZVEwVUxVN3BFbktpL3dEMmFab1ZYb1FvR2xjYnRvK1dTa2tFbEZnbXdwTTJTVlZxS0JrMkxGbC8wSWJOVkhpSEFRckt6YUNEZ09MK3dnbDNkS0pYdEM4REg2RjZEZEtOdW9ZZ2oxZ3FIQ3MvS0cyMkNTbThDU2VJSjN5UDF4VGdZY2k5UmYxUklkcjROTWs0Y0lUa2VRZXpGODVCQS9adC9nVzZOMVVVMFBCVkxWQ0k5UlIyRmhYcGRnMUkzSEtNTTF5TFY0RVdCQ1M2WGNzRG5RaWpGVzFoUjVqWjBUTVVWQXplNUVocTlFeW9tQ0plcFBxLzY2VXVnaWlhTDZ0NlBrYzBpUUlSWk5FVjZ5TjJJclhmOC9nUUk2czFUSFN5bHNkR0tVdlFOYVlRaWI1ZGJNb0Y3NFl6UTAybXNxNVExZmtxSnpJYTR6VW0vbEZVODROUXNoUWFWRXNLTjZHVW9HbTdIT0NtM0ZEMFFScUlGV1JlSEYzOEd1a1U1S1ZDSG1Yc3hZQXFTSjFpejRaWng1Slp4cUV4SVE5TGRPUzdsV3VpV3htSW9LWEh4UXN3TEVwTDVOcFg2a0p3UzY1OGlLdFRyRjJmWWtZd2pEcHdGN0l2NERheEZlVnhLOExHWE9KM0JEMmFpYzlmK3RWRFZURnY3WkVFVk9rd0ZKTkJDV2VCOGkycUxYcXhJb0xYaUpTRDlvbE5jNEpsZkhIOUVuams0RlJDOGlBYVY1S2kzcUpiRllaWHNRS0VYS1Q3VDA4bExHcW9NV3FyWTZNWnkyM0dKWmdaYTVueVU1WmE4c1ltMGtXazgvSnlkUk81ckhCQlBJL1lYeUNCcG9PenJ2eVFFTGhDZ1JTczA5aUpvS21yWkZ3Z2tLVC9BTTBFVTBOTElVb2s3c3ZoMEpxRWE0bEJrZWtvRjR5N0NvT2ZjdDlEWDltV0NySGxiRUtPeGpSeHU2NXJ6Vk05UCtvektwclczTDJFNU1mbzN1Yksyb3ZrejBNdm9lcEpMUkZCTVl2MzhqVXEwMElwMXZiZ2I5cEZ2SmFSUkRvR0Q0NTNJYW8xQkJVQ2xscXBrSXArZ1VRdzBxaVJ6QnlveWNGbEljTGhMb3FkUXQxRFh4S3BOdmM1SWV0UGFRcXhGWmoxYWZSNjUreDZnTkRRb2tuY2Vxb3VrRVQ3SkVOb29WT3dtUWl4UVdtT20waktxMkthNDNxeWUyTnhyU3piSkZMSlJCWWdWWTVrbXF1d2xML1hYK2czbHZtU2k5d3pJNjlHYVpJYk0xS25LNlRHTkkvVWU1aUswLzZTdWpRZFl6c1IvVXIvQUdMZ2N6WHVQUWhOVVVDUXE5WG05UXZXR3doQ0JVSVNKbEMrNlBESnBVdEsybUdQNVJrcDc3a3cyb2ZaQkt0cVBBbnBQZ1ozTGY0T2dzSE5XTUpHQ0pwcjBodk4rWi9CclNxT1NZeVFheW5QUjlOSDMrQnZLRllRbnFUUHUvMFNEU2o0Wm1HVEw1Q3FvMUZSd0ppNjNpNVNZcXZxTWJsdVdQbzE5UWNpMlU3K3dxUHlKL3JzTmsvSmFLdnF4SWNwTHBzdHQzc05WRjBldXNkdzNpdHpzdGlERDZIaDkxTHJ0b1RPbkhQL0FFRmd5MlJBcEZtbHNGZEtWTm1va2tSSEI3aTVvc1RRUzZQZElVSC9BQURaWHBCZm03TWV3a0haQ2NVZTFoWGdybkFoOHVTVDdNTnFhZUhSQ29NaVFtNlJySk01ZGZvU2tNMURVZ1NsZHZmMHBCUXduTmlOck4zNmxiS05KNjh2NUxkaG11UnF2Sk9tb0lXRzNxSW1HVDBhRW9TRmt0QkpxWDdmWjZodGY2OWlvMjA3c29WUStsc2pvcGdrTmdlQVcyNDdTaFV0b0RHREVKTEk2MGZMTHhZcEt1K2pKd2tUYkpLTlZrWGhXRTBmODZGMUtpZUdGM0pITDlNRHNxZVI2RFY1YVY5S0JSbWJXei9CTk1WR0tZWjAvd0NBWm51Q3Qvc2h6R1ZVU0lDZ2ZtUjFQc1gxSm5TUGZvakkrV2hhU2ZLRk4zUWxyK1F4MkpTTG5GVThGVmptdmsyVmVxUUpreEh1UDVUK3VpTE1RbkNyOUZDN2psR2pmcEkzd1NUMlBrUlN5SmFsUVNpRXowU2RoRlZpSVNTVFREWDhmWVJ3cHVUK3ZZYmx0bTVkMjZ5TDFOeThIUFYzeXlGQlV2WDNHaGU1TWlYNkphTHBobWRmcStLRzRTeHN6dDBQb2ZTdVpGTlJhRGlFNzhmaXYvTXRxQ2FwcThJYWRPWHFETnlxRTBrMTNIeGhLSWtPV04yREtCb3BQSy9vYXBhbTNKaTZxVkYxVVNsci9NMW44ZUNid1FadHQwTnA3bGhMKzBPRklCeTNJcDJveGxDUWh5UWpjbDB0NkdTVXAwZ2lwVHFTNG9jUGNmd2JRS0ZDODlMdVZXOHVoSmlaMS9WN1FSZG15Q3BmUFFuMlVDWWhxdzRmREthWkt6YU1reVBRUkpjUXNDQmFaVFU4WDJGVGVXZjE3RGQyM1hMWnJocU12U0tIY2U2UTIyUWFoajJHMlcxc0syVXg3dVhYWmdkYThHenErbEpndTNDUVNHMnhaRXRIY1M2TlE1Rk5SMHFUcUplVGI2clgva1loRXQyRjJFNVRiNWZ3TitDb1VKN1A3Q3F1U2M2UEtKSmxWK3BTTXNvTEkrY1FyVXNwSmJSNkNjWHNXaHpFbEg5WVBSam9vYm9oakRSb2N2dWZrSlVKbjViOWtESEFxVDBzR1BDSlRUWG94TjM0RHdSVWQ4aVl0Q1VhVk9TdjBheE5MaER5eWtrMno1S0wwRk54QmRzZWdodDZ2Z203Vm9MVEdrZHhsUnNKZWd0V1JVcWVheE1oTkVKbE1MSnFlTDdDakw5RTQ3RTI1YVhlWGtlaGVYVHFWWWpQdksyTnJ2UWlIRlN6YWJQMXNPcjZNaVhFWUR1OXZtVGpFcHF5Q0IxY0ZleW1mb3V4S3lpV3laRFRsQzFlYkpsZnErZitSNjdWWlBUVmtwUWtoVUpvaTFuekd1aUhlUzJTMTBYbGhqcXF1ZUJVMnlnU3BPV1dRMU0zK2g1blpOSi9xRVFHVTdqMEhWT281RUVvazNIdG5GaDZodDRSei9KZEtHdHJUeWhUN2RkWmNDcEkxaVNJMWZpWkx1R2hEbDBGaWNyR0ZWa3NYYVNrblE0bWRqdTY0RDBlMFlHZjZwWmVyTkVHTDBKZHg3aUVha1c4TWJqb0VSNC9VY3pQY25TYWl0YktncDdURno5dnM3QzczbmpzT3JiZFhtUzJWRnlKSjZXTGxaMGw2aU8xbExLSk5XekZHSUlSOEwzeU9wd0pTN01XWEx3TGZoK3YyVnhydDhzbHNjUXVpS1ZTN0dMYXU0bUMzNENDaGNpZHZZNUhLVTcxL3dBUnQ1TkJTS3EvbmRqM0l4dFBxaEp1cXdTQ2lvNXd6YU1iV1pVYWk2b1VtcE1QVVJBaW1zOWY3SGJUSmtub3RWQktZS2lHcVpEUWtmY0I3bktxUmJKYTc4REVmOS9zdDhGVG9Qb1hwR3VsaURWR0NSS2RvVFVVL3dBUjdTN3VySURkRUVZYlZPRVZsMUc4bklaY1ZmcTBRN2Fub2JZMnZrL2Z5SUx4YWdyblg0R3lSaXF3TzVDN0phS2k0UDhBZ3VpNkQzczY0Y1ZlWHNWMm9kTXRUOG9XTmFGVnNRbmh5T3lvbDZML0FNcDhzakdEbFFEdDhrekhwV3ZkMUhSTHU0a0lSWlNWTWZvSEdYa25TS0gxaVUzZS93RGo3ZjhBRml4S2s2YXZ3YkVLeVdpd2hMR3NXYXNjVkk1YjFZdDByUU1iVVlRNjVyN1JRRGJ3Zk9mZ3VFNXZoQ0RYb211L2NkZktKUlNYVVdncUVCSlRUdEtlUkNDcW5OS2xlaHlNaXZWWldHcE4wVFBEWWE1aEYwOERHQ2VwMkhzMDFEV0JvZ21DbHZac1YxVk1PNWMrVWJHb3lBMVpHVFdsQ2plbzlGN0NGVFY5U0JxbFBTYXlOUTl5UVVUTHMxMFJJc1dJQlJPWTJyQmFMK0NoN2hRUzdsSTVFVUlKVnBVWGF5STVyYnkza1JWY2ljdnArVUk0VlZLYUR5Ynp1VEZPMGVRc3Uza2NOcVVQdmNMbHMyeTdGbFZpSkNLSlhzdS9zTEpNelpFaUJwUUUxSENwYlJGSUtxYUN3aEtXVktPb0pDZTNNaGw3Yy84QWdTYkpLN0ZUdlE3Sy9yN0UxaVNZR1FJMUNVa2tKaldXU1FaMGFjQ2FGV3dUSVpEYVU5QktwSldLTFhHbVFpR3Znbk5NblVFbHlxQmpteXZxSVRJTEtTWldTRlM5RFZiQ3BNM1Z2cDdGM2trUlpkU2k2RnpsdE1ja0NHV2lsbjhoTEtRdlNVYU5PUTEwUmtYRC9xckhJeFFkblZEL0FBb0tpUHlORDFBMlVjWDNRbldSMTJhQjFEVkpodjBpc0ZSZllBbnkxRkp0U1Zrb2wyRkpobGtzbFpiZktMbC9ST29va3NrcUlRV2lwb3ZvM2VCTkZoV3JmNGJzZmp3OWxoODNZNXFWNUxnK2s3QmN4cXdIcXk1YktDc2hJUkUzSHNvQzB0dFlYejRKSWFDMUlFbEtFNmd6SlEzWCtRLytCa0xEcHpnZ3JUSENMQ0t5VkMyUytTQ3VSYW1saldiMG1NUlFhcWhIWktLeTl6RWRaNm9iRmwySnFoQ3JUUnVOOGczZmdYc0lWTEVwUTZoNkZXS2lIeDh1UEtnZ09HL1ZVYkpwMGxKVHVoTzFOWHRTKy9EMTVKNXNWUXdOTVdMNUphVEt4UHdQOHQ3alNUbW1xeW5WQ2xlb1hkWko4czhwcmdvclQ1RjFrZ0pOTmpRNTBjRVhpN3ZzdlZuRlpINHVoYzVIbVA4QVFTYlE0SjJzMUkyOWlpcE1jcWxRcDVUUUlhTjBwamhndWlwTW1zM2Znc2pVcFc2YThqSkRKUlZiZGtha3VwaXh5OWhPVmZxM2U1dllaUm5KZFpzWktPWWVTL1E3dm8vY3pjUUp6VTVhTy84QUFqRXJzaVFpWVFyMmlRdGM3dHU0d3Z5WDBMMFJLZ3hNZ3FFTU10OEZ3R0RuK2M0eXJGT1hiMGtsVFJVd0tmdFRqQXlFZ0JiTkNEc0doSnpHVCs4UXlhbTNjRzVGSVJuOEVTS09GVWZSZ1ZhaVZiSlpUc1dKV0JQOVE5Y0ZQRHlVNmRLSERLQSs0VWUwUHVXRzZteEtUV05HT3lNT0RmdnlMZFRaWlYvSW5LN0dTTVp2RCtoZFQ1NnEvd0JrajBFMnIrNUhiVjJaVG5adFZIYXU3REVQYlM1NlNqZzdGVTM5SDBXdjhrb2JrRlN1TFNKVyt6RnlqNTBJUndhWllhZ281OE1EWnBkU0NTUmM3Y21JWm9yZzhMUGMzWVlMaWcyOEdleEdWTkZDYUlrbGJUWjc2OEUwbFV1ZXhaSmtoSWdSV3BWUmExWTdqYzdydG9uY1hvOTZuNEV1NDBaTmtOdWFMcFlPaWhmWi9RN2ZJOVVoMVpZTG83cTVHTlJUWks1RmtVN0svZW44dHoyUjRvbFNYTnZRVG9WQ28zSEJFa21XdkltV1VTelM2b0RyNEpRb0VOTnZnYkN2TGdKdDVUaHJLRXpZMFRjYndpMmlsVDV6MGluRmhLVFVTNDA3RUd0TGY3Zll1RGhFZ2xXY2FyVkR5SnlVNGZZYnV3Q2x0eXhGME1aVTBQc1licWNCMWFocS9yMkJIUjczOWt6RGE0THhWSGx6TzBNVTA0WE1EVzkzTVJVcDMvWS9FSS9GMFBYR3lxRk44ZEtnWnU5cTBpdVJMOTI0OHEvb1Nid2syM29WWWU2cjNlUGNUVElsckw3S2RVWk1NN3EyUjdDckFpZG1LNzM4RG5zeWQ2bTVZUkZUcVVJeng0Y3NrZWEzU2MrNmNXSlo2c082WitKcCtmUU5jR2dFYkpXcllVRkUyU3NtRWlSQ3drRUVTMzZFVWhQRSt4OWphc201dDZqWXM4U2pxeDU0MExtVS93QW52NS9sRHJWb05lbE1jWUdxYnNLNG5uRmthbG9FWXJJV2xPVmtkVUtleHFuaU5oblFHVU5hbERiWWc1ZkVtd2lhbFBJM1VrRG1wbEMwRjdQa3BoVE55QmhYaVZiSHc4RURxYWs1MFRzeHprWFN4d3ZIc01TZTlMREd5Vy9VUDhZMmxCNDlWRTVIdk5FV0tSK3Uvc2xpTXBma0VndnZDVFZWeVZOaWcyTVMzVWd1em02Y0xDUHo5RDFURVVHY0w3RkxSUkRvcWpFMHE4OXdzbENIdi9wZGgzWVdFaGdwVmdoZ2dwVEcyUW1BOVEwWGNaVVZxZ0phcG9JcWxXcC9uQkdDS3VVVzdZMDZQYjV2UVFhMHBSeElVYjVlQjVTbUQxbkhzOTVGTWkrQkthc1NMVmVCTlVKbW9Vc1ExV2NyT1QvYUNYVndjQW1TbVlZN2lGN0ZENmlERFhybHZVMHFUNE8zOGRwUFU2ZlpOU0xhWFROQVRscWxCK3FRYXcySWEzc2Evd0NreS9DS0oyS0JQVFpXUm55TkUwSmExYjBkRUdYOW9SUVVYRlJsQm5WUGMycDBJU05XdEY2VzRwVmdHSDl1UmpmSDZSNktzT3ExUW1vVkhjaGlobFMycTVRbFNiMXlYVXlkMzBLSi9VZjJNa25QYzBVUm1NbFlRb01nb3ovZ1g5dURCbEgxS2d5bUpNbUhEYThtalVmWE9jbjRnRDh3U0ZjakljUzlTT1hKbU5BWDZCUzFGSkF0ZXA5ZFBhM2tZOHF0aWtTdnFhaW1mSFNVSnk3dnNKMUdzSHd1aVJiNEt6MzRoZTVYYk4yMlR6d0lna1Fpd3h3SDhjL212VFhqNFFaeDZ6SUJ0a1dDR21aSFNBdmtRVkJLcGlrdWtQSmY3L0JLWEFyZlAwVlBzZVRUZFZNT0YwUWxLbnpJOUxtUVpzajNQVUt3MklpV2pndkJRaENjajVjR09mRWx4bmVDWE15TnhRMUtIcUpVM1JhREI1UU54elQwN2xDNXl1aHN4c1dFR0txRVZTcHFpSjY5M1hRbFdwVU55MHloaGJYNENaa3lvdGQ5QldIUmpDS3JjRXV6N0lhSFFtV1ViOEp5MlBaZXhKK2loQnAyKy9SYUxTaXJUdWw5OURkK3o1ZVJ0WHdTNUlOSnhFcUd4K1ZIY2hOVmY3THQ5RkFXREVDNUxCWENQY2tub3NTaXE3S3V4VTYvUVcrUzMzQmFkS0pmdkh1T1NFNUxqOHcyOHRpWGtMTkRGb05HcUw0SmNpdGNaUXpIeUlUZEQ0SktCWmVnNm9WcXVzMWNmbi9EZ1ZUWThYMzdsZmFJM0l5TTV0QjBxNkdGNkNsZDcwTEMrRkYyUGNaUFJKSklyUjNZc0FUY2tyRWtXV2cxZy9mUndJTGNpbm4wRDBFeHVVTEhqYUdyYW9jOHd5VTlCYWtVSmozWFRHTktGcEs3aUdUa2F4c3JORlU2YVhOdmdodWwyeENIQ2t2bnh3VkJmVGtTWnh0ejJZakdKbHRTYmh3S0NTV3l1bFVJVVFoY21iRDlxT3BmMElMR1h6NnZ1WGNhaUcyMEc5MlZ6cXF1RVFqUkM4cDhyN0NIK0FqY3QzZlU3S1ViUkJkUCthUlppQktmNmhLMEZ4MGhrbFRmOHhHME82Nng2MWE5Uk0yOXlEN0JJejZpdEhkdWpTaGxwTHVNT2d1QjY1cE96YTVFaFc1RUl3bG9LSjNWZ2xMWGJUOENSZWJOOTBDVGFmQzA5Q2EyMG1jZVNKUmNmTkdreFBwY1FhS2FiM0hSc3IvaDRaV0V6clo2RnhqU2hhL0EwUDF6cE80dkFoRnNpYXFwSndxL0J1RUF0cWVYWEFYT2ozaExkT0w3RlNuMmdueE5pV3hGV3ljdnpjYmJjdXI2WWVTMHZWZmV4VmNXUkF0Wm5RVG9YNWNtUmRFeWxpcjJGeGxrbFJ0bXJHbnRydU4veVFud0U0WmhoWlR5aWVqVFFiTUQzQ0dvMjFYU2l3LzRRS1ZDSmxNSnA5eUpsQ1ROZDY5WTl1ZlFhT2lWRVovYUR4UW5nMWhYSXFrS1luVVJvbFU5cWtUTk1yRDFKcDJWVGhYaGFJWHl4V2EyclBRb0ZSY09vVHJ2YmpTVlo2V1prdExqUm9xNUZyVGdoaFg1TVFzcnBiN0ZldkIzSmo4eXhvR1QzWTU5bVRZbUtEWFJqU2hDMHZvUnFLVGJzY2dQZGttR2hlWC9BRWlGWFM3aUdzKzFHVE00T21nK29TZWVtQko5RGZrTkRGMmdXcmNtL3dDTzQzS1hWa0ZMYUViSkUxcFhZV01FTlFtU0MyUWp3SlIzRUpFTEpSVWlYZ0NSZE55Slg4TE44dVVKMXZKMEswWGM5VThWWFZ1WHpGQ2I0eDdpdXZNcWxWVCtNSnNiUWg0eW0xa0VwVzN3SFdaYkY1WTNXU1ZWcDBBaTZneGlnUlhZblZIcUNxemovU0lTeW5WbytraTg1Sk42allwS2FLbDlCN0xuVnBQV0taanI0VWwydkxnZisyTCtqWlVQWEFZNmY0cWxSdlpIeG9OVVFkS2dSUVErNFNrL3ZxbEJGckoxa1pkR29taUMyc2NQdjBRUU5sb3NqVlNxWGRGMzhHN1VVSmFaMjRWUHMzUU5rOFZmTlltajhpVTIweTBjeUtUTUd3QWl3SEx3TmNjM0pFSWxHVzRuMGgvZGZIWU9tWFpHS3Q2akhVYWlTZU5CUkNqbWk5anVoeEZyaVNlQ2FCaUdsL3hUTjFvWTdlWnRzUXl4TC9RaE1hNmE0TWJnMFNSMzE3aHFEWkY3aFNsUWJwR0ZUa29NbGhWcWtYTytsNmRZbjRMMC92b29KeXp0dVh3ZFh4NGdXWEQwK1hKUm5WcFFocGRxdXBhSDNMTjJFTmw4NGZ0MkVYNzl5V3hwZE5oYXJqa2FMQmd4UDhFaVJva0xFcHlpb3lETnA3c1V1RGhsK1N4czNyTVlpYUtnNnVjaXNKRmsxWVNTRjRzbGUwU1pjMFIrck5YdGI3eGIwTnRHaEVYTkszdExFbTN1UmJiSDMvNjJTaVRsWjFpT0dWZEV3eUcyNWs2dldQSnBJVCtzSU5aY29PcFhkd0pNMTVpemdSMFR5YjFZMDJxYWU0MnpxNUZRc3cyYmdYNDBKS01VdFVham91cENXRUpnTFo1TzJSVk5Cb1Q0Y25zemUzWm05SEplekxXRUVLTFIxSC9SWHNaWGQzdUkwMXRKNUZjM1g4N29xdEZEeTNTYVYyNEUvcEJpaWZxYUVXeWd1anlaQTd5V3hPdUkyR3hxZGhTamREOHRwYjdsdjgvd0JCZDFyTmlYY1pweStRT050cTdqbXNlQmpMRzNHb0hzUDlramY5UnBjcm1xcUZlV0p5dUxWZndUYkZvaTlJOUdwU3l4aG82QmhmTDJvb1hsamRkc3IvUThZRktjWGdpWVVPaDBLc2lpYzBtS0NGTFZXRkhzSUY1aWtyaGlMdnlJVzd3VzZkaG9WK2lWakNRaDBiMVJDTFQzQy9hdGtGL1lzYnd4Y3JvbkZwUmx1Z243VFkyVjZDYldST0l5aHFXUGhKSFdJYWYyanN2VWdOdzk3bTRZMmtJVFFrSlk0ZmtVWm5rbklSM0xYaG1TNzdEOXVpenlIbFMvVWsrNFRKWlZrbU5ZZWJLUzg3WmkyOCtUVzgwbSt5ZjZjLzA0bks4alo3Q0I2SUYydXIyRFgxazM5Ui9pU0VidlErQzVKN2lkQjJEUHZnL0NLanh5SHFaVTYxeFNVY1lOSU5rZTlVTGtucVJYWndrTmZnSlA5ZXB5RVhzSDJMWlhVRWpramxvcjJVczlUZGtxSVNrbEZOeU9jUXRoTE5TakU5Q1dWTEZib0k3RStCWFNmRVlzL3dEYko2d2xCMFNReUJXQkpOMG1VWXI3azRwN1VKYkk1R3V6N2hkUkNGUEpYYy8wWDBNL1g5QkZQKzFKM2ZZNHJCaDMxN2xVU0VHOUZRMTBEbU5XQ3BLQ2ZRYm5Ba0w2Y1BYczZldDZCTVQwQWcxaW1ZRnZTVHVWUnRCN203T3hnb0R1bTl4L3VEL1FIK3lQOWtmNlkvMVFtazB0ck1uMkJFQVQ2SmJJSzlvbDR1UlZjMjNIdVMwNitHMmY2OUJoTGN3dGxMc3VpUkQwWkxVVDFlRGNlQ1dqOEdialFzZyt0VUU5SU80bHFNbHNLQ1RpakU3anFKWUtXaVlrZ0NxM1lwZjRwR3RLRDB0QkRYMUd3U1ZYWW5RVXE0alU0WWswSEt3Tk9XQ2NTSlNuWUcyNFZkNVpMb2xvUzNKYmlkcHNXVlNha28xVjdEUWJSM0JQTm1KeVhRa1NKa3lSSFkySkl1NXJGMkNuQ0JralRwVU8vd0J4OUEvaURzSW9mUXJpNEg4YUVJMmRpL2djVkdpb0lXWXhmOEJpZ2dobXd4WCtPRXJUNHBaS1BlaEpWMlFrbXFZd1FUalc0UG9kbDk5NkQrSGU2WnZUZGkxSXV2YWZvajhVTGFpV2hRTkFsWmhSb1FnMWlzUG9qbE5WWVgwS2l5RVJDRWNhWnNHM253WDBQMm1zMEVNYW9hRUtKWG15TXFJWVI3WWFwVVpUMlJldEdHZ2srWnpnaHlsVTZiZW01NmZlRzVKOGplSHM0SjlETnkvUWROZlJqVGsyaEpmb2haUVZDR2NmUWxQOEFmNEUvd0F1ZjQ4L3o1L2d4dCt1Tnk5TU9JbEI2Q1VxVjBXRU5uNGVldWMwMFpwbDZzMC9ReWozSmZoajlQcGxkTWVmNERtQWZBN2h4eXV1MzdJL0tEODBqOEViendiendJb2J0R1lSMElMR3U0bmVPUTlxSUZwZEdSSjNEMFY4K3FFL3Z4UTJtNmpwWXVpY3ZBOXR2UnFCRFNUVW03YTJpOVVPdlVXckJTUWpUMGY4SWtZZ28xeVZHb1BoMEp4cDZXVWNFa1Y5MDl6d2oyUjU1WWpzYnMyeEtZZHdoRWtEVHBKNk9TSWZCT1Q5REpZOERHM2FYcUlZYmJtdzIyaGNEYXB0c2tWN3V3V3FkM1U5ejNWSi9aKzc3RHBJNWRoNWNDU25STFUwZWpIS3YvSUYxQlpLUjFZL3Y5N0RWbGp3UlRLbGgzNmZ1NTZlcUc4Sk5HTVVqZ25KbG81TGFQaGliYVZSNmlid2hlbzZIdjUvbzFYNFNEZDdmVTlSVlY1bEZ1WFluK0xHUzAzbytHVGF0b3NpK1JhcXFHeXgwcnpFTFljeTJnWGxDdHkyYXYwSk9GU2V4TXhHc25wY2VRNXRHaFZETlBabU9jQWcxTW5xd3JoalluM09kNUpWUkRpcWhycGVCVWNDWGM1RW8wMzBrZ1JPcllpSlUzcCt0UFFpUkFWbFNoMm51MmFLNG9ObmNZZVBSaFh2SjRSOVpGR2pEcldwNm1XSXNqN0J0Y3o3OUZTTWZBNHBjZXJ3UE9PaWZKWXhMZHl5UlBvWFFjcHBvaFNVNk5ENnVxVXNjN21oNmsxbWZUQWxyN3FhdzdLREgva093bDRJTHVQa2RCNjRxSHAwby9iZnA2b2YxZWl3SkJVMUtBMThqa3lsMk04UnBYa1Z5WEJrK2U3b05HMnFHVFdvTGgvRTlEMCtLRDlUQi9WS1JwcTZqbzBNTVd1TGt0bHU2SVI4a1AwbHV2Z3hoZG1HbXJwanltN2wwTHNITnpvNGlrSjZRRWxOZ3llcUxQcnEwK2x4aktOR2h6S1QyS2t0QzlLc2hyb0ZIaEdTaUJxVE5DWXZFdWxoRFoxYmI1SGtkeENKUk5KSDRSOUNsTEFyTjNxVm5zUzZGc2Fsb1hCbUswUmZBVVM0UmdUZWlwbGJteVZKc2dkU3g4dm9yMUhHRlFYQmlnZitRTVFZYXl2QW11eW9PMDJKQU1HZXEwemdhcm9QZlkyd0hrRXJuMFVQMjZQdThmVHBjaC9Cc1F2bElzRmJxTkhnMFJKWEVXSjMzRW1ub2pWMkROUW5jbGJqeHlyb0diOWJQalpuNXNQVVNXNENBd2h6bzFBeU9oWmZCbEhvOHloTDdNRmNwNGk4SDRDWVpaQ0UyVkNHN3lKeENhZ0dhN3FpdzUzVENNT0NOWEFtYldqZ1dEUE1RdGhvYnIwVGM4djdyTDNPRUtSTFVXa2tsUy9NVGUzY05VZUF0aE5Mc0hsYmtOU0VydVZIME5GU1RXaEhvOHhGMVhpQ3JTTGlXT2ZLTWNzWU5kSE1jWWhtMnVyd09QQVNSZVRVQTM5QXk5eEJWNjBubzBXUnB5MlBTRzRlUnZxSVJSaW9HcVBnVGNuMDdDZmJyTXdpVFk5NHR3MEphc2R4YXZCaWZxdVJXWVFRTlU2R2p1aHJ3WjZqbCtvbGJLSTVSZFIzRTRkS2NFYWhLTEZTOVNxMG1ZSkVQbDk2Qjk3WlhnVXNYNTNIeTZrRDJtaEZFZmwwSWJRN0tzdjRIUzR3TVF5SWtNWUNxVDlUR3VUbTBhbGlWZEVudmFFbDNVa25BcldaVnFEcFdjMWhFZGh0aUU3VmZ1aWM0VkNUYk8rd2tPUVFzb2hHeFVObUkzQklqdVE1bWhDSzZHeWlMNUlzYm9DOGZZcUlmck1oUzNtNmFFMTJoUXZRYmxMcTl5NVZJYTh6d0p3TUJRYXpadUVtZ2d3MVVTcVV5MGhKeVJpaVkzaUVpVWpmZEY0MzduclNqWVE5cFRKVkNsemtub3gyY2VpLzRJRXFTMXFFSm9JWVpqdERVVHloSkVzb0p0Z29kb1pCQkEyWUdMMUJ0aENNaE1DL3NoQWJFK3NBR1g3SUo5a1BPRmR0RVFLMVNJOUF3UWlpS0w3SmU1alJPS3RzMjNjaWNuQklNT2hWNFJsSXkwcldoQ2NRYTZsTWVHYnYrUTNMYjdtb0tGM2Rma2tlMG9UVXlJbU5DcU4vWmxXYWRHdWxBNklrYkdLUm9XRHdublFjTDY2S0JGTEFvcU5hc0dxMVJ5c0h0aUdFNFRjRjI2Y21PK29keFBrN2FrWkcxdHI4OWVzQ2VCRzhhaE5IZE94UVhYa1JJek5VeS9xY3g2cFBpZjJZMG5DQ0pDYTFxOWhReERSZzRoT2NpbVVmWWlwQTE1KzJtZzVkMkduNWV2VmRKbVlrRXZ5NldtSytBdmtjdUxzVEt1WDBOWmFic2ZXWWx0NTZRT1VTb2RWZGk2MFk4cjBnTWxOTlhOcUdLb1FrUWp0NlFEMVNpNXNnUXhxRXBCcUdWUERveVNFNER4L0VKam94TThGUGZHYWRPU0tVUk9Sa3duREhRRVJOQzNIUXRXMnFQM1V6QTRLTTQ1RFo3R2tNUlE2QkVvVmQwSThOUFgzVVR1UUt6YjlrUldxVEhLcitTRzVUTDI1NU05TUlkZkE2aVJSbHh5ZTQzeE1RcUcrQmxHUklOdDNiWkdsZGtVTlc1aEhsNjhJY1YzR3l1T3czSkJIUnRYQllKVmU3R05NaTRqSzk5aHJaQ2hWQ2h4bHRHN0dONm9iNlRudG5SY3NWOGpmNllxdWNpRy9ReUNhSm9pZUdQbDFkVmVTRHlpK0ZjdWhCaE5hV005Y1YrekVsQmxoOUUzVWlVbzZDblYxWWUxc2V2VGlseGpZUnQxaDlEWFJvY2ljcEJNbkJ3MDVRalRzZ3FaRm9FMjFHeGpmR01ZazQ4Z1h4Y2l6SndRVFZkTzdHaXNwSGlLc1U3aUZ2MGFmQlUrN0hjNFNyUitqcThLUUhBeVBab1dkRlUxRE01MkdOQ1F4Y0VvekhHb2gyQWN4dWtxWFlTZ29EY0RaaE02aHFOTVM2NklNSkNSVGhNa1MyVlI3elU5MWk5V1hJMkd2MU12a3BDeW9TYmhWYkhTVXVyN2g2Y2lraE4xUmFic2VYbWJsdGlab1NXN0paRjFqaGIzRHg3a0VDTFdlK3BkbllqRnJRa1hyVVEwZDE2bENjTWVGdXdVNXRLd1RPNjdJbUc4c3AxMW95Q3RIZ1QwcU5NRWl5Uk1KR2dZdThQMmRGWXRCUHZIbzd0anNSYUhXeDdEM0Y1a3lJYUd1bGFRNkMzYVNWd2c5ck9jckJCUDBIcHRGeUlURTVHT2JhNkhSMUxqSGNTSkNWaW8vN3gxS3pzMWs0M2FlcW9UY09rWlpRUFFYVkRxVWtyVkJVNHZjVHcyVitlam9CU1FKTnRJcGFpU3lPcE8xVlowZGg2b3VzUTN5S2pXNGdTNTFXQ2ZqY3NhbmZZNXZncUYwNnhQOEFkOEloelVGcUU3RFNiT1JWT2VvN3VXRVE2U1RMSWtTSGRzZ2diM3VGa1ZNTjNsK0YyS1VDUWxoY3pMZkNKdElrb0NzTVNFNFpmNUtDbHlTcnZrU2xDZ2tXU1J5RHhYN2ltZzJpM2RIaGdsbVREb1RKVHZBamxRbEZxTUNkSHdlQ1FpOVg3dGZLSEpUVlJQMEllb2U3ZW5hejJHSncxVkZqQnVpNTVQM0I2RFdhM0pld2hpNFhVWlBDbVFWbXhHSHhCRWYrRWRSdFJlSDd6L0hHU2JoS1Z5TlVYVkthQ3gzd0ltelpkWU8vUmF2UjJhaHVFMnlYcDlqc2hKZk52YUxoZE81UnVGdmNKMXMxMTE4TlJUR0hYbDVuOEliSTBuRldQVGViRmkzSFlIa2xONHh1UDVUZVpSTGw0Rk0wVi9STFBjckkxR050cTFZMFQ3MG90VDNPNHMwSW9MSkNSanpIU3NUMlo2dzN1WktrMWNrQ0lFTXE3RkVoN0RDb1ExUnJkT3FZcXVDZXArdzAzYWFhYXVtaVJyY1hRbU9xYkM0MGl6VjBhZm9WVnd4eWh2UEthKzZZZ25ZNktlejNEaXRmOFM0ZTdZcVdDVzBxalFuS291ai9BTEZYWWN0MFhROUxaN0RWRG93aElraWJrakZCM0dhZ0pmeVBUa2ptc0dpTTA0RUxxU1VXUng2dDByeTZJa2FLcnNPYzFGWmFGb1R1TnNsU2hRMzl3ekhmd2dyMzhERytNc0tsa1lPMHVmb2ZXbTFZMFNqUTlXTk10NUp0N1BoQ2xPcFR6Q1NRNVNWN3ZBakFiVWtOS2lTb1FzYWN5Z1hBSlRmcURGaGlLVWNNU3Jra1lFL29xSWxWazNnSWlFcDdrWjFiVWFHY2xhRVpKS0xhb2JXMitpdVdTM29ZM3FaQ3ZyMExZRTF6WWR0R09MYldITFJxUlhYdVdIWnJkNC9PQ1FzQk84cnBQU3BhaWFvblpUYzJnZUhlY0U4SFlJVEsxaXo0S3loT2FDRW1tb3BEZG9iNkQ3R2hFeXlYelNoL0Y2aE1yMG9XWkRsMVY4RWxTUzdHNjJYUWpoemZweHdrSmtJbHVrRHBUNkp5NFJ0dzJrTnpxT01USWhKSG9lbjloYlEyV1N5YUV2QjBjdjRSRmFtajhGNkZLeHEzc0pMcTAyOERYdlR5OTMwYkN0QlhnYXRQWHVaVFg5eGpZMnpMZFJRV3h0TFNiQ1M0MUkrMTdDYWlhNTBSNk1oSzFzWFJpSElIV2J1emdJOUhram9SaWVOT2RuWWNtdCtFZUdKbWxFcWgwZm9QczZYWHlScEpiV0pPUFJvOTlSSzJhclVWNmlvdm8zRVViNXUzdG5zUUpTOVhlZ1pJNW1ub3V3Ym9UempiNmR4bktVUU4rTEV4UmNKbUFUcXIrd1ZPaFRPaDZtbG05cjlQU3I5QmNqYy95a1FadEVweVBWb2tTV1hNQXlaNUVwY0ZHNmVMTnExR1NTN0l1QStpRVRxVlBBOGlLL01IeHdpNFZoSFQ5NDhrK3pSQ3drdEVzQ29uUnV2ME1ma2VSbllTdlFTRlNxN0E0MUo5OXpCSW5wSWxWcjc5VTdGNnRpMGNqUXFoMlgyVDVROE5QOVJsZUwvSHN5QmxaajZGZHZRYTRZaWhLb1NQRjhXSTBTUW84YURWV2g2TWFhdU1xWmxCdUxPVm1PcmFqVU1VcDBhTGdMcTUxNWZQRngwa3VQMWErNDVxN1FwWmg5R0tncmc2RmcreHFOSlZJSlFFeVpKTWtzOVJZZjJCS3daZHpKVWF2L0FNbVVHTFord0dTYUhsWk1oam9oU2R4Q1dlcTd0aHoyOEluYUE5ZWtDSWNQR1RIRTlXcmhkRmZCbEZscWpzKzY1cTFaSS9uVFV4alZJZ051MEtMdW5ZNDE1S293dGtzdjRKRVpUamJPMitld3lNeExieUpWcVdibFpXUk52VTcreVR3UWhwKzJ4WGsvdzdNZ1loa2JoSkgwTGNsWWZaMTBORGF2d0QzVmhpT2laMHFRamFrUzFrc1JHMHNWdWhxbXpUUXFiajFYd3p6ZmtaK0l3MWlNMVQ4dTJwQStrQWhYSXdKcWpOeTZsMVJjSW55aTNRdkhRMUxLckZ0YXpqbjk3ajI1WkxJL1JWR2w5bC9OT0dTd0lKYmRDb21oR3A3SXVUcGRoREhWUnRqcEpQM05XcEdwZFlvWFNCSTBZR3E3dUJ1WC9HRDBRajBhWXJMWUcxUlc4aUN0ZUlQVUJKcEI0SmxpN2cyOHZ6UGl3K2tFREhnbXBCRzdGNVd2NFZQSWhaZXIvV09yMExSSnJjV2JiY2ZsU0laTmlDTGJFSlZITXhBbTlqVlBIMEVRSWJLbEtYNHVMUEE4bzVEU1pHUVFMVENIUnFrRk1kdTBmNjNJZ0cwTzdlNDk5V1lUMGx6bXFrNVE1dXV6OGwrbmtSNkhmeU5UYXNsZm43UnVFRm8xdHFSMG9RTkVaYUhkdEhwM0tHMDZOZTRobG5jUXhPZ3BrZ3FkWDcvYURPekpmOE1uZ1ZTSHdPY25nVmJ3U0lJbEhUaHVteUcwa3VpUldUbFRFRTVGQU9zVTdzZlk0alV6Si9zMHNKY0EwVmFTdTBrRDFNTnVpU0drQXFuS3Zzc1ZWWEVKWVRSYUQ2UWNJYVZobXZOYnZZdlVaMVhXNjJXWGtSRHVvank5bnoyR09iY3QzM0ZxZnRjK2tWSE9jbXlLZkZJU2UzSk8yRm91eUVqTWhHeGpUSXpaNnR5ajJnaUc0RTBJSXBHYUNxVHdrQloxTlZib2tJY3JSRDMzdGdXU05KNHFqdGNvdVhsWU5WRnlUTmV3M0F1cVNMZTZZSDV5NjZHL3E3ZUJqMk5WM0VQYW1CeHVOSVNhQjZFb1dudVdwVllTbnFIeE1rcElKcWF5WkN0Rm9zSTNZT0JsZjhNRGtwbjZCekk1NmEzeVhTQ2dsQXB0N252c01ZMTJNMGlLRUNKL2FGNlhacjJIVGhHTk5yaFpEWFVBMjNMWkdsNkQ3SjFObjZnaEIzU3FFbHFFNnRqZlR0cU5VUDZ2WGcxQzhTbytXTWlwQ0NydXlEdXk1UHRYM3V5TXREZjl1L1I2TjZEWHFjT3NFbHlQMHRaUHVpVW1leFJvdkNTOWx1VERnNDArK2d4TENlU1ZGRDhBZjlPai9QUi9oeFZZSjlXM1FuZEQ4UmRMcHBvNm9hK0VYd0lxT29JYXZRVng3aWJVOE92MmNqN2ZlOU9COVplcXhjU2lkbk13YnR1cUVOYVVPY3B4UmFodmhObWVtZkY0L3h1T3JsQTA4RFUxRVRJbnlUc3hNOWFKbjdEVmxrRmk4czI2SmFtVEd0Ky9VSFE0bFArTXh5NkhKbEFxQ3pjTVNCRzlRMkloZmFQVWlibEp0WkU3anFyMFRkNEt4K08vTGNqSGlRUnJhU0NlSHRyUFBTT2FvUFhNNG5oUG13cHBOZmFlcjM2VUtTd2F0ejhpbzk4dFY4SzdGUVJHR25iN0ZFSXMxbHdod3JscFVMSnNEUTBVeUdMMGZsYXl5UUZoMHFtSUVHeW5SRXlOZUJCSlVOVDhINWYyZmgvY2Y0UHMvRSt5NG1tZ1pBa3k3RG1XOXkyTmxYd3dMVkROeEUyVGFvaXd1ZVAwR28xRTBWeHlTdzRTOW45TmpRUFNyb3YwWHBzeGI1S0NxWDMwWi9XS1hYeXVzaWcyaktHVW9VUTgyb2h6bHNMYlFLYXFoQmlIVTFjQ2h0RUk0YUZsdDRWeGVyVDdnN2FXeXhxRUwyQS80MDRjazNzSFV5SVdZNm9TZmdUZy96RkNsc1pFMjlFajJYaHV5UGp1bGpsNnZrazlGZHV5RlpQUnVFTm1sdVc3dGlGTmhtNFNXU0Y4YmZOWHlldzlRN09yMEVSa2Vpa1ZjajlDeDNQelMvaEQrd2J0bGs1ZE9SYXBXTnNxNlBZaVM0MjZIcWhZMVh1eG9UOVVIMVA0R29hbU16SGtLcG9QVjBxV0c1YmVwYWFJU0pnWFBwSGVDRTFLRFlVdEJ0TmFEWFl0MlRmanl1UnByd1ljckdVcEtvYXpjVHdwNE00YjVyaS9JMHVLZzA4ZndUZ21ZZUlhdXRqV1I3cXRWM3pMWml0alhWQm9mL0FGNWFsM3E1L0lzZTFnay9LeC95eHZwRXRvVWFJQzFYbUd5SFc1V2hEUWEwd2txWDJsbDNMelpXU3N1a0RDbFNSTDBKMWJHQjdrb2FvK0E5UkpBcm13blBDVjNzOXlSMC91YzNEbHNhakxya2FCeXgzR01TSTZKd2owY2tpaUlmYm92UTM0Y3g2UDFSRDZNUCtiSWVyR3lScnVrdWRFSTJLdVFoQWxJaFhWUzhLd1R1WEZPM1NpOFIvWTAxRGJhb1ZaT3Ewckk2cWZDUlZOWVhLM3VaMUsxQ2RVOGlSMGtub2JHbER4QThXcm9kK2d1WFpYLzU1VmFqcVZidVFtSHdiWXUramNLM0h3UytpUkN2YXNYNGNpVU5IS1V3dTdidTkySUpsN05FNzVJQWRHLzBKTkNYZ3VVTHVNYmFGcUdtMHRKQkhTR3cwcVRCeGQraElQREVoa1hvL1gxbHI5VVJQUzRiOTJSZUVJNmZlK2lwclVyVHlWQ0VwRE0wNEVUVXlSQnJiSkxLTWkwVHVLNVE5QXhYVjNSRjBDOTZTVjJoTmRkeGhpcXZIRk1OOUV3L1FmOEFGVU5HeG1GNjkwUzBhZEtjZS84QXp0REZKSFN0WDZMRjg3cDZvbWIxQmp0emQzY1FpQnBXMkUrMTJNbWpISFlIVkVWckU0UkVsd2N0RVUxTGFDRWRIUWVnUUpFTzVad1FWdDFGOGtHNm1KZ3ZRdjZNeUtXc2ZTNnRFSDUycnFSME90UmR3UUMxUWt0YWV0T21nanhxTXhnZ2RWSXFud0tvWG9pcjlZUS9zVFRlZHcxZWpFeTZTV21HT0tQTlJSSzlHdEJocHhybEl6MVNiZEN2cXJ0SUpRdGZjRTFFNmpBNi93RFFrSEtaR1ZKU3UrU2FRMlRxaGFZWjRRbVhtaXArQTFpYlRlQldRMGF1c1VEdHF2UWQrNmFJUWdRMmxlZzlBbkM2aW1WdEdwT090WkdTeTU1SGVHMEVGZWcra1labTVRemQ1SWpjajlUV1BWVVRHQ1lyNVJRdWxKdHJGT0p5UnR1ZXZzT2kvVWhwWTJocHczb3NzanVUVkNGUi93Q0NSUnJNN2lLTlFWZTdJM00wVDNGRkV6U21yQWxMQnRBUFV2UFJYc1dSU1U1cHFua2tEVURxSk5DVmF1eHZJcWR3U3NCYWtia21MYkZ2QS8zUWRKTHprSm00eVM1cjJ5MVpPTHorWmZ1QmtwVlk2VC9wUmNpY0pHTWt1aGRnMUNWS1RWWHZidmdZem1YYmN2b2pIWkZiZ2d1amFEbllUSTFzYllsb0szUnI5eDNncU9rbFdXWkR0TkkxWDlEUXN2cS9sOEVYSjBwWEliOGE4VXFORGdaRTNsRmRpMUdzenUrcjQwRzVTb242Y2h5bWdrbjhuMFBVcTZIOENmbkFWa2FwTW8vN2JsUy9oUlFRZjlXUzRlR2JhVzBtd3JCRHFhTVpvTndJRFZlcUlKUndWYkl1Tkdxa2xXd2hFcGpXWGExSmwvU2hxUTZwSzhIYjl2ME1zc2Y5VjRxaVJVTkRBcElCTWlJRXRXSVIwYUJ1dFFjMEw2aGJNSzZHdndCVkRPMlJBaW1wSzVGVmU0NFg3SElub3cwc3Q5RWhnZmJ4bS96NUZYQXJDbXY5VEZBdnZTSWJhdjRSRVNWd2VIOU1tOVRTT0d0QmZ3NUNYdVdRaWlzck9FajZBckdJWmlkQnlLZHBIWkZ1TEx6WDVLQUZmNktpRVRhVDJrSVpPOGVCaFJrU08raEJMU1B3NkoxZXFIdFBzVlZvOXhGMm9obGlpTHZBd2svQ1N5TmhlWWxrL2VSamJZbHQ1R1QwWC9WdDBNVXNLYjRaUk10Qmh0VEphOUdSMENIMWkrcGp0UnU0V3FUVzRZR0daYmxtaEZSQXRCNUhoZnRCZ3AzYnllU3dJRlljV1V5d3lJdFBpMVhrVHdKTUFVQlRrWE1ES3ZvL1l1aUVEV2xmUWRYSUdMN3kxTVNLKzF5aWpmbVFqR1hXdWZUM0ZidDJTZlRsWDBxcVdScFVZR2thbE5iUFFhZmloQytQN0I1b3pFMUdvOFJ4ellKSWRjMXJOMytFU3pHdHRsUFFxNVRnc2tTYmthNXVNRUNSZHlKWGE0bWNKS1d4WW9ub0s1ZDVnbjd5T3d0UzJ1Mk4vd0RZMVF4ZW5SRGZDRTdvRmZBZjNyaEQ2d21MKzRqdzNnRVVPUGhJZTJTclVua1FTYUNad3RUbEV6VjNkeHVCTXJPQ2VFcldsV3dpVFFpTW9jYzZtd3N5ZmhHTlBYN2lIb2hzcndKRGJ1NmlPVkpyZ2hCcVZOV1ZRZ3FrRkVyMUo2T2NWNUlOYVJCRUlpQ1N1VG9xdUJwcnFKbWRvVWJpYTVZWDd4R083YnV5V3haWTJJZXVob0RTM0VYcTdzWlVPQjZHbVNSTDFlYkxkNkROVWtZOXY5ZVJoZVlsdHVyWXpULzdLY2RLOXJETnBUaG9Vd2UrU3IvV1JNOXh0SnQzbDNJYnVSRUlJNlFOVUZZc0pLNTZXSnZKU2dzSDFMM0g1ZWpvaEMvcHlMeGlKaU5XZEFOdzJDaER3L1JoZEVTcTROaW5ka1ZITFpMTUtoWFZJWHF5UlNSWTZrdS95aVN3dEpUK3d6MDEvaWZaT1JzbC93QzNKalltbVNPVit6a1BXYlpZSzhWLzRDcFFhbGRIcjBUOGtTVnRNOWU5d3Y2c09pNkszK0pGNHhJWHh5SmJrbkF3NnNTM0hWSFM5TkRDS2wyTm5aUUttV0V6dGpjaEtzenFZNWJGRWdmbHlVUXVxczJ0aFZRbzdybDBjU1QvQUwwZHhkQ1hQVEt3eFpReVBaOEQyMGcxU1NQNVdIUmo5R0hJOUNtWis1cVB5dFA4Q2ZveUx1aUY3Q1ZMUVNNekh5SkY2RnFpU3ByRm0yTGxha1hPclRBOUM3WUtybWlFeXNhNUxlaStoZHFWaGUvZHg1MFV2UVhWay84QUFoSmxjM0UyMHB0UFlSdHFqVkN5bzlDRTl2WVlyL3h4THhYWFNwaVpxTkt0Q1ZPamU0c2ZxbitCZnpaZFNQVGhJN2NibXA2S0U0d1BQWVVwOEQwZ25Ba3QyeHZmc2hWdlFhOEFvcHEyU3YwaUF0Z1hYc1dRMm42Ukk2ZEZ1ZjhBd2s0TzBKNEd4Tk93SzI3U3pFMHhvTVFlWWVqR3l1UjBpb1duUldYUldSYzlnNXpZUVdQeFQwWFN2N3NpNWpFZWpIbHQ5SDZ3bU55TXNiOEJjU1ZkSFE5MGhHak1pTXZYZEw4RGVteWlOWHdTNGpQUTRmOEFqckZleGhDYzJMalBIMkQwT0xDbVJDYUtrTVMvd1ZHTGZveUpNM1NacnlOQVVPZmsyL3cvbTZpOWo2UFNTbTJpdjBxRXBZcUZDV3dtcHFPT1NTc1NwZlJzbDF0ZWcwd2ZLK1B5SmlqRTJYWWtub3RuL3dDU3RkU1RjNzlHY29jQzdocTVkSlRITkswVkpoSWZYZWVCT0hKYmVwK2piMXZHUEwyTVF0dzRncWJ5T2lZZzRNSzJPZ2ttMndSRGxxb3hrbHQ1VWtiNGRhZXFGa2MvL01UZzBFaVIyYzdaL2hoem82bGp0aWpKSEVGbEQ0Z0JibithQ3FZcXVsWkVmNFlkWHIwT05Wa2lsNmpvamhYQ1ZhaldyVHk0TDFKWnlJRXhRT0NFSVlacFN5MHJ1aGVQNEl5R3p0VC9BTkZLdlZDY0V0ajRMRTlITXB0bkJZbjJWSHFSSTk1Z29SeXFHOHlMVUh5YU5KL1FRVFpwUllwSTc3U0REajR6U1JmWTRCMUd1QW43RWtvTWNtOHQ5V2tub3EycU5SY2tOVmtNaC82cWJXV0pXNG0zbGNFcDJVbXNEcC9HbTNTU3o2a3RTZGluOGI3aTBCNWs3RFJjZkkxdHdUUC9BTGF0R3hKM05aT3dtaC92UnRhVDE4amc4bTBiUnhlVGVua29CbzFjSWpzbUlZWHVQQzQ0Rzd1Ly9BLy8yZ0FNQXdFQUFnQURBQUFBRUxITE5OTU9QUFBQUFBOTlBMT0RMREdQUEhMQkxQUE5PUE5IUFBQUFBQUE9QSFBQS05QUFBQUE1wRXVPdVZsc08yUHNQUExEUERIS1BQT1BQUFBMQ01NUFBQT0RHZndWaDNVMGsyZ3VLTXhaMkZmTFBQTlBOTkxQUFBQUFBQUFBQRFBNcHVZRC9HVEEvamFxN0hQMlErdjlQUEhQTFBPT0lQUFBQUE5FT00xa0lZR0RnKzJDU0RETHlkNDNacko4bS9QUFBQTkZQUFBCT05EUEtBcmVCU1pSM3lwUjM2R2xRektnNDYxWEd2M1BQUEhOUEROUE1QSk5wc090bE1VT3pXVStQWkJsZzZMVTdZZGs5dHYvQUN6enp6enh4end3ZHEwSE9mSFRFcmdSL2lwMlpUN1B6aUhUb1NkNjk4anp6emh6enpSTjRZblYvS2d3MEZHd2U5RXNFcXB3M0xjU3IvWW8weXppeHp6RHpSYkdCQStFdTd6WVBSRzd3VlpmODN4WVhMenEvd0NqcHptOFY4ODhVODh4L3MySkRLN1k0Tk9pQjROdkxHL2RzQXkranFBZC9ZS3NUVTg4ODg4UTQ5cTdNNURSN1pKMmJsSGxJT3h6WG1yOEgvdnpOWG5tWjA4ODg0RTFTT0FaNlRwaU9ZWm0vVk0rS0tsYWVXWGpUZTFVL3V5UkZSODg4L0U1UmpBWXFCNW55YlpJK0hra2M0ajBPbUtYcUpocDFVSmJINXg4OGVRUlNpU2IyMWlUNGtqdnMxam5vVGRYeEVpVEo1amZvajJwWDB2OG9kb1gzVmlHVUdMUGlZVHFyQlFZQ1dxQWdOU3JWanhodUprbGNVZU1yZmJEQVJmNDNWR25mZjZEYkJIOER5Y0xRNUFjTStJRkNETGJTbVo4djc3bmxJODlTanZTNVhBVTNLZ28xbFlVQjB6U2V5bDVDN2hROC80UWduQnM0V3Z6aDNadURRcjZNR1BXMko0UTZKWTlnTkN6ZjVHVWRXOWxrUUE0SWErSVRFN1lQYkVieTkzQUo5bFdUTExUTFNGL1liZ3kyUW1Yb01vZjFxUksyVUphM3lpeUxNOTFReldDbmdpMHROQzFjWlJrZ2ErWEJNSVNKTWxUb1BqTVpCUmhYdGVaaHl5blBLM2YxeHJDM0pQc1hBUVhiK1RHTm5wQ3VpWVNLb2tsSEh3aVJkdi9BTHQzTklNb3V2ZGVKU2twOS9GMXZLL3Jwd2dBS21DZHRMY1l0Y0gyM2xNY3ovOEFsVFY3dk01ekJGYnpEWHBBSk1yYS9RQnFQVzNaRGxpaitlWmhEb0VsVyt0NE1HYm80azJ5bHJ2V3NLOW9qYTc3RmtVMXRybmd2azhYUVBJU3ZSNjJKd0xsMkp5UWZ0M0RmYVIwaTVaVFQzcnJ3S29pdTRzdWcvWW9OZUg4OFV6Q3lmenp5S0RPdEJkanNVYUx6d2ZpT25yVCtxU2lpdVo5T3JoWXdlajFEM2p4ajR2K2NIZXQrSE9vTXcvU3lkSWM1ZFNlUExIcHllSGpEeHJSZml6eXcxeFBsU2Q3WmpueXBaQU9vUW5adXJHeml3RXBOd0c0dTNueFh6elRpemMyaTRBb0lMZ0NJUThkS05NZldpNWdCWlMyVnhJcENXSy9Uemh5enlGeGJWcXhidEM4TmNMYkxMdmo3NHIvQU1pRzZLeStuQVg2WTA4czg4czhnUzY5ZjloU3pkbW91Qkd4TEFCWkF3dDlKbWcxS3B4TjgwNDg4ODQ4OFlrOS9ITEtMNkdjSmxJbkVEUy9pMzdUK2kyREl4TEU4OGc4OGNzQWNvRXdBelFVZUo5ZUZiN0JpQlJlYnF2N3pwbkhsVTg4ODg4ODhjNDg4MDhVbEU5RHY4Zmd4RmpHVGVLK3pNM3o3WkxQUGc4Yzg4NE04MDRFczgwOHAzSE5zdUd1M0lBRmJmS1FwRi9LaGRWZDg4c3NNOEVjNDhvRThNTTg4c01ESE9jRnExQnBXYmJESEtVRTQ5czgwODg4ODg4ODg4ODgwc2M4ODg4TW83THVScENMVW0zK1dJRHM4czQ4MDhzODg4ODg4ODQ4OHM4OG8wODhjc2xKQnhCYmlpM2gwc2M4ODg4ODQ4Yzg4ODhjLzhRQUloRUJBUUVBQXdFQkFBSURBUUVBQUFBQUFRQVJFQ0V4UVZFZ1lUQkFjVkNSLzlvQUNBRURBUUUvRVA4QTFray9tVXQvVjN3eUIvYlI5NGo5UUgvYVVMSHlXd21GRXp0aVh2Q2V1Tml3OFZXV3A1SDdoMy9WZXI0a3F5TUV0RHllRmZaUjd1anR0NU50dTJFcU9vL2Q3L3BERWlzQ01YYmVGMXpoVzQ4UWZXWHNmbG5Hd3lEWkNscC9vWjlFREFPMmNXeTgrUjN1VSszVXRrRVBmL1l0eDR6K0d5Y2ZCL3pmQWtXQUxUNU9udDAydm5HVEJoTEo4dXREbEk3TmlUcVg4UXNrMlMvVC9KOEMyZ25sdUtha1Bra0d2WnlPM20rNWR5N0NYbzNtK1hrdkJNbGx0V0NTK0grTEhvalRCNU1CbWlJVzNaTExQTEtiZGIwTUwxTW02eDF3VGdDMlpxd1p3TytTNnlaYWY0TUVkdGd1anBHRXl6dVMyYjJRaTF0NDY4ZFFoR01ZeVhyaDBQQWNPTFZzQ1hmTC9zdFp3T3VCTHp1SFQrZXpITzJWNzFhalM2ajdicytxL3BaK3pCa0Nlc0VUMDhNNnlBTVBKOVplSkphdGdTc1ViQURYZ2dFYXR0c2tPUDhBTEF5R3NldW9jV1QzSTZNK3JzaVVKV1dXYk9JTzQ2bnU5YkRyZ0RNNExsa3hIYU05K1hYb1NHTUdjTm5VeTAvaXQxSERiZDZ1amtNN2lINWRkbzh4ZElUYzloSGxFOUhjT3VMeWtoMXNPdVArVENTUmIrM1V4NU8zaEk2ZC9nOElhejBYMlAwbGk4NFN0c0xrZ3hnWEhzdXgxRG5zbStjRnZWMGgwWGk5TGNMVmd6MjM4NEl0YlBpRUhiZDIyUkx2STVmSmFjcmVvZlpUWWpwazRHbCtUMjJ1K3ByN1BYWk9XSjJRajdldG44bWZMeGwra3Y1UDl3L1dQMi92QytibzkyUjF3dVIrc0ovTSt5d21HdHEzRDlod1BzZ0kyanN5L0RkazQydlhrSkcrM29JY2J0c0VON1o3Nm44Sjc2M1JEN3dFcGtiSTIzajZjUGtUcXhkRnBhU0ptYnRQSExMKzRmYjA0SDl1b3QwZDNjUzlqZkdabHdqb2o5NFRXTWNBVzIyM1ZraytSM2VZU25nMWtiL3FNSUkvVTFJenprdExjYzR5T0ZHZFYzSWIzWmtkdDJlQjJzdkxiWm41ZDJ2QUZ0OHZQQWt1ckpuK3JzZTdFWmJkck85MlFuNUw0a3Q2ejk0TWhaeG9qU3d4djdDblhEQ3g4NFNSK1R6MHRQSTROZmJWN1krUmVlSTR5Q1NlUy84QVhJMDlMUHhlRGo4dTJ6KzdBdExUeGxQV2Z1U0QxWk5LOHRDN1NSYmRjdHN2MmVIZVBnd2YzaFIyUWpTKytHWXMyT3dQQmJiN2YzWDlsL1pDZFc2dTdMdTB1bXdsejVOZHpxVkxNWEU4a0M5dDFXRDJId2p1eTZ1dmtETXVvbG4xa2ZsZjAzOUVuN2VVV1BDOXZFOXlSSVp1SDI3KzJJVG5XMCt5S1Y4WkgxSWZaYnllQzk1R0hrSnUzc1FQa0MydnJkV0xXV1FuSnpwa0MweCtvQjVCeDk4UnhKTE9lckV6UjVhemcyUmZMRVQxa0ZxYmFhdTVZRUVnTHFPcExDRStXcHRyYWZZQlpuOE00TytQaWJWMmNOdW95OG5na1hzOUY0WGFDenJMb2o0U2JoSlp4NlEyYnh0cEhkbHBZNGR2RHhlWmt0NmhzR1JCWkxuY2YzQjlpRHVFc2g2N3Y3czExdEN4Yk02anlEdXpXN09TSFVvbTA5T3c3MmNQZGhBV0JiTDFmSTRmWituOENXZTA5OG5Uay9idU03Wi9JdDN5ek8yYXpZWWJiUHkzZzd2c1hYenFNZFR2eTN2SWJKNjd0NGZjdnZJdHprRTM0c3pxRnJyQ0dFbm9jSWJQMlFlVEJ6cUR1OTIza3JidUxZMjlzbGdKQWc3cFptcnNkeHd4TWR1L3dKRHFIUXM0V091NC91WmRoSGMrUkJoSHhlMlQ2NnRESDdQK29zWDcyM0QyVDdFUmFRSmpmOG1MRU05ZGwvWmJ3ekIxSDhHNll2SmVGMWtFdlM1aDN1d0d5Tk1wUXN6U1hjdWtaZG02SFVaeHM1aGFtTmhsMGNHM2hFSmJia3ZBR0QzZVd6WnJIYi9GaDlqRFpzQ3lHZlo3SC94RERKaWI3TUFXdG13Nnl5SjRMK3FXUWwrNCtMZG9Ya0hYSGNmYWJ6NVl0c0lzZG4vSXhISS9KY2pxRFA1Sm5jZHVySkVaQ2VjTjhtT214Z2ZPRzVMdTZhUTBYMXVxMGNObWVJV2JZU0ZvWFRjbjg5WHNQcTBPY2V1d2Z6Wk42c0hHOWt0bkN6TzRMT2N2MUxISGd1aVBlSWlmSkZpTytQWm0xbzdjdmZVSHlQOEFBa044OXRMRjlzdk9Wc2paVm4xTExlN3BUZmJkYStYY3lDdjZUMk5rdld6MjNnRUk4bC8yNmVTZkN3Zy94SmZRZ1BML0FGTzJXM0l5YitXQXhNZC9ZM2dPblh5MG16ZFdQYTZyUEhKVFZpZGtQN1p4dWRRUWY1RXRPejIxNmZiSXkyMjliRFlRd2t0aWRNWU9ydXNXd2IyMmhqUDVRSEczWEQ4RUVIK1pJVzMwZzcyZnl5OVhoZVo5b3RoNjRlV1VQYlY4Z0VIK2drazQ3aCt1Y25nZDNoZUwwankybmtjUEg5STE3QkIvcHNRKzJ6MURJQnR0SVE2WG5pZkxTSEdEMjArV2Z0a0grdmtsaHN2Ry91VEo1QU1aQllKWUVQZTVmZ1dMNndZTFA5dkxPU1dMSDV3eHNiTFA4LzhBLzhRQUlSRUFBd0FEQUFJREFRRUJBQUFBQUFBQUFBRVJFQ0V4SUVFd1FGRmhjVkQvMmdBSUFRSUJBVDhRL3dDczNNR3hXYk5telpYa3YyMkt5WklRWWlFd21LSi9YWWRZaE1Vb2hpREU4Tmx4Q0NMOU53TnRpRWhmSjVRVDhhVVkwSmlmMFBRc0lObDhVUEQ3dUQySWZtMWhQNXZRSkVoUHcvMDE0b2JHOUdxT0tlaGZvK0N6TW9lRS9rOUNFaGxFeWpSR2lqRmhqZXhqY05xWVU0VXVKaTVrRS9pWVNHR3hrS3hNUkJxQ0tNZmFLL1JxSk05NGFJVERmZ21YQytCdUVyRW9QUW5TRDBRenB0Q2R5eGowaDBhSTRFOUppemMzQ2RIcENRMEw0RzZJYncyRXN0SklOQ2tLSmpZMXNhUEVJb2ZqQzViWm9oUFZZbUVvZGVZSitUUVNHdkNIMFlid0owZzBORXdoOEZnK0VqeFBDU0ZHZndNMzBRaGtMNU4xaTBKaTB4b28wSlFldy9Vc0U3NFRDNE5FR2hMTkltMkdRVVlXV2hlREVzSVFUcUhyRHJWRFZFdUdKTUpWSCtrRS93QncrQzRQbVVUREdQYkhPQ2FTRXJoREVYekpEd21leDRhb2hHbldPMzNEa04raXA5SU40OUNFczNEa3ZCYmk4RmhERTh2b25saVFzdGUwT01TajBMWi9NUk1yWFRUWmVsOUN4Y1NqSXB3UkJFSWJMaGl3OFFobzBVcFNsTkhDSDlFOStDMFBvYjJoNkxuaXl4T0ZFeWx6RU5DdytDSG01cUVRaGR3b21jMWhvaHdoYURGcUZzZ3RzWlM1cFZqZUtKNFdTSG1qTnA3RXpzU0drUU50bjlCeGRFK2gvakJUUWtud1NaV1VpSVFoR050ZEV4Q2xLaUx3V0RjR2JlRkczU3B4aVpUR3lFTkR2b2JQWWtlY0YwQjZESDFna3hZMFRPbXhKaW9KZjBRa1JLU2l3c1ZFeFJSUlFuUWtUR2pSQnVFSDhpc3EwVUxIUVFUUWlHaldJY2pCZnJOSklraWdzRU5ZTWJSZjBxSVRGS1JGRHFHMCtqVDl3ZFVxeHdoZEUvUVZLTkZMaG9aRXhNdkFKWVF4ZkFSbEd4Vm5vNEpWVU5WVWdjaVVRa0lJWXh1bndXRXVFekJaV0dRclJTbzFtbElKWWVqbUVpYWdsb2FIK0V6M3dUS0xOU0tid2hZWjZFOFROR0w5R2lMYjBJNmJlTnNrektiV1VPK2lscGlzZXRpL1ZtRUlpajU0TVdMaER3OWgraUZSRW1MK0U5NE4rQmtFOGZ6RC9BdlJtNmViOEhoNG1XSnJzYUkwS0ZJTndZZWc1S2lZbVFLbEpob05wb1NORGRjRzE1TGUvRml4UjRXSEV6RW9wNEgwSTFleHBzcUpqNE5HSVJSS05rTWRIckZ5eGVMRnJ3NjROcERkNlI3MlZKQ2JiV0RoQXREYmcyNExRSTZKaDZSMGM0UXBQWTJtaitCTjBTeE9PWXVPK2JMUmpnaERadGlRaWlUZlJZaFBDYUVTT2hHMktGV09VWCtDN1BRdVkySlJwb1JScWpaY1B5eXF4WUx6YU9ZYzJLTU4rQ2Zva1FockpONE5Sc0VDVEFpWWVSdTJkRU11K05pZTRQQ05pZ1NJVExHK0RzWFFtaGRpRUd0NHZoQ3BhMDgwWHhOQzNtQ3d4dUNjZXg4RTkwWGVOb3V4cGlEZXg4T1I0NHlwazhJVmlYeU5DZDh0OUlWajFDd2xHalVSaWhqUndjR3pva1V1V1FueXRGeHJNOWpWRkhDRU1VNEhydzNzU28wU0pURnkySmZQQml0ZEZsaUlOWWNqNkcySXV4TllmaFRiRWhMNk1JZjBYd1lnNXlOdkpZZWFUNnpSUzRKL29tdkR5Y25RaElURktKRSt6Q0N2UnNwbWlnK2pvVEZwMHJaTUo5K0VSQk9FK2wvL3hBQXFFQUVBQWdFREJBRUVBZ01CQVFBQUFBQUJBQkVoTVVGUllYR0JrYUd4d2RId0VPRWdNUEZBVVAvYUFBZ0JBUUFCUHhDVk4vNTMvd0RaWCtSSy93QkQvTEgrVC9EYi9TLytUZjhBZ2ovQi90ei9BQm4vQUJyRi93QUpMU3BYYVZYSHVWMVBmODJOU3BUcC9DVi80YS8rY1FIdEE2SHVsOFM0T053SHkzOFRBRk5oSHdTa3NUWDVRck1RUTVxUG9JUm1EZFAxZzQwMG8rcTRDZVIvQlAzbStJcGhRNC9vamlHOVB4eXdyOVdmUlVkcDk0UDFHOGJuYVBmM1Fmd3daZHgrMFNWalkzbmhJQW96L2VyUitNNmlvOXltT1A4QVZYK0Qvd0RBci9WWEVJdVRZTGZVUTZ4YitqVjlRaGxTNklQZVQ2bkhMQ1g5QjhRS1lpcVErQkVGVXVLR3Z5elRVNkxiOHNUTjQ4QkV3dDljemVZZXJRTzlFc29CVHhaRVc1OFJNWm82RThEcVJ0OXova2RnWHpDblMzcTVSUzFPOFp0eGR1bWVnWUg1ek5tTUtaOGhqWnc1WnQ3Rm54QUhkWjlkTCtoQ2c3Vlg5UWlWaW0vL0FJT24rL1A4Wi9saGRRczdPL2lVd1pkdXIyTlhnSmNWMDlQZVg3SW9VbXFOTDMxUHVXWnp5dHUyTlN0QzVhTTJ3SnRPQ0s4REZ0VjE3ZkgzaUdaMm9QcXpOQlhSWEo0Q1dsUjBUOVdLMDdKVFE2ZmdFdFdpS0xGeVp4OFNsU1ZvVVg0bWVrMXQrQkF0Vzd5THBIY2ZlVlNpM1VIdFpHUHBETVNJYVpFQlhVNUJsTlBMbXlOWEN1dXNBRTBiRWFUenJENzR4bzY4NWgrWjZsYzg0cCtzRmphM1VPbG4zSXZGRFdOdnNNU28vd0NPL3dENm1FSXcvd0JhSUFxNkJOQ2FyUFJ0NXFWRDdPTisvd0JIYkJpNDV5WGQvYW82dU4zS3ZseExzdStQNy9FcGJ1ZEErOVl3MitGL09QeEw0UGNDbjFNUzhHN2o0Rkl0Ykx6RldxWnBzT1RUN3cvQXdFS3RmeUcvdUZXWmdEU1ZuQUNQU1gzU0lHRFM4NFA3OFF1akxSVDNadXd2aVphRFVxTHZyMXNmWSs0VE5PcUEwdnhITExIblNWSmNjWUlLbDNxNmZUTVQ0eFQ3MGxFcFZQR1lvNDhtWTlNRElsSkU3T1VNVk8vNW1aSE9wcmRuSHFwdndqWEs2bXAvcVA4QUMvOEExTVA1QmRDWmtrRmhITmJIVnFGUTNoWDZmajJsaCtnWVpYVllGRmhWb2JlQ09CTmFnRDdURlU2cSsvOEF0Y3NrR3d0ZVgyakZxMVl2bUZtTXhIQXQ5STRYVG94Vm9yMElJdTJVTm1Pc3FRb1c3TmVsbnV6SWdkZDRrZzU2dzlDOWJPOEd0TUE1ZmVROFJHTlc4bWg5NGl1VWJPY0gzajNHWEdQdjJsNGFyRmJOMk14aG1xRTNXSDRsUWpnbkRSOHdjU3R2TSsyR0cxSGNpR0JSNVpkdzI5SStlTlUvcUpncStRdC9jWW9oZWd4T1Q3TXlHTEhVcW9XWXJxMTJsNHJlemg3N1AxaFMvUFFPcHRLZjh6L0Yvd0JEL3dDUjNncUltM2dESzlDRjRuQXcvUUQzMFJVdzBwTDFFNVhWUUZMcFdsYSsvc1RjNE5WVy9WbGJXbFdqN2EzelVwVXpSTkhzTUV0OHZxYVVtT0xDZW1aV01hNTFZY0M4WCtJWm9QV09kUU53aElxUjhzZDNCNW15bGFqUi9BVkZnaVJnYTRKcVc3WW1oYjlLOHpXdzlXeXN6d283QU1IeEZZRGZ3T0Ura3dDTGVyK3MwbUJGSEhFUWF4bkFZZys4SVdwWFhrTXZWZW9RRkdpN2hpeG03S0wxdDZ5aGs4cFMwRVJ6UTlNeHVxNGxieERqSk5kSWJaQjl5S05ucnlYNGlnRlJIU242TWJHakliTTJZNW5MSEZpbTc1VHNmYVdHY0I4RC93Q0Yvd0RJUlU3UURMTDl2cTdWM0ZaL3VFZ3kyaTVLdHdiZWhubGl3UUc3b1d2TVBlMWlCM2Q0MERURkdIWFVmUHFPbSs3ZEhBYUIybEZWeFFSTk9zTEpjYXY0elNkK1B0QzhGc1UreE5zVmNMUjZsUlFWQU9nVnhHVkFwMmJSVlJrTjZXVjdiZkJHSFZmWmVueFV2Y3UwYWpjNjFVd2xsVTNncC9vOHhuLzRVKzdNUU1nRnJCSnR1ekdIRi9QeENtaEZsTy9KS29NR3plOWZtQmJMTndNaXM0WUR6VkVYSEo4V1RSd2JHME9ac3RQaGxYdWUvd0RCU2Ewa0JicXVpTTBENm9kME04UzdRczNOcGtWYjB6Um11ZFI1SUlOeEdPUk5RaTAzM2o5cU5SZjl2ckVWcWsydnNjOXRZcXdValZmN3IvOEFEdjhBeVVRRkxBdVhRRGQ2RVFlQ3hLWHFXaDA1NVRTSlFucERnaG9kaUtpd3N4eVQ3Sm1wS2pLL0oyUExHQzI4SDJBZDlacUpXVkpYNU12YVZwUXhsTFg0aEZBSFZOZkxDaWFKdHE5elRDblg4eXk0YjFkbzJkWHh2M0JOQVBWWDZJcU5FMlVNOWlGaHczaERLOVFpVnlCc2pIcWlZR002WE15VGZTRXhUVmJYck9aUlRlNThGaDRsaGNsRDRQdkFvRkprdkJaQklwWnJhOE16OWRnNk1QMCtZVmUza1RoeCtKYmtzT0xtK0NsZHpNeGFPSjFHNWlvR0MyZGZ5U3BKQmc4a0dDVWpvM3FSTjdPNVVSNGxpWnd4UnFLY3c0NXBPTjViaWgxVGdLMzRaa3c4bXN5Ylp1Vm4xQnhNYkM0OGNUQlBrclh4QUlZc09XNXM5eU1xVUtwcTlmMjR0TWRPQnlPNS9yZjRyL1JjUDlJYjFpSXFYa0xRM0k0Nmo0ZzNGSXdqcE5SMVpkSmFyRTBBYVYydUpkTUN5OEExV0dFdkxlZzZXaDBKeWJvUkk2aWpCQjhHbjBOcHZJTzZ1N01GWGg2SHYrNG9GZ093YkVzWUZYNWxSdXM2NXkxQndySEZueHBCUUhZYllmaUprUGFOaUNIUm9SeXI0b3YxTkhoZ3BBS095TXIzOUlMY1ZxTVdBQmQ4dzlYaktCclAwcnpNVEM2NlczQXVvb1BRd2ZlQzA2a3JtVlcwRmJPTnlialErbytiVFBKbWlUcEZ0VUdrZVNGaERpdUE1TnBtZlBYeW43UDFsNEN5dnp2RU1rVGZJY1FXb0M1YkNPVTl4ZXF0eExyVXZrbE5GRDVtUlJSdzZ3TGJ6V0YvUjRjc0J3S1lONGJWOW1GaXEzUXlkNVpScFR4TW1SMGJIaUhSUEJhM2Y3KzVuTzd3K3p3L1dKVzh2L3pWMS94RjlYWWgrZ2xHMDFxdlNPN1JFTExTVWVSN3Z3R2t3QUtNNTBPMzVnR1VvRFR1OXUycjBsNlNNVTRJYkVNYWlyV3BYa2k0TkR1L2FBZ09ObjBOanJBQ0ZIYVhmZDNoaHBXaHMvZTBwVmo2MG9PejVmWDVuRFE5ZFpqdGVsTnhEc0s2a1FMWmZkTklFSjFDTTJCUU9CbFU3VDlIajJXL2NRS1JhdTd1elA2ZFVXQUNacDMvQUZpSWdseFdEK2w1am5DVVRxd2ZLVFVNanVTMEFhU1N2MnFIdEMwcWdlQjlXVExjeTZhMVRtVlc5bTFoZEdJYmZKVXJIU3IxQ2JOL2UxL01kQUwyb0dWR3NPSVpGWHFjTXFsQVY4Zm1XaTd4Ykk1V1llZDR1NHM1TlNJTkpTYTNOZzdpZGhPZUlpSUEzc3pPNHVONDBhcmtjSGYvQUpMM3RtekVwaldYSXlhcFE2cCtJVE93ako3L0FOVnZ6RXJVL3dEUFg4aEZJQUExaEpFNkR3TGZsbzdzUWl4VVAvUmJybDNsamgxVjYvbnZwT0t0T3pZbk45RGJtRlRjWVd5OHQ2eWpuY0s0NjdQSHFZY0wxOHlEOXlHMmdjSCtEYjFGdy91dG5jYkdVaEdhR2gwdlI5eE90ME9EMkRXS1dBNXZYM3RGMERKdVo5LzNLMTdJMUhUZG1kZzRMZlg1Z3V6TTB2S2VEQkJDdzNKRVNtdW1LeDJuVTNIZlRMMWlNaG5UMjIrNTlmeEEyMkx4SHE4SXVVUm5XUDZtRHhMTERaQTRNZkorSlFEdTNLdUYzSTZOSzVjVjB5T2sySGZxdy9ueksrdEk0ZE5EODFGYlIrSWliV3gvTVhneXl0Vi9VYjRmTXlBTk9mek1oOFp3OHhKcEcrTklONlo3eW82eW1ycUxpNEJiZDV1RUhNeENJMUNOMlo1YmZnOHN2QXBvdi9BaUtLMXk1Wll2Wi9jekYvdnQrSlpqbUsyN2FmUThuREgxeHNMSnVoeHliYlkwZGRLL3daWCsvZjhBd0ltbzBEVllRWEJLYTVUL0FNTkRNUlE4UlJ0QWZ2WE1mcXBmUU4xMlByR3FqZm9WZE8rOEUxVCtJYU9IVTJpWXFXcWJEdkNMV3RSZXlOVTZVWXM2N2ZDTGRVUjhadjhBTXJHTng2VWRING1yZW9OL3N4NFE2bHg1UHhNeTFpekcrYk5QVURiZmx5dm04d0xSY21wbFJ4Y0VHdW8vdFM1eXMxZDRtQm02eHYwSWFyam96cnFmdjZFWXkxNFF3ZkVSZ0RnalloN2RzdGRNN1o0cnpEQ3RWZGMzR09SK0lueTJ4Q2RwYzNRa0ZmRGpXZC9pT0FXMEhPMm55Rkh5S1F5MjMvZWtDTm1WTUZtRkthN3h0MXRwSHRxRDVOWHdzTlRxVGxtYXpDTzAxekxqRlhOanRwRmdwdDA2elBGemZDNDlqNHRYdUM3RTlWdWNDTmNiN0dyTEc1Zm9HcjhSclBxWXZoTEx0VUx4QXJxb2RyVjNpTVZYeER3RFl1Lzl4TTB3K1JWUHAvYnJFUVZsSGw2b09tNTVNU3Y5MWY2RUFGcm9FdVVYVE1jcDJhMWJIV0FUTkpvV2dmdk1JYUt0UWNyeEUrV3JHYU9yeThlVEdTdE5xK2JvNUh0RkdsQjg2MjdNSEVDc3VGOXVuV0gxcVNxMURwMWw4SUwrRnRIU2xzYzlobWJjUWlEekRUVFF0UTdEWHpNT1JCR1hwZUdXcHJrRDZlcDdsaXFsN0wxcWVZMVd1UjFOVDhTNklkQXArWWJmUkRJcnJUS0FFUUx1QS9pZ2RieDZaZkVZbXFHODI2dnEvY1pzVVJkY0lsWkc4YVp6QnJnRldmMGc4elArRDZsWVBsam9ic015K3BjSENTb1hVU3dCcElET0w1dXg4TlBpTmd0UnIyekMwR2RKVnBobmc3emp4YkpueEZUbnBGQVcwZUJ5UXcweHRNdGE3SFRtZXJ2QkRLRjFxMlBiUWI4ZVplamZ1blI2dUZiZUliOGxwNGx0S01YWFBuV2NaY01FYjVZT0F3N3hxMnoxbGJFVXRXdGFNYXhnRzYwcmIyMmQycFhGbmNweXYySWxsM2RHQTZsYTVoTWl1T3dQczhNMndPMmQ2bXhiazI3T0VUL3lCY01zRVBNaDBEbmFOakxFRGI3Wjl4ZGJjcTNGOU5hb0Jxcngxakt4WkduaXVPRGFVRmR1bkJlNDZqQUpBcTBGN3RIOXhLQVM2WlJpdXB2QjJ6Y3IxOU9mRDFHc29jR3BuUk5YMHl3a3JlbjEvRVRLOE5VRHIrSXBhSUxzeGZBN1IwaXFScDhSYVliNWRZdlVqclg2ZFNiTVUxRHQrVUFWMTNBOG1HQjVMLzNOSDRpamNXbFgyakFESU9xYlByNlJDcnBIbjE5Q2ozQk5OTndjejVDaWJrdnFYQUdRYVp3WEFOS01IV3Q5UThRRnJXMThHRDV2MUxtbnRLMmZxMitLWWY4QXRHenhCVjdwSzd6WWMxMk1QeWZNWUZYWTUwS3ArYWpPWXZVbE1ycmRUZGFqYmxaUHZFMzFWa3FHMEJtY1ozakVIdW1RdlkxZlV5UUJveEhnZmRpTEI3bW5zRUl0STJLRHRINzZRNENMbUlVSzg3VFJiOW9KQUtxR2Fhcm9RSVdtWmZhMjkyaUZLdVlQSzA3RDNMclZuZE5lOFdTMXVwcExlckczRXFHcmI3REtCTDFnQmJ5M29PUTVNOTlJWm9JSElUNkhialNKVmRmOU8vOEFwekJoNloyRFhwUGxvbHlodEhWV3I2ejR3U3h5WTNhYUhsdU1WV2htaDBYb3JCdlY4UlcyYldZZjhneXhTV2lCcmVvNk9wRjh5eFlGdlRRa0Nob2FJbGpLY3ZOQmtIYmJ4NmdWb0J3bGF2NGVhV0FvdDFnb3lkamJ1eW9kSVpiNk9xOWRJSUx5Mkg1bVloRFNKbUZaWU5hL0JUTTIzcmNyN256QkRucklRZ0Z1bE8zQnJwbXZtRGk1dXJ2OHVJNHRxVHF0L3dBRkdDQ3Uvd0MyQVlqa3R4VytsZVkrR0tSd3NWbXVZOEh5M0NMZ1A5WlgzOFRvbTYvUndYKzltV3RUY2VFQzM0aytadnJZaFBoK3pGYUFDSThPckZYT1dxdDZoeU5jemF2NGhjYUcvR2RQbURSWGhxcTFoU0phUGtUcDRnemsxVmtSSVhXejhUcThoWXhab0ZpYTFFRTBBZ3JLdGVDRWx1eUJEcHJPN1VlQmtVNVh6cDRlNDZLMWR6UGU0SVVvSzRFWkZhY2Jlb25VM0VtSmwzcWJNUkFZWnBUUi91ZGNlcFUwdWwyTjE3SGZ3N1N2cjVDT1E4bnpoMy94ekgvVS93QU84RTVrdUIxWUlvbzFoWnAwdmsyOFRCTXNYVEoyaDNZUzBHOUhvYStvQVpyZU9qWDA3Uk1kZFNWaUNXZnhkaE5aUUJpV3JSMGRTVW9GclRPelFmckM2QlplVGtZaTEzTVZ6Ym1wNHgwaHNMV2ExanNmb1lnTk5ScmI2d1ZFZEFXL0x6RmxIZjhBUWhoaVpHODRsMzQxRDZKcEZGSlY2VmRmd2g3dSs3T1ZTYlcxRm9uRWJUa0NHS2pRakpLSjVOditLQlVscnUwSHl5cTJ1akhmbUcycUlQVWwwczd3Wjg1ZVA3WEtvSlpFRHNqOWlyOWt0M1IvR2ZXdlVTbUZvNXYxT2dEc3N3d1ptbURFczlTV1ZsSGsyaFJySnBsYnBwcmtWYXg4U3hCTlZjeFhDOW8zYVloTjNETkFYZWhEeUprR3g2YmU3Uk5ZVFM0OHpUd2VZaWJ0VmVWNnNMUW1sZTBDcFdhOUNCT0VtNEZncWNQZ0gwekF0V1RacXNSRGxKc1dhWFZZN1c3UU1HdUdLTkFiQm9kcGVJVXcvbVhXcmdqc3gxRUhwNGJjbG5FdUdNcTBHeWNpWlA4QXdYWUhSSDNsT0RUcXVGME9ETXZCRm9vUTZHWGtVdWt2cnNIT2RvcW9lem1qZDk3aElLTTdRMThibmVaUnowKzd4cDZtTWJIci9DeWk4a1g5ZzJsVmVVdVViVHdzNFBZUVVnemtDK3pveFJLUzlqN1JPUTZsYWoyL0ZRMHdDMU9QWjU3MURsQ2hSdThFcDJHWXJyM1AxbmIzQm4yL2dXWWh0SGlJZVhUY29MVGRDNWZaWVY0enZRanhNcmxuckJndno5SmFEM2VqQ2E2dUp3QitKZ0VLMmhtNVFIMW0zSlZjS2Z2RWlSWE9CL3RNSEJGUFNLWEZibFREOUp2YTFIWjErME96MmpjYXNLeXI2OXB3QnQyakMyWHRGYUJybUY1QytzVEExclJVT3N4ZEFlbTN2UWxsYnN2RzdPbllKYXFUbFhMMWIrOHZRWDlQelBVbHNUcmJaUU00alNxWGNLM1U0bGh5YWNsZzZ1SlFaR2dkRnk4cmwzaGhESFdwYUNQK3ByTEd3dXBvZGwzaDdMMGRJNExLOE5ja1RsVFFZUk0yUUFCanJYVngzMU90bThSR2twTWY2TlpuK1QrQm5meENOQUMwejBlcTE2UkdJNmFBYVVIRlZpTnRvb0RsdEQ5L015d1VhME9BNkdrWXNpdGVla3h5WXgwZmZtM3BqVXRHamtSTStFam9wZDRYVHVRbFF0R1hTb3JKV1oxSjFQN09IYVZTRnB6anc4Y1FHcXF1RTBnNmlnQ3RoMDFFelJJaXhaNmFHSU9YQW5aeEsyMWp4azhibmpIU01DVGVMZjB2dkNLc3NhQjZsNFZOVmsvcUlFQno4aGdSMmppOFJhd2J3UTlGNEFDam5JVjVpN2FvY1htYWlnZG9NL054d1c3S3lMY0h0VGdJRndtY2RpbTN5d0RubW5abERaeHBHL1pMei9lT1p5R1ZiT0U3NCt5VW93aUwzZ2tXcXJ1TXVGczB5MGJ1Q0t6R1FTMUhpQW9BenAxaXBqa04vT2VhUzlJbXZmMmRQRjVZMlZ3c3NyMXpEaE9EMlg5L0UxTGZSd2VvbDV5ZnBGQTFKdUN2TUFXRy9XNVpWQjR5eERwdmNKcjBHWXp0dUtBQWFBWUEyRFNPR0s0VVVqSTA4Vjl4dmFEWklHWHAvd0JpdGsySEVWVkVReU96Mmhtc3RKcWNTKzVQSXh2L0FISFdIeGtxc0xuUEdyc2pIWFArWi9rS0YzZDM5T2tJc0VwYmhuc05Eb1RSV0tMYmR1VmlHK3hsWmFQbnQwaGNPN3dSWWxEaE4rV0o0b2RUaGg3YmRsaVF0L1VCMjYvWlVFcFF0UERIdlNKTXArQ085NEtWTm9vYUk5SlRncEUvVkRmbEZnQVRvQTNrOTdITVZkSmlWZGdPR1VORFlXNjd0cDIxT3Jlam94THV6RlV1VEV5YkVOREIvWGoxTlhQd1lmTy9iRE1DTzB6VHh0RXhCc1UrT1lLQ3JVSmtpMlE1SU5Tb244QVBnSG1YL3E3MU8zeWtVSXBKYXV0N3lqVVM0RGpraEFlTFhzY3dCR1NLT3dWK2pwR04zdnBia3VXdXF6WEcvd0FUNUFZSVc4MWNxSERpNW5lUTMwSDdUSnV0VDBsS2NOVHU2UDJsUVhhNDJhUWJybU1yOVlnQU5qRUtHbWFZYzZsZGFFeGtiZ2EvczZkb3ZyRVZTMXFMdDVZSlFBeFpvZjNwSHNnMUIwUEVMVzh6cXNFQzhITDAxam9LRlFad2I3NndNWkNrRnJlZ2NxNGx5ZzJEaGNBOE4xdUJCek5xUjNXTUExTFVPVXYyT3FRcXlUL3JSV1hsV094YU5ZQUtDVjBpRWNYOFM1N3MwNzhSQ01yYkZ2ZzZyazZuV0R2VkFwamFIUkpmK3R2Q2dCdXc2eWh5bWcvbzh3VEc3R05qZjVtOGNNcWRzK2p0M2kyUEJpbjRJa2cxUitpVng2K01BN3hJQTBvRGlJZlNXamF4Ym9hUFR0RW0zQzEzTzRZYWR3WFMwbzdQMURtRkZNNXFQMTlIK3RZckc2b0R3eFRYOUpiQnZYc0dZMzRiZUlyb0FlQVBvSXU1TDJubUNIUVRyRW9DRDNob2dXaUxSMGRTWHRaYnRxK3pvekpWaW1DNzhRN1pHMm92cHVRbUN4Zld2V0ZsaklkdHZ4S3pDaGR2NG1GU0lUVFZZNlllSlg3bGorbTc4VFROaXBpRjBpNDRnOXpRdmhmbUN3aVM5MnZnekdneW9OZ01lTkplZ3ZNMXltL3ZBaUJ5WUM1UmtOaDBHUGtxUEdMeEF2Q0NPNkYrV1h4cXBUa2FmcDh3S0ZXVVhjY1AybWFnc01YeXlxb1hkSFdBck1OT09oazcwSTlZNnl3bDhPbmFQTVMySTJTM3FWMWxlb3QzWWp0SWpRU2c4Zm1YMVcrOHFhWllPVmFJRXBRSzhaKzBDdHJrdVZuYkZhdjc2Z0I2cUYzbFBJN1B3YXQ4aDRZbUlUTlZwVW9xQ0I5K0s3ZFVOb2JLVzVCK3NSTnlyY3lNYXc1UUdKWjlZYVZyQStSMHlIZDZUYUJwVUhnR1FhUjVJYlVkQXp5L1ozRWRmOWEyd3Rub3Z3bHhFR053REFkOTNxeElxd0p5dGp2ajNMdUtyZzREb2FlSVFyWFdYUW5vVEVvUlFubERBK3JWam85RGgyakdHZ3JHeDA2ekJHeUJxeXE5dit4bk8rdzQ3enhxOE1YUWhvYy90UzQ3QU5ZUjM4L1c1VWFHREhuWDdscmlPTXo4WSthenVIYUx6ajV1SXViT3BBZlRHR3ordWI1bVNYYlJ5NmpSWTJ1RE45UGlIRFRveU5IUjFJRTl6VnF0NmFHSmZnT3p1elZpcHc2ZTlTVmdIdmFEZU93NnhjNGQ3YlN4WEFEeHI4cjZoV3paYjdqdGlwd2NNdnZTTVNDNlFHajZ4elJkaGV4SkJsT24rTWxoWlJjaDBzZlVoSjhrWGFOYnBYOTRqazdxam13UkJrMjY0dytnUWQxRlBvbnVtQUtGSngxaFBMQ2VQdDdvZ2lIVXNnL2xqd0hkbGx5cmFXWHVzTUw4TGJYdmVPNTBjRGoxS1gzbkVZWmhRNnhGNWpjVGo2SUVnT1NhZlZXZ2MvZUlJNzdCMUExZlkxMWJDWGQzY3V1cGxjNDFIRHltQjFVSXVBVG13ZCt1czV3YngvS0RtVmRWbHhyUlJBZ0JzaTVtaDNndjF5TFFPWG9aZkUwQUVEMDc5MWJlOHYzZFlsTzBNR1kzTmpwVHBmcFo1Z3B5ZFBEWjQvMUhGWkFkNGo3VVZobzVmMHdUTFZ6YWFQU0xtbk9yVER3ZkxMSUwxTHhLdGFDdWgrUmp6S0Z4Z2pRZno5b3lBNmsrVHVheGtnQkp3cTE3UjAzZFp0dmQ1OGZpT29tZitCK3J4TWdRRk9vTUY5dEhyM2hFcGFWVzEzWGppS29OaWowU09GVzBJNUV5UUFYMnl6NlZIZ2RERDlRRS9sblJwTndqMERHK0VBVCtSV2x4Z3l6L0FBSlJCY2pDUlpLcmxyczZrcC9WeTFYMmRJdXRYbUtUcUpYTzN6SGJaSHFNQlF3ZkltUG1NcVBGOXJyZktWNGdnMHI2R1M0S0NudlJmOUJwTEZMN1dVdFJhRDdqVDZSaU1CZDYvd0IwQU9scjgvM1V1SXczN2ZaWmFyYnRMV0c5anBlamlCd2RUQ2RZUVBJMjd3bTRmalNZMXF1OFlpM21MY3JyQUV2TUZ5eGw3WmVrMmdlU21jUTZLSWJTR0VOYXU2TWFETGNLUjB1aW83RUx3RmpWMnJuNnFKRHBjRHlKYitoTUdOU1Y4MmloQUZWZURXSlVDcmR4cXpteGVEYUdNL3FkSTRYcmRRUlNSTlpWd2pwdWprMmw1WTdEekx2NGdxSzZ5cmVNU3NSWEhWczBQbkQzMWY2a0xJcmNOWDR2a3c3YU5Kc0F4NENwa2pIVjFkRDk2eDBhU054ekxCa0RYdjhBaVdGSUY4STZ5elpleGFBLzY4d2JjcE51OE1wVzFWOWpWKzg5UWJSV0VPdlErN0U0QnFwZDNkaWlGdFh3dHdhSHJVUjlaRzVmUFdabUZWVy8vdHgyL2hJajZnNTNEMzE2eE85UHpGc3N6WlN6SXhsbFAvRmN2aVZrUnBoQ3hWbERyTFo2UkswWWRNV0dJOW5XdTJINWErTXhXT3FSU1JScEk4SUpsTlNyTVdMNzlPcEdkSVV1d1pBOC9TWkdMeWhMSEJ1L0ZYTERoVURvNWZnK1lmVkVadTlqYWk0ZUJEeERwNmZmeXczMnNDUnJNdENQZ0s4d1RZMmRLaEd6VVRla25hbElOeTZ5d05SYnJCMHBoUzZCNjlZZ3UyUXhMdkxyL0YweXNBY3hJL2s5eFR3M21XYXhBaGpCaCtUbnByQzBsbzY4RGJ6bnRHTHNBRm0yblY1ZE4yeE5FcGxHQmRDM2JheTlBZ2VFN2lzT0JSYjZ0QzdoV093bDhkVzM3am1BV3B5ODh2bUZlOW14Z0R0S3NRT09kanBYcjBkWTZTWXlkV0sxWDhKZkNoS0xJR3B6REdZVHVUMWUrMWNwRmR5YWJneXZBSHUrWXhCbmVKYUtWWXpSMWl2OXpBVmpuSnNQaHA5ekgxbmpUV3J3MmVQOUJsV2dCeXlwM0wwelplY1BLQ3hMcWQ0cndEaTNXaDRQckZvTHJMQ2NwMFB1eDBlSDVtR1ZUYmc2YUhzc2hHbm9WN216OW9td1FEbEdrMXJqdWx1K2RwcXZRRkFiRlRKc2c3NC9YaU9VdGJvdjcrbzh4aUE3QWJRVGNvZERVWWpaR1ZNb1RZQzVFeVJzTGRJUkhGblE1K0VpQ2FTNnJ3N2h1czk5WXJhVUJ6eVBjeERwWXNCMDc2TmxRK1plajhHM2ZTQWdXYW5UektIU2hXaTZiK3pjRFRCWXZKSFh1U3FEYnBLTUlqMWlWRzB3dENReWpNcCtuYjNMamxLanE0RDBmTUpyVkdPcUVHNEJDQngvcDJoL1IzejVqNnd0QlVkMnZ0TGErWlRWVVYwTlQ2eStUZVBVM3VCZk9ZWUxCckNBbE5xMERtRjBBSlZxeDlXR0xXaE96QmdqK2h3clYwbU5JdjJMYTl2YUlWN0RERjBEU1d4Q1YwZjdMMk9vTnEwamNZQjh6ZW9EckNsZno1UVlHYmF5eVBNRnEzNTJQYU81MksxUzNXa1VHRW5pL1M2cnIwR1dFVXAxYndjVVVIRlJ4Ymo2eW9nb3VaRXl0Q0ttTFhNV2srVVB1N0NrdGdTOXUwS0oxbERyWFhtR0hJdDZRU29YTGRYUUJmWG9aV1gvQURvL2FYbGEvTHhCY0taOEErVzN6R1BCTmUzNWFJMlNrOTZwaTJaaG01Z21vcnUzbFdGMmxyb1B6VWJLMkp1STJSc2FseE9nOFAyaGppcjZBdzdZVDk1cWFrUlVKRU5MR1B6TkEwYy9MNStrcUpYTUR2OEFSZmNJbng1ZzgrZGZjcnJEYksxeStuM1lzZEpMRitrZk1TVlM1OGcrVWpFSEJjQUgxZzhHOWhkb1BmVTJTR2dROVFLN0J3NGRHWm5FR1RiY2VhOWtvZzYwWk9vY0IyamZUZGNMcU5WSERCem9PUjNKaGo4UUowWW9KNkEwWUFXZnd2eUlxdENPaVV4SzJjQ0JFcHdPV1l6QUFmcStaUXprR1d6QkRldlIvUjlBOVJ4RGp6dXI5WWFYcmZPREhlcStzTmppeW5nZmsrWXkycmVqQTBVQ25iK3JuZVNXQU5zM3pIVWRmRWVkSUthcHFYUjFXTjZ6eGJTKytyNGp5NGRFb1BFQlcyNk1zTWpsRHY1THV3ZFl0Vm5xYWZ3SFFvN3h5K3Azb2JtOWFIVjZNQUxKYVM5ZkZOYzBjekp2dm9rbzZHeUtiRGhpRW9LV3VjN3huYW05YnZ3bzRQcUN3TUJ1dWhBMUJEb3Y4V3pvZFk3dXRMb1FBZDNWZ2lFWFFselRvaHhrNGxUWWRWUjdpTVhTRG5nNmFIaU5XM01wRHV5N0tsSFdycDNpWjF0YStzYWRhbFl6UjZZUDNKNWc2WmQrR3o1Sy93QWd3dkUwTjlrOWM5TFBVeWFLZkRUNi9TVVA3Vm5IN20yQ0thdHN4WXlGNTUybWZheVl3a2RkNXJXQVNNRlBVdTZwa3JnQmg1UHBBRVNyRTMvckVwaHp0R1dkT2Z3bERiQU5iMERhRnJaMUhPcExVaGFiVGQrVHJaQUNWaEhJMmlXNVFUUlY4bXhkZUdjTW1MSTUwQjFqdHBjTG9QMmlZN2x0bEduZjBoRzlsOHdzSkFoU3RialRqdVRUVUltWWVsRFIwdzhIV0ZSbGxBSWFTOXdaSUtPdkR3KzAyQTdZeWViMVV5c0pSV0IwWXQ4VllSS2I0U1hCVnkzWjBKb3dZSmNIelhIbUxjQzhpcFhNQ0VVUWRIMGZPbm1XREE3NC93RHNicWw2d2NkQVhvcStVOVJtbTZqdGVJTWZIMUVGZDE5WUNUUW9keko5SW9jaFUrU0cxWlVlMmt1S1dGcDJoaitvUERwNVpRSGRZSFRYUjdFV1I3YUZEc2I5MkkxWHl4QzhaS291VXdFcmRLdXFsNm56dzZPc3ROTUV1Nit4RnQ1VGFBV0RvQnQzZ3o2MTVrZEY2dVh1c3ZzUUpPZVI2OUdnNDNqVnFUcnAwUFgxang1b1ZyL3pmYUIxbUpSRkc2aTNUQlZ4bXhwMWduOVVDanNyRjlOV0VpbkhHZzZDL1VSa3cyUHRIZWpzUTRDWU5aY01nYTFCc3pWWmpCNko4SXcreDlyaUdnME5ZYWptQ3hXeFVFQUh2TGwremMvZVpTc1ptTDhHTmcyUHVHK3ExN0YrTFA4QUl3anBDOEhNeWllOUJROEQ1Z0hSOXYyNVFpY20yeEVxQzFsTmswaXU0SVFZYTErc3g4dCsvd0R1NDNOQXpia0xBZTdqT3ErWWlyRGNhUDhBU0FYT0VTa1RSZ2xwK0ZQZXNSUk1qN2Vac1pTbXZST3R6ZVhMM2ppUHFRR3dFM3JmOE1TMkprRmpuYzYzUm1EVVNZVzE0eGlkSzk1YUJkOXRSQ3pSaXdhcW5FWTU4WGU5NmRxOTRBMHlvTnRNK0duM0NSMlhpZ0xFcUowSGFISzlMWTgwcklBTTllc0lHUTNYaHg0bEpTalFRL0VRdW5mZ2NkM0VWcVV1REY3cnluK0h0S1RJV29XM2luUitzZVYwenE2L3QrSWhzd2FzTjVjK1BpTTZ1STdoZk9mSS9XWmFvWTlycGxCbEdYOVNHbHpsMEljR3FNMlJxWHRvUlFZOUR5ZFllTnBzR0RzSVJjMUFMVmdtRU42YjhSNkY5a1FORVpwZWVycTJ5N29PTkFkdXNKd28zSjVEOVdDUW9lYlg4Z093NU1xS1h0MDJnaU1aUi9WWEwwR0RnUXprYzNzSG9uQXlwTEZxMzd1eFE0M2xKaHBVSHE0TzJ2QkdyV3ZSYmZ0ajRrc3ZXeUd1aGxGVU44M25NTG5oTk04ZEFIM21WYURtQld0b1VsUFdGRlczS3R3bU1yc2wwOWlsZERyRld0enFDc3JHY3JhNVpaTzJVTmcyWnU5NVY1aHdMdG54R3JkYzB2UnpHYkRHOTkxRHlDSC9BQmFzeUE4VzVmUXk5VU5RZGhnZXFqdVZwam0zSDVab2pnd1NnVVp3OGJ3V0IwSGFiRG1zUWtMWVJkNExnVlVuYTU3TVlNYW1rSHdmSHFOcmVvdUFSMHpUTnlXVWh0dVJ4YjFsaFcxYXErWGMxaGdBaE9ScmZtRzVYZXlmdTBZaTBGTWh2NHo0c2p5R2dUYW4wbHE5Vkh4c2Z2YUpZV3hnN3RiazdiUGkxMGdsTGJaRDNlazZQU0ppamhPcDZ6NmF1SU9kdWMyNTlhdzlwWS9TWWVpTDNBLzRRQkd0YTU1OVJTQVZ3NTZuU0RFcFdocEhtTldkRnBpZGRvVlBPZDA0clZTMko2WGs3ZG9nTWVWUTlvM3dDN3FaWFREcW9URUhndWpYMmVvTUVQN20rZnN1WjE0S2lkWFBuR1BvWXNMM0VZMXJISzh3S2xhN1FLdDRxMThhejdZNVNLaWRLYUV1TE1IcDVMTElXWUJtZkpubVBTRWZJZXB5eFpjRUV4cnc5Vmp0YnRBaHl0Z2RDdGpwMEk0OUFCekRySTFiVnJsK2c4d0Zxc0xmZFNqeTNOSlFqS2o5TjhMdkhialF3dkIwSDFkN2hHSENvV3ZRNnl3Q2RDQ2JHeHgzUWlMVlhkR2U0dDVsQVJRcVVhcGNkVjRJNFVUQUJsWFFsME1LMEc5eG9IVHFqSTV1d3VVNlBPV0wrVVFBVXlsdEpxcm5FVjRUOG9iTG84a09qU3p2dVFzY05KMFQraEtaS2RqNjN3YThmNFZiTHBzVVR1MCtCZVlveDAvY2U0eHhnaTY3SDNqNVRmRW82Z29DM01kQ2tNR3F5eEVON3JQQ0RMaW1oTEtqOGhMaGJ6UlBkdnhHYk91NEp4ZmJwQW9vQ3RDS0Nhd0RBUlkrVWh5bmJkL0NEOHNYOVdabGFHbmJZN1J5UWlrMUYvVitucEdIMUJtdDdqR1M5enRmNDNseDBqWmdJbEltRW1nRkNISjRIeWNrRUVvU3R1bG1LWVFWdmdtU20rdkk2UmJEaEY1eVpwVTJOM0l4ZWtHanpIVFFHT0QrbzJ4U1NyVzdtajBUUmg3Q2FySnplcWpUZUluRTVHRmRBdzBwSHFiUzNLdmQ4aFI4cEJFc0s5M0w5bzR4UVFVemRQUUQ1U0JmKzE0aUNnN2hkWFM1UXFhQTFCdytvbk5ZNkQ4M0xiTERSQXFHdFF3RGxPQTZzYktVdTI3ZnF2MWNVTVRnTFRvR3hCeW1jcmFVKzFiNUNDSEdvUElkZnBFQVpMUUdWZUlqb1ZyYjVYY1FJY290aXA2cWIwZlJIN2lLSTNKYW5GTzhJNXBrQjBPTDZ0dldLMVcyTWdaYkEzMXM0WHlpSW9NNUsxZDdpTTRPaEJpNnFHSGFiMkF5NVVxc3cwRldEdUtmQU5IWG9oU3NZNzZURUpjV1BrZ1F2dTFQak1vK3ZjeEJ1M3FJOExQU09rTUxaQzZQMGxGdFFXUWFha0Jzamg5eXNBRnZOOXg0aE4vNFlocW9RQ3JGL2NhZk1WQTZmZjhBNnhtSkw0eDlZUkVGNUFjeXh0TTBhL1RwTUNqYkNmZVh4RW1TTnRmemo0ajdQaHZxVVMvY3U1OHRRb25XNmtzaDlFa2VXRW9FN0ZIeEE2QlhlOHdYQjZtSlpqQTNUQ01xZXdVMHZuc3kzTEpZcjE2UTlNdW1xdWYyN1E1Z3hyZjBybmhsT1ZKYjlQVXgxMjhpWnFpSW1lTm1GV1hPelhUOFRDb3ZWMkY3UW8xZTF3K1RnN2wvMVBNSjNES2J4VXdHakwrRkRYaEQ2UXdpMHc3UU0xZXJZT3p0Q2xXVXhYY05rd2laWGdHM0cyYWpYcWlDK0x4OFRLQ25uamFmQjhwVytmcTR3VUZnQ2k0OXhyOFJrWEh6bVltc3NaZUhsd0wzejJneHM3MUx6ckx2NENIRnFiRFFnaHBadGhrc2J0WmxFeUZPMDhINnFYYktxNzh3alpXaE5hNTdTMzNZY1VYZWQzbUplUlRDSVdIQXltdmsvQkYyNXVGaWF5bWdEeXhQMlBlSUtHUk9oYWVXVThzb1U3ZUVwQkF3MzRqRkM3WUtUaDJNK2tvdHBnRy9EWWlkZXloWnBqZDJCS0lkQ3B2TzBiZzdGTzhIcmptUjZaU29uT1Q4UkJTTHBrUGlJdnVGY0FFYU41bDBibkJqMU5HVVBCYzQzOEwxSCtjNUxGYnhtVUJpK090WDhsQlpwNFFGK3NDcUNJNGk1V3J6NWlGQllQQk5IeXh4dVh1eTNyOHkxRHU0KzJiZysxdzlFcHo5NFlUQ1BHTDRhZzNRdWZFY3BzeTVjVEZaTnhUOXpHS1dtUjE0aTNhbWRiL2R2ckQvQUtjTU1iQit6UHNGQjBxSW4zVG9nb3ptWU5ZU0RveFhVbG0wenArOVlyb29xQmhKVnd6bUNhZWtLNUsvNytvUk5uYUIzcFBtYVhLMGNRUnNnQlF6MmxoVlpWSTgzRFJiRFNyY1BPbFhCdlNEcXpEWjVJQVB6Y29ORUc3b1dXcDk0QVVRVkkzZWt4WE5kLzA1SXpHZzMyY1B3eFh5cHZyT3ZFZk1pTTlHQmhpbUZVUVE5UlN0RHQrc1JLVlZWdFhtRVFVeGJnNVhvYXZhTTFXU2xJMVhxbGZYRUJJVzJ4MWpjUzd2QSt3WTh4bVdGMEwwTm9kNGFTNUJiS3ZXaEhJZkl4NEVZMnRBT3JFVjVMZ0ltSlNHRFRPMGVZeHlBSGFkeGw4WExhMGhQcHhCRGtlazFOZ01OTXRaRSswUnhldHRYMWhKS0N6a3d5ZG1WRzNUZEFUN0lwS2tST3Y4NG12NWJMNEdHanVueE1qVXYyT2ZnWnZKYTZ3dHRVeU9zK01CUmJIbEtpNkN1c3k0S0t0Q3d5MGJZb3VacjF4d1JxYzFDN0lOS0NIWFhtOFlocWtQV0dyRm9nZDdxb09BQldnbmdyOFRKcHVWRWVhSlp4TUl1TjhCZm1CWkpvUjJYYVdMSkJiWmFKV1NVd2FTMHFYTUJTNStzR3FBOWxxZlJsaUdUbVh5TFJXNDJYN010bUNKbm0rNkRxY1FHdVQ1bDZLRTE0U3gwaHBZa0hWVWZXWWlqcEovMFNuL0FLSDFmRVpteXVkcisyQmlEYWxGcll4N2lpS3JvWHl6bVBhVlIzc1B0QkJkQnRVeHJMN0poKzhkTkNLd210Q1VDRUtMSitucU9rVWJWYlZtc3ZzeEhmNzRQQWVZcW5SZzRJK0FQbGFBeXJHMWFDamdiK1dZdC93RHRCWUdOQ21ldzlCVzhRQWdPcVpXTkE4THBKWHFMNVp5QTlKUHZLbnlYTW85RUw2aDN2V1VWeVh0RUV2VTN6RWJIdVRVRDRsREZPZ3hMUitvUGNpT3c5bU9vOUVSTlJQRXZFVmRabXJoc2g3Z3kwN1AxS0lmTlFxVUdkRlQ2L3lRTTErcWg4c1pRdDhQdVVHeGFyd2YzS0RRdUxMUXVBNm9VNUl1QkJ4UXVtR2k5MktMV1hQaUd4M3FaZUVkMEcxNmFFS2FFUE1ycVFJcGdNanQwSDZ3eWlCcUI1VitJZjB5KzEzb1RVMDd0KzBYNWx6QzBJdzlYVVVjVjZMajVoelhUTlBOZ2hiNk0rV01pWEhJL1NNdmdjK3NzcDdybXhNUktpVkZTZHpocXdPVzRkdGowdlNDRGRkSG4yaXNzbzhrUGRpczFFK3B2TFNWS05rZ1lncGFTWERBYXJhV2tGTFRqSEI3U1VFdFdPNWYwQ09xWmE2dHZ5ZTVhVEJMdXkvV1dkMm9VcFJKYU5aWW5zM1g1UVZ6UVRrSDVHZENWWGJhWkZ0cWVtUjk0K3B5L0VIaWxCb2EvWFNPaUtOcXVWakdhRmR0dld1cmdPckdGQ0ptd1dCNkFINnpXUFdYaUxIS2wwVDE5L21JY1VjQndFQzVmNEFDMVgzaUkyUFM3RllPWGQzbW5DY0tnSW9iZjlJQXpaQnNGWHRBbW1xZWt4bmIxS0FDTnpYMlV4RnRCM0I4TnpKY0RvWHlIN1I5VWNucWtzVFRncDhSc3NVbUtjVFhNOWZ4VnhiSWVvSXVNQ3E0cCthaHJxQXh6Mm4weVN0SE5lcGYySDgzRHY4QUlmdExSK3Q1bEhTUGIvVXBXdDRRcUxPN1VOTFFCdWZJVktla00xend0L0V2VXNhZzlwOGtTV3EwOUpCZk1hS21zQjh6WHhGdEJZR2p3R0pXSnV3L2JBTEVEWUtnZFdUR2EwK0NXSDNaWStiSDZxSUZRMnRvZmdqVDV5ZnF6U0dEaUxiY1dieTRDM0tXbTJ1N2xXWVU2cEdqeVdGWDF5Y1NvY2FvTnVpNFBFekpCb080bSt4OU12dE5ENE8zTU8wVUdXbXlXcGZrdzcrTllMQTFuMFBzaXNIV0xkbURnTjFMODFDT1pHQ3RaV3BraGJpaExNNE1IMGdKQmt2UUgwVTNIRE8xNCtLaFFnQ3ZjZEFMOUpxdGlqMDlkNWM3a0R4aytqQUJLUG90UzNkazdyOEw2bFB1U2hwUmRHdDM2aVpBMjJxSytaa2wxbG1QQzRWWVN2MW1lcThSaXF2YjNsNGRMTHBvTkEzWmxST3BBNExkdnZLNTdGRDlZbXlqZTNFWU10cm9Cd05YamFKZ1EwRlR5cGkrMFpjSVlkSm8zbnZLTWVBczFZZXdTQ1orU1NwdytFTGx5bWpXakRvRVlwN2NuMGxCaGVLSDFaaW50Q2ZFdmVyUUQ2TStDdGo1SytaVmdiY2o4TXJ6WENmVkNkTjExK3pIR0hCT1NwZ09qTjFCZm4rQ1VUbjBMd0xyeVA3OHdJMmFSRjFvTkcrc3JzTzNvODBmVkd6T2FMRDczek11OWh0OUFrR29Ib2ZlSDFRYlZVOVE3TmFxc1Q1WTVmN3ZTV05qNzc3Ym1pbndzUFJVR2FrUW4xOWQwN0RoenZtR3FVN3pjRXl5N2VKbDJnVEtXVHZkTEV4QjFSYWQzSHE0WFhYWStUSStDTVJ0R1M4c0hnaTZzdDgvVTBCOHVueEZjc3JWVzc4eDdNUEM0Z25INFdud1JXMG1GRTlOU3BlV1VxVERZVTE3RXJaRjJLSjRRdytSVkR0MGJlSmVFUVcxZmQvRXNkcXZLc1dFTTBlbW41RXNUUXVVclc5ZC9hUFd5cGo1VmlMUVlKOFhtSlNxVXIwY2ZpSDFXcVl0ZGowdE1NZTZsU0JVSzlYNjArSTBWWE5WMW5nYzlhZ2ltVkVpcHp2SzZTNFVrTkxvMHR1b3FXNDZ3akpYV0tDV2psOXBoYUs2cGwrSml6ZTE0K2RKa0tTcXBLZUlZY3lyaTV0eE5Xa00yMDVSNlFRRUwzcVVMU3lqSjZHOHNadXBFcEdBd0hvdGs1dlRVR0daNUlicTZCQk5BOW1GcThIblNkOUhLZk55MDhubGZLSWdhNWJhZG5BKzhRMThDS1U2bk1jSGRWcm9ZZmlWbUdoeWhNM3o5SWZhRnJVYXRUQ0ZxalgyZ0lKRzdRbHFNNnFwaVY4QlFIN3JaUTdkZ2xGckx6TGxGemdoRU9XV1BVbUlrQW5GSmgrcHNqQ0xPWlJtckZ5bXp0bzdMUTczeEt6RGFPT0NQNFRxZVVxZ1BNWGtldU4yVmoxRlZlVU1MNnVOZXNXcmw3SDNyR0hJaVZpWk1Jb1RRTDlFTFZ1NlFuaGZ3aEtNMkluaTM3U3RyUStoMG8rSXNPWDFGZ0Vab2gwYVR5eDNXMTJEMDBtVUxwV3EzWVFmZVA4QWVnK1lPRGx5RFY0cjVNTTRna3lObURKWm9zMTBrc2FEQmRjcStwZlJVRVZCVFRSYkplbWNZZ1NUY0VBUGJBOFFRWXhlWXRxRVNsdW4yaXhHOVJLUFRNNTFGYStjZk11NkRuSTltSmZ2ZlM1alFuRjJRakMrbVZ6ZUJQVXhFcTV2WTlUVXA2azlrU0VlejlOTXZTK29STVpqWnJzVFFyeFBRMGJreUFOOUY5eG1pcWFNb0hYTTNHOW1hT0pHcjRnVHZXenNmVDdkQ0t4Q2tTaDFNdkZIU2I2NTNpNnl6T21tOHVLMU05WWJNdm1BSjhLTmc3UWlXZzlvSTBndmtoRUl4czBWUU5neEpYVi9kamhaUWVTZk14S3RIeUlhdkhqTWFsUnplcnF4eis0YkU1bUhNV1lEL2RNcThTblg5RmZhTlB5Tmo4Ungvd0JCMG05SDl1SWM1K25FL2V2dEw0akdVZ2RRU2xhSTZ4azQzZHB5NTZHdWh4VEcwUFBYN3pZZnU3d0JiWVpvRjk1ajNGb25UZ2FUUy9OMGZ0R0E1aW1hNzhSazZ3Vm5zWWdVMjdxOFRaK0NiRyt0M2p1d2ZFcjZRVldtOEVmaXUweVB0ankyK3l3OUdJa05rWXR0b251bGFKUkxmNEZaVUhsTWZ3VFA1UWFncGdENW5MOHhTUVJSUUQzYjhTN0htL3lETjBMWFI5VFNnYXFOWmpZektaTUtBZDJ0OUlNRkxrS1U2aEJCS1lyV0hJNnowTlhaOHd4T3ZMWHhHQ3I1eVBaRUxiT2dIN1J4cTkwcWowL21hWTNsK2NmTWJNRGFPT0Z1YVRQTVBycVRpQmtxY0pTT29aYjJYeEVTcjdZSjlwbUNPbEgweExKbkpGZVZoRGxLOUhxNG8wdTVKVEkrYUd1c0FhUGNQQUR2SDFxeG1KMlo4akswTzBBM2dOaDhTanlTK2ozbVd5OHc4aEIrSjA1eU1vWXlReFlMVXNIRnk1dUxTZFpacldzZC9sRWZydEhXZkFSMTB6OHJNRk53K2t1d3VqUHVKc1NneEdGMFVyekZqN3d6WjY5TDlHZ2Q1ZGY5dUpNcjFWanQ5Ni9OUDB6N3pybmY4azVoL1RtQ2J2NmN5ejl6NWxuN256SHJSWUhZOHpGdkRlcitZUVlmd1FFMEFQUWVnZmhMdVA3b1R5WitJWXdKOXcwSGZjQUhvZ0NlVkh0ai90bG5HSGFEN25obHNYSjdVLzdTQ0lWa2dhWG1GY2FvcHFuSlhxQ09nQjViWks3a0NZWU50VTFtc3hWY0pSWFd0WTViNmt2Umw3UzFuSjZDNnVvZ1BCQmpONlFBZ0xMeUdLZDVWS1NyV2g3YlFraHd0R3krTzhWWkJFR1Z2U0tBVUxXWXRvK2pLaEJrcGRHdGFsZFM2OXhXdHl6Y2dWTkZ0UG95aVZlcGd6ZzNla1YxdWJyRkRSOVJYRDZqenZVZUQxWjBQSW1tenNOVGMvYUpLTVUrTm8zMnUrQzN4QW50STUrWVVXSU9qRGl3dDNJck5RWFpuU1pUcVZHS2V4Nmx6a3Z4RzNHSWFzd0xVUWhwQjVpbGtkbkVQVktOVXlSeENiWVBDcVQ4UkhNQnBaT0hhVk4zek1ESlpkdnRFdVJkUU5WdGU4Y0xua0g0bW5pOEdlS0V1aFE0S2pvVlJGdDJZVVA0QXhqblU0VlN1RnYwNGxIN0h4UDNyN1EzdjNla0pVbEd5SWVhclBhSU9MTkFSdGVDTHl6dDk0QlF6clY1UGNQbWV3aVBsZmFKYUIxajVJL0VaanpvVHhtT3ZnNlgrWUhwNldBL0QvY3NIMG1WdXYwL21XZjFnRGkwS1p4Z3BLOGlsUmU5d3hoRkdwUmJ1cVhrc1NMQUc2N3BVQVJCbE5xMzJYVUhndE8zUWxhMU1Zc050R3J4cDFsTXN3Qkt6UEhWR0FYS01GaUNjaHBWQXJxWjd3TkpHRHRWZ3FvcFdDQ3NsYzRpZnBvQ29hVFpqeDVpUUZDMDJyZGRPaEVyVmgyTHBlbDNGSG9iMXNIRlYxZ0k0TktLeDRsRmw4OVg4eGR6QzUrMUZkVjZpK0pQOWhIVmU2Ry83LzdscjZKZm1BMmZ0R0xaNzFFR2RXQVBtN2wrWlBBWEVtUE1zSGFVSXFWZWRJQTBBRmY5ejlJKzhEK3o2eitxUHpMdng0MTZjaUdMUUdkRU92akFVb2RaSXhSdzU0SzJ3ZEw3ekNvVWFtdHdSTGpjTHJCanB1cjlKWjJVK29oS3RCVUpnd0tNUlRTalY4V0g2akxkeU0wdDhpZk1kT0dvZ0gyZnBFZ3hxVXM5a1VwMXdCOXBkL1UvRVA4QWhQeEE5M3ArSWMzMStFNncvVGlOZUZYWitKL3dINGp1K2grSTZVTlNpSEJvcU5zVHdlWTBaOEVFTDRGMFZBbFZOU0YyR0ZNdjkwM2VNZkVDdmpnVDlUNG1saE00ZmcweHJLbUJyZVdWQXNiU2tXTXJNZzFLczl3MVJXN0YrNTVibER5Tmt6OVR2dnFENlI3c1JEME56QjNiQ1BwbWxLMGlxN2l5QkNvelk2Y3gxZEZ5MmVFdnJNeVBVaWx1NHowZTVwTEhLbE9Ia1poV3R3VDlpK2lPdy9XMHYwSjRSV0U4eE9HclEzTnRab3U1VjBlaXJYdlNXa29IOER0TmYwcFh6Vy9CSEtiTi9xYlN0MTFCVU93WS9qU2V0SFdHVUFhanRVZnJBSkU2cDNxSDhsNEhBNVRSUEtPL0w4R1IwZGVTUHg3WXpndWVrK0ZpMUVjWXl5em00ajlLdmR4QWdrN0h1YnJ0S1MvUW5ZL1hSZmR2eERMZDJMWWRWKzBkSituMGhqcmphVDl2ekZIa2gxamtWeFdrMWUvcHFEMzI4WUlWNGxqS3k0QUc4V2dWSGRVL0F2NFRSejk0MGo4U2pDTzQrWUI5WWg0UG1qdVkrWjhsS2dFd2pMelVVTll4L2hweFhXeldHVTNxZjA3dzd0WGZOWXk4Zk1CNUpxeks2U3MxdjJpbHQ2TE1LeTZLVHlSaFVneVlid3h5bUM3MVBCOWt2UmRoSDMrRXdBR2FEK2o0U20zWXREOHh6aHBvbElWZTQrek1vQ1g2ZDVWN1ZWSVFaUWJLS3Z3MmZTQnFiNHpyblo3eXZlTEhXVzFVdTJ2OVIrMDB3TVgyU3BUbTRVd1MxQXM1VlU0SFdXWEovUXRUdEdlNGlLbndVZkUwNTl5K0NLSW9PeHA4UlcwdlZibERvZGIwTzdvUzRJN0w5eGZyRWcrYlI5V0FPQko5OXE4VkZhb2VEMUdzQTRNeTNjSXhHYkh3TGxMejdFbnVCMVU2M1QyeE5LT1prK3hDblQrSERWUGM2cDdodTJqL0FOd0ZCV3A4bXlSbk55dUxmZ2ZUY2RZcnBMdEE3b2N1a0U3SEN2b3VVc2k5RStYOFNyU2ZLZmlVUndnWFkvbVppcmQ3clg2eFV5aDhRMnZpUmpLaG12Wm0zaWRsMStQNHFtNkpZWEFQbUdpdWpManNuNFdLa1o2UnBscnRCYlFOQy8wWlQwRTMvSWlzUGMzZjFteTI4YWpGajl5ZGVJS3Zpb1ZVUjFMNWMvTTFXYm5MMDJURjhKK1F5K0k2d0hZZXFqOFMvcmpjRDJSQ2tSclpVUjc5U1VHU29UQ05yNnpHY0FqQjNLY3I1S1pveW5HSjlHQnIweXIyVXpDV09MTXNSUTB3NEphbFRpa1FzRHJSOWtWQlJSRmEwQmlJOGFWMWZac1lPeGJFSDJQVVlVUHM3ZkQ0VHQxaFB6Q1k5eWpNcU9vV1orbHl5c3hFWEYzQWdwOVgwaExwOUFwamd3UkFNbVBGdFg0STZkWDRSZ3J3VFB0YzVYVUIzNW9XSHZTV2FlemcvZTFQTlFOZllUNU50ZW9rTEJzK2F4OFJmWXJXWDJOSmFBR3F0VDVabWF6dllsVmFPWFNYb0RlT2VjMXl2aVBualZIb2lSNDBMNWF4bjVXUTE1aUFaVnZVU2NnT1cyUE9DdlVsclY4QmZyQ0ZCeUFSMm82TUk5aG1aTHlINWFpRUJ4UVR0V251QXVuWEcvYmN5MTdzcUhpS3E1Vk1HQjRoTVVoeEZtbDFnamRaUXRYdkswcXRoYzdwQWVtYUVzTEFGK2NzZk1jTlJVM1VpTkwwSDNqclhJVk5FYi9OZjNndmQ2Z0hRY1ZFMFdYR3c0MGdZSWI1TG16cjJpektHaXpDRW0yVXg2UTRwSHFhNlpqQWRxcVZRSmhQUnVQR0YwUUhxVnVnS05wM0taYXB2ZkEvVHJHY2JhSnA0V1Q5T0Z3TXpxeXhyNW1lMHpsOFVVOHl1d0Y4dnpBeWdObjRETTJ6emVuRXNGWUxRNGZhTm90eEZlSE1xUnVCdXNwZEZkTlQ2enAwcUlaTFZzaFJNNHV6MUJ3azNvYThSNGdFdW9oeVhwT1VtUGNGcmxYcC93QVlOZlZxZENZTVhRTU45MUsxbGtrSElBanJXL2FJYzErTHA5U01BZFQzd2ZTWEZpRVdGRFRob3NkUWpDUlpGSjZERTExYmlqNWx6YWRiWE5mbzIyZWtFNXRON1pnQ2VWTkdLK3hHUUtkbjh3UEh1d2VXRjdKYVh2RWI1ZmtyMUJ6SFFhZ0NpanhtT0dzY1ZwTDg5NW1admhEK3VXaGxPVnQ4NlExQ3pOSStpMzZRYWd6QTNQZHAySFJVOUVMM0M2cUIwZzVtbDlnVGJXK1djT2Rpb216b0hjdUJyU0kzV0lLeXVrb3YySjhDaE5hbUh4TjZYYTQ4cmsvSEg4eHlzUG1ZUnJZbmsvcUxIY2xvcFY5T0IvVUF5bkJLTVdkRlQ4OUFoRlY0Um90dkZ4ZlJpYS9kb01PRzhQd3ZpVThEMk1IL0FDbjRoclU2V01PcnRaQ0ZiOVJQeE0zOGdtUVN1Vm40aTNrRmhKNHEwckJrS0crK3ZpQVFwVlZUcFROc0FyUjRwK3c4cEs0bWpXUlhMUHlKcnlRMDZMYTNTQkFGbk9BWEpDTDBPTVNsWVRiMi9zdk1iTTRIZ2xKVE81cEJVUHFWZ1p1Z2JmWUpkOHdUVjIra3Y5b2VXakdwSFVQb013dlFoZnpIanNvcTF0dmtMMHlNcGtQQXI2ZUVCQ3g2NkQ5U0Y2TjBIeEs0WjEzVXErcXhtZ3RLdnJMYTl4ZEkyeVdLald3TFl1ekRZVmlZMGR6OTVqSTJTWUJOV3B6RXBwY1RaRXQrNVFOYWRIaEpmVkJyTHZOaUtrS1hhSTRTMzRqd0hYSHlaaUx1RXJQVUNOWXBadFcrNGxaNU5zU3YxSUxXZXF4SlZTSXNRNzNmd0dnQldkcFJ1eWtCTUlkTzh3UFlNRmNyNkZ4RkNyM2k2RDFDNVZvbVNZdEVVbzkzOFJ6WGNKZCtHM3VXZnQvSks2UHcvd0J6QkNFT0xTQllnMC9XUGlxYUFmcDFobWFicGUyL2xNaGUyZlpaS0FPeldweWhQb3FZTTFlUkJNanMxR2FUeFpNQ0E4TVZvc0d5UlZaaTlvWHRjOTVxeEhwaUphWEtCNnIyL3FYb2h2NW8zNm5WN3dkeVRJMjZTeFA0QnZ2cEdPRnZyTFF3Nm5nZm1WSGkzQndSOURid2ZLK29RbUZCR3dVZkQ2eGpMYTZ3OEFOYXg2cGwxM1Q5TVJjQ1hVbDVuVHppczluYm81UHBMTWRSK1Q4MU1XNlcvcitaUmlBT0dHMTZEOHhFQnNvcW55elVxV3A3b1NueFNPK1hiQlcyUzlNcjljUXl1RW1wK3M5b0RqK010SG5hb0RpR2xmUzlvaDBvcE9HRlFiUTdheW1ZWVUvaGhpSTc5SldsNU9KUUp0M2RJWDJHcXV2WDFsQ3B4NUUyUjNHRjB6Y2FzQWRwVmwybDZiZ3RnU0hGRjZ6c2cwek5HdlZHMkUyVTdDYWZNd2xSclUzeEt0Rk9jQ0NjeDNJQXZmbGoxSGk2Ymh4Zy9MTHZzek50RVB2WDh1K1Zma3hIYkUvSVJUWDBJWVVPcFVld25nWmhaUDFVZkpBeXI0b0g3MWhybGRiUWZMSHMwQzk1UG1MdXVkQytiU3doZGt0S3hNWmxGVkF3Nkh2V0xGV2Q5VUZickhNS3U5RG1VQ2pWcU9sN2F2V2phRlpWNGk3c2RKZHJsTjI3TjRFMGZ4cFNEQS9XYkVIQjBHa1hNWllBc01uM0dyeEdoWlgxRFE1SEVLS0Y2Wi9TaWFyYUFLam1aWjJpdUlLS2F1NktnYkNRaGFxaDcvdWNZa2JGTGNSd1BvRVZCY2I1MWdsMVFuYUN2dE9HUUhvYnZxNEtrR0YwMXdReS9oWUZUQzVOVFVkbys1QkpUTk1MMk9kbWFGM2x4ZStQTXZEektyV1ZHS3BpMGc1Mk9ZQWlicXpyTUZZMnVxT1h2TXA1SmwxKzBxeHZGbWtLMDIyamxXSFRTYXB1TTFYeEdNWFArUkFZUmJxb3RTR3hZd1Z6eTE4RWVKMnpIMnhsa3VxNWh3cE15ZnFEQVE2Ry9MOUtnRG53SUFqaE1jcitBanIvQUExeHNucEFFR2t1N1FUMUxOd2ZNU2tCRTh5NHNCdHFtb0hLeU1RQUQ3KzRqV3VtU1Z3aDZ3SlZINjBQNXVmbVk5NjNWK25tV1pETjZuZHVwZDdCVmw5eDNJUExNU1hvZENVVU1LaUVJcXdkWDNQZm1YQ2Jxc3E2ckdYR2FIZy91V2N3eWhoQ20wTExwYU9qZFhRT3JpTkJRc05iN3k4NGFzYXg1N2ViOERDU20yNmJ2SGlLZDdVUVk0T3RnL1Erc2I0Rmh5c1ZKUVNNclFlVXdIVmlTckY1YnVnNWZlam95dkxnQ2lyTktEWWx4YW9Td3RPMlZtUFJVTW1OcXVFdXFTY3JlVWNncVd0ZFYwaW5QVDBId3NveUtDRi9nWmowTGxwWDlUekYrdUlLVHhCamxsSjh3c3pEdWNRV2NXZlNVeEJsVzV6R2V0V0hoc3lxcmw1R053ZGhkcjB0eEdoaVdEVm5JNkoxTVJZNlJ5SkVJYlFSTk4ra0xxQ1ExRTNqa081UmFidU9IVThtMG8yd1psTHI1ZmFGa1NialZROVRHOWZJZmlMMkZXOGV6cFV0QWFhUDJpYjZHd2ZMV0c3RGNvL1dZNU9xT1hRTXZrV004cWhCMnhLVHFiOExsdzJLWFl3ZlNVc1dOM1l5L1NVazJFWHNEK2U4c1M0OGhtV09pZHBwREhsS3ArU0t5N1FBQng2ZzFGTnIxOXpVSndSTGZPQm1UUmFJRGNBMjFPMlk1VFF5Y3hxYldFeDVpNDZzcUFhR2tkN01LTURxOTNRNnNRck91WUhRKzcxWmluSUc3c1MzQkxKZnRIQVRhT3dDWGVVeUxzWnV5ZGdsTlpsSUoxQmM5NDlwVU50cTRQN2dHS2lnTjQvQTUyYUxyNE5QZk0yK1hhdTg2S1ozK2pUZVcyM0JhL3ZFT3NaUUxWd0JLbHhSU1grTDU5QnJPamh3THl0VjFiZTBhdDA5Q0pZVUJnYWJCUEtDd01SeEJhZjdFMkZMdlladHZGZENXUlJZdXgrVjlSTGxrWnZybU5PM0VNR0l4YlhaZU9ta0FUcVNNOXg5ekVBbDdjN1JodHpLVVBKeEVCeFdweVRFd1ZsYjcvVVNWY1Y1cmw0bXhrQlVMM0YrVlhSbDBwc29PMzhBMTBNVGh0T0k2am1kTmxJd0thTGlDeWNiN1BXZDdkbE9UcWFrQVVORjFJbmVYS203Zjk1aU1Ld2REekZtb2hwS0dJdVdsWEUxcWQ0VkFaZ0tvTXhHc0ptZElkM3ROWHRkdmlDNitlbmhaKzBzbGZubUVZdTJ1Zy84R0srdGI4dC95clh4Q0l2SytJbWZyMW1wUzk5QnlmSXkzT2QwU0pqZkduU2ZPM0J6RjNLREI4MjVnays3bHJEcEJRMzM0aEVaRFNQaVRxU3RpRVI1RzBXeDQwZFdBQXcxMzh3MGpOclhsNWdsTENBVnJRVmNZWUxROXRWaW5aOHhPalBYZkVyYjZIUkFTRkd5RDBkUFoxSVhBMmZGNEdQT3JIVWRabnNwTTJuUHdQbElNQkYwSHl5bUNkREhkNlJDUzdSbGhhNFZDK09zKzJPc3E1dFNvOWhNSHA1TEEyaHNVYXZtSGxCcXd4Q1crR2pRZjdxWXZxWmc3ZXcrWnBJelAySHBCUmEwdnJBbk9RekJzaUh1ejlUSzV5eWg1dU91NUZoZGdjTTA4RGJobVdEMDNYNmFTbHF0ajRVd1FLcCtzM05EZUxTcWh2czRscHRSZHdjZU5Jd3UyL2FWODQyakt6ZXYyWk9TRzVtd3FENVR1SGFIdVMwb2ZlZG16cEhyQ0oxUHJmRTV2MkltUWFoV2twV2JLMGhibHZhUzhMTUcwd0xhblFhdjNIVytaYVN0WGVBamx3WWxEMURGak0yWldpMjA0ZDQrSjJvK1lPanRBT3lDcUhTREVDbjFCZTM2eEdONlNuK2o1alE5VzVuaXVIdGFRNi96ZTBHN09VcnlmMURBWFdLY1c5c0dUN3lwRzVueEZnbTBNajBsK21rVnpnc2QyL3FNTjZ3aXEyNnViZDVTNEMzaVlGTWpNcXNFcWNJSlA3SzBPc0ZsVkZxeEwwRllPejh3M0FZWXhONm54TzA4bmJIS1NsWjRTUGhEMUw2bzhzRldQM3BxK3VodXdMcDA5aCtBOEhlSzR5OEJMZWZlTUd6VEhBYnJOT040RGZ1c0lWbjBEbEE3WnBnZVV3Tzhmc3FyUDNPWDF3Nk1hQlhHdTF0WFRwcDBsM1NudTRGVHJ1NlliOFlmSnRCQU1uZ0YxbDdYaUlIWXJvNmtWeGdHbjI0SHlmckFYTUNQYlYrSUFPOHpwdEtnNWw5aENqYzJ4RVdRNDNQRXBnWWxrUWVEZUlqQWFCR2RkMlU4dnN6WnBTQ2R5R2RtRWJJS0RtZkR1ZWFtYklrZHcxZFgwanJidFZKMFpYQzA2cDZHcit3bWtrc0dHdzNKMUliMG9FZGswZTlkVTFleFhMMExrNzQ2eGRNTEQrWTF5cll4b01DRnNDSnNtOEUxaGFocHk5dnFsTDdvR0lZVGhZSHIrSTJOSlNZanBpT0lOM0lDdlYyUDI5UitKY3VsMWE4UTBqVFdZTzhEYXVNZDhFVmdRZVQrZ2kwcnpOZ2FRYzFYMVdhditHUU5iR0JsczVpSGtkbjJsTGF2YXlmRWVvNmtWeGRZbDNCc1cwUFRtWkE0dnlqVktzVUE5b1lPc2RLSDBmQTZyaW9VQVFDMExRUXRZSHM4UzlhVS93QXBUZmdMWGlBNklPeVRsYzkzcW1DRjJ3T0EwRG9ZamdJaTNtTFRmR2lJR3VMTkRnNE9DSTZhNkZiVEc4NFhWZEE1anRkcXQ3dzNCYUI5cjVmZzZ4UWJpVWVFenNhYXA0MkQweTlEV0RxQ2JQVHd2TDFiWmJMT214RGpaY29ZSUx0K1NMVHdHczA1NVYwdDUyOGU0dFFWcnJlc3RWTjdqNW1aWVhHTkorc2JUQzNWdk1LdXcxZFZ4OTQxSFI4UkxJMEpkYnpnOUtna3lQTXBSVk5qNmt1TU50akhTYnNhcTI2b1U3TlphODNFOFBLcE81dDNpTjZxM0Zjd2dDQzJoNVQ3d2l4TEJUbUdzUkFsS3h5VFZoamZWMEpkVnIxQ1BYRkl5Z0Y5UWFtSk1tTmpoNU9qaVh1OG1aOGhwMzlXQmpLNEVka0dqeU5QU0s2WHBCVTkyNXFmYzFJcGw0SzJwby9rNWxrNVdMUmd6YW5ja2VuTXJsS3pJNk50NFFPVTdtOENzNXJXbTBWMU1vQm1WcTVkZ01Iem54R3VtdnNqNHFZWUhDZERNcUpLZUEvdS93Q1grS1RqT2pUMmwycHRwRHlyMGV2M0Vvbkl1RWFGVHdSZHQyVkdGRjlCL2Y4QUMxdWpXQUdOSTJ0OUJ1eTVHSTN3ZERROHdzWnRCeDFqaFMzenpDM0kyTlp0UTVlZFlQSjFtVE9ZeGVGaEY0Z0sxZENhOGFCZlhwYS85R0lySktzbzJWWFhwdXdyUzVPRVB1NlRYV3V3QTBBMVhwQU5OTDZBY09oN2w0R1hackF1b0xpcWhFMXZWMFFqUXBZU0hyQnQ1aVZBdHZMelBMMm1pRlYrRXE4bW4weXVleW9Pcld0RFY1WDQzbHVUS09tZURaK3UwWVVqalhFeFBOSStKbDFWWVBCVU50U3R1MlkwRlNXek9kQmZ4TEMxWUdLMVJqWWJMTXVNUE1YUDBxa0draWhlL1h4TUVEYzRYM0owMXR2TFRYV09GbnMxaTBCYzJzdkcwTVZtb0NVMDdMMTd5c1ltbEMwem1vMjhVWWx2bDAzRDFJdkpqYmkrd2RmUWxxVFRFby90Zi9FS1JRRmJOazg2RjRkU1dxV2FQbUhiU2k2VExYdDJkZThkWkl4VHRDZExwaFczYUE0UDBQNHJEbytabis5TjUvcE1vM2ltcjhCM2FmZVpYckp2dFgrQzAyMGIrdDZqSlZ0VzEveE5aWUoxTE9pUjBMdEM2NmRqSjgvV0lVT3BCVk5YMGc1SFpEcExoVzZvZ0RWZ0FTMDFlV09DOXRJTE5CTm5iZTkwUE1VdFZGc1ZPbzRPaHhGYkQrRHpHdVRNYVlnRFZhNFBpVVFOVlV1L2JHaDhtNnpReUYrMXB2MHQ4alNNSzRZZ0xRR0FiQmlDYkZKWGJqdzM2c0F0TWN0dTBiY3F1OFNjeTNkcTRsZ0c2ZzI5SDFZbkVSdG5ZYUVzMStzRXk1Q2xqakZCdjJHTmdwN2FJRSsrSWNEYWFNemhxYmliSHd6aVlSeXZyL1h2S3l6ZVYzRXNLalZoc09NUkxYdUd2RVl2aUNPSEcxMGV1bjBIZUt0V1RrV1N0VnJ1V2pCc0FkaU9vRVRVaVZGWG1FVWgzWWV2U0ZRdVczaDRZYVI3cndMQ2ZwVUd0UjJrcHJxaWVEckZLQmtBK0QvWHVnRFRpd1FXUlpqbWFJbk1tSnVOU0pUc21iNGhhL1VDWTZPMTM2OTVVdXk5Nmd2REd2bUlqYlRmbnJHRVpXRFIxbGJyNFpYTnh5KzB4L0lQZlI2UHZObEduS0Q1cXZjZFFaVGFNSCtyK3I4UnpWSCtTM25jZ1hEaCs4RXJRU2dDdnFkQjUrc0JrYVJjRjQvK3pLVkdiMVlabFFtK25TRnJ0TE90WU1LMlBWaDhoWmpRQXdCTmVaYmEzZUptaHB0R0NnaEZhTndZNWV4MTlTcWE2VFN5YmRHcjFpSmRBM1lIVTJIczZhUm14S09XOVA3allNZGVEOCtJdjZpcG9ZS0I3WGdPWEJFaGczTXo4TGY2Y1hyQVdUM2hlRG5yckMxL01DQmY4SEc2aVYxZVN4WFRxakJ4YTRsdFh5eXRRYXZvYWZrZ25LVUNNMHJuSFVjZFh1VUtURDVPbzNIOXltcXk0ejkxeHpIWWEwdVVrUTFFb0xhd2hhenJNR0Z6VjZUVlAwU3lYOTZ2VlRYY0xYYnJLalNOR1dqcW5hQVU5VGM4eHhpcU8za05VN1NsUlFDcXpsQ3JzN1Zjd3B1STFDeEdrZGtaMDJRdDlqK0Q3RUk3VWV4SmgwV3E0WWk5dzZySTVWOUd2ZldMTm9Ja3dSM21IRGlwazk0c3V0cVFxaFl3ZHJ5WnZ0Rm96ZGNic1VEb2Rla3RWYi9TVkpHdDlzaEtuVUhCRC8zTHpQeGlMc0R2MWYzNGdoYzV4NmFmTXp4ZHZBZnp2L2dnSk5aM1dUc3pMZjhBcUZUWDNwTnoxbnhFc3QyejJnc00zaGp1Y3ZNeGhnKzRhdTROeUVCeXkyNDZwM2Rmc09reE9PQThjc3JVYjZ2TXl1Y3dqRm8rSnppRUZlVlorNzVuU2d5SndXTWQvcVFRU3FqZHlkaFFCYjd0aDkzUEdQSFRyRENHaWFoOGlENVlocUMxaFJycVBpTjBtRmt4c28zK3d3NjZ4SzI2eXIvZ1czRHZBTUpyZ2lJc3QweHJBbkFxalFKUysxM0hLRzA3eXY3dENGN0sxVkdkQ3dWWWlxYnBZT2h6c1lnemlJZFhvSE41dmFvMEFGWWlHTm9vOXJpV0hFWnEyWDFNeWFkeTFTdklrYktpckVHdjNiUlhWbllxWFcwU2xob0lHa2d6RzcvQXZ5bGRsMFNjSWlhSjBtcnBLNU40bjVzZHpBVVRBUmNtSWpWa0hzMTlvSVpvWXhla0wwSHpIb3VFSHRhSVVyVHNSa2JtWHdXSUVLRFZWeFNhajF1dDZ6T0tTeTdWb293SGtpaUZ4VWJwUjBTV1FrYkduSzZmVlVDS1ZVaVVuVkZlRXdOMUJLZG04aXBsYjBnenEwQU5YT0QzVWVEMVVicTc5MzRFeUMyMWhYOEwxQS81ZitpcFczcDlES2x6eFhhWDBoYk43UTFZQ053bko0eVM3MEJqc2owL2NJQVlsT2hDaXNkOFhmdTZkb3JRM0V0YUlwUWNFV00wL2daa0xKZ2dSZEFuaFBBZXVpY3M4b0gySjBWMFJ5RUhSREwyTi9wSFRwZEc3dmU0NVhWc1VnWUJhcnNFUE5Kc3pXcWFZZGx1dGFpNUdJQU5nQmdkQ0xlSmN3TFlINDR2cHl1eEZLbjFZQjQra1dpV1FxV2lCV1VXOEJ4QThETktWWHNGZEhFREpWTzViWDNHZXhpRGMyU0xTZEVTYWNMSHEvbGV1MDAvK1hLN0EzWDl4MW5WYiswdTdBbU0zRkFhcU9vS0c4NG1NT1hUTUZOV1VPVlFzTjNMRXpnalpWUzJnb0RsZDcxdVpkVjZpN08zbU5tZGFaa2Q0WmRub1NpSk1YaUhEdVZGSStWNmFPNUFkY3RxeXJJNkNyQ3p0THJoRFFYWmxNME15L3ZTbm1FelFzdXFsbWJMQ045WFZmYkR1VEpBU1EvZjdpMTc3b3h5Z3oxN0RybzdPMFRBUkE0bE9qRzh4dFRKK2tIbysxOE84WUlGcnhlYS92Nnl0SFVla0VZMmRaYmRaOEIxbm96Nmk0dDJKMlBBVkdwY0xOYkVDMHM4V2w3djhQOEFreERnaXNxR3ZNT2hNNWwxR2hMZEQ2aDlKVk5PK2tFMk11Ym1ncTJjbllEZnNPLzBuYk5UYnAyaHFtVzE2eFpCbGh6QkRzcnlqaytnWXc2OUhoNSs0MjlZM0xyVjFDdjFtNmVidS9kOGQ0clZLNHpEYjFoTjZBZ1lIZVloWUQ2N1JrenNtZVFPZXBxOUpjRnFpOWFNZk1Nczh4YUFGWFFDN2lMUnBYckI0aUZBdGtxN2oxZ2RZa3BLakZlb1o4aktCQ3FHdEpXTzFxVERSbFd3dlAxbVdyUGxRV0hWZzFSTWptWFFEbDB2YVk0WTFkZGcxVkdHVXdXK281Vzc2amFXMUtpcG1LUk1aN3dOTFdMUDIvaU45L3A5b3dCWHgrTWVxaW5VaXE0c3lsOTBJQVVHUkhXNVFPUmltenVPSWkzMDFWZm5xUEY5bzd2K21VRHJ4NWlxalkycU1BdXUweGVOT1NnOXhVVTR4RFR2Ukx6UHYrMFZQdkZwSHR4TXJMQTVWMUxBV1JPVCtnekRXSDdCTWlha0ttZWh3TU1KMldpOXlNYTlsR1h1bFgwYjRiSmgrNDlLN1JGNnRSbVdodnhXa1lFR2gxQU9FZWpERi81S09vNnhyTlN0dmVaZDNPOGF1WnlDNElud2NmZGMzWGwrQnpNRkxicmNCVXdlYm1LcXEydXYrb1RUcGw3U3drMFQyUVYwRGJXOFBrR1JXbTRIMU9rcWlibGtGbTFSVXNoYWErNzhPa3dvZzlPaHpCQ21EVTlLNE9ZbUIxVW1MQjVyTm5BWVgzcUdTb01TNERZN0hBQjBnSGdWMFgyRFk2c2REcVpUUGUxZnAwZ1dYbk9zNlBqMmhCRTBVQ3hWWTdaZUhWeExRSUVxTHo2OWQ0QXhHMXNRNE1Wa2lIZndtZW9CVS9kTUhtZWlPbDVGK1U5b2JkYWhSOEJnT3hLdDFyckxDTnVlSlpDMUVaQnRtQkFtSFBhWUpsM3BzTjYySm1WRHNVME54aWhtVWg2em5WZWZFUk52bVhkWTQ3elByazFZM1lpT0t2T0E5UTluRGRLK1VJd1hiNVJRVTZJQzF0aXRuYVJjNkhQd21MQkRSTEU2OHd3T2pLdmZWNEtkQ2JRV0h2OEFKcDJhWndMOUtqYmV0UUYzZEM5cW1zQ0NsanVhbnFKOEMyNW9ZRXcxckVHN05oZzYydmhjVkdYc1dMS2dITkRvNzh6Vld5dzdsK2ZBUk1vYlM4YXpDYUpSSHBJOEFJRUI2TkRNYkdoVlRZTlgwWlhBRlViUEVPT3N6eW9mQ0QyZEgzdEJBRFhBWWFBN0xucEs2eS94cjNMQTZ2U0JLd2xvY0IwQ2lFSGR5emJEMDZ2UCt0aUdwQkpiR3Y0eW9NYVovcU1XVWI0bmIxOUxta2tWdTdpSVRRc2ZycS9TVm9BZlNOWTdiZEplNndBMmRXUEtONEhXRExhZzBubGM5YTNTcGFESEFPNHpJZFBzZHg5WFBhSlhabVFyRkRHV0N0VG9BYXNIWFFoc3VVMGVMUnUzaVppdHhlcG80Q3RpTzJpZ2FDQUxMMUxvaHJ5SGFEUUhZRHcyZWdYckhhWmFxZVdVQ3dIVlgxbThIbXZ6TGd1ZGlHRlVkNExHeXE4a0tsN3dWYXJERksrNU1wbENyaW9KK2h4ampMTWR6YTdKTlNFWG1QTkNNMFpPWmVCeS9XYnl6WnBZMjZ6M0xEYlJydkFURVJOSlRUaEhVVFJPaktsQzJ3Vzd2SHBKM0ZwNmR6VWlEbEFLcFBNc3cyc1VyMzBmTW9qVVduWHB2NFlxVlJxajZtcE1KQTNNS0xBNFAxekhEUXRodVV5QUN2QVdvV1RpSlNqWmpGWVI5R3N1ZzJoRDNWZ1BERnpMbzZBMHV5bk5Uc21rQkdsVWNKTUZ1azVFZGN0dnVOSHBVQnhWdHRBM1hRSmNNRE0wNnZhMitxeEYwYWhtTXp0VWRFWFAreGpMNm5lQUN1dVhveERSUUluTXpCV2l6VTArZGVrUTJsYTc4ZndKOTBSTFdiYXJPN2hlVHJ1N0h1VUl6b0xzbjMvZ1NZSlV1MExrbGdQbDJ1YWJjTkxnZjJ0MDBscnFoV2wxaHp0ZVdGMDIxUnZ4b1BFWERFclNEcVplS0prRTF6ZDJ2OXcyNzlaOVE4aW52K2phWExSMWRJSk1NMUFkeWNGQXZEQUcwSEhhRnVnc1g3U25talUveHg5bkxyK0NqcVQvQUhVVVdaemtSK2FLKzU5NWNEZE1wQXVoclpGWkd3UWVKUVBucEZlTlhhV3Bad3VDQTJLeVZyTUV3OXZjSnNWdm9mVzhjWXRLY2Nrb0ZCMFhJZkthYmxPb0JkT2pkSEdrR0lOcURDZnZNSnN6S2hxUWRKMkIzQ3BXbFF0TEhRV0IxaVJkUnlsOW1XTjh5OXVwWURIMXhlbFhadzlKU0xHZU1QR3ZlamFOMDVWVzdXMVlGNFRJbjZSbVY4QjBqbi9aZE15TmQ2a3dhM3Y0ak9rdmlxeDhid2dDNVZyZmwxNDZSYnJ1NER0R0Z3Wmt5YkR6ckRCbXEvaTZJdjdVUzgxQTZITHdkWEVzUTRscCs4SFFyRXdCSmxhM3VMOER6TW5oczlvREs2cXc1T2RnV3lzb1ArL3NRb2s4bGVYVHhMSEh5d0p0TUpnMVE3d01CZldPU2RaV1VWQTNiZTVsOUkzWWcrSDdUYXltTDJUSHFML0IrWXE1b2Q0RlhFL0tDclpCVkxIWi9SaS9ick5wMWhXWTkwTFhnWDdSM3RjdWJqM1lMNEpib0FUS016REYrdjhBVWFMYThielRRQjNaWjlveExlb09MMWVHTkZ2WUg4TUNxSTBha0lETTBhTzI1NGx0VlhWYnFXZmM4ekprVHhKM1hlTU80eTgzTVZtL3ZHcloybUttdFJjL3lPS2xrMWNUaFVwTkhRRGVuVGxlakZFRENYQTZEdDhxeEx5VzhHN0tReFd0T2VQOTZHbTBJTnp0K0loc1YwSXRiUkJOZGhPdkhubUd5MkhvMmlmdXNxbGc3bkI1YWoxMnRyckZVU3BpNzBPWWtnUmQwdWZwY0RNR2s2WnJTblVOaG9OZ2doZHJPdXhjRXM3L0FLSmZuQXZqM0JrejZoUzkzVmxUY0RBaUJhaERxamNTMFdMZ3lscHVRM1hPVlEzVEFOVSt6USs4Rmh0SlJyZFdmU0pheGVZYjdrckxxeUk2T1F3WHQ0ZzRJYnNnNjB0TVdnM1BPY1RwY2RZVXZ2RXE3UDZNcWdZQnUxQWRHcXJ6aVVJQUE4LzJNZkdmRnlsWkJxdFl1anZRbWFpelNSN2xHelpqbHJRek5NTUhnbXRRS2I3ZmxOYUcvZGhDaVduNFFlcmNUbjVnRko0ekdHME5yejNDSWJIU3JHcTlWeG1XYjlkTjBaZWZlbWtjTGF0bUdaVW9XSFdBRlFtYWNOOHROZVhhQmFQV0tFWXg5MTcxV05zTzdNd1o0QnQxaVZici93Q0I3YmEra3p6bzBTd2lPVFJpcWxWeE9vZWo5cmkxd0JETm1Qejdpc3FvQlY3UmFNd3gvb1o5d1FBTnBaK3BkeGFDTTNIeHNlSUROb09zSW91aFd5RjFTczZCQk5pYTcvZ0RhcExXcjk1ZFcxaEpvdDFqZ1pGMDNiSGxRZ1dkdUFpc1lGMkt6T2xRTHFldXRPdm5Yek1adFMyQjVWOVNDQU5FS2JsTHRyV05ZNXkxMm55NGNFMmlDdzdXVlhraHQvQlc3Rks4cVBaWFBBYXFnUWVjTlBMcFE1N0JqQWo4a3RtTjd6SGtzSDZBb3RnMlZKbFVhbXIwbzk1WVpUVVI1cGxHS0ljMG8xS0xDY3BGdWU0eEVTbFZmQXI3VEF2UUJLTjA3MHZ6RjN0U0lvMWNzNjRIR1YxZGtScXhuYWVxY2ptS21LcUs4Tk1RbzNWT1dVWU1jZnRFSmpYVDkra2RndnBCZGhmU1dQb2RKbnFwNTJpaUFwdmVkZkRxcjd5Z2RDTkwzM2VJRUU4cm4zRFVoSW5aTGx4eWRON29FcGNVeGNMSWRkZkd4ajNsRndobHJmb1JVOFh0eC80citmYmZwTVJidkVSdEVzUnpIUVZkQUlZQzhYKzhSMUE4ZmxuOUZSemtmYkhkZjRuUS91eEd5cnh0S1NDb1RWVTl4bldJelNudUZaZFJkT1hwSzlwTm4zMWREM0RhS1VPUXZKYkJiUnhFdU5BcXRsKzc2aHRqYU1pb3A4b2ZFb1ovWTVWVDVnRjgvV2kxSzZEOFJtYTlac3ZBUGVOQzNmUVJVOUN4V1hTNkdWb014eVVDdnZ6SGhlR2d4cmFzVnU2M0dHeWJlMGNqcE5RSFh3WlozYTlwWHlXOEFybDRhaEZCVkRvVW85L1dYS3VaZjNGZkV2N05ldWN2bUxYMW44RDZNYjBabFVEcjk1SFFlc1UvNDhETHh4WUk5UWppaEJqQUYwZHJTSHRBbkpveThGRlJXUUxNZWZyRUtZdVhMNDRqUmc0SFNKVzl0aVdMUVFJNE9yYUxvTndiWnJCZTFTQlBVeWh3Rks4dXlicTZFTFU1RFhpNFBCdHF6VksxcUl1bHJtV0tZT2h6MS93UDVmOEFaY1FTOWRIckNxeXMwWURYd040UVVOZmpxZGZyM2cxa0RXY1ZGYzJRQWdUU1ZCTGM5SnBzSGFDaTF2TXAzNEp5QllxdnNhdmlJanJCanV4cS9FOU9vZmcxOHhEYzdHczErTlFPQzFxc0ZIaVlZYXRFUXdOVnVPdDJMcVdwVUtjdEhVN3pWNnFFNk15bGVIMnV2d3cxYzNQbVVIa1plak0zWUx5L0NLQ3V6czZDY1dtZ2QxWUcrQW9yb1A2RG5tS3hxUVpRMGpBbnRhWno2clVlREk2MEROMDYycStZb0prM3p4YnlGeVpZUVRGcG1aeVBXSTYwK2tOVzZBMzRaZytubWhlRzlrcnZKSFRWZTB3alVEN3FWV0FLejNVUE1FNHZmeForczBObTVkajRqVEkvZlNMQ25jTlR4RTZzUkV5WGlWWDV4TE55NjIxZ3RvYUJyQXlqb2tCMHpFVTNZRzhINXcrMWRJM0dJYTI4ZnVXZEF0WXBGN1U2cTh4TTF4amQ1amNQOXovaUtyR282VTc2L21DYWw4b21BM0NjUnlGMjBRY25Ycjc1Z282MFFWVHc4UUZGNDFoR1czZ2lHeEtPSmoxOWh4R3dNR2tNN3VoN2p4T3ROZDVjSGdtb1Y1WHNaaVpQTVZyVzRvUU80bUxQa2M5bEFLQU1VNzU4eWpPM3d6Vnl6Rm1EaW42eWt3NEFKZml0N0pabCs0aW11c3JjRG1BV1Rrd1hqdkxDT25WWUt3WmpWYUxBRmFjNlBiTElXMXlPdXJMcWswdTBjUWVvbnFlRHFvcDVNN01VM2swQW9XcnVSYU8zeUVhQVdiQURCaVZmblRUanJic20yZVlaMm40bmJ4a21mNlFrV1Fab1BLR0EzWW5Rd2ZCREZheGRQQWMwQWlxZFlkRmN2UmhYNGhrdUVhYklEVWV2VjFxT0UzMUZYTUxOV0IzY1FFSlJ1YXo3Z3A3bXBCd0hIaGlWMWhtTjJkcFJDRXhicVE4VmtiNm5qN3hqWWdmZGlTenJ2ZTNCeXhlZEZkczIvclhVMFlWd1lmdEdxeWd2QmVoRzJkY1AraGgvcXY4QXdTck5ZVHk1SDJoV0ViSFNNSTBDTXZCRUJvcDUvYjd4ZXcxdSs5eWEraHl6a2hPaSsyNzRpa0JhYXYwTlg0aFhiTDhacjV1QWFVY1MzeFNEdHFvRzdBN0loeWlsN3BXdkg1ZVpacUxrVHZNRHJNNmlORWk3QTZlOURiZWJvdnRGVGRyQllTa2wwYVhuckZROUZVZXZ1T0VaaEFNMDNNQzBBRjFLbkhlTFdyRlBWaWl1cG9WdTI5ZDVSMXdGOUdpWHRFSWt5TGJiWGRqcWxYQTVwVFNROGpac1VhNDEwZzBNWFViYStEQUZxMjVVNnl5NHFMWWxVY1VtYkNORUZ5cTFmbU9vMVhJSHMzRTIvYUtPcXhHZEFtU2dwcGVJSVdHK2x3dXc5NGxqUjhabEFEWkFkRWRWbytKUXpKM3lKaXNqa2pyQllZeUZiZ1BmWStyckwwb3VEMFJ5YmVWbkFtdmo1UnFxNnNZQ3JPUm1iLzhBbllpRXgxaHVIUFQ4UVNqbHVnbHlMRTFJZEdDK21lbjZTcFFtdFR5T005VVQzOG9tcFgyZ2hrZ0doUE9DSlg4THJia04zaHhlczR4VTZHdjRXZHFBZWNmYUJXYnVZeUx1RXpEaWNMZDNqTUdZWmtlSXB0UVM5U3JPUko4TXRJTlZQbU92Mkk1R0c0ZWNRVWpERWFzYlJDenFSYUJ2S0hxTGdYSitoNGo3Z2NzYkFYWFIyN3hQdTdCbGp1bXlBWU9oTlFDOGhyVU1hajEwSmFLc0tGbzFWY2djMDI5cEMydXdlcnZiNDJCb2J4cGFMdkwrWVlXdllqWVhqL3diL3dDc295akpucm93V3hycHVRcTR4MmxDZUFMMlhyOTVsNThtUjd1blg2U21MMk5qdHpMN2E4U3FoNVpyeDIzbFM2eEtzNlFhL2VBZ2x5cVc0WXpuTUxyTEtxY3hDbW0wSFU0WU9RQVVTa2d6QkVlS1VUU2d2K0swMHY4QUV6cEpiNWlPY0lyNUNKelU0SVFBYjVacExoQ3FHQmNSb2l1MElCekcxV3hYRlRXbk1Rd3c4N3dOQkE2OXZNdVU5Q094dkxLcnQ1YldCVE9kZ3pLY0tlR1A2ZHRZQ3VRVjJBTlE5TTl0WWFWdEJBMHgrbnU1ZDEwMG1sZFk2d3Y1bDMvZy93Q2k1djhBNVA4QWlmNGJ4c2ZCbXVOZCt2YVdKU0xFWUw2cFk4VkhPNDhSdm84WTdROGV4a3lmbUZTMkhlWU1jdzlkWXhNU290cllianpLd2N5cTBtQTNZdjJuNElzRm9INGdyK0MxbFFQNGFGTjFKdXhTa1YveVozQ2Z3QWNrM3VNUk1CNk1zN0VxS3hVQ3JSaUdFSFhVbEJxYmsyd3V0ZkU4bUpRQW13MGVONWdWNUpjVTBUZzl0K3hEUWkvSUN1RDh4cTZhUE51aWZvaUJnd1pRY0d4ODh4ZDlKUWExTEhIMy9pdi9BRHYrYlBPUjI0bEJzMkhVZzJaWTVJTU9tN1ZKL2M0VnNhRHpGaGQ0YlR1ZmlWTHUzRUs0STlZaUUvY1RTSmNHRkJnOGtkSncyd1dva085WWphYkVnTWJtRmFaT3lVUnNnai9ISlI2Vzk0Ni93L1FjTTVvV2t1dlV6WjREN3c5UVpnYUNxVUZRMmpVd2lQSXZ4Q0tDRHpjTnQwV0QzQnFrVnNGQkFuQUhCdkV6bXRUanV4ZytZNUY4WjhNUW56MFNrNEduWUY3UkRKYUxOZFZmeVhyRkwxNTVpcG5FcnhjZGY1SCtHZjUxbFEvd2Y5OWl4YmxyYTJOdG9TcFUxYmMxd3pXMHdxRHFqRDNJNGxqaXpKMW1vZXpsQWMxdEtqWDZEV080SjBkNVp2RlBESzV4M2pZSEx0TGk4WWw2dDFHcVU1TGxXSk1BNEsrWlZSdmY5OXdsR29PbVZnb3BML0F5NkxuMlRWRGNQNkd6TWZsMStaVFlFUXRzcVZZcU94ZVhlYU5hczI3d0k2d2ZiZzdSNE5ZeWw5YTAwN3VoSFJZUU54NHZWOFRYbzJnaDAyK2M5SVFoOG03RFYrRG94UnE4YTA2SEIwSTV6ZWh2QUQ5WTdnYmlycTMvQUxnLzA2elQvRFgvQUVzMGwraUVNckRVZFlCdkk5TWFwWnAxZ0l2N3hmaUZNZFBQbHB6M3krUHhLcHJOY1dldFlrTlVucEZRSkthUEZ5aGlNMjBCaDQ2b2xlejJUdXByM0RVMlZTTENTNVlmeEY5Mm44aVk1bUdJNmY4QWJNQlpZTkhXN2l4dlNDeTkzTURFRmNRMlBMY2ZZTG1lMWxnQlFGNWZpSTZKd0Z0N1B1d01BRjNDN0RBKzJOcmdZUzlRT2ZvNlN2TDZGNlJnamxsdjdSQmx1Q0dFbTRVZituU2Evd0M0VWJNVE5qYm5lSFNuUFkxSU41QkIycVUvdTRzUGNncmo1MElkOWYwKzRWYjhmWDRoc2J0cW5wTEUySTdSclQ2Z1ZrbHhISXJ4S3pnaktJWUlWTkNUaTRTbUczOEdTOTBGeHdYQUp2akREUTBOWFlqdmRLajZaeFc4YmdUZVU2TVd3d2dMVTZCckNyNHppSzdhL0VNclhjOFh3by9WSnBaRFFyMTR2dmNkc1dyMTR2VHhFRXlYTG4yVnZId01FYy8vQUMwVmpUekVOQTg2TUpzeWJzUTY3OW5FV3d2UGVDbWpVTERxSlQwd3JLa3BPbjk3eHVtT3dzNy9BTnhRSTF3UHB4Qzhkc21IdUhrV05tWFJUOGt6KzlKWVF0Q3JnRGN2Umd6SmlwZjRCbktISUNPaE5LN3hVYmNXKzJXSWJPZzNnSytQeUtoREw3cTJEcHNmTXNPcVZwOG41amJhckMrY2IrV2VJeG8rRkU0TkEybGN3T0JYNG1zaGVETTBoNGY3ZC84QUEvOEFlTk5pakt3WFNaemE0MUpabzlxS3FuRHd3aFoxbzZ5bERSOUg1dVo5RDQvTVVkWFhkN1hFMTRNRjRmREtsb0NobUR5UVYyd3dYNVliKzhmOFRJS2RUK2tWOEhuRlFJbFh2aU52cUF2eEVMTjNxNzhzTTNzeSs1ZzYrT1ZQb1RUUERSWDNMWURva0t2TjlDR0tSMkJUcFpuNWkvZnRiOXJNdEphYW1JRllXNlNoZmMyV2RpNVhTRFVzT0QvTy93Q1gvd0JiL2svNmxMQTdNSXBvOVNhUmZsUU1DYjJYTW9XT3VtWXQyTzhwNGpOWUJuSkRvOUpvWVE2aERSTDJpdUZweGJIa1BNclllbzFldjhVOFFheXRUT2kvbEZidzVaZHMzVEpqR1I1V0lIUWg0RlJXcFY2Ly9ZUDR1dUpwQzh4eWxCMUlOOVlxYWdkaHVDYUc0VXFzUFVHeU1kSXMwRWN4MG51UEc5eTdXa0tORDdSTlk1cTluZWorQWNTWnlkQThDYTJQbVgvNy93RC8yUT09IiBhbHQ9IkFMS0FJRCI+CiAgICA8cCBjbGFzcz0iYXNoIiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij5Qcml2YXRlIGxhdW5jaCBzbmlwZXIuPC9wPgogICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJwcml2Tm90ZSIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyO21hcmdpbi10b3A6MThweCI+VGhpcyBkYXNoYm9hcmQgaXMgcHJpdmF0ZS48L3A+CiAgICA8ZGl2IGlkPSJvd25lckdhdGUiIGhpZGRlbj4KCiAgICA8YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9IndhbGxldCIgdHlwZT0iYnV0dG9uIiBzdHlsZT0id2lkdGg6MTAwJTttYXJnaW4tdG9wOjIycHgiPlNpZ24gaW4gd2l0aCBteSB3YWxsZXQ8L2J1dHRvbj4KICAgIDxhIGNsYXNzPSJidG4iIGlkPSJvcGVuUGhhbnRvbSIgaGlkZGVuIHN0eWxlPSJ3aWR0aDoxMDAlO21hcmdpbi10b3A6MTBweCI+T3BlbiB0aGlzIHBhZ2UgaW4gUGhhbnRvbTwvYT4KICAgIDxwIGNsYXNzPSJub3RlIiBpZD0id25vdGUiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI+T3duZXIgb25seS4gU2lnbiBpbiB3aXRoIHlvdXIgd2FsbGV0LiBGcmVlLCBhbmQgaXQgc2VuZHMgbm90aGluZy48L3A+CgogICAgPGxhYmVsIGNsYXNzPSJyZW0iIHN0eWxlPSJtYXJnaW4tdG9wOjE0cHgiPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9InJlbWVtYmVyIiBjaGVja2VkPiBSZW1lbWJlciB0aGlzIGRldmljZSBmb3IgMzAgZGF5czwvbGFiZWw+CiAgICA8ZGl2IGlkPSJjb2RlU2xvdCI+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDx0ZW1wbGF0ZSBpZD0iY29kZVRwbCI+CiAgICAgIDxkaXYgY2xhc3M9Im9yIj48c3Bhbj5vd25lciBiYWNrdXA6IHlvdXIgY29kZTwvc3Bhbj48L2Rpdj4KICAgICAgPGZvcm0gaWQ9ImNvZGVGb3JtIiBhdXRvY29tcGxldGU9Im9uIiBvbnN1Ym1pdD0icmV0dXJuIGZhbHNlIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0idXNlcm5hbWUiIGF1dG9jb21wbGV0ZT0idXNlcm5hbWUiIHZhbHVlPSJhbGthaWQtb3duZXIiIGNsYXNzPSJ2aCIgdGFiaW5kZXg9Ii0xIiBhcmlhLWhpZGRlbj0idHJ1ZSI+CiAgICAgICAgPGRpdiBjbGFzcz0icHciPgogICAgICAgICAgPGlucHV0IGlkPSJjb2RlIiBuYW1lPSJwYXNzd29yZCIgdHlwZT0icGFzc3dvcmQiIGF1dG9jb21wbGV0ZT0iY3VycmVudC1wYXNzd29yZCIgcGxhY2Vob2xkZXI9Ik93bmVyIGNvZGUiIGF1dG9jYXBpdGFsaXplPSJvZmYiIGF1dG9jb3JyZWN0PSJvZmYiIHNwZWxsY2hlY2s9ImZhbHNlIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBpZD0iZXllIiBhcmlhLWxhYmVsPSJTaG93IGNvZGUiPlNob3c8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gcHJpIiBpZD0iZ28iIHR5cGU9InN1Ym1pdCIgc3R5bGU9IndpZHRoOjEwMCUiPlVubG9jazwvYnV0dG9uPgogICAgICA8L2Zvcm0+CiAgICA8L3RlbXBsYXRlPgogICAgPHAgY2xhc3M9Im1zZyIgaWQ9Imdtc2ciIHJvbGU9InN0YXR1cyI+PC9wPgogIDwvc2VjdGlvbj4KCiAgPG1haW4gaWQ9ImFwcCIgaGlkZGVuPgogICAgPGhlYWRlcj4KICAgICAgPGRpdiBjbGFzcz0iYnJhbmRyb3ciPjxpbWcgc3JjPSJkYXRhOmltYWdlL2pwZWc7YmFzZTY0LC85ai80QUFRU2taSlJnQUJBUUFBQVFBQkFBRC8yd0JEQUFRREF3UURBd1FFQkFRRkJRUUZCd3NIQndZR0J3NEtDZ2dMRUE0UkVSQU9FQThTRkJvV0VoTVlFdzhRRmg4WEdCc2JIUjBkRVJZZ0loOGNJaG9jSFJ6LzJ3QkRBUVVGQlFjR0J3MEhCdzBjRWhBU0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQnovd0FBUkNBQ3dBTEFEQVNJQUFoRUJBeEVCLzhRQUhBQUFBZ01CQVFFQkFBQUFBQUFBQUFBQUJBVUFBd1lDQndFSS84UUFUQkFBQVFNREFRUUdCZ1VLQVFvSEFBQUFBUUlEQkFBRkVTRUdFakZCRTFGaGNZR1JCeFFpTWtLaEkxSnlzY0VWSkRORFlvS1N3dEh3VXdnV0pUUkVZNU9pc3VGRlZHU0RvN1B4LzhRQUdnRUFBd0VCQVFFQUFBQUFBQUFBQUFBQUFRSURBQVFGQnYvRUFDc1JBQUlDQVFRQkF3SUdBd0FBQUFBQUFBQUJBaEVERWlFeFFWRUVFMElpWVJReVE1R2gwY0hoOFAvYUFBd0RBUUFDRVFNUkFEOEEvQU5TcFVyR0pVcVZLeGlWS2xYUllraWRJYmp4V1hINURoM1VOdEpLbEtQVUFPTll4VFVyMlhaYi9KL3VreEtaTzBNajhuTVkzakdid3Q4anQrRkhqazlsYVIyNStqajBkL1J3a1I1RTl2UXFhVDZ5OW50V2ZaVDRZcGRYZ204aTRXNTR4YWRnOXBMMmdPUXJOTFd5ZjFxMGRHMy9BQkt3UG5XbFk5REY2S1FaZHd0RVByU3VRWEZEd2JTcXREY2ZTN2M3cTRSYXJHclhRT1NsbFo4aGdmT2s5eDJtMnFhdEtwYzJVbU82KytJOFpsbHBJM2lCbGFqa0U0R1FPODlsYTJEVk5rVDZJWTZOSGRxSWdJL3c0YjZ2dkFxdDMwVVEwajJOcW9nVi92SVQ2UjhrbW0rejhHNUNGYzd2dERQbE9RNHJXVXR0dWxCS3VKT25ZTVk2MVVzMnJoWFdEYzIxMjI0U0JCa01wZGFTdHdxNzlUNEh4b1d4ZFVycXhVLzZMWjZRVEd2TmtsSGtsTW9zay84QUZTbjc2VFhMWVRhUzFORitUWjVYcTRHUyt5bnBXaCsraktmblRkMjYzcU8zRldoNUx3ZDNtMWgxQTBjVHhHUmppQ0NQR3JvZTEwNjN1QnhVWjZPNFAxc1J3b1B5bzJ4bEtSZ0tsZW5QMzIyN1RLeGNXWTB4NVdtKzZqb24vd0RpSndUNDcxWis1YkhOa2xkc2ZVci9BTlBJSUMvQlhBK09LTmpLZmt5TlNySDQ3c1oxVFR6YTIzRTZGS3hnaXE2STVLbFNwV01TcFVxVmpFcVZLbFl4S2xTdlhmUkw2SGw3V2JsNnZZWEhzS0RsQ003cXBSSEhCNUlITlhsMWdOMExLU2lyWm5QUjk2TEx4dDYvMHJROVV0S0ZicnMxMVBzNStxZ2ZFcnNHZzVrVjdOTXZleFBvUmpHQmFZM3IxL1VuZFdFS0NuMUgvZU9mQVAyUnIyYzZBMjI5Sjh0VHJXeWV3MExvMldraEJsTklMYWVqK3ExMUpQMStmTHJPQXRKc051dkNsU1dYYlBkaXJLbWJza3Z4MUhyUzZuQzA1NjFCUTdhWG5raTdsdkxnYXpYZHR2U1dzbTR5VGJyVXJVUkdBVUpJN1J4VjQ1cDNhZlJmYkxha0tVejB6ZytKZXRhcU5makNqdHV6N1k0ekhXUFlsdzFpUkhWMmhTZUZNR3J4QXVDZnpXWTA2ZnFwT0Q1SFd0WU5YZ1N0MkZDU0dtV2tCUjBTQUs4NjJrZGJ1VzNjYTFzbk1HMEo2UHNVc2FyVjRxUHlyMkM2em05bk5uYmhkblBmYWJQUnBQMXVBK1pIblhqSG8zdHlycmM1RXAwbFJlYzNWS1BNRDJsbWdaUHMxRzJNVUN5Mm14aHd0RzV5RzB2S1NNbEtWS0JPbmlnVXE2TVNkbW1BcGZTTzJ0WllLeU5WSUJ3RC9EdW53cnU4VDFYVDBsV3VJRGxETXhsdkhMUFNBbjVuSGhWVmhlUWJqZUxjNTdxM0hCanVVZndKOHFqcmVyU2MzdXYzTklnY1k5WmZrUWtuZFZJU0gyRDlWMVA5UmtWOFkzSmNkS3lrQlhCU1R5STRpcTduMHNGNWx3SEQwVjNkUDkrSHpvcVdsTFVnU21jZXJ5UUZFY2dUenE1MW9WeTdReTluMkFEUXlET3QyaUZGNWtmQXM4TzQxbzJvVW1TQjBiSzFKUFBHbm5WY3VDbUVrcWx5R21RT0lKeWZLc0d4YUpFSzh0ZERLYTM5MFkzRkhEaVBzcS8vQUVkbFp5NzdPdlc1Q3BMQ2pJZzVBTGdHRk5rOEFzY3UvZ2ZsUmN5NFExUFlpTkxrT2pncyt5QjVhMGZhTHhKUXI2VVljU25DbEZPOGhTVHhTc2NDRHd3ZERSNEdWb3hkU3RiZjltMlZ4WExwYWtickRlREppWkpWR3pwdkFuVXRrOCtLU2NIa1RrcVlkT3lWS2xTc0VsU3BUZlpmWjZUdFRmWWRxaUQ2U1F2QldlQ0U4VktQWUJyV00zUnR2UkQ2TkR0cGNqT3VDRkN4dzFEcE1hR1F2azJQeFBWMzF2dlRMdGRjNCt6N0RGaWFTenM5MHhpT1MyU04xeFNQMVNRT0RZd1JuNGlramdOYi9TSmYyL1Ivc3JEMlgyY0Jia3ZvREtWcDBMYUZaeXNua3Raemp4UElWUnNaWldJT3pCMmR2QzFQV203amNWdmY3UElQdXFUMUFrQWRpZ1ByR3A4N25PMjM5VEVlemZweGNsSlppN1YyOUVscEFDRVRZcUFoMUE3VThENFk3alhwS29PeSszZHB4SFhHdWtkSXlNYU9zaytSU2ZLdkNyaHNWUHM3OGlQSllWdXNPRnZwVTZwUFVlekkxR2E0dFZ1a3haUWVnUHV4cHpJSzB1TXFLVkVEVWlnMmtyUk9Vb3I2b210bjdGYlM3RHlISmV5OXhrTGpISlhHUHZFZFJRZlpYNVpvU0Q2UWJST1gwVi90SmhUQWNHWEJHQUQxcWJQRHdwalovVEMrUWlOZm8zckRmRDFocElRNk85UEErR0tjM1RaelozYnFNWmNGNXA5MERIU05IZGRSMktINEd0ZmtaU1QvQURDWDByYmF4YnhaN1hCdDh0cVEydFBTdk9OSzBWdTZESTVFbkp3ZW9WYnNJd2JEc3pJdVRvd0dtaXJYclY3UitRQS9lckRYUFlTNDI2YTJ5bEJmak9PQkpkUU1FRFB4RGxXMzI2bmZrSFl5SmJjYnJzcFc4b2RtaWovSUt6MlFaYktrSU5rVkNSdDNZWlRxeXBjbVl3NHNua292WUk4eFJMYklhMmh1MHNMd0dIMUVENnhMcEdQTE5KZG5nbFV5ejVKQ21XeTZ2bG9GcVVEWDEyVVk2THF3U291bDlCQ3VPZ0pPZkhJcVB0dTlTT1I0SmFuTlA3ZnlHN1ZNajFoeFNSN0w2TjhmYUg5aWhiUmRvVE52SHJwU1cybFpDU2NidzRnZWVhWXpsK3YyVnAvSDByQjlvSGoyL0kxaFZXaVpjSlpZanRLVWh2T29HbU92UElkOVhpN1IyWTk0ank4ZWtLWEpXcHVFbm8wSFFZR1ArLzhBZkNrTEVDYmVIdDU5VGkxY1NNOE8va0tjTTJpQlowQlV4MUszUHFKT2g4ZUo4UE91VjNSeWM0aUxDQ0dnbzdxRUFZeWZ3N3ptaTJrTTVLSjg5U2hXbHNGOWFTZU80ZzZIeDRudzg2QWszaDZXbGJVTmpvMmtwS2lRT0FIRTQ0ZWRVeDRyc3RUanpoM1k3ZUM2K3ZVRFBBZHBQSUNyNGtSTjRscGlNYjdNQnNkSStzNnFLUjhSN1RuQUhESkhhYUNkZ1VyRDdGTW5RR1lzMWFnbFNsS1MwcFl6dnA0RUtTZENrNnB3ZU9DS0MycXNURVpMZDF0cUNtMlNWN2ltYzVNVjNHUzJUekJHcVNlSTA0cE5jWHFXdWMvMFRmc01NRUpRaFBCT0JnQWRnR25tYWM3UDNCcm8xczNGdGE0RXBKWWxJU05WSXpvdFA3U1RoUTdSamdUVEQ3cmN3VlNtTjh0RHRpdWtpQzhwTGhiSUtIVWU2NmdqS1ZwN0ZKSUk3NlhVeFFsZThlaUcwUnRtTm1KMjFOd0lRdDV0UlNvOFVzSjQ0N1ZLR1BBVjRyWjdhNWVMckRnTmUvSmRTMk96SjFQbFhzbnBTbklqV3UwN0xXNDdxSHluZVNPVFNORWp4T3ZoU3k4RThtOVJNM2FwOHphNjZYSk4zSWJqN1RLM1dGcU9qRDdmNkVnOGdNN25jbzE2RnNQZEdyeGFwRm91aVA4QVNNUExFbHBXaFVNNEN1L0l4bnJHZWRaYTZXa043STRhRzQ1RFVoMUJHaEdORDhqbndyaTZUWFl6bHIyMXQ0QmRkK2hudGpRRndEQnoyS0F6MzROWVI3bTF2N1U2ZkJWSlpkSXZOb1R1UGtEL0FGdU9kUW9qZ2VaSVBNS0hWU0haNDIyWmRvTHA2T0crWEFsUVZub1ZoWHNudFRvVDFqdXJSL2xkdVd4RXZGdkpkd2dxM0J4Y2JQdnRudDB5TzBkcHJMM0sxSmp6VzVOdldneFpKRHJHVllCenJnRS9kVVp4VFJ6WmNhYWZSbTdyc3ZJRndjZ2hoWHJLU1VoczhWWTZ1dk9OTWNlVlpocVBQdDhzT3dYSG1wTFowTFpLVmpzeHg4SzlYdXFWdHpKRGkyMVBSQXN1dGxKdzR3b25lMDVwT2VSME9QR2ttME53aVhweE1xUXlaRFVuMlJJWlNFUE11SkdveHdXRG9vQW5PcHdyU21oTFVoc005U1ZnZG85S0xxUUk5L2lpUWthZXNOSndzZDZlQjhNVUJ0ZmRodDV0YkJpUVY5SXdzSlpiV2xKQXlyVlNzZG44dFV5b3U2eVg1cktidmF3ZDMxMlA3TDdQWXZPdWYyVmpQVWFaYlB4TE5ZNE43djhBQ3VIckx6RU5TSXpaVHVyYVdzN3AzaHhCd2RPV3AxcHFMYVV0MEFOdnNwVmMzV04zb0V6R2JkSFVPSlR2Si9sYkovZU5EZE9pUkVocEtoMGt6ZVFyVGdwQTNScjNnVU0wREh0Mnk4VTZMbFNsVFY5bzN3MmovcFVmR2dHbHJGclc0ajM0VXpmSFlsZW4zcEhuUm9PazBFYTl4bTEzQlVoVzdFY084QVFjNDRBWUhaU2E0Ylh1dmdSYmN6MGJXY0pBVHFlNUk1OXB5YU5laDJSRGIwdTdUWG1rT0tDbVlrVUF1TzZaeVNkRXB5Y1pwYVZ1UGhLWWNVV3VHOGQxQ1d3WEpFanNCOTVXZXpBckpCaEZKQ2R4RXAyUnV1aGEzMWZEbmVWNDFwdGtMQTlMdThWeHpLR1duQVNzRVlKSEVBblRUbVRvUElFZEhRMmhsYVMzMGVWZEZ1b0lVdFN2aXlyZ1NCeUdtVGpYQnJSTXlKYTVMR0d1aFEwZzlCRFpHODQ0ZDBnRWdjZ1Q3eHdPT0tubGRLa1E5VEpxTlI3Rms5cUEzMGJUOHBUc1pyOUZFZ2pUSjRrclVOVkhyQU5mYjJwaXpSaEJpTXBZa3VZTDRTc3FJV09SSjQ3b09PcmVKNnF2aFd6OGlNbTZ5bldTdGtsTENFSzM4T0RHVkVqUTdvT2RDZmFJck1PdktrdXVTWE02KzZPSkE1RHZyUWoyTmhqM1oxRmlxZmRiWVJvcGZFbjRSek5jU0ptYm52UjhpTEdBYVNPdFBNOS9PbVRnL0pWclU0dkhyVXNjUHFvLzcvZ2FVd1dpR3NuaXNrNjg2c2RDTkJlb3FienN5SGthemJOako1cmlyVi9JdFhrNTJWaEszMnoweHFGTGFNbktvaXQ2UElUOVpoWTNWZjhBS1NlOUlySFhlMnUyZTZUTGUvOEFwWXJxbWxFY0RnNHlPdzhmR3NneDhHeTlFa0hwdG8zWmlrNVREWkpIMmxleVB4clJTYmMvZjl0WnQxY2RqeDdaR1BRTnZ5WEFsSjNkRHVqaWRjMEg2TGltRFpybExWb1Z1QVo3RUp6K05JckRzaEsyaVF1VThpV3BDMWsreWtnYW5QRWloMlRmTFo2OUMyMjJMMmVUK2R6QlBmU01icUU1VDVBR3NudEQ2UjlsSmJFNlBiN0d1T3pNSDBqYkgwYmFsY2w0Sk9EM0FjS29pK2plMm94MHFXeGppSHBPVDVKelI1MlkyWXRZeSs3RFRqamhzRStheVB1b1doUHBNenNGdFMzQ21HM091L21zcFdVRFB1T2YwUDM0cmV5V1czRU8ydFpBanlzdVIxZjRUdkVwN2pxb2Z2RHFwV05vZGtMWHFsQ25WRDZnUDhxUjk5TGJoNlZiWXlDbUhaZzZjNUNuTURIVWNuZU5DN00ycGJJK00zU1N3cFVPWGtxWUpSZ2toU081UTF4enh3N0tCeXd4S0xEaWdpM1hOT2krVERvT2gvZFVmNFZVdmpYK1p0cnRCSGpSN2NsTXQ4YmlFTWtrclBFWno1WjByVjN6WWVmWkxISVRlWkZ0akZ3ZE0weXFXZ3ZOdUFjQ25xVU5EZzhRS3lWQ3FLaTY0TTYycVExTWNUMHE0ZDFhSmFVdFB4NDBLRmpnb2RoME5CVExiRHVUaGFLRzdWZFhQWlNvWjlWa0hrT3Rzazk2ZTZybFBmbFczSW43dzlhaUJERW5YVlNPRGJ2OGhQWWsxb05ucmZJbnlJOGlYQ2Y5UWpMRDdzbFRSRGU0ajJqbFJHTTZZOGF6ZElkeXJjU1hHQUUzeDFUZ0tXYks5QnR5TmRONEgyOCtJVWZHazhLQXNvTFRhZ3BOeWp1RWJ4MEMwck9QK241MW9GSmYvSU5rZGNCVS9lcm81Y1hPc3BDZ2xQektxQWJiNkcyUnBLY2d3SjVCK3d2WDd3Zk9rOXhjQ2U2dUJmWmJFN2ZaL3ExcFo5ZW5aRy9MY0dHR0IyQThlOCtBcG5kRng5bjVLN1BhSlBybDZleWliZFZhOUVNZTBodjZvQXprOGVWTTcxdFM3czVzdkhzbG9pT01QTEN2V1p6YlpBSUtqZ0pWMWtZeWVYS3NJeXdxTkViWlN0Q0pWeDAzMXF3R21jOFNlV2VQY08ycUxjdEYzdUdOdXNGS3JpVUVRNGVJOE5zNkZhK0pWNERLajJsTmR3cFVxN3ZvZ1E5eUt3N2tyQ000Q1FNcVV0WEZXQUNkVDNDdmwxaEdjaGxxMkthY2dRazlHMkFzYjZ6OFN5T3RSMTdzVUpDdXJsaFZLWUREYTNIUUVMWHZhN28xM1FSeXpqUFhnVUdreFpSVWhqZjdpSmJ6VUdNQ2lGRlFHMEk2Z05RRDJra3FQYWV5bGJNMkd3K2xVamVVMjJjaHBIRlI3K0FvdEYyaHZxeTdEU2xSNHF4K0l4VnhhZ3ZEZUNWZ2RoeVBtRFJUU0NtbHNDcjJoaXlwTGowbUlGaFI5bEN5U0VEa0JnOGgyVmFKbHNmL0FFYWx4eWVSMVRWYTdaRWMxUXRCKzBqSDNHaGxXVktqN0FTcjdMbjRHanNOc01HbE5uZUFXbHdFSFZKNC93QjYxeHR1a3lWMmk2RWUxTmhwUTZycmRhSmFQaVVwUWYzcUVqV3RjV1MwNFV1cENWRGluUWpoVEM4L25PeURSVm5lZzNCU0IySmRiQis5bytkWkdUM0htektpeHNQSUtkVkxEcXNmS2t5ZHM3NVAzVzIzUUZZd0VvVGsvUE5OdGw1UFJiTGc2bm85ODZkaHpUVzI3VDI5TENrUTd6TGhCemlraHRTVDRMUU0rZEpMVjBpT1J5MzBxekpTRGNaS2N6YncwblA2dnB5cFE3d25RVU8xQ0RUZ2NibXhndEp5Q3BSSnovRFhvd3VWOFduTU8rdzNrRGgwa2REWjh3a2o1MVE1ZXRyV2NuUjFJK0podHB3ZjhvTlJmdVBvNW04ejZYNy9BT2pIU0xkRnVoU3N6b1VlUitzU1NzSVdmckp3azQ3UjVkUStKMlNjYVVoeERrU1VnLzcxYmFSM2twR25jYWZ5TnRyNkFwdHlTVUVqQkJaU2svZFdUY256VzNTb1N6amtIaVZKOHptbnh4bjJVd3JMOHRob200ejRqUzR5YnpGdFVjK3lwbTFOS0tsanRVa1pQaXFsNlYyVmgzZlhCdXQyYzY1RG5Rb0o3a2dxK2RmZlc1enplKzVEZlUwT0xrR1FyN2dTUGtLcWJtTkxWdXQzeWZGWDlXVVY0SDd5VCtGVk9vMGRtMmhjUUZpQ3UwN05JeHVsVFVKeDU1USswb0tQekhDakhibmE1N2lUZHB1ME8wTGc0QjF3c05lQTFQbGlrc1Axd0lVbFJsWE5CK09GY1ZFZ2ZaNCtZb2lLOUNhY0NSZHJoQmRINnFjaFduN3lUK0ZSeWNiSE5sWGovdjhBSjZCcy9hWHRycnZiUkVnZXJSNGlFTXg0NkNwUVNnS3p4T3BPdEJiUVdCVmdWTml5WVJlUTZvYjdaSlRxRGtIVG5UYll2YTJmc3Zkb1RyTTNmV1NoVGJqVGhVa2duUWcwUHRKdEhLMnBsekpUMXhUR1NrNzdyejdpZ2taT0J3emsxNU41TmZmSjh3bjZ6OGJYNlo1cEpFUnBTdWdkdU1BOHhucEUvaFNhWTRvckhTZEJQSERlVXlwS3NkK2xhR2JJZ3FkVWhGd3VOelh6VEVRVXA4emsvS2xFbG1Zczc1ZVhBYjQ0bFRUdkh3NC9Ldll4WFc1OVZodXR4UXB1T3JYb0pNZFhXZzd3K2V0ZEVPdUpDUStsOGZWZFNRUjUvd0JhdVUreWxXNGJqTWt1ZlZqNzJQTlJ6OHE3VXVXeW5JaXFaU2VDNWJwejVFajdxcVhLR0lxeVR2S1UxcnczQ3NmS25iTWYxUVpSQWNsTzQwV3RDa0lIZ05UNGtkMUlVekhPbUNubkM2bk9vYkpTRDQ0cmZ3L1NYZlhHUXczSnZHNmxQRmk0dkZTVWptQmtqVHVxR1ZTK0tPVDFIdWJhRlprWFlFbDF4YmltSDBMVWNuZFJwNVlyajFPY2dZU2hhdXhTRkpOYkNWdFJ0ZzJVcWEyaHVpMkZqZVN0eVl0c2pzVUZLeUQvQUdNMFAvbmh0T2pWN2F1ZWtjdzNKZFdmUElIenBFOGhPTXMvU1g4LzBaWEUxbFNRV25tMUU0R2hBTk5aYUFiQnRHeVIramVqdWdkUkMxcC9ub2lmdHhjSFVKRHQ5dTBsU0RrZEpMT005d3o5OUR6VkZWdTJuVWZpRFBuMHcvb2F2ajFmSTZjWHVmTkZteDYrbXREckdmalVrK0lvU0RicGlJaVVOc01TMGprMDhONGRoU2FIMk5rbEM1TE9kU0FvVjlldDZQeWpOVHZLYVdITjlLMEhCd3JVZmZUOWx1MmRPcFJHV2VraHlvcXh6Q0NQbUtzYXVqcUNPaHVTc2pnSGNINzlhamQydlZ0S1VKY0Vwa25BQ2hrK1ZXM3U3SWFqb1E3QmlHWXNaUHM1M1BMUTBUQnFkcGJpRUJMeVdwVFkwd1RrZVJ5Szczb054ak95SkZ0RENFYUZhRmJnSnhyakJ3ZkxuU1d4VzFVaHd1THdnckdTY1lDRTh6aisrUXEzYUM0N3lVUTJCdXNvOWtEKy9uMjByMkZkSjdDdUc3QlJKZWRVWmFBRDlFR1ZKQ2ozcTVlQXBpemRwUWh2U1poWmt4MEhjYlJJYkMxS1BmeDBxVzdaaHhTQTdNY0VSb2plQVVNdUtIV0U2WUhhb2dkOUN6RXN1VGZWMGhSdDhMVlFKeVZuUERJNGtuU2hGcHNXTWxLVFNDclZCa3pYR1ljTktVWEM1a0tXVUozZWhaQnlNWTRaNDl3RmFtK3pMZGFMbEdzemM2VlBVcFFhbEdRc09OdFpHTUpKR2Q0RWc2SFNrYk56a1d4cDlpQ2tyMmdtakw3cU9FVkgxQWVSeHhQTHY0Sm0yR0lQU3JLVGNaYlNla1VsdkpaWjE0cVY4V3A3Qm5yck5XTTQ2dVRSdzU2MjJiU1NvcFhHaytyS3dlSHRBajhhNVhLVk50MGFHci94Q2ZoUno4Q1RyOHlhVUIxUms3dzFENzdNZ0RxSk92NDF3MU1LQ0hRTklERGhDVHczMUtJL0dwKzJyc2lzU3V3cVJlWmx5Y2tzc1RuR0l3V29OTU00YlJ1NTBIczR5Y1V1Y084MnpJVzIyNUlpYUxTNGplRGlPUkk1NDRkMktpR21YbEFOSjlVZk9GZEE0cjJWWitxby9jZk9yQTZwdDM2VkJEcWRGSlVNYnc1ZzFSS2l5VkZreTl6VTlGMGJpR1lhL3dCWEdRbHJ2R1VqTkNTVld4MlF3dHNUQWxSK2xTNnRKVU81V1B2Rld4MldSSVRIZjNsUlZIZlFVcUNUanZPUUNPM3FvMmRzd3RLVkxndWV0SVNuZVVnSnc2Z2RaUnJrZnRKSkhiUWxKSjdpU21veVZsTHdoVzRKY2JnSmNCT0Fwd2x6WHhPUGxYQzd2TVdraEFTdzMxSndrZVNjVjFFV0hvcW0zQmxJR0ZEczVFZHRDeTRaQ2Q3Q1ZPdGFuSXlGcDY4VVZUSGpUNUtYWkt6a3JsSnoreHhxdHRzeUNkMXQ5ODlpU2FaUTdpRklTMnpEaHRQY04vY3p2SHh5QlFUOXd1VXhha0xjVWdKT0NrYVk4QlRESGJWdmRXNjB5cHBEWFNMQ2NMV0FyVTQ0VTB1andUWmIwNE9EOHhwcFBjT2tWK0FvV3lRUW1jMUpXU3IxYmVmVVQrd2trZlBGVVhod3MyVzN4eWZhZWRja0tIV0JoQ2YrbFZiczNMQUxISzlVdVRLODRTbzdoOGExZHhiM1gyWkE0S0hSSzd4cVBrVDVWZ3dTQ0NPSXJjUUhoZGJlRWxRQzNFZ1o2bkJ3L3A0MFdHZmtzUyszR2JYSldjSmJHbmZXY1lRdTVURnlIUjdBUEQ3aFZ0eGVYS2NhaE5aQVJxdjdYUHlwcENiUkNZRGgwQ1BkNyt2KytkQUQyQ0pzc1dxSDBJT0gzTlY5aDVEdysvdXJtRmNvbjVRWmF0ekJDMXJDZlczd0M0a2ZzSjFTbnYxUGFLUlNTOWNaWVFoQ2xyVWQxS1Vna2s5UUhPdFBZYk94YTdnMHVZOEZTMmd0WmpOS0JMZUVFKzJ2Z2s2Y0JrOTFSblhMT2JLNDFiQTNvczZTdzlLV29JUTM5SnVMVnhWeEJVVHhVZVdjazhoaWxhU20zTm9EemhTb0hwQ0U0SzFML0RISW5uclRpR21UZW5pVnFEVUtJMnR3cTkxdG4yU1FlZXBPT3RSN2FTU25tbUhRSWUrcGVmOEFXSEI3YWoyRDRmdjdlVk5COURZcGZFTWFZUXB2L1NEcW9FRSswSWpHcjczYWM4UHRLOEFhWkdXL010aGd3b3FJVm5jVnVodHZVdXJBeUN0WjFXUng2aHlBcFcxc3ZjMU5GOTlybzFMSUtXMzE3cnJtVHhDVDdXTzA0RmFLR2tKZVV5MGQ1aTJOYnljY0ZLM2s3eXZFaytBRkxrbld5Rno1ZE95Q2I5NlByN3NldTJPWG1FcGhtU3kzSVljQkNrdU5uQ2dRb2FFak9vNGlzYzhuTWR5TWdIcFgzZ0NjZkNNNCtaK1ZmcTdZWEV6MFRYWkczS3M3SHNCWDVNZFgvckNKT3VFeDg4Unh5T0hIdHgrY1pFQWlYMHJhQjBhRkZRenp4d3JrdytwYmRTUE05RjYrV1J5aGs2ZlBRQy9HTTQzQS9SdU13dDBibWZiQ1BkM2s5Z09NOTlLK2xVaHNJWCtjeDA4QVQ3YmZjZjdGTmxvWHMvZHVuWmRTOG5SVzhvZXk0bFNSbEtoMUVFZ2lncnJhaDAvVDI3ZlhGY0hTTnB6OUloSjVFYzhhakk0NHpYWENlcC9ZOVBIazFQN01IQ0JKWkpaWHZsdjIwWjBVT3NFVTZ0Y09ZMElhdjBrVjFZS2R4WHROa2taS0NOUVJubDRpa01CTFpjUFN1S1pkQjlsNUk5MC90RHE3UnIyR3RFeDY3WUxpMjJBRnhuMUlkVHZlMDI4blFoUUk2czhSZ2pzbzVIMGJPOXFSMDVkNHFwcmpkempsUzBxVTJxWEhTQTRvWkk5dE9pVjkraDdUU2NMNlpJM1RsUU9VSHI3UHhIYjMxcEw5WjRNcTd6bTR6L1JTUzhvcGJlT2l3VGtZVno0OWg3NnpTNFVpQklYR2t0S2FYeHdvWXdlUnBjYml0MEpobEdyUXZrdEJsMFBOajZOZnlORnV1QjViYnc5NXdCSy90RG40aXJIVWgzSUtkRkhkV25xVWVmajk5Q01OUElrQ0tsQmNjV29CdEkrTWs2QWQ1MHE1MTJQTjMxT3l1clNQcFpiZ1lRT3RJd3BYejNCNG1zemZuZzVjQ3lrNVJGUWxoSkhQZDRueFZ2R3RIZVpiY1dWdXRyQzJiV2pvMEtIQmJ1ZFNPd3JKOEVpc1NTVkVrbkpPcE5GRFFYWkthMlNhSTd4WldjTnUvSTBxcUE0T1JvYUl6Vm0ya1JXeThaeWRDNW8vZ2U2cjYzNzMzNW9ZeVkwMlF0RHNnTU5NcHpnSktsS09jQktRT0o0blVnZHRWMmE2SmNSdXZKMy9BR2R4eEdjYjZmd1BNSHJxaHl3VEV5Q2lHMjVJUTc3VGJ5UmdGSE1xSjBTYzZIUERGSTEwU2t1Z3hOMkZ1Yld6QmI5WFFyUmF3ckx6ZzZsTCtFZnNweDIweHNGdkx6eGVlUzdsYkRuUXhZNmN1dTVTUmxJK0ZPdnZId3pRZHVadDFtVVhaNmtUSHg3clRTdm9rSHJVc2pDdTVJSTdhK3pOcFhudzRpTWtOdE9ISzB0WlNsZjJsZTh2eE5JNEVuanZaZnVObHNxWlN0cTVTRzQ3SVFVcGd3aUhGb0dRVGs1M1VrNDFKSlBaUzVkL2kyL0tiVEZSSFh3NlZKMzN2RjA4UDNBbWtUOHRidUVPcnlPVFNCZ2VYOWFiVy9ZKzczUmd2SmJSRWprWVM0OGNieE9nSGlTQjQweWlvanFDZ2pxMnlYcFpmNlk3eTFuR1IyZzhUenBuc2tvTFRjRXJIR01RZjQwVU5zcmFaTnd1MGUydGdJbHlYRU5wRG1tRjcyTmZuVEhaMk9CY0x5MmpPNEdTVTl4Y2J4OTlSelZWSE42cHFtZy9hNzBqM25hNHdJMXdmUUkxdVlUSGpNTW9EYlRhVWpHUWthWk9OVHpyZXY4QXBzdTJ4VE1XeHhMZFkzb3NOaHBLRnliZWh4eFFLRXE5cFI0bkpPdGVTUDJKOXE0WEJ0MTFwREVIVjZTck80bkkwQTB5U2VBQTFQZHJUSytRdjg0OXBnd3k0aHNMYWJLblhUaExhVXNwS2xLN0FCWE5MREcwamhuNlBESnhpMTlPN1BucEUyN25iZVB3Wjg2UEFZV2hwVGFFUW95V0U0Q2p4QTRuUE9rTnhrR0VZeUFoS3loS1VicXV4T3ZEaHFhNm5XbCtQS3Q4SnhPSGVsV3lwUGIwaEJvNWRnY3VWNG1zUFRJc1pNQkx6enpyKzl1QktYQWprQ2VQWlhWamlvcWx3ZWhnaERGRlJqd2hhN2NJOGdEcDJpb25UTG52RHVXT1BqVE8zU1MzMFNFdUpmakRHOUZrSEc5ZzZGS2hvRlkweU1IVG53cWk3Ykt5N1BiSTF6YWxRN3BiSDFGdjFtRzRWQkRnR1NoUVVBcEp4cU1qVWNEU0p0WWRKNkJaUW84V3ovVCtsTzBwSXE0eHlMWTEyMHNCcVM1S213VnJkUTA0b090ckdIRzBsUktTUnpUcVJ2RFRRWnhTbGkrclV5bUpjV3hNaEowU2xhc09OZHFGOFU5Mm83S0ZpWG1UYjFwT3AzRGtjd251NWp3cjVQZGozUjNwbUV0eG5GRDJtK0RhajFnL0RucTRVcXg5TWxIQlMweTNYa3Z1YTRLSFduSUQ2bm0zVWUyaHhPNnRKendWeXp3SUlPTzdoUjBGYUxUYkZYVnhPWmF5cG1Db2pYZXhoVG8reURnZnRFZlZOQVdpd0tsTGVmbXFWR3RzUUJjbDhha0RPaVVjaXRSMFNQSGdDYUIyZ3ZoblNPa1MybGh0Q1ExSGpvT1VzTmpna0hueEpKNWtrODZwRlZzWHh4cGFSVGNKQU83SFI3cURsWGFyL3NOUE9nS2xTcUhRbFJLbFNwV01kdE9xWmNDMEhDaFduZ1hORW1NdU82VmVyT0VGU1VuVkN1U3dPR2Z2SG5XVnJ0cDFiS3d0QndSODZ6UXJqWThsVzE2TStoQ2txa3FkMWFjYUJVSFIxanE3UWRSVi93Q1RVc0ozcmpOYmlKL3dHL3BIajREaDRrVjNhcjVodHhramVaZEdIR1NvcHoyZ2pVSHRIamthVkYyVnRTRlBRbGw1cE9xa2tmU04vYUhNZnREVHVwZU9STHJrNmJ2MGEzcDNiUmJVb2MvOHpJQWNjN3huMlI1R21zRGFDTzNDM3J0NnhjWk1wd0tkU2lVV2xNb1FjcEc5dW5pY3F3QnlGWjdvOTNpTVZ5cHNZSjZ4cldhdllFb3FTbzlaWTJsMmZQcEkyZjJraUtReEVrcWJrekdGS0o5VWUxUzRDY2Fna0JZSUhCVlp1M2hFS1pLY2FueEgrbFlTZ3BaS3lUOUlnRWpLUnBwV0lnck80dE9kVW10Rlp3bDE1S3VBU0FrK0swSCt0UW5qcEhKbHdxTUFpNVhwaTYzQ1pDZmRiUkJVb3JaZFNORXU0OTlYV0Q3cDZoakhDaWJyY0lkdjljTHJQVHlKaUcyVk5KZEtDaHNJUVQ3UUh4SEhnRFdRV2o2Wlo3VFRuYTFrSXV5azQvVnRILzQwMEtXcElOSlNpdnQvUVU3ZVVYQzUydWR1bHZva2tMYlVvcUtkdys5dlkxeU1hOVlORnRTWWMrODdVSlhjWTBWcWJIZGFZZmZKRFpLbmtyR29CT296eXBNcHZvTFd5OTladFNCNHVIOEJTTnpKUTNyK2tjcWtZcDhGWVFUV3h1N3ZOdHV6dXl2NUh0MXpidWQwblNHbjMzSXlWQmhoRGFWYnFRcFFCVW9sWnpwZ0FBYTVyRHV5a3Y2eUk1U29mckVEQitXbGZXVWh5UW9nWkNkQlJ5R2xPSENRVkhzSENuakdpa0lLS0FXM0ZJMVFzUG9ISTZLRk5iUlpmeTE2dy8wb2hSSTJESWxPQTdqSVBBWStKUjRCSTFQZGtoaTVzeEV0YkNKVjlkVkhEaVFwdUswQjZ5OE9XQWRFSlAxMWFkUVZTYSs3VE9UVU14MjIyNDBLUG4xZUd5VHVOWjRxSk9xbG5tczZuc0dBQ010K0MyL1g5dFVabTN3a0xadGtZa3NzcUkzM0ZuUXV1RWFGWnh5MFNOQnBxY210YW5GbFNqa21vdGFuRkZTamttdWFLUlJLaVZLbFNpRWxTcFVyR0pVcVZLeGo2Q1VuSU9DS1pRN3M0eXRDbEtVbGFUbExpVGdpbGxTc0JxellOM0tMTVIrZHRaSi9YTVlDdkZQQStHRFZxYldKQS9Nbm01T2ZnU2NPZndIWHl6V01RNHRzNVFvZzlsRnQzRWpSeEFWMmpTaFhnVFJYQXdSR2Rpem5tWFdsb1hqTzZvRko4alRTMXJLWmJiZkQ2VnMrRzhLRWliVVNtRUJDSnEranhqbzNnRnA4bEFpaldMK2t1aDFWdXR6cm8rTkFVMmVPZmhVQjhxV1NiVkU1eGxKTlVMT0x5K3JKclE3YWdDOXF4L2hNL3dEMUlvUVRyYVNWS3NaeWVPNUxXQjh3YUx1ZC9nWE9TWkx0aEhTa0pUckxYdTRTa0pHZ0E1QVZMUTlTWkZ3bHJUcmdEdUxxQlpMY2hKQlVDNFZBY3NIVDc2VFI0ejgyUXd4RlpkZmVDVkhvMmtGYXM5d3lhYnZYOWxDVWhGcHRUUVR3THFWT2tmeHFJK1ZEVE5zTGhJWkxDN2k2bVBqSFFSVWhsdjhBaFFFanpxc1kwaThJdEtnK0hzOG0zSUNyM0xhdC9Nc0tWMGo2di9hUmtqOTRwb2wzYTlpMElLTEhFRVpRL3dCdGxicTMrOUk5MXZ2OXBYN1ZZbGM0alJwQVNPczBLdHhUaXNxVVNlMm1vcHB2a05tWFI2VTg0NHB4YTNYRHZMZGNVVktXZXNrNmswQVRrNVBHcFVvakpVU3BVcVZna3FWS2xZeC8vOWs9IiBhbHQ9IiI+PGRpdiBjbGFzcz0ibG9nbyIgc3R5bGU9ImxldHRlci1zcGFjaW5nOi4xNmVtIj5BTEs8c3Bhbj5BSUQ8L3NwYW4+PC9kaXY+PC9kaXY+CiAgICAgIDxzcGFuIGNsYXNzPSJiYWRnZSBwYXBlciI+UEFQRVIgTU9ERSDCtyBOTyBSRUFMIE1PTkVZPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iZmVlZCIgaWQ9ImZlZWQiPjxpPjwvaT48c3Bhbj5jb25uZWN0aW5n4oCmPC9zcGFuPjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9InNwIj48L3NwYW4+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBvd24iIGlkPSJ0b2dnbGUiIHR5cGU9ImJ1dHRvbiI+UGF1c2U8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0ib3V0IiB0eXBlPSJidXR0b24iPkxvY2s8L2J1dHRvbj4KICAgIDwvaGVhZGVyPgogICAgPGRpdiBpZD0iYnVpbGRUYWciPmxvYWRpbmfigKY8L2Rpdj4KICAgIDxuYXYgaWQ9Imp1bXAiIGFyaWEtbGFiZWw9Ikp1bXAgdG8gYSBzZWN0aW9uIj48L25hdj4KCiAgICA8c2VjdGlvbiBjbGFzcz0iYmFuayIgaWQ9ImJhbmsiPgogICAgICA8ZGl2IGNsYXNzPSJiayBtYWluIj48c21hbGw+VG90YWwgKHRyYWRpbmcgKyB2YXVsdCArIG9wZW4pPC9zbWFsbD48YiBpZD0iYlRvdGFsIj7igJQ8L2I+PGVtIGlkPSJiR3Jvd3RoIj48L2VtPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJiayI+PHNtYWxsPlRyYWRpbmcgYmFsYW5jZTwvc21hbGw+PGIgaWQ9ImJDYXNoIj7igJQ8L2I+PGVtIGlkPSJiTmV4dCI+PC9lbT48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iYmsgdmF1bHQiPjxzbWFsbD7wn5SSIFZhdWx0IChsb2NrZWQgcHJvZml0KTwvc21hbGw+PGIgaWQ9ImJWYXVsdCI+4oCUPC9iPjxlbT5uZXZlciB0cmFkZWQgYWdhaW48L2VtPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJiayB2YXVsdCI+PHNtYWxsPvCfkrAgU2VudCB0byBzYXZpbmdzPC9zbWFsbD48YiBpZD0iYlNlbnQiPuKAlDwvYj48ZW0gaWQ9ImJTZW50VG8iPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImJrIj48c21hbGw+VG9kYXk8L3NtYWxsPjxiIGlkPSJiVG9kYXkiPuKAlDwvYj48ZW0gaWQ9ImJTdGF0dXMiPjwvZW0+PC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPGRpdiBjbGFzcz0iY2FyZHMiPgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48c21hbGw+TGF1bmNoZXMgc2Vlbjwvc21hbGw+PGIgaWQ9ImNTZWVuIj7igJQ8L2I+PGVtIGlkPSJjUXVldWUiPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxzbWFsbD5QYXBlciB0cmFkZXM8L3NtYWxsPjxiIGlkPSJjVHJhZGVzIj7igJQ8L2I+PGVtIGlkPSJjT3BlbiI+PC9lbT48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PHNtYWxsPldpbiByYXRlPC9zbWFsbD48YiBpZD0iY1dpbiI+4oCUPC9iPjxlbSBpZD0iY0Jlc3QiPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxzbWFsbD5QYXBlciBQJmFtcDtMPC9zbWFsbD48YiBpZD0iY1BubCI+4oCUPC9iPjxlbSBpZD0iY1BubFVzZCI+PC9lbT48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PHNtYWxsPlJ1bm5pbmc8L3NtYWxsPjxiIGlkPSJjVXAiPuKAlDwvYj48ZW0gaWQ9ImNTb2wiPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxzbWFsbD7imqEgTGF1bmNoIFNob3Q8L3NtYWxsPjxiIGlkPSJjRmFzdCI+4oCUPC9iPjxlbSBpZD0iY0Zhc3QyIj48L2VtPjwvZGl2PgogICAgPC9kaXY+CgogICAgPGRpdiBjbGFzcz0iZ3JpZCI+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPuKaoSBMSVZFOiBldmVyeSBsYXVuY2gsIGFzIGl0IGhhcHBlbnM8L3NwYW4+PHNwYW4gaWQ9InB1bHNlIj53YWl0aW5n4oCmPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0idGFwZSI+PHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBsYXVuY2hlc+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn6SWIEF1dG9waWxvdDwvc3Bhbj48c3BhbiBpZD0iYXBTdGF0Ij7igJQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJhcCI+PHAgY2xhc3M9ImVtcHR5Ij5Mb2FkaW5n4oCmPC9wPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIG93biIgc3R5bGU9InBhZGRpbmctdG9wOjAiPjxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBpZD0iZnJlc2hCdG4iIHR5cGU9ImJ1dHRvbiIgc3R5bGU9IndpZHRoOjEwMCUiPvCflIQgRnJlc2ggc3RhcnQgb24gdGhlIHNhZmUgcHJvZmlsZTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHByaSIgaWQ9InYxMEJ0biIgdHlwZT0iYnV0dG9uIiBzdHlsZT0id2lkdGg6MTAwJTttYXJnaW4tdG9wOjhweCI+8J+nviBTdGFydCB0aGUgVjEuMCB0ZXN0OiAkMSwwMDAgcGFwZXIsIDElIGJldHMsIHN0YWdlZCBleGl0czwvYnV0dG9uPjxwIGNsYXNzPSJub3RlIiBpZD0iZnJlc2hNc2ciPlN0YXJ0cyBhIG5ldyBwYXBlciBhY2NvdW50LiBUaGUgb2xkIHJ1biBpcyBzYXZlZCBhcyBhIHN1bW1hcnkgYmVsb3csIHNvIGl0cyBsZXNzb25zIGFyZSBuZXZlciBsb3N0LjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn5SQIEN1c3RvZHk8L3NwYW4+PHNwYW4gaWQ9ImN1U3RhdCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iY3UiPjxwIGNsYXNzPSJlbXB0eSI+TG9hZGluZ+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn5OJIFdoeSB5b3UncmUgbG9zaW5nPC9zcGFuPjxzcGFuIGlkPSJkeFN0YXQiPmNoZWNraW5n4oCmPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZHgiPjxwIGNsYXNzPSJlbXB0eSI+V2FpdGluZyBmb3IgY2xvc2VkIHRyYWRlc+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn6etIFRoZSBzdHJhdGVneSwgaW4gcGxhaW4gd29yZHM8L3NwYW4+PHNwYW4+ZXhhY3RseSB3aGF0IGl0IGRvZXMgbm93PC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0ic3RyYXQiPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfmoAgTW9tZW50dW0gd2F0Y2g8L3NwYW4+PHNwYW4gaWQ9IndTdGF0Ij7igJQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJ3YXRjaCI+PHAgY2xhc3M9ImVtcHR5Ij5TYWZlIGxhdW5jaGVzIHdhaXQgaGVyZSB1bnRpbCByZWFsIGJ1eWluZyBzaG93cyB1cC48L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPjxzcGFuIHN0eWxlPSJmb250OmluaGVyaXQ7Y29sb3I6aW5oZXJpdCI+8J+OkyBHcmFkdWF0ZSBzdHJhdGVneTwvc3Bhbj48c3BhbiBpZD0iZ1N0YXQiPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImdyYWQiPjxwIGNsYXNzPSJlbXB0eSI+TG9hZGluZ+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn5GlIENvcHkgdHJhZGluZzwvc3Bhbj48c3BhbiBpZD0iY3BTdGF0Ij7igJQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJjb3B5Ij48cCBjbGFzcz0iZW1wdHkiPkxvYWRpbmfigKY8L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KCiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfjpMgQWxsIGxhdW5jaGVzICZhbXA7IGdyYWR1YXRpb25zPC9zcGFuPjxzcGFuPmxhc3QgMjQgaG91cnM8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJnciI+PHAgY2xhc3M9ImVtcHR5Ij5Db3VudGluZ+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn4+GIFRvcCAxMDAgdHJlbmRpbmc6IGhvdyB0aGV5IGdvdCB0aGVyZTwvc3Bhbj48c3BhbiBpZD0idFN0YXQiPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9InRvcCI+PHAgY2xhc3M9ImVtcHR5Ij5Mb2FkaW5n4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn6eqIFdpbm5lciBMYWI8L3NwYW4+PHNwYW4gaWQ9ImxhYlN0YXQiPmNvbGxlY3RpbmfigKY8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJsYWIiPjxwIGNsYXNzPSJlbXB0eSI+Q29sbGVjdGluZyBsYXVuY2hlc+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn46vIFN3ZWV0IFNwb3Q8L3NwYW4+PHNwYW4gaWQ9InN3U3RhdCI+cmVjb3JkaW5n4oCmPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj48ZGl2IGlkPSJzd2VldCI+PHAgY2xhc3M9ImVtcHR5Ij5SZWNvcmRpbmcgbGF1bmNoZXPigKY8L3A+PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJvd24iIHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tdG9wOjEycHgiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9InN3QXBwbHkiIHR5cGU9ImJ1dHRvbiI+VXNlIHRoZSBzd2VldCBzcG90IG5vdzwvYnV0dG9uPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJkYXRhRGwiIHR5cGU9ImJ1dHRvbiI+RG93bmxvYWQgYWxsIHRoZSBkYXRhIChzcHJlYWRzaGVldCk8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJzd05vdGUiPjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn6eqIEV4cGVyaW1lbnRzOiBzYW1lIHRyYWRlcywgZGlmZmVyZW50IGV4aXRzPC9zcGFuPjxzcGFuIGlkPSJ4U3RhdCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZXhwIj48cCBjbGFzcz0iZW1wdHkiPkxvYWRpbmfigKY8L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPjxzcGFuIHN0eWxlPSJmb250OmluaGVyaXQ7Y29sb3I6aW5oZXJpdCI+4pamIEdyaWQgdHJhZGluZyAoaXRzIG93biBwYXBlciBwb29sKTwvc3Bhbj48c3BhbiBpZD0iZ3JTdGF0MiI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZ3JpZCI+PHAgY2xhc3M9ImVtcHR5Ij5Mb2FkaW5n4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5PcGVuIHBhcGVyIHBvc2l0aW9ucyA8c3BhbiBpZD0ib3Blbk4iPjwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9Im9wZW4iPjxwIGNsYXNzPSJlbXB0eSI+Tm90aGluZyBvcGVuLiBBTEtBSUQgb25seSBmaXJlcyBhdCB3aGF0IHBhc3NlcyBldmVyeSBmaWx0ZXIuPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPldoeSBsYXVuY2hlcyB3ZXJlIHNraXBwZWQgPHNwYW4+dGhlIGZpbHRlcnMgYXQgd29yazwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImZ1bm5lbCI+PHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBsYXVuY2hlc+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5MaXZlIGRlY2lzaW9ucyA8c3Bhbj5ldmVyeSBsYXVuY2ggaXQganVkZ2VkPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZGVjaXNpb25zIj48cCBjbGFzcz0iZW1wdHkiPldhaXRpbmcgZm9yIGxhdW5jaGVz4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPkNsb3NlZCBwYXBlciB0cmFkZXMgPHNwYW4+YWZ0ZXIgZmVlcywgdGlwcyBhbmQgc2xpcHBhZ2U8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJjbG9zZWQiPjxwIGNsYXNzPSJlbXB0eSI+Tm8gY2xvc2VkIHRyYWRlcyB5ZXQuPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5SZWFkeSBmb3IgcmVhbCBtb25leT8gPHNwYW4+aXQgaGFzIHRvIHByb3ZlIGFuIGVkZ2UgZmlyc3Q8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJzY29yZSI+PHAgY2xhc3M9ImVtcHR5Ij5CdWlsZGluZyBhIHRyYWNrIHJlY29yZOKApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5XaGF0IGl0IGxlYXJuZWQgPHNwYW4+ZnJvbSBpdHMgb3duIHRyYWRlczwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImxlYXJuZWQiPjxwIGNsYXNzPSJlbXB0eSI+TGVhcm5pbmc6IGVhY2ggc2V0dXAgbmVlZHMgYSBkb3plbiB0cmFkZXMgYmVmb3JlIGl0J3MganVkZ2VkLjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5EaWQgdGhlIGZpbHRlcnMgcGF5IG9mZj8gPHNwYW4+c2tpcHBlZCBsYXVuY2hlcywgMzAgbWluIGxhdGVyPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZnJlcG9ydCI+PHAgY2xhc3M9ImVtcHR5Ij5DaGVja2luZyB3aGF0IGhhcHBlbmVkIHRvIHRoZSBsYXVuY2hlcyBpdCBza2lwcGVk4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCBvd24iIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+WW91ciBvd25lciBjb2RlIDxzcGFuPnBpY2sgb25lIHlvdSdsbCByZW1lbWJlcjwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiI+CiAgICAgICAgICA8ZGl2IGlkPSJuZXdDb2RlU2xvdCI+PC9kaXY+CiAgICAgICAgICA8dGVtcGxhdGUgaWQ9Im5ld0NvZGVUcGwiPgogICAgICAgICAgPGZvcm0gaWQ9Im5ld0NvZGVGb3JtIiBhdXRvY29tcGxldGU9Im9uIiBvbnN1Ym1pdD0icmV0dXJuIGZhbHNlIj4KICAgICAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIG5hbWU9InVzZXJuYW1lIiBhdXRvY29tcGxldGU9InVzZXJuYW1lIiB2YWx1ZT0iYWxrYWlkLW93bmVyIiBjbGFzcz0idmgiIHRhYmluZGV4PSItMSIgYXJpYS1oaWRkZW49InRydWUiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJwdyI+PGlucHV0IGlkPSJuZXdDb2RlIiBuYW1lPSJwYXNzd29yZCIgdHlwZT0icGFzc3dvcmQiIGF1dG9jb21wbGV0ZT0ibmV3LXBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iTmV3IGNvZGUgKDEyIG9yIG1vcmUgY2hhcmFjdGVycykiIGF1dG9jYXBpdGFsaXplPSJvZmYiIGF1dG9jb3JyZWN0PSJvZmYiIHNwZWxsY2hlY2s9ImZhbHNlIgogICAgICAgICAgICAgIHN0eWxlPSJ3aWR0aDoxMDAlO2JhY2tncm91bmQ6IzA3MTAxRTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMXB4IDc0cHggMTFweCAxMnB4O2ZvbnQ6NjAwIDE0cHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0taW5rKSI+CiAgICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJuZXdFeWUiIGFyaWEtbGFiZWw9IlNob3cgY29kZSI+U2hvdzwvYnV0dG9uPjwvZGl2PgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9Im5ld1NhdmUiIHR5cGU9InN1Ym1pdCI+U2F2ZSBteSBjb2RlPC9idXR0b24+CiAgICAgICAgICAgIDxwIGNsYXNzPSJtc2ciIGlkPSJuZXdNc2ciIHJvbGU9InN0YXR1cyIgc3R5bGU9ImNvbG9yOnZhcigtLW1pbnQpIj48L3A+CiAgICAgICAgICA8L2Zvcm0+CiAgICAgICAgICA8L3RlbXBsYXRlPgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiPllvdSdyZSBzaWduZWQgaW4gd2l0aCB5b3VyIHdhbGxldCwgc28geW91IGNhbiBzZXQgdGhpcyBzYWZlbHkuIEFmdGVyIHlvdSBzYXZlLCB5b3VyIGlQaG9uZSB3aWxsIG9mZmVyIHRvIHN0b3JlIGl0IGluIFBhc3N3b3Jkcy4gVGhlIG9sZCBjb2RlIHN0b3BzIHdvcmtpbmcuIE5vYm9keSBlbHNlIGNhbiBjaGFuZ2UgaXQuPC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCBvd24iIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+8J+UjCBDb25uZWN0aW9ucyA8c3Bhbj5mYXN0ZXIgY2hhaW4gZGF0YSDCtyBUZWxlZ3JhbTwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiI+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luLWJvdHRvbTo2cHgiPkNIQUlOIENPTk5FQ1RJT04gKFJQQyk8L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJub3RlIiBpZD0iY29ublJwYyIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5Mb2FkaW5n4oCmPC9wPgogICAgICAgICAgPGlucHV0IGlkPSJycGNVcmwiIHR5cGU9InBhc3N3b3JkIiBhdXRvY29tcGxldGU9Im9mZiIgYXV0b2NhcGl0YWxpemU9Im9mZiIgc3BlbGxjaGVjaz0iZmFsc2UiIHBsYWNlaG9sZGVyPSJQYXN0ZSB5b3VyIEhlbGl1cyBhZGRyZXNzIChodHRwczovL21haW5uZXQuaGVsaXVzLXJwYy5jb20vP2FwaS1rZXk94oCmKSIgc3R5bGU9IndpZHRoOjEwMCU7YmFja2dyb3VuZDojMDcxMDFFO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHg7Zm9udDo2MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1pbmspIj4KICAgICAgICAgIDxpbnB1dCBpZD0icnBjQ2FwIiB0eXBlPSJudW1iZXIiIGlucHV0bW9kZT0ibnVtZXJpYyIgcGxhY2Vob2xkZXI9IkRhaWx5IGNhbGwgY2FwICgwID0gbm9uZSkuIEhlbGl1cyBmcmVlIOKJiCAzMywwMDAgYSBkYXkiIHN0eWxlPSJ3aWR0aDoxMDAlO21hcmdpbi10b3A6OHB4O2JhY2tncm91bmQ6IzA3MTAxRTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4O2ZvbnQ6NjAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0taW5rKSI+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tdG9wOjhweCI+PGJ1dHRvbiBjbGFzcz0iYnRuIG1pbnQiIGlkPSJycGNTYXZlIiB0eXBlPSJidXR0b24iPlNhdmUgY2hhaW4gY29ubmVjdGlvbjwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InJwY1Jlc2V0IiB0eXBlPSJidXR0b24iPkdvIGJhY2sgdG8gdGhlIGZyZWUgb25lPC9idXR0b24+PC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSIgaWQ9InJwY01zZyI+PC9wPgogICAgICAgICAgPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxNnB4IDAgNnB4Ij5URUxFR1JBTSBCT1Q8L2Rpdj4KICAgICAgICAgIDxhIGNsYXNzPSJidG4gbWludCIgaWQ9InRnUGFnZSIgaHJlZj0iIyIgc3R5bGU9IndpZHRoOjEwMCU7bWFyZ2luLWJvdHRvbTo4cHgiPkVhc2llcjogb3BlbiB0aGUgc2ltcGxlIFRlbGVncmFtIHNldHVwIHBhZ2Ug4oaSPC9hPgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJjb25uVGciIHN0eWxlPSJtYXJnaW46MCAwIDhweCI+TG9hZGluZ+KApjwvcD4KICAgICAgICAgIDxpbnB1dCBpZD0idGdUb2tlbiIgdHlwZT0icGFzc3dvcmQiIGF1dG9jb21wbGV0ZT0ib2ZmIiBhdXRvY2FwaXRhbGl6ZT0ib2ZmIiBzcGVsbGNoZWNrPSJmYWxzZSIgcGxhY2Vob2xkZXI9IlBhc3RlIHlvdXIgYm90IHRva2VuIGZyb20gQEJvdEZhdGhlciIgc3R5bGU9IndpZHRoOjEwMCU7YmFja2dyb3VuZDojMDcxMDFFO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHg7Zm9udDo2MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1pbmspIj4KICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbi10b3A6OHB4Ij48YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9InRnU2F2ZSIgdHlwZT0iYnV0dG9uIj5TYXZlIGJvdCB0b2tlbjwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biBwcmkiIGlkPSJ0Z0NvZGVCdG4iIHR5cGU9ImJ1dHRvbiI+TWFrZSBhIHBhaXJpbmcgY29kZTwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InRnVGVzdCIgdHlwZT0iYnV0dG9uIj5TZW5kIGEgdGVzdCBtZXNzYWdlPC9idXR0b24+PGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0idGdVbnBhaXIiIHR5cGU9ImJ1dHRvbiI+VW5wYWlyIHBob25lczwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biB3YXJuIiBpZD0idGdSZW1vdmUiIHR5cGU9ImJ1dHRvbiI+UmVtb3ZlIGJvdDwvYnV0dG9uPjwvZGl2PgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJ0Z0NvZGUiIGhpZGRlbj48L3A+PHAgY2xhc3M9Im5vdGUiIGlkPSJ0Z01zZyI+PC9wPgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiPlNlY3JldHMgYXJlIGtlcHQgb25seSBvbiB5b3VyIHNlcnZlcidzIGRpc2sgYW5kIGFyZSBuZXZlciBzaG93biBhZ2FpbiBhZnRlciB5b3Ugc2F2ZSB0aGVtLiBUaGUgYm90IHRhbGtzIG9ubHkgdG8gcGhvbmVzIHlvdSBwYWlyIHdpdGggYSBvbmUtdGltZSBjb2RlLjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwgb3duIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPvCfkrUgTW92ZSBtb25leSA8c3Bhbj52YXVsdCDihpIgdHJhZGluZyBjYXNoPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj4KICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2ZsZXgtd3JhcDp3cmFwO2FsaWduLWl0ZW1zOmNlbnRlciI+PGlucHV0IGlkPSJ2MmNBbXQiIHR5cGU9Im51bWJlciIgc3RlcD0iYW55IiBpbnB1dG1vZGU9ImRlY2ltYWwiIHBsYWNlaG9sZGVyPSJBbW91bnQgKCQpIiBzdHlsZT0iZmxleDoxIDEgMTIwcHg7YmFja2dyb3VuZDojMDcxMDFFO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHg7Zm9udDo3MDAgMTRweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1pbmspIj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIG1pbnQiIGlkPSJ2MmMiIHR5cGU9ImJ1dHRvbiI+TW92ZSB0byB0cmFkaW5nIGNhc2g8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJ2MmNBbGwiIHR5cGU9ImJ1dHRvbiI+TW92ZSBhbGw8L2J1dHRvbj48L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJub3RlIiBpZD0idjJjTXNnIj5Mb2NrZWQgcHJvZml0IGNvbWVzIGJhY2sgaW50byB0aGUgdHJhZGluZyBwb3QsIHNvIGl0IGNhbiB3b3JrIGFnYWluLiAoUGFwZXIgbW9uZXk6IG5vdGhpbmcgcmVhbCBtb3Zlcy4pPC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCBvd24iIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+U2F2aW5ncyB3YWxsZXQgPHNwYW4+d2hlcmUgeW91ciBwcm9maXQgZ29lczwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiI+CiAgICAgICAgICA8bGFiZWwgY2xhc3M9InNldCIgc3R5bGU9ImRpc3BsYXk6YmxvY2siPjxzcGFuIHN0eWxlPSJmb250OjcwMCAxMXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCkiPllvdXIgc2F2aW5ncyB3YWxsZXQgYWRkcmVzczwvc3Bhbj4KICAgICAgICAgICAgPGlucHV0IGlkPSJzYXZ3IiB0eXBlPSJ0ZXh0IiBhdXRvY29tcGxldGU9Im9mZiIgYXV0b2NhcGl0YWxpemU9Im9mZiIgc3BlbGxjaGVjaz0iZmFsc2UiIHN0eWxlPSJkaXNwbGF5OmJsb2NrO3dpZHRoOjEwMCU7bWFyZ2luLXRvcDo0cHg7YmFja2dyb3VuZDojMDcxMDFFO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHg7Zm9udDo2MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1pbmspIj48L2xhYmVsPgogICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7ZmxleC13cmFwOndyYXA7bWFyZ2luLXRvcDoxMHB4Ij4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIG1pbnQiIGlkPSJzYXZTYXZlIiB0eXBlPSJidXR0b24iPlNhdmUgd2FsbGV0PC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBwcmkiIGlkPSJzZW5kTm93IiB0eXBlPSJidXR0b24iPlNlbmQgdmF1bHQgdG8gbXkgd2FsbGV0IG5vdzwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSI+V2l0aCAiYXV0by1zZW5kIiBvbiAoaW4gUnVsZXMpLCBldmVyeSB0aW1lIHByb2ZpdCBnZXRzIGxvY2tlZCBpdCBnb2VzIHN0cmFpZ2h0IHRvIHRoaXMgd2FsbGV0LiBJbiBwYXBlciBtb2RlIGl0J3MgcmVjb3JkZWQsIG5vdCBzZW50OyBpbiBsaXZlIG1vZGUgaXQncyBhIHJlYWwgdHJhbnNmZXIuPC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5Nb25leSBtb3ZlcyA8c3Bhbj52YXVsdCBsb2Nrcywgc2F2aW5ncywgcGF1c2VzLCBzdG9wczwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImV2ZW50cyI+PHAgY2xhc3M9ImVtcHR5Ij5Ob3RoaW5nIHlldC48L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIG93biIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5BdXRvcGlsb3QgPHNwYW4+b25lIHRhcCBzZXRzIHRoZSB3aG9sZSBzdHJhdGVneTwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiI+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDtmbGV4LXdyYXA6d3JhcCI+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgZGF0YS1wcmVzZXQ9ImRlZmVuc2UiIHR5cGU9ImJ1dHRvbiI+8J+boSBEZWZlbnNlPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBkYXRhLXByZXNldD0iYmFsYW5jZWQiIHR5cGU9ImJ1dHRvbiI+4pqWIEJhbGFuY2VkPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgZGF0YS1wcmVzZXQ9Im9mZmVuc2UiIHR5cGU9ImJ1dHRvbiI+4pqUIE9mZmVuc2U8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJwcmVzZXROb3RlIj48Yj5EZWZlbnNlOjwvYj4gc21hbGxlciByaXNrLiBUYWtlcyBwcm9maXQgZWFybGllciwgc3RvcHMgc29vbmVyLCBwYXVzZXMgZmFzdGVyLCBza2lwcyB0aGUgcmlza2llc3QgZWFybHkgYnV5cy4gPGI+QmFsYW5jZWQ6PC9iPiB0aGUgZGVmYXVsdC4gPGI+T2ZmZW5zZTo8L2I+IGJpZ2dlciBzd2luZ3MsIGxldHMgd2lubmVycyBydW4gbG9uZ2VyLiBOb25lIG9mIHRoZXNlIGNhbiByZW1vdmUgbG9zc2VzOyBEZWZlbnNlIGp1c3Qga2VlcHMgdGhlbSBzbWFsbGVyLjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+UnVsZXMgPHNwYW4+Y2hhbmdlIGFueXRpbWUsIGFwcGxpZXMgdG8gdGhlIG5leHQgbGF1bmNoPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj4KICAgICAgICAgIDxkaXYgY2xhc3M9InNldCIgaWQ9InNldCI+PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJvd24iIHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tdG9wOjEycHgiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9InNhdmUiIHR5cGU9ImJ1dHRvbiI+U2F2ZSBydWxlczwvYnV0dG9uPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gd2FybiIgaWQ9InJlc2V0IiB0eXBlPSJidXR0b24iPlJlc2V0IHBhcGVyIHJlc3VsdHM8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiPlBhcGVyIG1vZGU6IEFMS0FJRCB3YXRjaGVzIGV2ZXJ5IG5ldyBwdW1wLmZ1biBsYXVuY2gsIHdhaXRzLCBydW5zIHRoZSBmaWx0ZXJzLCBhbmQgcHJldGVuZHMgdG8gYnV5IHRoZSBvbmVzIHRoYXQgcGFzcy4gRWFjaCBiZXQgaXMgYSBzbGljZSBvZiB0aGUgdHJhZGluZyBiYWxhbmNlLCBzbyBiZXRzIGdyb3cgYXMgaXQgd2lucyBhbmQgc2hyaW5rIGFzIGl0IGxvc2VzLiBXaGVuIHRoZSBiYWxhbmNlIGhpdHMgeW91ciBsb2NrIHRhcmdldCwgdGhlIHByb2ZpdCBtb3ZlcyB0byB0aGUgdmF1bHQgYW5kIGlzIG5ldmVyIHRyYWRlZCBhZ2Fpbi4gQSBiYWQgZGF5IG9yIGEgbG9zaW5nIHN0cmVhayBwYXVzZXMgaXQuIFJlc3VsdHMgaW5jbHVkZSB0aGUgcHVtcC5mdW4gZmVlLCBwcmlvcml0eSBmZWUsIEppdG8gdGlwIGFuZCBzbGlwcGFnZSwgc28gdGhleSdyZSBob25lc3QuIE5vIGtleSBpcyBzdG9yZWQgYW5kIG5vdGhpbmcgaXMgZXZlciBzZW50LiBMaXZlIG1vZGUgY29tZXMgb25seSBhZnRlciBwYXBlciByZXN1bHRzIHByb3ZlIHRoZSBydWxlcy48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgIDwvZGl2PgogIDwvbWFpbj4KCiAgPGZvb3Rlcj5BTEtBSUQgwrcgcHJpdmF0ZSDCtyBidWlsdCBvbiBTTEFQQk9UJ3Mgc2NhbSBjaGVja3M8L2Zvb3Rlcj4KPC9kaXY+Cgo8c2NyaXB0PgooZnVuY3Rpb24oKXsKICB2YXIgQVBJPSgvZ2l0aHViXC5pbyQvLnRlc3QobG9jYXRpb24uaG9zdG5hbWUpfHxsb2NhdGlvbi5wcm90b2NvbD09PSdmaWxlOicpPydodHRwczovL3NsYXBib3QtYmFja2VuZC1wcm9kdWN0aW9uLnVwLnJhaWx3YXkuYXBwJzpsb2NhdGlvbi5vcmlnaW47CiAgdmFyICQ9ZnVuY3Rpb24oaWQpe3JldHVybiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCl9OwogIHZhciBwYXNzPW51bGwsdGltZXI9bnVsbCxzdGF0ZT1udWxsOwogIHZhciBGSUVMRFM9W1snc3RhcnRVc2QnLCdTdGFydGluZyBiYW5rcm9sbCAoJCknXSxbJ3Nsb3RzJywnU25pcGVzIGF0IG9uY2UgKG1vbmV5IHNwbGl0IGV2ZW5seSwgMCA9IG9mZiknXSxbJ3Jpc2tQY3QnLCdCZXQgc2l6ZSAlIChvbmx5IHdoZW4gc25pcGVzLWF0LW9uY2UgaXMgMCknXSxbJ21pblRyYWRlVXNkJywnU21hbGxlc3QgYmV0ICgkKSddLFsnbWF4TG9zc1BjdCcsJ01heCBsb3NzIHBlciBzbmlwZSAoJSBvZiBBTEwgeW91ciBtb25leSwgMCA9IG9mZiknXSwKICAgIFsndmF1bHRBdFgnLCdMb2NrIHByb2ZpdHMgd2hlbiBiYWxhbmNlIGhpdHMgKMOXIHN0YXJ0KSddLFsna2VlcFgnLCdLZWVwIHRyYWRpbmcgKMOXIHN0YXJ0KSBhZnRlciBsb2NraW5nJ10sWydkYWlseVN0b3BQY3QnLCdTdG9wIGZvciB0aGUgZGF5IGlmIGRvd24gKCUpJ10sCiAgICBbJ21heExvc3NTdHJlYWsnLCdQYXVzZSBhZnRlciB0aGlzIG1hbnkgbG9zc2VzIGluIGEgcm93J10sWydwYXVzZU1pbicsJ1BhdXNlIGxlbmd0aCAobWludXRlcyknXSxbJ2xlYXJuJywnTGVhcm4gZnJvbSByZXN1bHRzICgxID0gb24sIDAgPSBvZmYpJ10sWydsZWFybk1pbicsJ1RyYWRlcyBuZWVkZWQgYmVmb3JlIGp1ZGdpbmcgYSBzZXR1cCddLAogICAgWyd0cDFTZWxsUGN0JywnQXQgdGFrZSBwcm9maXQsIHNlbGwgdGhpcyAlIChyZXN0IHJpZGVzKSddLFsndHJhaWxQY3QnLCdBZnRlciArMTAwJTogcmlkaW5nIHBhcnQgc2VsbHMgaWYgaXQgZHJvcHMgdGhpcyAlIGZyb20gaXRzIGhpZ2gnXSxbJ21vb25Ib2xkTWluJywnUmlkaW5nIHBhcnQgbWF4IGhvbGQgKG1pbnV0ZXMpJ10sCiAgICBbJ3NtYXJ0Qm9vc3QnLCdCZXQgbXVsdGlwbGllciB3aGVuIHNtYXJ0IG1vbmV5IGlzIGluJ10sWydmYXZvckJvb3N0JywnQmV0IG11bHRpcGxpZXIgb24gd2lubmluZyBzZXR1cHMnXSxbJ21heEJldFBjdCcsJ01heCBiZXQgKCUgb2YgdHJhZGluZyBiYWxhbmNlKSddLAogICAgWydkZXZFeGl0JywnRXhpdCBpbnN0YW50bHkgaWYgY3JlYXRvciBkdW1wcyAoMSA9IG9uKSddLFsnY2FzaE91dE1jYXAnLCdSdWcgem9uZTogc2VsbCBldmVyeXRoaW5nIGF0IHRoaXMgbWFya2V0IGNhcCAoJCwgMCA9IG9mZiknXSxbJ2dyYWRPbicsJ0dyYWR1YXRlczogYnV5IGFmdGVyIGdyYWR1YXRpb24gKDEgPSBvbiknXSxbJ2dyYWRNaW5MaXEnLCdHcmFkdWF0ZXM6IG1pbiBsaXF1aWRpdHkgKCQpJ10sWydncmFkTWluTWNhcCcsJ0dyYWR1YXRlczogbWluIG1hcmtldCBjYXAgKCQpJ10sWydncmFkTWF4TWNhcCcsJ0dyYWR1YXRlczogbWF4IG1hcmtldCBjYXAgKCQpJ10sWydncmFkQnV5czUnLCdHcmFkdWF0ZXM6IG1pbiBidXlzIGluIDUgbWluJ10sWydncmFkQnV5U2hhcmUnLCdHcmFkdWF0ZXM6IG1pbiBidXkgJSddLFsnZ3JhZE1pbkNoNScsJ0dyYWR1YXRlczogbWluIDUtbWluIGNoYW5nZSAlJ10sWydncmFkTWF4Q2g1JywnR3JhZHVhdGVzOiBtYXggNS1taW4gY2hhbmdlICUgKG5vdCBjaGFzaW5nKSddLFsnZ3JhZE1heE9wZW4nLCdHcmFkdWF0ZXM6IG1heCBvcGVuIGF0IG9uY2UnXSxbJ2dyYWRUcCcsJ0dyYWR1YXRlczogdGFrZSBwcm9maXQgJSddLFsnZ3JhZFRwMVNlbGwnLCdHcmFkdWF0ZXM6IHNlbGwgdGhpcyAlIHRoZXJlJ10sWydncmFkU2wnLCdHcmFkdWF0ZXM6IHN0b3AgbG9zcyAlJ10sWydncmFkVHJhaWwnLCdHcmFkdWF0ZXM6IHRyYWlsaW5nIHN0b3AgJSddLFsnZ3JhZEhvbGQnLCdHcmFkdWF0ZXM6IG1heCBob2xkIChtaW4pJ10sCiAgICBbJ2NvcHlPbicsJ0NvcHkgdHJhZGluZyAoMSA9IG9uKSddLFsnY29weVRvcE4nLCdDb3B5OiBmb2xsb3cgdGhlIHRvcCBOIHdhbGxldHMnXSxbJ2NvcHlNaW5Vc2QnLCdDb3B5OiB0aGVpciBidXkgbXVzdCBiZSBhdCBsZWFzdCAoJCknXSxbJ2NvcHlNaW5XYWxsZXRzJywnQ29weTogc21hcnQgd2FsbGV0cyBuZWVkZWQnXSxbJ2NvcHlNYXhPcGVuJywnQ29weTogbWF4IG9wZW4gYXQgb25jZSddLFsnY29weVRwJywnQ29weTogdGFrZSBwcm9maXQgJSddLFsnY29weVNsJywnQ29weTogc3RvcCBsb3NzICUnXSxbJ2NvcHlUcmFpbCcsJ0NvcHk6IHRyYWlsaW5nIHN0b3AgJSddLFsnY29weUhvbGQnLCdDb3B5OiBtYXggaG9sZCAobWluKSddLAogICAgWydncmlkT24nLCdHcmlkIHRyYWRpbmcgKDEgPSBvbiknXSxbJ2dyaWRTdGFydFVzZCcsJ0dyaWQ6IHBhcGVyIHBvb2wgKCQpJ10sWydncmlkTWF4JywnR3JpZDogdG9rZW5zIGF0IG9uY2UnXSxbJ2dyaWRMZXZlbHMnLCdHcmlkOiBkaXAgbGV2ZWxzJ10sWydncmlkU3RlcFBjdCcsJ0dyaWQ6IHN0ZXAgJSddLFsnZ3JpZE1pbkxpcScsJ0dyaWQ6IG1pbiBsaXF1aWRpdHkgKCQpJ10sCiAgICBbJ2F1dG9waWxvdCcsJ0F1dG9waWxvdDogcHJvdGVjdHMgdGhlIGFjY291bnQgYnkgaXRzZWxmICgxID0gb24pJ10sWydhdXRvU2xvdHMnLCdBdXRvcGlsb3Q6IGZld2VyLCBiaWdnZXIgYmV0cyBhcyB0aGUgYmFsYW5jZSBzaHJpbmtzICgxID0gb24pJ10sWydkZEJyYWtlMVBjdCcsJ0F1dG9waWxvdDogZG93biB0aGlzICUgZnJvbSB0aGUgcGVhaywgc3dpdGNoIHRvIHNhZmVzdCBzZXR0aW5ncyddLFsnZGRCcmFrZTJQY3QnLCdBdXRvcGlsb3Q6IGRvd24gdGhpcyAlLCBhbHNvIHBhdXNlIG5ldyB0cmFkZXMgOCBob3VycyddLFsna2lsbEF2Z1BjdCcsJ0F1dG9waWxvdDogc3dpdGNoIG9mZiBhbiBlbnRyeSB0eXBlIGF2ZXJhZ2luZyB3b3JzZSB0aGFuIHRoaXMgJSBwZXIgdHJhZGUnXSxbJ2tpbGxNaW5UcmFkZXMnLCdBdXRvcGlsb3Q6IC4uLm92ZXIgYXQgbGVhc3QgdGhpcyBtYW55IHRyYWRlcyddLFsnbGFkZGVyT24nLCdTdGFnZWQgZXhpdHM6ICsyMCUgLyArMzUlIC8gKzYwJSwgMjUlIGVhY2gsIHRoZW4gdHJhaWwgdGhlIHJlc3QgKDEgPSBvbiknXSxbJ2dyYWRNaW5MaXFQY3QnLCdHcmFkdWF0ZXM6IGxpcXVpZGl0eSBhdCBsZWFzdCB0aGlzICUgb2YgbWFya2V0IGNhcCddLFsnZ3JhZE1pblZvbDI0JywnR3JhZHVhdGVzOiAyNC1ob3VyIHZvbHVtZSBhdCBsZWFzdCAoJCknXSxbJ2dyYWRNYXhJbXBhY3QnLCdHcmFkdWF0ZXM6IHNlbGxpbmcgJDEwMCBtdXN0IG1vdmUgcHJpY2UgbGVzcyB0aGFuIHRoaXMgJSddLFsnbW9tZW50dW0nLCdNb21lbnR1bSBlbnRyeTogYnV5IG9ubHkgd2hlbiByZWFsIGJ1eWluZyBzaG93cyB1cCAoMSA9IG9uKSddLFsnbW9tV2luZG93TWluJywnTW9tZW50dW06IHdhdGNoIGVhY2ggbGF1bmNoIHRoaXMgbWFueSBtaW51dGVzJ10sWydtb21CdXllcnM2MCcsJ01vbWVudHVtOiBkaWZmZXJlbnQgYnV5ZXJzIGluIHRoZSBsYXN0IG1pbnV0ZSddLFsnbW9tQnV5U2hhcmUnLCdNb21lbnR1bTogYnV5cyBhdCBsZWFzdCB0aGlzICUgb2YgdHJhZGVzJ10sWydtb21OZXRTb2wnLCdNb21lbnR1bTogU09MIGZsb3dpbmcgaW4sIGxhc3QgbWludXRlJ10sWydtb21SaXNlMm0nLCdNb21lbnR1bTogcHJpY2UgdXAgYXQgbGVhc3QgdGhpcyAlIGluIDIgbWluJ10sWydtb21NYXhNY2FwJywnTW9tZW50dW06IHRvbyBsYXRlIGFib3ZlIHRoaXMgbWFya2V0IGNhcCAoJCknXSxbJ2F1dG9UdW5lJywnQXV0by10dW5lOiBhZG9wdCB0aGUgU3dlZXQgU3BvdCBldmVyeSA2IGggd2hlbiBpdCBwcm92ZXMgYmV0dGVyICgxID0gb24pJ10sWydsYWJGaWx0ZXInLCdXaW5uZXIgTGFiOiBza2lwIGxhdW5jaGVzIGJlbG93IHRoZSBsaW5lICgxID0gb24pJ10sWydsYWJNaW5MaWZ0JywnV2lubmVyIExhYjogdGhlIGxpbmUgKDEgPSBhbiBhdmVyYWdlIGxhdW5jaCknXSxbJ2xhYkJvb3N0JywnV2lubmVyIExhYjogYmV0IG11bHRpcGxpZXIgd2hlbiBpdCBzY29yZXMgMi41w5crJ10sWyd0cmFpbEF0NXgnLCdUaWdodGVyIHdpbmRvdyBvbmNlIHVwIDXDlyAoJSknXSxbJ3RyYWlsQXQxMHgnLCdUaWdodGVzdCB3aW5kb3cgb25jZSB1cCAxMMOXICglKSddLFsnYXV0b1NlbmQnLCdBdXRvLXNlbmQgbG9ja2VkIHByb2ZpdCB0byBzYXZpbmdzICgxID0gb24pJ10sCiAgICBbJ2Zhc3RMYW5lJywnTGF1bmNoIFNob3Q6IGZpcmUgYXQgbGF1bmNoICgxID0gb24pJ10sWydmYXN0TWF4TWNhcCcsJ0xhdW5jaCBTaG90OiBvbmx5IHVuZGVyIHRoaXMgbWFya2V0IGNhcCAoJCknXSxbJ2Zhc3RCZXRQY3QnLCdMYXVuY2ggU2hvdCBiZXQgKCUgb2YgYmFsYW5jZSknXSwKICAgIFsnZmFzdE1heFBlck1pbicsJ0xhdW5jaCBTaG90OiBtYXggYnV5cyBwZXIgbWludXRlJ10sWydmYXN0TWF4T3BlbicsJ0xhdW5jaCBTaG90OiBtYXggb3BlbiBhdCBvbmNlJ10sWydmYXN0TWF4RGV2UGN0JywnTGF1bmNoIFNob3Q6IHNraXAgaWYgY3JlYXRvciBib3VnaHQgb3ZlciAoJSknXSwKICAgIFsnZmFzdFRpbWVvdXRTZWMnLCdMYXVuY2ggU2hvdDogbXVzdCBsaWZ0IG9mZiB3aXRoaW4gKHNlYyknXSxbJ2Zhc3RNaW5HYWluUGN0JywnTGF1bmNoIFNob3Q6IGxpZnQtb2ZmIG1lYW5zIHVwIGF0IGxlYXN0ICglKSddLFsnd2FpdFNlYycsJ1dhaXQgYmVmb3JlIGp1ZGdpbmcgKHNlYyknXSxbJ21pblByb2dyZXNzJywnTWluICUgYm9uZGVkIGJ5IHRoZW4nXSxbJ21heERldlBjdCcsJ01heCBjcmVhdG9yIGhvbGRpbmcgJSddLAogICAgWydtYXhUb3AxMFBjdCcsJ01heCB0b3AtMTAgd2FsbGV0cyAlJ10sWydtYXhUb3AxUGN0JywnTWF4IHNpbmdsZSB3YWxsZXQgJSddLFsndHBQY3QnLCdUYWtlIHByb2ZpdCAlJ10sWydzbFBjdCcsJ1N0b3AgbG9zcyAlJ10sCiAgICBbJ21heEhvbGRNaW4nLCdNYXggaG9sZCAobWludXRlcyknXSxbJ21heE9wZW4nLCdNYXggb3BlbiBwb3NpdGlvbnMnXSxbJ21heEV2YWxQZXJNaW4nLCdMYXVuY2hlcyBqdWRnZWQgcGVyIG1pbnV0ZSddXTsKICBmdW5jdGlvbiBlc2Mocyl7cmV0dXJuIFN0cmluZyhzPT1udWxsPycnOnMpLnJlcGxhY2UoL1smPD4iJ10vZyxmdW5jdGlvbihjKXtyZXR1cm57JyYnOicmYW1wOycsJzwnOicmbHQ7JywnPic6JyZndDsnLCciJzonJnF1b3Q7JywiJyI6JyYjMzk7J31bY119KX0KICBmdW5jdGlvbiBhcGkocCxvcHQpe29wdD1vcHR8fHt9O29wdC5oZWFkZXJzPXsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbicsQXV0aG9yaXphdGlvbjonQmVhcmVyICcrcGFzc307CiAgICByZXR1cm4gZmV0Y2goQVBJK3Asb3B0KS50aGVuKGZ1bmN0aW9uKHIpe3JldHVybiByLmpzb24oKS5jYXRjaChmdW5jdGlvbigpe3JldHVybnt9fSkudGhlbihmdW5jdGlvbihqKXtqLl9zPXIuc3RhdHVzO3JldHVybiBqfSl9KX0KICBmdW5jdGlvbiBhZ28odCl7dmFyIHM9TWF0aC5tYXgoMCxNYXRoLnJvdW5kKChEYXRlLm5vdygpLXQpLzEwMDApKTtyZXR1cm4gczw2MD9zKydzJzpzPDM2MDA/TWF0aC5yb3VuZChzLzYwKSsnbSc6TWF0aC5yb3VuZChzLzM2MDApKydoJ30KICBmdW5jdGlvbiBzY2FuKG0sc3ltKXtyZXR1cm4gJzxhIGhyZWY9Imh0dHBzOi8vY3J5cHRvYml6bW8yLmdpdGh1Yi5pby9TTEFQQk9ULz9zY2FuPScrZW5jb2RlVVJJQ29tcG9uZW50KG0pKyciPicrZXNjKHN5bXx8Jz8nKSsnPC9hPid9CiAgZnVuY3Rpb24gdG9rKG0sc3ltLG5hbWUpe3JldHVybiBzY2FuKG0sc3ltKSsobmFtZSYmbmFtZSE9PXN5bT8nPHNwYW4gY2xhc3M9InRva24iPicrZXNjKG5hbWUpKyc8L3NwYW4+JzonJyl9CiAgZnVuY3Rpb24gY2FMaW5lKG0pe3JldHVybiBtPyc8ZGl2IGNsYXNzPSJjYSI+PGNvZGU+Jytlc2MobSkrJzwvY29kZT48YnV0dG9uIHR5cGU9ImJ1dHRvbiIgZGF0YS1jb3B5PSInK2VzYyhtKSsnIj5Db3B5PC9idXR0b24+PGEgdGFyZ2V0PSJfYmxhbmsiIHJlbD0ibm9vcGVuZXIiIGhyZWY9Imh0dHBzOi8vZGV4c2NyZWVuZXIuY29tL3NvbGFuYS8nK2VuY29kZVVSSUNvbXBvbmVudChtKSsnIj5DaGFydDwvYT48L2Rpdj4nOicnfQogIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJyxmdW5jdGlvbihlKXt2YXIgYj1lLnRhcmdldC5jbG9zZXN0KCdbZGF0YS1jb3B5XScpO2lmKCFiKXJldHVybjsKICAgIChuYXZpZ2F0b3IuY2xpcGJvYXJkP25hdmlnYXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KGIuZGF0YXNldC5jb3B5KTpQcm9taXNlLnJlamVjdCgpKS50aGVuKGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nQ29waWVkJztzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nQ29weSd9LDEyMDApfSxmdW5jdGlvbigpe2IudGV4dENvbnRlbnQ9J0hvbGQgdG8gY29weSd9KX0pOwogIGZ1bmN0aW9uIHNvbChuKXtyZXR1cm4gKG4+PTA/JysnOicnKSsoK24pLnRvRml4ZWQoNCkrJyBTT0wnfQoKICB2YXIgcm9sZT0nb3duZXInOwogIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdjYW5ub25WaWV3Jyk7ICAgICAgICAgICAgICAgICAgICAgIC8vIGFueSBvbGQgZ3Vlc3QgcGFzcyBpcyBlcmFzZWQ6IHRoZXJlIGFyZSBubyBndWVzdHMKICAoZnVuY3Rpb24oKXt2YXIgc2F2ZWQ9bnVsbDt0cnl7c2F2ZWQ9SlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnbXBTZXNzaW9uJyl8fCdudWxsJyl9Y2F0Y2goZSl7fQogICAgaWYoc2F2ZWQmJnNhdmVkLmV4cD5EYXRlLm5vdygpKXtwYXNzPXNhdmVkLnBhc3M7c3RhcnQoKX19KSgpOwogIGZ1bmN0aW9uIGtlZXAocil7CiAgICB2YXIgbGlmZT1yLnJlbWVtYmVyZWQ/MjkuNSoyNCozNjAwZTM6MTEuNSozNjAwZTM7CiAgICBwYXNzPXIucGFzcztsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnbXBTZXNzaW9uJyxKU09OLnN0cmluZ2lmeSh7cGFzczpwYXNzLGV4cDpEYXRlLm5vdygpK2xpZmV9KSk7c3RhcnQoKTsKICB9CiAgLy8gc2hvdyAvIGhpZGUgd2hhdCB5b3UncmUgdHlwaW5nCiAgZnVuY3Rpb24gc2hvd0NvZGVGb3JtKCl7CiAgICBpZigkKCdjb2RlRm9ybScpKXJldHVybjsKICAgICQoJ2NvZGVTbG90JykuYXBwZW5kQ2hpbGQoZG9jdW1lbnQuaW1wb3J0Tm9kZSgkKCdjb2RlVHBsJykuY29udGVudCx0cnVlKSk7CiAgJCgnZXllJykub25jbGljaz1mdW5jdGlvbigpe3ZhciBjPSQoJ2NvZGUnKSxzaG93PWMudHlwZT09PSdwYXNzd29yZCc7Yy50eXBlPXNob3c/J3RleHQnOidwYXNzd29yZCc7dGhpcy50ZXh0Q29udGVudD1zaG93PydIaWRlJzonU2hvdyc7dGhpcy5zZXRBdHRyaWJ1dGUoJ2FyaWEtbGFiZWwnLHNob3c/J0hpZGUgY29kZSc6J1Nob3cgY29kZScpO2MuZm9jdXMoKX07CiAgICAvLyBvd25lciBjb2RlIChhIHJlYWwgZm9ybSwgc28gaVBob25lIG9mZmVycyB0byBzYXZlIGl0IGluIFBhc3N3b3JkcykKICAgICQoJ2NvZGVGb3JtJykub25zdWJtaXQ9YXN5bmMgZnVuY3Rpb24oZSl7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTt2YXIgYz0kKCdjb2RlJykudmFsdWU7aWYoIWMpcmV0dXJuIGZhbHNlO3ZhciBiPSQoJ2dvJyk7Yi5kaXNhYmxlZD10cnVlOyQoJ2dtc2cnKS50ZXh0Q29udGVudD0nJzsKICAgICAgdmFyIHI9YXdhaXQgZmV0Y2goQVBJKycvYXBpL2F1dGgvb3duZXInLHttZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sYm9keTpKU09OLnN0cmluZ2lmeSh7Y29kZTpjLHJlbWVtYmVyOiQoJ3JlbWVtYmVyJykuY2hlY2tlZH0pfSkudGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29uKCl9KS5jYXRjaChmdW5jdGlvbigpe3JldHVybnt9fSk7CiAgICAgIGIuZGlzYWJsZWQ9ZmFsc2U7CiAgICAgIGlmKCFyLnBhc3MpeyQoJ2dtc2cnKS50ZXh0Q29udGVudD1yLmVycm9yfHwnV3JvbmcgY29kZS4nO3JldHVybiBmYWxzZX0KICAgICAga2VlcChyKTtyZXR1cm4gZmFsc2U7CiAgICB9OwogIH0KICBpZigvb3duZXIvLnRlc3QobG9jYXRpb24uaGFzaCkpeyQoJ293bmVyR2F0ZScpLmhpZGRlbj1mYWxzZTskKCdwcml2Tm90ZScpLmhpZGRlbj10cnVlO3Nob3dDb2RlRm9ybSgpfSAgIC8vIG93bmVyIHNpZ24taW4gbGl2ZXMgb25seSBhdCBjYW5ub24uaHRtbCNvd25lcgoKICAvLyB3YWxsZXQgc2lnbi1pbjogcHJvdmVzIHlvdSBvd24gdGhlIG93bmVyIHdhbGxldCwgbm8gY29kZSBuZWVkZWQKICBmdW5jdGlvbiBwcm92aWRlcigpe3JldHVybiAod2luZG93LnBoYW50b20mJndpbmRvdy5waGFudG9tLnNvbGFuYSl8fCh3aW5kb3cuc29sYW5hJiZ3aW5kb3cuc29sYW5hLmlzUGhhbnRvbT93aW5kb3cuc29sYW5hOm51bGwpfHx3aW5kb3cuc29sZmxhcmV8fG51bGx9CiAgaWYoIXByb3ZpZGVyKCkpe3ZhciB1PWxvY2F0aW9uLmhyZWY7JCgnb3BlblBoYW50b20nKS5ocmVmPSdodHRwczovL3BoYW50b20uYXBwL3VsL2Jyb3dzZS8nK2VuY29kZVVSSUNvbXBvbmVudCh1KSsnP3JlZj0nK2VuY29kZVVSSUNvbXBvbmVudChsb2NhdGlvbi5vcmlnaW4pOyQoJ29wZW5QaGFudG9tJykuaGlkZGVuPWZhbHNlOyQoJ3dub3RlJykudGV4dENvbnRlbnQ9J09uIGlQaG9uZSwgd2FsbGV0IHNpZ24taW4gd29ya3MgaW5zaWRlIHRoZSBQaGFudG9tIGFwcDogdGFwICJPcGVuIHRoaXMgcGFnZSBpbiBQaGFudG9tIi4nfQogICQoJ3dhbGxldCcpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXsKICAgIHZhciBwPXByb3ZpZGVyKCk7aWYoIXApeyQoJ2dtc2cnKS50ZXh0Q29udGVudD0nTm8gd2FsbGV0IGZvdW5kIGhlcmUuIFRhcCAiT3BlbiB0aGlzIHBhZ2UgaW4gUGhhbnRvbSIuJztyZXR1cm59CiAgICB2YXIgYj10aGlzO2IuZGlzYWJsZWQ9dHJ1ZTskKCdnbXNnJykudGV4dENvbnRlbnQ9Jyc7CiAgICB0cnl7CiAgICAgIHZhciB3PShhd2FpdCBwLmNvbm5lY3QoKSkucHVibGljS2V5LnRvU3RyaW5nKCk7CiAgICAgIHZhciBjaD1hd2FpdCBmZXRjaChBUEkrJy9hcGkvYXV0aC9jaGFsbGVuZ2U/d2FsbGV0PScrZW5jb2RlVVJJQ29tcG9uZW50KHcpKS50aGVuKGZ1bmN0aW9uKHIpe3JldHVybiByLmpzb24oKX0pLmNhdGNoKGZ1bmN0aW9uKCl7cmV0dXJuIHt9fSk7CiAgICAgIGlmKCFjaC5tZXNzYWdlKXRocm93IG5ldyBFcnJvcihjaC5lcnJvcnx8J1lvdXIgc2VydmVyIGRpZG5cJ3QgYW5zd2VyLCBzbyBzaWduLWluIGNhblwndCBzdGFydC4gVGhlIHdhbGxldCBpcyBmaW5lLiBUcnkgYWdhaW4gaW4gYSBtaW51dGUuJyk7CiAgICAgIHZhciBzaWc9YXdhaXQgcC5zaWduTWVzc2FnZShuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoY2gubWVzc2FnZSksJ3V0ZjgnKTsKICAgICAgdmFyIGJ5dGVzPXNpZy5zaWduYXR1cmV8fHNpZyxiaW49Jyc7Zm9yKHZhciBpPTA7aTxieXRlcy5sZW5ndGg7aSsrKWJpbis9U3RyaW5nLmZyb21DaGFyQ29kZShieXRlc1tpXSk7CiAgICAgIHZhciByPWF3YWl0IGZldGNoKEFQSSsnL2FwaS9hdXRoL3ZlcmlmeScse21ldGhvZDonUE9TVCcsaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nfSxib2R5OkpTT04uc3RyaW5naWZ5KHt3YWxsZXQ6dyxzaWduYXR1cmU6YnRvYShiaW4pLHJlbWVtYmVyOiQoJ3JlbWVtYmVyJykuY2hlY2tlZH0pfSkudGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29uKCl9KTsKICAgICAgdmFyIHNoPXcuc2xpY2UoMCw0KSsn4oCmJyt3LnNsaWNlKC00KTsKICAgICAgaWYoci5pc093bmVyPT09ZmFsc2V8fChyLnBhc3MmJiFyLmlzT3duZXIpKXskKCdnbXNnJykudGV4dENvbnRlbnQ9J1RoaXMgd2FsbGV0IGNhblwndCBvcGVuIHRoaXMgZGFzaGJvYXJkLic7Yi5kaXNhYmxlZD1mYWxzZTtyZXR1cm59CiAgICAgIGlmKCFyLnBhc3MpeyQoJ2dtc2cnKS50ZXh0Q29udGVudD0nVGhlIHNlcnZlciBkaWRuXCd0IGNvbmZpcm0gaXQuIFRyeSBhZ2FpbiBpbiBhIG1pbnV0ZS4nO2IuZGlzYWJsZWQ9ZmFsc2U7cmV0dXJufQogICAgICBrZWVwKHIpOwogICAgfWNhdGNoKGUpeyQoJ2dtc2cnKS50ZXh0Q29udGVudD0oZSYmZS5tZXNzYWdlKXx8J1dhbGxldCBzaWduLWluIHdhcyBjYW5jZWxsZWQuJztiLmRpc2FibGVkPWZhbHNlfQogIH07CiAgJCgnb3V0Jykub25jbGljaz1mdW5jdGlvbigpe2xvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdtcFNlc3Npb24nKTtsb2NhdGlvbi5yZWxvYWQoKX07CgogIGZ1bmN0aW9uIHN0YXJ0KCl7JCgnZ2F0ZScpLmhpZGRlbj10cnVlOyQoJ2FwcCcpLmhpZGRlbj1mYWxzZTtsb2FkKCk7Y2xlYXJJbnRlcnZhbCh0aW1lcik7dGltZXI9c2V0SW50ZXJ2YWwobG9hZCw0MDAwKX0KICBhc3luYyBmdW5jdGlvbiBsb2FkKCl7CiAgICB2YXIgZD1hd2FpdCBhcGkoJy9hcGkvbXAvc3RhdGUnKTsKICAgIGlmKGQuX3M9PT00MDN8fGQuX3M9PT00MDEpewogICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnbXBTZXNzaW9uJyk7bG9jYXRpb24ucmVsb2FkKCk7cmV0dXJufQogICAgaWYoIWQuc2V0dGluZ3MpcmV0dXJuO3N0YXRlPWQ7CiAgICBpZihkb2N1bWVudC5oaWRkZW4pcmV0dXJuOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gbm9ib2R5IGlzIGxvb2tpbmc6IGRvbid0IHRvdWNoIHRoZSBwYWdlCiAgICBpZihlZGl0aW5nfHwoZG9jdW1lbnQuYWN0aXZlRWxlbWVudCYmL14oSU5QVVR8VEVYVEFSRUF8U0VMRUNUKSQvLnRlc3QoZG9jdW1lbnQuYWN0aXZlRWxlbWVudC50YWdOYW1lKSkpcmV0dXJuOyAgIC8vIG5ldmVyIG1vdmUgdGhpbmdzIHdoaWxlIHlvdSB0eXBlIG9yIGVkaXQgc2V0dGluZ3MKICAgIGtlZXBQbGFjZShmdW5jdGlvbigpe3JlbmRlcihkKX0pOwogIH0KICAvLyB3aGlsZSBhbnkgb2YgWU9VUiBzZXR0aW5ncyBwYW5lbHMgaXMgb24gc2NyZWVuLCB0aGUgbGl2ZSBudW1iZXJzIGhvbGQgc3RpbGwgc28gbm90aGluZyBqdW1wcyB1bmRlciB5b3VyIHRodW1iCiAgdmFyIGVkaXRpbmc9ZmFsc2UsdmlzUGFuZWxzPXt9OwogIGlmKCdJbnRlcnNlY3Rpb25PYnNlcnZlcicgaW4gd2luZG93KXt2YXIgaW89bmV3IEludGVyc2VjdGlvbk9ic2VydmVyKGZ1bmN0aW9uKGVzKXtlcy5mb3JFYWNoKGZ1bmN0aW9uKGUpe3Zpc1BhbmVsc1tlLnRhcmdldC5kYXRhc2V0LnBpZF09ZS5pc0ludGVyc2VjdGluZ30pO2VkaXRpbmc9T2JqZWN0LmtleXModmlzUGFuZWxzKS5zb21lKGZ1bmN0aW9uKGspe3JldHVybiB2aXNQYW5lbHNba119KX0se3RocmVzaG9sZDowLjAyfSk7CiAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdzZWN0aW9uLnBhbmVsLm93bicpLmZvckVhY2goZnVuY3Rpb24oZWwsaSl7ZWwuZGF0YXNldC5waWQ9J3AnK2k7aW8ub2JzZXJ2ZShlbCl9KX0KICAvLyB3aGVuIG51bWJlcnMgZG8gcmVmcmVzaCwga2VlcCB3aGF0ZXZlciB5b3Ugd2VyZSBsb29raW5nIGF0IGV4YWN0bHkgd2hlcmUgaXQgd2FzCiAgZnVuY3Rpb24ga2VlcFBsYWNlKGZuKXsKICAgIHZhciBhbmNob3I9bnVsbCx0b3A9MCxlbHM9ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnBhbmVsLC5jYXJkLC5iaycpOwogICAgZm9yKHZhciBpPTA7aTxlbHMubGVuZ3RoO2krKyl7dmFyIHI9ZWxzW2ldLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpO2lmKHIuYm90dG9tPjgwKXthbmNob3I9ZWxzW2ldO3RvcD1yLnRvcDticmVha319CiAgICBmbigpOwogICAgaWYoYW5jaG9yJiZkb2N1bWVudC5ib2R5LmNvbnRhaW5zKGFuY2hvcikpe3ZhciBudD1hbmNob3IuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCkudG9wO2lmKE1hdGguYWJzKG50LXRvcCk+MSl3aW5kb3cuc2Nyb2xsQnkoMCxudC10b3ApfQogIH0KICBmdW5jdGlvbiByZW5kZXIoZCl7CiAgICB2YXIgZj0kKCdmZWVkJyk7Zi5jbGFzc05hbWU9J2ZlZWQnKyhkLm9uJiZkLmZlZWQuY29ubmVjdGVkPycgb24nOicnKTtmLnF1ZXJ5U2VsZWN0b3IoJ3NwYW4nKS50ZXh0Q29udGVudD0hZC5vbj8ncGF1c2VkJzpkLmZlZWQuY29ubmVjdGVkPygnbGl2ZSDCtyBwdW1wLmZ1bicrKGQuZmVlZC5sYXN0RXZlbnRBdD8nIMK3IGxhc3QgbGF1bmNoICcrYWdvKGQuZmVlZC5sYXN0RXZlbnRBdCkrJyBhZ28gwrcgJysoZC5mZWVkLnBlck1pbnx8MCkrJy9taW4nOicnKSk6J2Nvbm5lY3RpbmfigKYnOwogICAgJCgncHVsc2UnKS50ZXh0Q29udGVudD1kLmZlZWQubGFzdEV2ZW50QXQ/J2xhc3QgbGF1bmNoICcrYWdvKGQuZmVlZC5sYXN0RXZlbnRBdCkrJyBhZ28gwrcgJysoZC5mZWVkLnBlck1pbnx8MCkrJyBhIG1pbnV0ZSDCtyBQQVBFUiBtb25leSc6J3dhaXRpbmcgZm9yIHRoZSBmaXJzdCBsYXVuY2jigKYnOwogICAgdmFyIExCPWQubGFiOwogICAgaWYoTEIpewogICAgICAkKCdsYWJTdGF0JykudGV4dENvbnRlbnQ9TEIucmVhZHk/J+KchSBzdGVlcmluZyB0cmFkaW5nJzonbGVhcm5pbmc6ICcrTEIuZmluaXNoZWQrJyAvICcrTEIucmVhZHlBdCsnIGZpbmlzaGVkJzsKICAgICAgdmFyIHJvd3NXPShMQi53aW5uZXJzfHxbXSkubWFwKGZ1bmN0aW9uKHIpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKHIubGFiZWwpKyc8c21hbGw+JytyLndpbnMrJyBvZiAnK3IubisnIGJlY2FtZSB3aW5uZXJzPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyIHVwIj4nK3IubGlmdCsnw5c8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk7CiAgICAgIHZhciByb3dzQT0oTEIuYXZvaWR8fFtdKS5tYXAoZnVuY3Rpb24ocil7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+Jytlc2Moci5sYWJlbCkrJzxzbWFsbD4nK3Iud2lucysnIG9mICcrci5uKycgYmVjYW1lIHdpbm5lcnM8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgZG93biI+JytyLmxpZnQrJ8OXPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOwogICAgICB2YXIgaG90PShMQi5ob3R8fFtdKS5tYXAoZnVuY3Rpb24oeCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+Jyt0b2soeC5taW50LHguc3ltYm9sLHgubmFtZSkrJzwvZGl2PicrY2FMaW5lKHgubWludCkrJzxzbWFsbD4nK3gucHJvZ3Jlc3MrJyUgYm9uZGVkIMK3ICQnKyh4Lm1jYXA+PTEwMDA/KHgubWNhcC8xMDAwKS50b0ZpeGVkKDEpKydLJzp4Lm1jYXApKycgwrcgJysoeC5zb2NpYWw9PW51bGw/J3NvY2lhbHMgdW5rbm93bic6eC5zb2NpYWwrJyBzb2NpYWwgbGluaycrKHguc29jaWFsPT09MT8nJzoncycpKSsnIMK3ICcrYWdvKHguYXQpKycgb2xkPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyICcrKHgubGlmdD49MS41Pyd1cCc6eC5saWZ0PDAuNz8nZG93bic6J2FzaCcpKyciPicreC5saWZ0KyfDlzxzbWFsbD5+Jyt4Lm9kZHNQY3QrJyUgb2Rkczwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOwogICAgICAkKCdsYWInKS5pbm5lckhUTUw9CiAgICAgICAgJzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luOjAgMCA4cHgiPlN0dWRpZWQgPGI+JytMQi5jb2xsZWN0ZWQrJzwvYj4gbGF1bmNoZXMgwrcgPGI+JytMQi5maW5pc2hlZCsnPC9iPiBmaW5pc2hlZCDCtyA8Yj4nK0xCLndpbnMrJzwvYj4gd2lubmVycyAoJytMQi5ncmFkdWF0ZWQrJyBncmFkdWF0ZWQsICcrTEIudHJlbmRlZCsnIG1hZGUgdGhlIHRyZW5kaW5nIGxpc3QpIMK3IGEgcmFuZG9tIGxhdW5jaCB3aW5zIDxiPicrTEIuYmFzZWxpbmVQY3QrJyU8L2I+IG9mIHRoZSB0aW1lLiBBIHdpbm5lciA9IGdyYWR1YXRlZCwgdHJlbmRlZCwgb3IgcmVhY2hlZCBhICQxMDBLIG1hcmtldCBjYXAuPC9wPicrCiAgICAgICAgKExCLnN0YXJ0ZXI/JzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luOjAgMCAxMHB4O2NvbG9yOnZhcigtLWdvbGQpIj5TdGFydGluZyBndWVzc2VzIGZyb20gcHVibGlzaGVkIHJlc2VhcmNoIGFyZSBzaG93biB1bnRpbCBpdCBoYXMgJytMQi5yZWFkeUF0KycgZmluaXNoZWQgbGF1bmNoZXMgb2YgaXRzIG93bi4gSXQgZG9lcyBub3QgY2hhbmdlIHlvdXIgdHJhZGluZyB1bnRpbCB0aGVuLjwvcD4nOicnKSsKICAgICAgICAnPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxMHB4IDAgMnB4Ij7wn5SlIEhPVCBSSUdIVCBOT1cgwrcgc2NvcmVkIGF0IDkwIHNlY29uZHMsIGJlZm9yZSB0cmVuZGluZzwvZGl2PicrKGhvdHx8JzxwIGNsYXNzPSJlbXB0eSI+V2FpdGluZyBmb3Igc2NvcmVkIGxhdW5jaGVz4oCmPC9wPicpKwogICAgICAgICc8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjE0cHggMCAycHgiPuKchSBXSU5ORVJTIFRFTkQgVE8gSEFWRSDCtyB0aW1lcyBtb3JlIGxpa2VseSB0aGFuIGF2ZXJhZ2U8L2Rpdj4nKyhyb3dzV3x8JzxwIGNsYXNzPSJlbXB0eSI+Tm90IGVub3VnaCBmaW5pc2hlZCBsYXVuY2hlcyB5ZXQuIENoZWNrIGJhY2sgaW4gYSBmZXcgaG91cnMuPC9wPicpKwogICAgICAgICc8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjE0cHggMCAycHgiPuKblCBMT1NFUlMgVEVORCBUTyBIQVZFPC9kaXY+Jysocm93c0F8fCc8cCBjbGFzcz0iZW1wdHkiPk5vdCBlbm91Z2ggZmluaXNoZWQgbGF1bmNoZXMgeWV0LjwvcD4nKTsKICAgIH0KICAgIGlmKGQuYnVpbGQpJCgnYnVpbGRUYWcnKS50ZXh0Q29udGVudD0ncnVubmluZyB2ZXJzaW9uOiAnK2QuYnVpbGQ7CiAgICBidWlsZEp1bXAoKTsKICAgIHZhciBDVT1kLmN1c3RvZHk7CiAgICBpZihDVSl7JCgnY3VTdGF0JykudGV4dENvbnRlbnQ9J25vbi1jdXN0b2RpYWwnOwogICAgICAkKCdjdScpLmlubmVySFRNTD0nPGRpdiBjbGFzcz0icm93Ij48ZGl2PuKchSA8Yj5XYWxsZXQga2V5cyBvbiB0aGlzIHNlcnZlcjogbm9uZTwvYj48c21hbGw+VGhpcyBib3QgaGFzIG5vIGNvZGUgdGhhdCBjYW4gaG9sZCBhIHByaXZhdGUga2V5LCBzaWduIGEgdHJhbnNhY3Rpb24sIG9yIHNlbmQgb25lLiBJdCBjYW5ub3QgbW92ZSBtb25leSwgeW91cnMgb3IgYW55b25lXCdzLjwvc21hbGw+PC9kaXY+PC9kaXY+JysKICAgICAgICAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PuKchSA8Yj5SZWFsIG1vbmV5IG1vdmVkIGJ5IHRoZSBib3Q6ICQwPC9iPjxzbWFsbD5FdmVyeXRoaW5nIGlzIHBhcGVyLiBUaGUgc2lnbi1pbiB5b3UgdXNlIG9ubHkgcHJvdmVzIGl0XCdzIHlvdTsgaXQgc2VuZHMgbm90aGluZy48L3NtYWxsPjwvZGl2PjwvZGl2PicrCiAgICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PGRpdj7wn5SSIDxiPkxpdmUgdHJhZGluZzogbG9ja2VkPC9iPjxzbWFsbD5JdCBjYW5cJ3QgYmUgc3dpdGNoZWQgb24gZnJvbSB0aGlzIHNjcmVlbiBpbiB0aGlzIHZlcnNpb24uPC9zbWFsbD48L2Rpdj48L2Rpdj4nKwogICAgICAgICc8cCBjbGFzcz0ibm90ZSI+PGI+V2hlbiBsaXZlIHRyYWRpbmcgaXMgYWRkZWQ8L2I+IChvbmx5IGFmdGVyIHRoZSBSZWFkeS1mb3ItcmVhbC1tb25leSBzY29yZWNhcmQgcGFzc2VzKTogYSA8Yj5zZXBhcmF0ZSBzbWFsbCB0cmFkaW5nIHdhbGxldDwvYj4sIG5ldmVyIHlvdXIgbWFpbiBvbmUgwrcgZXZlcnl0aGluZyBpdCBlYXJucyBjYW4gZ28gPGI+b25seSB0byB5b3VyIHdhbGxldCAnK2VzYyhDVS5vd25lcikrJzwvYj4gwrcgYSBjYXAgcGVyIHRyYWRlIGFuZCBwZXIgZGF5IMK3IGEgc3dpdGNoIHRvIHR1cm4gaXQgb2ZmIMK3IGFuZCB5b3UgZGVjaWRlIHRoZSBhbW91bnQgaXQgZXZlciBob2xkcy4gPGI+TmV2ZXIgc2VuZCBhIHByaXZhdGUga2V5IG9yIHNlZWQgcGhyYXNlIHRvIGFueW9uZSwgaW5jbHVkaW5nIHRoaXMgYm90IG9yIG1lLjwvYj48L3A+J30KICAgIHZhciBBUHY9ZC5hdXRvcGlsb3Q7CiAgICBpZihBUHYpeyQoJ2FwU3RhdCcpLnRleHRDb250ZW50PUFQdi5wYXVzZWQ/J+KPuCAnK0FQdi5wYXVzZWQ6QVB2Lm9uPydvbiDCtyAnK0FQdi5kZFBjdCsnJSBiZWxvdyBpdHMgYmVzdCc6J29mZic7CiAgICAgICQoJ2FwJykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5BY2NvdW50IDxiPiQnK0FQdi5lcXVpdHkudG9GaXhlZCgyKSsnPC9iPiDCtyBiZXN0IHNvIGZhciA8Yj4kJytBUHYucGVhay50b0ZpeGVkKDIpKyc8L2I+IMK3IDxiIGNsYXNzPSInKyhBUHYuZGRQY3Q+PUFQdi5icmFrZTE/J2Rvd24nOidhc2gnKSsnIj4nK0FQdi5kZFBjdCsnJSBiZWxvdyBpdDwvYj4uIEF0IDxiPicrQVB2LmJyYWtlMSsnJTwvYj4gaXQgc3dpdGNoZXMgdG8gdGhlIHNhZmVzdCBzZXR0aW5nczsgYXQgPGI+JytBUHYuYnJha2UyKyclPC9iPiBpdCBhbHNvIHBhdXNlcyBuZXcgdHJhZGVzIGZvciA4IGhvdXJzLiBJZiB0aGUgYWNjb3VudCBnZXRzIG5lYXJseSBnb25lIGl0IHN0b3BzIHRyYWRpbmcgYW5kIHRlbGxzIHlvdS4gSXQgc3dpdGNoZXMgb2ZmIGFueSB3YXkgb2YgZW50ZXJpbmcgdGhhdCBpcyBsb3NpbmcsIGFuZCB1c2VzICcrKEFQdi5hdXRvU2xvdHM/J2Zld2VyLCBiaWdnZXIgYmV0cyBhcyB0aGUgYmFsYW5jZSBzaHJpbmtzICgnK2VzYyhBUHYuc2xvdHNOb3RlfHxBUHYuc2xvdHMrJyBhdCBhIHRpbWUnKSsnKSc6J3RoZSBiZXQgY291bnQgeW91IHNldCcpKycuPC9wPicrCiAgICAgICAgKEFQdi5sb2cubGVuZ3RoP0FQdi5sb2cubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKHgudGV4dCkrJzxzbWFsbD4nK2Fnbyh4LmF0KSsnIGFnbzwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPk5vdGhpbmcgbmVlZGVkIGNoYW5naW5nIHlldC4gV2hlbiBpdCBkb2VzIHNvbWV0aGluZywgaXQgc2hvd3MgdXAgaGVyZSBhbmQgb24geW91ciBwaG9uZS48L3A+JykrCiAgICAgICAgKChBUHYucnVucyYmQVB2LnJ1bnMubGVuZ3RoKT8nPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxNHB4IDAgMnB4Ij7wn5OaIFBBU1QgUlVOUzogV0hBVCBFQUNIIE9ORSBUQVVHSFQ8L2Rpdj4nK0FQdi5ydW5zLm1hcChmdW5jdGlvbihyKXt2YXIgdz1yLmJ5VHlwZSYmci5ieVR5cGVbMF0mJnIuYnlUeXBlWzBdLnBubFVzZDwwPycgwrcgd29yc3Q6ICcrZXNjKHIuYnlUeXBlWzBdLnR5cGUpKycgKCcrKHIuYnlUeXBlWzBdLnBubFVzZDwwPyfiiJIkJzonKyQnKStNYXRoLmFicyhyLmJ5VHlwZVswXS5wbmxVc2QpLnRvRml4ZWQoMikrJyknOicnO3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPiQnK3Iuc3RhcnQudG9GaXhlZCgyKSsnIOKGkiAkJytyLmVuZC50b0ZpeGVkKDIpKyc8L2Rpdj48c21hbGw+JytyLnRyYWRlcysnIHRyYWRlcyDCtyAnK3Iud2luUmF0ZSsnJSB3b24gwrcgJytyLmF2Z1BjdCsnJSBwZXIgdHJhZGUnK3crJzwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrYWdvKHIuYXQpKycgYWdvPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOicnKX0KICAgIHZhciBEWD1kLmRpYWdub3NpczsKICAgIGlmKERYKXsKICAgICAgJCgnZHhTdGF0JykudGV4dENvbnRlbnQ9RFgudHJhZGVzKycgY2xvc2VkIHRyYWRlcycrKERYLndpblJhdGUhPW51bGw/JyDCtyAnK0RYLndpblJhdGUrJyUgd2lucyc6JycpOwogICAgICB2YXIgZj0oRFguZmluZGluZ3N8fFtdKS5tYXAoZnVuY3Rpb24oeCl7dmFyIGNvbD14LmxldmVsPT09J2JhZCc/J2Rvd24nOngubGV2ZWw9PT0nZ29vZCc/J3VwJzonYXNoJzsKICAgICAgICByZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSInK2NvbCsnIiBzdHlsZT0iZm9udC13ZWlnaHQ6NzAwIj4nKyh4LmxldmVsPT09J2JhZCc/J+KdjCAnOngubGV2ZWw9PT0nZ29vZCc/J+KchSAnOifihLnvuI8gJykrZXNjKHgudGV4dCkrJzwvZGl2PicrKHguZml4JiZyb2xlPT09J293bmVyJz8nPGJ1dHRvbiBjbGFzcz0iYnRuIG1pbnQgb3duIiB0eXBlPSJidXR0b24iIHN0eWxlPSJtYXJnaW4tdG9wOjhweDtwYWRkaW5nOjdweCAxMnB4O2ZvbnQtc2l6ZToxMnB4IiBkYXRhLWZpeD1cJycrZXNjKEpTT04uc3RyaW5naWZ5KHguZml4KSkrJ1wnPkZpeCBpdDogJytlc2MoeC5maXhUZXh0KSsnPC9idXR0b24+JzonJykrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTsKICAgICAgdmFyIHJzPShEWC5yZWFzb25zfHxbXSkubWFwKGZ1bmN0aW9uKHIpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKHIucmVhc29uKSsnPHNtYWxsPicrci50cmFkZXMrJyB0cmFkZXMgwrcgJytyLndpbnMrJyB3b248L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoci5wbmxVc2Q+PTA/J3VwJzonZG93bicpKyciPicrKHIucG5sVXNkPj0wPycrJCc6J+KIkiQnKStNYXRoLmFicyhyLnBubFVzZCkudG9GaXhlZCgyKSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOwogICAgICAkKCdkeCcpLmlubmVySFRNTD1mKyhEWC5hdmdXaW5QY3QhPW51bGw/JzxwIGNsYXNzPSJub3RlIj5BdmVyYWdlIHdpbiA8YiBjbGFzcz0idXAiPisnK0RYLmF2Z1dpblBjdCsnJTwvYj4gwrcgYXZlcmFnZSBsb3NzIDxiIGNsYXNzPSJkb3duIj4nK0RYLmF2Z0xvc3NQY3QrJyU8L2I+IMK3IHdpbm5lcnMgdnMgbG9zZXJzIDxiPicrRFgucHJvZml0RmFjdG9yKyfDlzwvYj4gwrcgZmVlcywgdGlwcyBhbmQgc2xpcHBhZ2Ug4omIIDxiPiQnK0RYLmZlZXNVc2QrJzwvYj4gb24gYmV0cyBvZiBhYm91dCAkJytEWC5hdmdCZXRVc2QrJzwvcD4nOicnKSsKICAgICAgICAocnM/JzxkaXYgc3R5bGU9ImZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTttYXJnaW46MTJweCAwIDJweCI+V0hFUkUgVEhFIE1PTkVZIFdFTlQsIEJZIEhPVyBFQUNIIFRSQURFIEVOREVEPC9kaXY+JytyczonJykrCiAgICAgICAgKChEWC50eXBlc3x8W10pLmxlbmd0aD8nPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxMnB4IDAgMnB4Ij5CWSBXQVkgT0YgRU5URVJJTkc8L2Rpdj4nK0RYLnR5cGVzLm1hcChmdW5jdGlvbih0KXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj4nK2VzYyh0LnR5cGUpKyc8c21hbGw+Jyt0LnRyYWRlcysnIHRyYWRlcyDCtyAnK3Qud2lucysnIHdvbiDCtyBhdmcgJysodC5hdmdQY3Q+PTA/JysnOicnKSt0LmF2Z1BjdCsnJTwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyh0LnBubFVzZD49MD8ndXAnOidkb3duJykrJyI+JysodC5wbmxVc2Q+PTA/JyskJzon4oiSJCcpK01hdGguYWJzKHQucG5sVXNkKS50b0ZpeGVkKDIpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JycpOwogICAgfQogICAgaWYoZC5zdHJhdGVneSkkKCdzdHJhdCcpLmlubmVySFRNTD1kLnN0cmF0ZWd5Lm1hcChmdW5jdGlvbih0KXt2YXIgaT10LmluZGV4T2YoJzonKTtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48Yj4nK2VzYyh0LnNsaWNlKDAsaSkpKyc8L2I+PHNtYWxsIHN0eWxlPSJmb250LXNpemU6MTIuNXB4O2xpbmUtaGVpZ2h0OjEuNSI+Jytlc2ModC5zbGljZShpKzEpKSsnPC9zbWFsbD48L2Rpdj48L2Rpdj4nfSkuam9pbignJyk7CiAgICB2YXIgV1Q9ZC53YXRjaHx8W107JCgnd1N0YXQnKS50ZXh0Q29udGVudD1kLnNldHRpbmdzLm1vbWVudHVtP1dULmxlbmd0aCsnIHdhdGNoaW5nJzonb2ZmIChidXlzIGF0IDkwcyknOwogICAgdmFyIG9rPWZ1bmN0aW9uKHYsbil7cmV0dXJuIHY+PW4/JzxiIGNsYXNzPSJ1cCI+Jyt2Kyc8L2I+JzonPGIgY2xhc3M9ImFzaCI+Jyt2Kyc8L2I+J307CiAgICAkKCd3YXRjaCcpLmlubmVySFRNTD1XVC5sZW5ndGg/V1QubWFwKGZ1bmN0aW9uKHcpe3ZhciBGPXcuZmxvd3x8e30sUz1kLnNldHRpbmdzOwogICAgICByZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3Rvayh3Lm1pbnQsdy5zeW1ib2wsdy5uYW1lKSsnPC9kaXY+JytjYUxpbmUody5taW50KSsnPHNtYWxsPmJ1eWVycy9taW4gJytvayhGLmJ1eWVyczYwfHwwLFMubW9tQnV5ZXJzNjApKycvJytTLm1vbUJ1eWVyczYwKycgwrcgYnV5cyAnK29rKEYuYnV5U2hhcmU2MHx8MCxTLm1vbUJ1eVNoYXJlKSsnJS8nK1MubW9tQnV5U2hhcmUrJyUgwrcgU09MIGluICcrb2soRi5uZXQ2MHx8MCxTLm1vbU5ldFNvbCkrJy8nK1MubW9tTmV0U29sKycgwrcgMi1taW4gJytvayhGLnJpc2UybXx8MCxTLm1vbVJpc2UybSkrJyUvJytTLm1vbVJpc2UybSsnJTwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrdy5sZWZ0U2VjKydzPHNtYWxsPmxlZnQ8L3NtYWxsPjwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij4nKyhkLnNldHRpbmdzLm1vbWVudHVtPydTYWZlIGxhdW5jaGVzIHdhaXQgaGVyZSB1bnRpbCByZWFsIGJ1eWluZyBzaG93cyB1cC4nOidNb21lbnR1bSBlbnRyeSBpcyBvZmY6IGl0IGJ1eXMgcmlnaHQgYXQgOTAgc2Vjb25kcy4nKSsnPC9wPic7CiAgICB2YXIgRz1kLmdyYWRzOwogICAgaWYoRyl7JCgnZ3InKS5pbm5lckhUTUw9JzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luOjAgMCA4cHgiPjxiPicrRy5sYXVuY2hlczI0aC50b0xvY2FsZVN0cmluZygpKyc8L2I+IGxhdW5jaGVzIMK3IDxiPicrRy5ncmFkczI0aCsnPC9iPiBncmFkdWF0ZWQgwrcgcmF0ZSA8Yj4nKyhHLmdyYWRSYXRlUGN0PT1udWxsPyfigJQnOkcuZ3JhZFJhdGVQY3QrJyUnKSsnPC9iPiDCtyBtZWRpYW4gdGltZSB0byBncmFkdWF0ZSA8Yj4nKyhHLm1lZGlhbk1pbnNUb0dyYWQ9PW51bGw/J+KAlCc6Ry5tZWRpYW5NaW5zVG9HcmFkKycgbWluJykrJzwvYj4nKyhHLmZhc3Rlc3RNaW5zIT1udWxsPycgwrcgZmFzdGVzdCAnK0cuZmFzdGVzdE1pbnMrJyBtaW4nOicnKSsoRy5iZXN0SG91clV0YyE9bnVsbD8nIMK3IGJlc3QgaG91ciA8Yj4nK0cuYmVzdEhvdXJVdGMrJzowMCBVVEM8L2I+ICgnK0cuYmVzdEhvdXJSYXRlUGN0KyclKSc6JycpKyc8L3A+JysKICAgICAgJzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luOjAgMCA4cHgiPk9mIHRob3NlIGdyYWR1YXRlcywgQUxLQUlEIGhhZCBhbHJlYWR5IGp1ZGdlZCA8Yj4nK0cuZ3JhZHNKdWRnZWQrJzwvYj4sIHNjb3JlZCA8Yj4nK0cuZ3JhZHNTY29yZWRIaWdoKyc8L2I+IGFzIGhvdCAoMS41w5crKSwgYW5kIGhlbGQgPGI+JytHLmdyYWRzSGVsZCsnPC9iPi48L3A+JysKICAgICAgKChHLnJlY2VudHx8W10pLmxlbmd0aD9HLnJlY2VudC5tYXAoZnVuY3Rpb24oeCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+Jyt0b2soeC5taW50LHguc3ltYm9sfHwnPycseC5uYW1lKSsoeC5oZWxkPycgPHNwYW4gY2xhc3M9InRhZyBidXkiPldFIEhFTEQgSVQ8L3NwYW4+Jzp4Lmp1ZGdlZD8nIDxzcGFuIGNsYXNzPSJ0YWcgd2F0Y2giPldFIFNBVyBJVDwvc3Bhbj4nOicgPHNwYW4gY2xhc3M9InRhZyBza2lwIj5NSVNTRUQ8L3NwYW4+JykrJzwvZGl2PicrY2FMaW5lKHgubWludCkrJzxzbWFsbD4nKyh4Lm1pbnMhPW51bGw/J2dyYWR1YXRlZCAnK3gubWlucysnIG1pbiBhZnRlciBsYXVuY2gnOidsYXVuY2hlZCBiZWZvcmUgdGhlIGJvdCB3YXMgd2F0Y2hpbmcnKSsoeC5saWZ0IT1udWxsPycgwrcgbGFiIHNjb3JlICcreC5saWZ0KyfDlyc6JycpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgYXNoIj4nK2Fnbyh4LmF0KSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPk5vIGdyYWR1YXRpb25zIGluIHRoZSBsYXN0IDI0IGhvdXJzIHlldC48L3A+Jyk7fQoKICAgIHZhciBzZz1mdW5jdGlvbihuKXtyZXR1cm4gKG48MD8n4oiSJCc6JyskJykrTWF0aC5hYnMoK258fDApLnRvRml4ZWQoMil9LGtmPWZ1bmN0aW9uKG4pe3JldHVybiBuPj0xZTY/KG4vMWU2KS50b0ZpeGVkKDEpKydNJzpuPj0xZTM/KG4vMWUzKS50b0ZpeGVkKDEpKydLJzpTdHJpbmcoTWF0aC5yb3VuZChufHwwKSl9OwogICAgdmFyIEdQdj1kLmdyYWR1YXRlOwogICAgaWYoR1B2KXskKCdnU3RhdCcpLnRleHRDb250ZW50PUdQdi5vbj9HUHYudHJhZGVzKycgdHJhZGVzIMK3ICcrc2coR1B2LnBubFVzZCkrKEdQdi5vcGVuPycgwrcgJytHUHYub3BlbisnIG9wZW4nOicnKTonb2ZmJzsKICAgICAgJCgnZ3JhZCcpLmlubmVySFRNTD0oR1B2LndhdGNoaW5nLmxlbmd0aD9HUHYud2F0Y2hpbmcubWFwKGZ1bmN0aW9uKHcpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKHcubWludCx3LnN5bSwnJykrJzwvZGl2PicrY2FMaW5lKHcubWludCkrJzxzbWFsbD4nKyh3LmxpcSE9bnVsbD8nbGlxICQnK2tmKHcubGlxKSsnIMK3IGNhcCAkJytrZih3Lm1jYXApKycgwrcgJyt3LmJ1eXM1KycgYnV5cy81bSDCtyA1bSAnK3cuY2g1KyclIMK3ICc6JycpK2VzYygody53aHl8fFtdKS5qb2luKCcgwrcgJyl8fCdjaGVja2luZ+KApicpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgYXNoIj4nK3cubGVmdE1pbisnbTxzbWFsbD5sZWZ0PC9zbWFsbD48L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+JysoR1B2Lm9uPydUb2tlbnMgdGhhdCBncmFkdWF0ZSB3YWl0IGhlcmUgdW50aWwgcmVhbCBidXlpbmcgc2hvd3MgdXAgb24gdGhlIHRyYWRpbmcgcG9vbC4nOidHcmFkdWF0ZSBzdHJhdGVneSBpcyBvZmYgKHR1cm4gaXQgb24gaW4gUnVsZXMpLicpKyc8L3A+JykrCiAgICAgICAgJzxwIGNsYXNzPSJub3RlIj5CdXlzIGEgZ3JhZHVhdGVkIHRva2VuIG9ubHkgd2hlbjogZW5vdWdoIGxpcXVpZGl0eSwgYSBoZWFsdGh5IG1hcmtldCBjYXAsIDI1KyBidXlzIGluIDUgbWludXRlcyB3aXRoIDU4JSsgYnV5cywgYSByaXNpbmcgKGJ1dCBub3Qgc3Bpa2luZykgcHJpY2UsIHRoZSBjcmVhdG9yIGNhblwndCBwcmludCBvciBmcmVlemUsIGFuZCBKdXBpdGVyIGNvbmZpcm1zIGEgJDEwMCBzYWxlIGdvZXMgdGhyb3VnaC4gVXNlcyBpdHMgb3duIHRpZ2h0ZXIgZXhpdHMuPC9wPid9CiAgICB2YXIgQ1B2PWQuY29weTsKICAgIGlmKENQdil7JCgnY3BTdGF0JykudGV4dENvbnRlbnQ9Q1B2Lm9uP0NQdi50cmFkZXMrJyB0cmFkZXMgwrcgJytzZyhDUHYucG5sVXNkKSsoQ1B2Lm9wZW4/JyDCtyAnK0NQdi5vcGVuKycgb3Blbic6JycpOidvZmYnOwogICAgICAkKCdjb3B5JykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIj4nKyhDUHYub24/J09OOiB3aGVuIGEgdG9wIFNtYXJ0IFdhbGxldCBidXlzICQxNTArIG9mIGEgdG9rZW4gdGhhdCBwYXNzZXMgb3VyIG93biBzYWZldHkgY2hlY2tzLCB3ZSBwYXBlci1idXkgaXQsIGFuZCBzZWxsIHdoZW4gdGhhdCB3YWxsZXQgc2VsbHMuJzonT0ZGLiBUdXJuIGl0IG9uIGluIFJ1bGVzIChvciB0YXAg4pqUIE9mZmVuc2UpLiBTbWFydCBXYWxsZXRzIG11c3QgaGF2ZSBwcm92ZW4gdGhlbXNlbHZlcyBmaXJzdC4nKSsnPC9wPicrCiAgICAgICAgKENQdi50cmFkZXM/JzxkaXYgY2xhc3M9InJvdyI+PGRpdj5Db3BpZWQgdHJhZGVzPHNtYWxsPicrQ1B2LndpbnMrJyB3b24gb2YgJytDUHYudHJhZGVzKycgwrcgYXZlcmFnZSAnKyhDUHYuYXZnUGN0Pj0wPycrJzonJykrQ1B2LmF2Z1BjdCsnJTwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyhDUHYucG5sVXNkPj0wPyd1cCc6J2Rvd24nKSsnIj4nK3NnKENQdi5wbmxVc2QpKyc8L2Rpdj48L2Rpdj4nOicnKSsKICAgICAgICAoKENQdi5za2lwc3x8W10pLmxlbmd0aD8nPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxMHB4IDAgMnB4Ij5XSFkgSVQgUEFTU0VEIE9OIFNPTUU8L2Rpdj4nK0NQdi5za2lwcy5tYXAoZnVuY3Rpb24ocyl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+Jytlc2Mocy5yZWFzb24pKyc8L2Rpdj48ZGl2IGNsYXNzPSJyIGFzaCI+JytzLm4rJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonJyl9CiAgICB2YXIgVFB2PWQudG9wMTAwOwogICAgaWYoVFB2KXt2YXIgc3Q9VFB2LnN0YXRzfHx7fTskKCd0U3RhdCcpLnRleHRDb250ZW50PVRQdi5jb3VudD9UUHYuY291bnQrJyB0cmFja2VkIG5vdyDCtyAnK1RQdi50cmFja2VkKycgZXZlcic6J2NvbGxlY3RpbmfigKYnOwogICAgICAkKCd0b3AnKS5pbm5lckhUTUw9VFB2LmNvdW50PwogICAgICAgICc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5OZXcgb24gdGhlIGxpc3QgaW4gdGhlIGxhc3QgMjRoOiA8Yj4nK3N0Lm5ld0VudHJpZXMyNGgrJzwvYj4uIEEgdHlwaWNhbCBuZXdjb21lciB3YXMgPGI+JCcra2Yoc3QubWVkaWFuTWNhcEF0RW50cnl8fDApKyc8L2I+IG1hcmtldCBjYXAsIDxiPicrKHN0Lm1lZGlhbkFnZU1pbkF0RW50cnk9PW51bGw/Jz8nOnN0Lm1lZGlhbkFnZU1pbkF0RW50cnkrJyBtaW4nKSsnPC9iPiBvbGQsIHdpdGggPGI+Jysoc3QubWVkaWFuQnV5U2hhcmU9PW51bGw/Jz8nOnN0Lm1lZGlhbkJ1eVNoYXJlKyclJykrJzwvYj4gYnV5cyBhbmQgPGI+JCcra2Yoc3QubWVkaWFuTGlxQXRFbnRyeXx8MCkrJzwvYj4gbGlxdWlkaXR5LiA8Yj4nKyhzdC5wdW1wUGN0PT1udWxsPyc/JzpzdC5wdW1wUGN0KyclJykrJzwvYj4gY2FtZSBmcm9tIHB1bXAuZnVuLiBBTEtBSUQgaGFkIGFscmVhZHkgc2VlbiA8Yj4nKyhzdC5zYXdCZWZvcmVQY3Q9PW51bGw/Jz8nOnN0LnNhd0JlZm9yZVBjdCsnJScpKyc8L2I+IG9mIHRoZW0nKyhzdC5tZWRpYW5MZWFkTWluIT1udWxsPycgKG1lZGlhbiA8Yj4nK3N0Lm1lZGlhbkxlYWRNaW4rJyBtaW48L2I+IGJlZm9yZSB0aGV5IGxpc3RlZCknOicnKSsnLjwvcD4nKwogICAgICAgICc8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjEwcHggMCAycHgiPvCfhpUgSlVTVCBFTlRFUkVEIFRIRSBMSVNUPC9kaXY+JysoKFRQdi5lbnRyaWVzfHxbXSkubWFwKGZ1bmN0aW9uKGUpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKGUuYWRkcixlLnN5bSxlLm5hbWUpKyc8L2Rpdj4nK2NhTGluZShlLmFkZHIpKyc8c21hbGw+ZW50ZXJlZCBhdCAjJytlLnJhbmsrJyDCtyBjYXAgJCcra2YoZS5tY2FwKSsnIMK3ICcrKGUuYWdlTWluPT1udWxsPydhZ2UgPyc6ZS5hZ2VNaW4rJyBtaW4gb2xkJykrKGUuYnV5U2hhcmUhPW51bGw/JyDCtyAnK2UuYnV5U2hhcmUrJyUgYnV5cyc6JycpKyhlLnNhd0JlZm9yZT8nIMK3IDxiIGNsYXNzPSJ1cCI+d2Ugc2F3IGl0ICcrZS5sZWFkTWluKycgbWluIGVhcmxpZXI8L2I+JysoZS5saWZ0IT1udWxsPycgKHNjb3JlICcrZS5saWZ0KyfDlyknOicnKTonIMK3IHdlIGhhZG5cJ3Qgc2VlbiBpdCcpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgYXNoIj4nK2FnbyhlLmF0KSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpfHwnPHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBuZXdjb21lcnPigKY8L3A+JykrCiAgICAgICAgJzxkaXYgc3R5bGU9ImZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTttYXJnaW46MTRweCAwIDJweCI+VEhFIExJU1QgUklHSFQgTk9XICh0b3AgMjUpPC9kaXY+JytUUHYubGlzdC5zbGljZSgwLDI1KS5tYXAoZnVuY3Rpb24ocCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+IycrcC5yYW5rKycgJyt0b2socC5hZGRyLHAuc3ltLHAubmFtZSkrJzwvZGl2PicrY2FMaW5lKHAuYWRkcikrJzxzbWFsbD5jYXAgJCcra2YocC5tY2FwKSsnIMK3IGxpcSAkJytrZihwLmxpcSkrJyDCtyAnKyhwLmFnZU1pbj09bnVsbD8nJzoocC5hZ2VNaW48MTIwP3AuYWdlTWluKycgbWluJzpNYXRoLnJvdW5kKHAuYWdlTWluLzYwKSsnaCcpKycgb2xkJykrKHAucHVtcD8nIMK3IHB1bXAuZnVuJzonJykrJzwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyhwLmNoMT49MD8ndXAnOidkb3duJykrJyI+JysocC5jaDE+PTA/JysnOicnKStwLmNoMSsnJTxzbWFsbD4xaDwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpCiAgICAgICAgOic8cCBjbGFzcz0iZW1wdHkiPlJlY29yZGluZyB0aGUgdG9wIDEwMCBldmVyeSA1IG1pbnV0ZXMuIFRoZSBmaXJzdCBzbmFwc2hvdCBsYW5kcyBhIG1pbnV0ZSBhZnRlciB0aGUgc2VydmVyIHN0YXJ0cy48L3A+J30KICAgIHZhciBFWHY9ZC5leHBlcmltZW50czsKICAgIGlmKEVYdil7JCgneFN0YXQnKS50ZXh0Q29udGVudD1FWHYuYmVzdD8nYmVzdCBzbyBmYXI6ICcrKEVYdi5yb3dzLmZpbHRlcihmdW5jdGlvbihyKXtyZXR1cm4gci5pZD09PUVYdi5iZXN0fSlbMF18fHt9KS5uYW1lOidjb2xsZWN0aW5n4oCmJzsKICAgICAgJCgnZXhwJykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgNnB4Ij5FdmVyeSByZWFsIGVudHJ5IGlzIGFsc28gb3BlbmVkIGFzIGEgPGI+JDEwMCBwYXBlciBiZXQ8L2I+IHVuZGVyIGZpdmUgd2F5cyBvZiBzZWxsaW5nLiBTYW1lIGVudHJpZXMsIGRpZmZlcmVudCBleGl0cywgc28gdGhlIGNvbXBhcmlzb24gaXMgZmFpci4gQSAiKzIwJSIgbWVhbnMgKyQyMCBvbiBhICQxMDAgYmV0LjwvcD4nKwogICAgICAgIEVYdi5yb3dzLm1hcChmdW5jdGlvbihyKXt2YXIgYmVzdD1yLmlkPT09RVh2LmJlc3Q7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+JysoYmVzdD8n8J+PhiAnOicnKStlc2Moci5uYW1lKSsnPC9kaXY+PHNtYWxsPicrci50cmFkZXMrJyB0cmFkZXMgwrcgJysoci53aW5SYXRlPT1udWxsPyfigJQnOnIud2luUmF0ZSsnJSB3aW5zJykrJyDCtyB3aW5uZXJzIHZzIGxvc2VycyAnK3IucGYrJ8OXIMK3ICcrci5vcGVuKycgb3Blbjwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKygoci5hdmdQY3R8fDApPj0wPyd1cCc6J2Rvd24nKSsnIj4nKyhyLmF2Z1BjdD09bnVsbD8n4oCUJzooci5hdmdQY3Q+PTA/JysnOicnKStyLmF2Z1BjdCsnJScpKyc8c21hbGw+YXZnIHBlciB0cmFkZTwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpKwogICAgICAgICc8cCBjbGFzcz0ibm90ZSI+TmVlZHMgMTArIHRyYWRlcyBwZXIgcm93IGJlZm9yZSBhIHdpbm5lciBpcyBuYW1lZC4gVGhlIFN3ZWV0IFNwb3QgYWJvdmUgY2FuIGFwcGx5IHRoZSBiZXN0IG9uZSBmb3IgeW91LjwvcD4nfQogICAgdmFyIEdEdj1kLmdyaWQ7CiAgICBpZihHRHYpeyQoJ2dyU3RhdDInKS50ZXh0Q29udGVudD1HRHYub24/J3Bvb2wgJCcrR0R2LmNhc2gudG9GaXhlZCgyKSsnICsgJCcrR0R2LmluTG90cy50b0ZpeGVkKDIpKycgaW4gbG90cyDCtyAnK3NnKEdEdi5wbmxVc2QpOidvZmYnOwogICAgICAkKCdncmlkJykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgNnB4Ij5QaWNrcyBjYWxtLCBsaXF1aWQgdG9rZW5zIChsaXF1aWRpdHkgJDYwSyssIHByaWNlIGJhcmVseSBtb3ZpbmcpLCBidXlzIHNtYWxsIGRpcHMgYW5kIHNlbGxzIHNtYWxsIGJvdW5jZXMuIFNlbGxzIGV2ZXJ5dGhpbmcgaWYgdGhlIHJhbmdlIGJyZWFrcywgbGlxdWlkaXR5IGRyaWVzIHVwLCBvciAzIGhvdXJzIHBhc3MuIEl0cyBvd24gcGFwZXIgcG9vbCwgc2VwYXJhdGUgZnJvbSB5b3VyIG1haW4gbW9uZXkuPC9wPicrCiAgICAgICAgKEdEdi50cmFkZXM/JzxkaXYgY2xhc3M9InJvdyI+PGRpdj5BbGwgZ3JpZCB0cmFkZXM8c21hbGw+JytHRHYudHJhZGVzKycgwrcgJytHRHYud2luUmF0ZSsnJSB3aW5zPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyICcrKEdEdi5wbmxVc2Q+PTA/J3VwJzonZG93bicpKyciPicrc2coR0R2LnBubFVzZCkrJzwvZGl2PjwvZGl2Pic6JycpKwogICAgICAgIChHRHYuYWN0aXZlLmxlbmd0aD9HRHYuYWN0aXZlLm1hcChmdW5jdGlvbihnKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3RvayhnLm1pbnQsZy5zeW0sJycpKyc8L2Rpdj4nK2NhTGluZShnLm1pbnQpKyc8c21hbGw+JytnLm9wZW4rJy8nK2cubGV2ZWxzKycgbG90cyBvcGVuIMK3ICcrZy5yb3VuZHMrJyByb3VuZHMgwrcgY2VudGVyZWQgJCcrKCtnLmNlbnRlcikudG9QcmVjaXNpb24oNCkrJyDCtyBub3cgJCcrKCtnLmxhc3QpLnRvUHJlY2lzaW9uKDQpKycgwrcgJytnLmxlZnRNaW4rJyBtaW4gbGVmdDwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyhnLnBubD49MD8ndXAnOidkb3duJykrJyI+JytzZyhnLnBubCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij4nKyhHRHYub24/J0xvb2tpbmcgZm9yIGEgY2FsbSwgbGlxdWlkIHRva2Vu4oCmJzonR3JpZCB0cmFkaW5nIGlzIG9mZiAodHVybiBpdCBvbiBpbiBSdWxlcykuJykrJzwvcD4nKSsKICAgICAgICAoKEdEdi5kb25lfHxbXSkubGVuZ3RoPyc8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjEwcHggMCAycHgiPkZJTklTSEVEPC9kaXY+JytHRHYuZG9uZS5tYXAoZnVuY3Rpb24oZyl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+Jytlc2MoZy5zeW0pKyc8c21hbGw+JytnLnJvdW5kcysnIHJvdW5kcyDCtyAnK2VzYyhnLnN0YXR1cykrJzwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyhnLnBubD49MD8ndXAnOidkb3duJykrJyI+JytzZyhnLnBubCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonJyl9CiAgICBpZihyb2xlPT09J293bmVyJyYmIWNvbm5DaGVja2VkKXtjb25uQ2hlY2tlZD10cnVlO2FwaSgnL2FwaS9tcC9jb25uZWN0aW9ucycpLnRoZW4oc2hvd0Nvbm4pfQogICAgdmFyIFNXPWQuc3dlZXQ7CiAgICBpZihTVyl7CiAgICAgIGlmKCFTVy5yZWFkeSl7JCgnc3dTdGF0JykudGV4dENvbnRlbnQ9U1cuY29tcHV0aW5nPyd3b3JraW5n4oCmJzoncmVjb3JkaW5nICcrKFNXLnVzYWJsZXx8MCkrJyAvICcrKFNXLm5lZWR8fDEyMCk7CiAgICAgICAgJCgnc3dlZXQnKS5pbm5lckhUTUw9JzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luOjAiPlJlY29yZGluZyB0aGUgcmVhbCBwcmljZSBvZiBldmVyeSBsYXVuY2ggaXQganVkZ2VzLCBldmVyeSAxNSBzZWNvbmRzIGZvciA0NSBtaW51dGVzJysoU1cucmVjb3JkaW5nPycgKCcrU1cucmVjb3JkaW5nKycgYmVpbmcgcmVjb3JkZWQgcmlnaHQgbm93KSc6JycpKycuIE9uY2UgaXQgaGFzICcrKFNXLm5lZWR8fDEyMCkrJywgaXQgcmVwbGF5cyB0aGVtIHVuZGVyIDQwMCsgcnVsZSBjb21iaW5hdGlvbnMgd2l0aCBldmVyeSBmZWUgY291bnRlZCwgYW5kIHNob3dzIHlvdSB0aGUgc2V0dGluZ3MgdGhhdCBtYWRlIG1vbmV5LjwvcD4nO30KICAgICAgZWxzZXsKICAgICAgICB2YXIgQj1TVy5iZXN0LEM9U1cuY3VycmVudCxzdD1TVy5zZXR0aW5ncyxjZWxsPWZ1bmN0aW9uKHYscyl7cmV0dXJuICc8YiBjbGFzcz0iJysodj4wPyd1cCc6J2Rvd24nKSsnIj4nKyh2PjA/JysnOicnKSt2KyhzfHwnJScpKyc8L2I+J307CiAgICAgICAgJCgnc3dTdGF0JykudGV4dENvbnRlbnQ9U1cudHJ1c3R3b3J0aHk/J+KchSBwcm92ZW4gb24gYm90aCBoYWx2ZXMnOifimqDvuI8gbm90IHByb3ZlbiB5ZXQnOwogICAgICAgICQoJ3N3ZWV0JykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5SZXBsYXllZCA8Yj4nK1NXLnVzYWJsZSsnPC9iPiByZWFsIGxhdW5jaGVzLiBUbyBhdm9pZCBsdWNrLCBpdCBzcGxpdCB0aGVtIGludG8gb2xkZXIgYW5kIG5ld2VyIGhhbHZlcywgZHJvcHBlZCBlYWNoIGhhbGZcJ3Mgc2luZ2xlIGJlc3QgdHJhZGUsIGFuZCBvbmx5IHRydXN0cyBzZXR0aW5ncyB0aGF0IG1hZGUgbW9uZXkgaW4gPGI+Ym90aDwvYj4uPC9wPicrCiAgICAgICAgICAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPllvdXIgY3VycmVudCBydWxlczwvZGl2PjxzbWFsbD4nK0MudHJhZGVzKycgdHJhZGVzIMK3ICcrQy53aW5SYXRlKyclIHdpbnMgwrcgb2xkZXIgaGFsZiAnKyhDLm9sZGVyQXZnPT1udWxsPyfigJQnOkMub2xkZXJBdmcrJyUnKSsnIMK3IG5ld2VyIGhhbGYgJysoQy5uZXdlckF2Zz09bnVsbD8n4oCUJzpDLm5ld2VyQXZnKyclJykrJzwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciI+JytjZWxsKEMuYXZnUGN0KSsnPHNtYWxsPmF2ZyBwZXIgdHJhZGU8L3NtYWxsPjwvZGl2PjwvZGl2PicrCiAgICAgICAgICAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPvCfjq8gU3dlZXQgc3BvdDwvZGl2PjxzbWFsbD4nK0IudHJhZGVzKycgdHJhZGVzIMK3ICcrQi53aW5SYXRlKyclIHdpbnMgwrcgb2xkZXIgaGFsZiAnKyhCLm9sZGVyQXZnPT1udWxsPyfigJQnOkIub2xkZXJBdmcrJyUnKSsnIMK3IG5ld2VyIGhhbGYgJysoQi5uZXdlckF2Zz09bnVsbD8n4oCUJzpCLm5ld2VyQXZnKyclJykrJzwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciI+JytjZWxsKEIuYXZnUGN0KSsnPHNtYWxsPmF2ZyBwZXIgdHJhZGU8L3NtYWxsPjwvZGl2PjwvZGl2PicrCiAgICAgICAgICAnPHAgY2xhc3M9Im5vdGUiPlN3ZWV0LXNwb3QgcnVsZXM6IHRha2UgcHJvZml0IGF0IDxiPisnK3N0LnRwUGN0KyclPC9iPiwgc2VsbCA8Yj4nK3N0LnRwMVNlbGxQY3QrJyU8L2I+IHRoZXJlLCBzdG9wIGxvc3MgPGI+4oiSJytzdC5zbFBjdCsnJTwvYj4sIHRyYWlsaW5nIHdpbmRvdyA8Yj4nK3N0LnRyYWlsUGN0KyclPC9iPiwgbWF4IGhvbGQgPGI+JytzdC5tYXhIb2xkTWluKycgbWluPC9iPiwgb25seSBidXkgbGF1bmNoZXMgYXQgbGVhc3QgPGI+JytzdC5taW5Qcm9ncmVzcysnJSBib25kZWQ8L2I+LCB0b3AgMTAgdW5kZXIgPGI+JytzdC5tYXhUb3AxMFBjdCsnJTwvYj4sIGNyZWF0b3IgdW5kZXIgPGI+JytzdC5tYXhEZXZQY3QrJyU8L2I+Jysoc3QubGFiRmlsdGVyPycsIFdpbm5lciBMYWIgbGluZSA8Yj4nK3N0LmxhYk1pbkxpZnQrJ8OXPC9iPic6JycpKycuPC9wPicrCiAgICAgICAgICAnPHAgY2xhc3M9Im5vdGUiPlBhc3QgcmVzdWx0cyBvbiByZWNvcmRlZCBwYXRocywgbm90IGEgcHJvbWlzZS4gUmVhbCBmaWxscyBjYW4gYmUgc2xvd2VyIHRoYW4gdGhlIHJlcGxheS48L3A+JzsKICAgICAgfQogICAgICAkKCdzd05vdGUnKS50ZXh0Q29udGVudD0nQXV0by10dW5lIGlzICcrKGQuc2V0dGluZ3MuYXV0b1R1bmU/J09OOiBpdCBhZG9wdHMgdGhlIHN3ZWV0IHNwb3QgYnkgaXRzZWxmIGV2ZXJ5IDYgaG91cnMsIG9ubHkgd2hlbiBpdCBwcm92ZWQgYmV0dGVyIG9uIGJvdGggaGFsdmVzLic6J09GRiAodHVybiBpdCBvbiBpbiBSdWxlcykuJyk7CiAgICB9CiAgICB2YXIgVD1kLnRhcGV8fFtdOwogICAgJCgndGFwZScpLmlubmVySFRNTD1ULmxlbmd0aD9ULnNsaWNlKDAsMTIpLm1hcChmdW5jdGlvbih0KXt2YXIgc3Q9dC5zdGF0dXN8fCd3YXRjaGluZycsYj1zdC5pbmRleE9mKCdCT1VHSFQnKT09PTAsc2s9c3QuaW5kZXhPZignc2tpcHBlZCcpPT09MDsKICAgICAgdmFyIHRhZz1iPyc8c3BhbiBjbGFzcz0idGFnIGJ1eSI+Jytlc2Moc3QpKyc8L3NwYW4+Jzpzaz8nPHNwYW4gY2xhc3M9InRhZyBza2lwIj5TS0lQUEVEPC9zcGFuPic6JzxzcGFuIGNsYXNzPSJ0YWcgd2F0Y2giPldBVENISU5HPC9zcGFuPic7CiAgICAgIHJldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKHQubWludCx0LnN5bWJvbCx0Lm5hbWUpKycgJyt0YWcrJzwvZGl2PicrY2FMaW5lKHQubWludCkrKHNrPyc8c21hbGw+Jytlc2Moc3QucmVwbGFjZSgnc2tpcHBlZDogJywnJykpKyc8L3NtYWxsPic6JycpKyc8L2Rpdj48ZGl2IGNsYXNzPSJyIGFzaCI+JythZ28odC5hdCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBsYXVuY2hlc+KApjwvcD4nOwogICAgJCgndG9nZ2xlJykudGV4dENvbnRlbnQ9ZC5vbj8nUGF1c2UnOidSZXN1bWUnOwogICAgJCgnY1NlZW4nKS50ZXh0Q29udGVudD1kLnNlZW4udG9Mb2NhbGVTdHJpbmcoKTskKCdjUXVldWUnKS50ZXh0Q29udGVudD1kLnF1ZXVlZCsnIHdhaXRpbmcgdG8gYmUganVkZ2VkJzsKICAgICQoJ2NUcmFkZXMnKS50ZXh0Q29udGVudD1kLnN0YXRzLnRyYWRlczskKCdjT3BlbicpLnRleHRDb250ZW50PWQub3Blbi5sZW5ndGgrJyBvcGVuJzsKICAgICQoJ2NXaW4nKS50ZXh0Q29udGVudD1kLnN0YXRzLndpblJhdGU9PW51bGw/J+KAlCc6ZC5zdGF0cy53aW5SYXRlKyclJzskKCdjQmVzdCcpLnRleHRDb250ZW50PWQuc3RhdHMuYmVzdD09bnVsbD8nJzonYmVzdCAnK2Quc3RhdHMuYmVzdCsnJSDCtyB3b3JzdCAnK2Quc3RhdHMud29yc3QrJyUnOwogICAgJCgnY1BubCcpLnRleHRDb250ZW50PXNvbChkLnN0YXRzLnBubFNvbCk7JCgnY1BubCcpLmNsYXNzTmFtZT1kLnN0YXRzLnBubFNvbD49MD8ndXAnOidkb3duJzskKCdjUG5sVXNkJykudGV4dENvbnRlbnQ9ZC5zdGF0cy5wbmxVc2Q9PW51bGw/Jyc6J+KJiCAkJytkLnN0YXRzLnBubFVzZDsKICAgICQoJ2NVcCcpLnRleHRDb250ZW50PWFnbyhkLnN0YXJ0ZWRBdCk7CiAgICB2YXIgRkw9ZC5mYXN0fHx7fTskKCdjRmFzdCcpLnRleHRDb250ZW50PUZMLm9uPyhGTC50cmFkZXM/KChGTC5wbmxVc2Q+PTA/JysnOifiiJInKSsnJCcrTWF0aC5hYnMoRkwucG5sVXNkKS50b0ZpeGVkKDIpKTonYXJtZWQnKTonb2ZmJzsKICAgICQoJ2NGYXN0JykuY2xhc3NOYW1lPUZMLm9uJiZGTC50cmFkZXM/KEZMLnBubFVzZD49MD8ndXAnOidkb3duJyk6Jyc7CiAgICAkKCdjRmFzdDInKS50ZXh0Q29udGVudD1GTC5vbj8oRkwudHJhZGVzKycgdHJhZGVzIMK3ICcrRkwud2lucysnIHdpbnMnKyhGTC5hdmdFbnRyeU1jYXA/JyDCtyBhdmcgZW50cnkgJCcrKEZMLmF2Z0VudHJ5TWNhcC8xMDAwKS50b0ZpeGVkKDEpKydLJzonJykrKEZMLm9wZW4/JyDCtyAnK0ZMLm9wZW4rJyBvcGVuJzonJykpOid0dXJuIG9uIGluIFJ1bGVzJzskKCdjU29sJykudGV4dENvbnRlbnQ9ZC5zb2xVc2Q/J1NPTCAkJytNYXRoLnJvdW5kKGQuc29sVXNkKTonJzsKICAgIHZhciBCPWQuYmFua3x8e30sdXNkPWZ1bmN0aW9uKG4pe3JldHVybiAobjwwPyfiiJIkJzonJCcpK01hdGguYWJzKCtufHwwKS50b0ZpeGVkKDIpfTsKICAgIGlmKGQuYmFuayl7JCgnYlRvdGFsJykudGV4dENvbnRlbnQ9dXNkKEIudG90YWwpOyQoJ2JHcm93dGgnKS50ZXh0Q29udGVudD0nc3RhcnRlZCB3aXRoICcrdXNkKEIuc3RhcnQpKycgwrcgJysoQi5ncm93dGhQY3Q+PTA/JysnOicnKStCLmdyb3d0aFBjdCsnJSc7CiAgICAgICQoJ2JDYXNoJykudGV4dENvbnRlbnQ9dXNkKEIudHJhZGluZyk7CiAgICAgICQoJ2JOZXh0JykuaW5uZXJIVE1MPSduZXh0IGJldCAnK3VzZChCLm5leHRCZXRVc2QpKycgwrcgc2xvdHMgJytCLnNsb3RzVXNlZCsnLycrQi5zbG90cysoQi5pblRyYWRlcz8nIMK3ICcrdXNkKEIuaW5UcmFkZXMpKycgaW4gdHJhZGVzJzonJykrCiAgICAgICAgKEIuY29zdFBjdCE9bnVsbD8nPGJyPjxzcGFuIGNsYXNzPSInKyhCLmNvc3RQY3Q+MTU/J2Rvd24nOidhc2gnKSsnIj5mZWVzICsgc2xpcHBhZ2Ug4omIICcrQi5jb3N0UGN0KyclIHBlciBzbmlwZScrKEIuY29zdFBjdD4xNT8nOiBzbWFsbCBiZXRzIGxvc2UgYSBsb3QgdG8gZmVlcyc6JycpKyc8L3NwYW4+JzonJykrCiAgICAgICAgKEIubWluU2FmZUJhbGFuY2U/Jzxicj48c3BhbiBjbGFzcz0iJysoQi50b3RhbDxCLm1pblNhZmVCYWxhbmNlPydkb3duJzonYXNoJykrJyI+bWF4LWxvc3MgY2FwIG5lZWRzIGF0IGxlYXN0ICcrdXNkKEIubWluU2FmZUJhbGFuY2UpKyhCLnRvdGFsPEIubWluU2FmZUJhbGFuY2U/Jzogbm90IHRyYWRpbmcgdW50aWwgdGhlbic6JycpKyc8L3NwYW4+JzonJyk7CiAgICAgICQoJ2JWYXVsdCcpLnRleHRDb250ZW50PXVzZChCLnZhdWx0KTskKCdiU2VudCcpLnRleHRDb250ZW50PXVzZChCLnNlbnR8fDApOwogICAgICAkKCdiU2VudFRvJykudGV4dENvbnRlbnQ9Qi5zYXZpbmdzV2FsbGV0Pyd0byAnK0Iuc2F2aW5nc1dhbGxldC5zbGljZSgwLDQpKyfigKYnK0Iuc2F2aW5nc1dhbGxldC5zbGljZSgtNCk6J3NldCBhIHdhbGxldCBiZWxvdyc7CiAgICAgIGlmKCEkKCdzYXZ3JykudmFsdWUmJkIuc2F2aW5nc1dhbGxldCYmZG9jdW1lbnQuYWN0aXZlRWxlbWVudCE9PSQoJ3NhdncnKSkkKCdzYXZ3JykudmFsdWU9Qi5zYXZpbmdzV2FsbGV0OyQoJ2JUb2RheScpLnRleHRDb250ZW50PShCLnRvZGF5Pj0wPycrJzonJykrdXNkKEIudG9kYXkpOyQoJ2JUb2RheScpLmNsYXNzTmFtZT1CLnRvZGF5Pj0wPyd1cCc6J2Rvd24nOwogICAgICAkKCdiU3RhdHVzJykuaW5uZXJIVE1MPUIucGF1c2VkPyc8c3BhbiBjbGFzcz0icGlsbCBvZmYiPlBBVVNFRCDCtyAnK2VzYyhCLnBhdXNlZC53aHkpKyc8L3NwYW4+IDxidXR0b24gY2xhc3M9ImJ0biBvd24iIGRhdGEtcmVzdW1lPSIxIiB0eXBlPSJidXR0b24iIHN0eWxlPSJwYWRkaW5nOjZweCAxMHB4O2ZvbnQtc2l6ZToxMnB4O21hcmdpbi10b3A6NnB4Ij5SZXN1bWUgbm93PC9idXR0b24+JzonPHNwYW4gY2xhc3M9InBpbGwgb24iPlRSQURJTkc8L3NwYW4+Jzt9CiAgICB2YXIgU0M9ZC5zY29yZWNhcmQ7CiAgICBpZihTQyl7JCgnc2NvcmUnKS5pbm5lckhUTUw9JzxkaXYgY2xhc3M9InJvdyI+PGRpdiBjbGFzcz0icyI+JysoU0MucmVhZHlGb3JMaXZlPyc8c3BhbiBjbGFzcz0idXAiPuKchSBQcm92ZW46IHJlYWR5IHRvIGdvIGxpdmUgd2l0aCBzbWFsbCBtb25leTwvc3Bhbj4nOic8c3BhbiBjbGFzcz0iYXNoIj7ij7MgTm90IHlldDoga2VlcCBwYXBlciB0cmFkaW5nPC9zcGFuPicpKwogICAgICAnPC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrU0MudHJhZGVzKycgdHJhZGVzIMK3ICcrKFNDLndpblJhdGU9PW51bGw/J+KAlCc6U0Mud2luUmF0ZSsnJSB3aW5zJykrJzwvZGl2PjwvZGl2PicrCiAgICAgIFNDLmdhdGVzLm1hcChmdW5jdGlvbihnKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj4nKyhnLm9rPyfinIUgJzon4qycICcpK2VzYyhnLnRlc3QpKyc8L2Rpdj48ZGl2IGNsYXNzPSJyICcrKGcub2s/J3VwJzonYXNoJykrJyI+Jytlc2MoZy5ub3cpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk7fQogICAgdmFyIEw9ZC5sZWFybmVkfHxbXTsKICAgICQoJ2xlYXJuZWQnKS5pbm5lckhUTUw9TC5sZW5ndGg/TC5tYXAoZnVuY3Rpb24oeCl7dmFyIGM9eC52ZXJkaWN0PT09J3NraXAnPydkb3duJzp4LnZlcmRpY3Q9PT0nZmF2b3InPyd1cCc6J2FzaCc7CiAgICAgIHZhciB3PXgudmVyZGljdD09PSdza2lwJz8nc2tpcHBpbmcgaXQgbm93Jzp4LnZlcmRpY3Q9PT0nZmF2b3InPyd3b3JraW5nJzp4LnZlcmRpY3Q9PT0nbGVhcm5pbmcnPydsZWFybmluZyAoJyt4LnRyYWRlcysnLycrZC5zZXR0aW5ncy5sZWFybk1pbisnKSc6J25ldXRyYWwnOwogICAgICByZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2PicrZXNjKHguc2V0dXApKyc8L2Rpdj48c21hbGw+Jyt4LnRyYWRlcysnIHRyYWRlcyDCtyAnK3gud2luUmF0ZSsnJSB3aW5zPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyICcrYysnIj4nKyh4LmF2Z1BjdD49MD8nKyc6JycpK3guYXZnUGN0KyclPHNtYWxsPicrdysnPC9zbWFsbD48L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+TGVhcm5pbmc6IGVhY2ggc2V0dXAgbmVlZHMgYSBkb3plbiB0cmFkZXMgYmVmb3JlIGl0XCdzIGp1ZGdlZC48L3A+JzsKICAgIHZhciBGPWQuZmlsdGVyUmVwb3J0fHxbXTsKICAgICQoJ2ZyZXBvcnQnKS5pbm5lckhUTUw9Ri5sZW5ndGg/Ri5zbGljZSgwLDEwKS5tYXAoZnVuY3Rpb24oeCl7dmFyIGdvb2Q9eC52ZXJkaWN0PT09J3NhdmluZyB5b3UgbW9uZXknOwogICAgICByZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2PicrZXNjKHgucmVhc29uKSsnPC9kaXY+PHNtYWxsPicreC5jaGVja2VkKycgY2hlY2tlZCDCtyAnK3gud291bGRMb3NlKycgd291bGQgaGF2ZSBsb3N0IMK3ICcreC53b3VsZFdpbisnIHdvdWxkIGhhdmUgZG91YmxlZDwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyh4LnZlcmRpY3Q9PT0nc3RpbGwgY2hlY2tpbmcnPydhc2gnOmdvb2Q/J3VwJzonZG93bicpKyciPicrZXNjKHgudmVyZGljdCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5DaGVja2luZyB3aGF0IGhhcHBlbmVkIHRvIHRoZSBsYXVuY2hlcyBpdCBza2lwcGVk4oCmPC9wPic7CiAgICB2YXIgRT1kLmV2ZW50c3x8W107CiAgICAkKCdldmVudHMnKS5pbm5lckhUTUw9RS5sZW5ndGg/RS5tYXAoZnVuY3Rpb24oZSl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+Jytlc2MoZS50ZXh0KSsnPC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrYWdvKGUuYXQpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+Tm90aGluZyB5ZXQuPC9wPic7CiAgICAkKCdvcGVuTicpLnRleHRDb250ZW50PWQub3Blbi5sZW5ndGgrJyAvICcrKGQuc2V0dGluZ3Muc2xvdHM+MD9kLnNldHRpbmdzLnNsb3RzOmQuc2V0dGluZ3MubWF4T3Blbik7CiAgICAkKCdvcGVuJykuaW5uZXJIVE1MPWQub3Blbi5sZW5ndGg/ZC5vcGVuLm1hcChmdW5jdGlvbihwKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3RvayhwLm1pbnQscC5zeW1ib2wscC5uYW1lKSsnPC9kaXY+JytjYUxpbmUocC5taW50KSsnPHNtYWxsPmJvdWdodCBhdCAnKygrcC5wcm9ncmVzc0F0QnV5KS50b0ZpeGVkKDEpKyclIGJvbmRlZCDCtyAnK3AuYWdlTWluKydtIGFnbyDCtyBkZXYgJysocC5kZXZQY3Q9PW51bGw/Jz8nOigrcC5kZXZQY3QpLnRvRml4ZWQoMSkrJyUnKSsocC5zaXplVXNkPycgwrcgYmV0ICQnKygrcC5zaXplVXNkKS50b0ZpeGVkKDIpOicnKSsocC5tY2FwTm93PycgwrcgY2FwICQnKyhwLm1jYXBOb3c+PTEwMDA/KHAubWNhcE5vdy8xMDAwKS50b0ZpeGVkKDEpKydLJzpNYXRoLnJvdW5kKHAubWNhcE5vdykpOicnKSsocC5wb3N0R3JhZD8nIMK3IG9uIHRoZSBwb29sJzonJykrJzwvc21hbGw+JysocC5waGFzZT09PSdtb29uJz8nPHNwYW4gY2xhc3M9InRhZyBidXkiPvCfjJkgTU9ORVkgQkFDSyDCtyBSSURJTkcgVEhFIFJFU1Q8L3NwYW4+JzonJykrKChwLmJvb3N0c3x8W10pLm1hcChmdW5jdGlvbih4KXtyZXR1cm4gJzxzcGFuIGNsYXNzPSJ0YWcgc2tpcCI+4pqhICcrZXNjKHgpKyc8L3NwYW4+J30pLmpvaW4oJycpKSsnPC9kaXY+PGRpdiBjbGFzcz0iciAnKyhwLmNoUGN0Pj0wPyd1cCc6J2Rvd24nKSsnIj4nKyhwLmNoUGN0Pj0wPycrJzonJykrcC5jaFBjdCsnJTwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5Ob3RoaW5nIG9wZW4uIEFMS0FJRCBvbmx5IGZpcmVzIGF0IHdoYXQgcGFzc2VzIGV2ZXJ5IGZpbHRlci48L3A+JzsKICAgIHZhciBzaz1PYmplY3Qua2V5cyhkLnNraXBzKS5tYXAoZnVuY3Rpb24oayl7cmV0dXJuIFtrLGQuc2tpcHNba11dfSkuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiBiWzFdLWFbMV19KSxteD1zay5sZW5ndGg/c2tbMF1bMV06MTsKICAgICQoJ2Z1bm5lbCcpLmlubmVySFRNTD1zay5sZW5ndGg/c2suc2xpY2UoMCwxMikubWFwKGZ1bmN0aW9uKHMpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXY+Jytlc2Moc1swXSkrJzwvZGl2PjxkaXYgY2xhc3M9ImJhciI+PGkgc3R5bGU9IndpZHRoOicrTWF0aC5tYXgoMyxzWzFdL214KjEwMCkrJyUiPjwvaT48L2Rpdj48L2Rpdj48ZGl2IGNsYXNzPSJyIj4nK3NbMV0udG9Mb2NhbGVTdHJpbmcoKSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPldhaXRpbmcgZm9yIGxhdW5jaGVz4oCmPC9wPic7CiAgICAkKCdkZWNpc2lvbnMnKS5pbm5lckhUTUw9ZC5ldmFsdWF0ZWQubGVuZ3RoP2QuZXZhbHVhdGVkLnNsaWNlKDAsMjUpLm1hcChmdW5jdGlvbihlKXt2YXIgYnV5PWUudmVyZGljdD09PSdwYXBlciBidXknO3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKGUubWludCxlLnN5bWJvbCxlLm5hbWUpKyc8c3BhbiBjbGFzcz0idGFnICcrKGJ1eT8nYnV5Jzonc2tpcCcpKyciPicrKGJ1eT8nUEFQRVIgQlVZJzonU0tJUCcpKyc8L3NwYW4+PC9kaXY+JytjYUxpbmUoZS5taW50KSsnPHNtYWxsPicrZXNjKGUucmVhc29uKSsnPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyIGFzaCI+JythZ28oZS5hdCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBsYXVuY2hlc+KApjwvcD4nOwogICAgJCgnY2xvc2VkJykuaW5uZXJIVE1MPWQuY2xvc2VkLmxlbmd0aD9kLmNsb3NlZC5zbGljZSgwLDI1KS5tYXAoZnVuY3Rpb24oYyl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+Jyt0b2soYy5taW50LGMuc3ltYm9sLGMubmFtZSkrJzwvZGl2PicrY2FMaW5lKGMubWludCkrJzxzbWFsbD4nK2VzYyhjLndoeSkrJyDCtyBoZWxkICcrTWF0aC5tYXgoMSxNYXRoLnJvdW5kKChjLmNsb3NlZEF0LWMub3BlbmVkQXQpLzYwMDAwKSkrJ20gwrcgJythZ28oYy5jbG9zZWRBdCkrJyBhZ288L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoKGMucG5sVXNkIT1udWxsP2MucG5sVXNkOmMucG5sU29sKT49MD8ndXAnOidkb3duJykrJyI+JysoYy5wbmxVc2QhPW51bGw/KGMucG5sVXNkPj0wPycrJzon4oiSJykrJyQnK01hdGguYWJzKGMucG5sVXNkKS50b0ZpeGVkKDIpOnNvbChjLnBubFNvbCkpKyc8c21hbGw+JysoYy5wbmxQY3Q+PTA/JysnOicnKStjLnBubFBjdCsnJTwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPk5vIGNsb3NlZCB0cmFkZXMgeWV0LjwvcD4nOwogICAgaWYoISQoJ3NldCcpLmNoaWxkcmVuLmxlbmd0aCkkKCdzZXQnKS5pbm5lckhUTUw9RklFTERTLm1hcChmdW5jdGlvbihmKXtyZXR1cm4gJzxsYWJlbD4nK2ZbMV0rJzxpbnB1dCB0eXBlPSJudW1iZXIiIHN0ZXA9ImFueSIgaW5wdXRtb2RlPSJkZWNpbWFsIiBkYXRhLWs9IicrZlswXSsnIiB2YWx1ZT0iJytlc2MoZC5zZXR0aW5nc1tmWzBdXSkrJyI+PC9sYWJlbD4nfSkuam9pbignJyk7CiAgICBpZighb3duZXJGb3JtU2hvd24pe293bmVyRm9ybVNob3duPXRydWU7c2hvd05ld0NvZGVGb3JtKCl9CiAgfQogICQoJ3NhdmUnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7CiAgICB2YXIgYm9keT17fTtkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjc2V0IGlucHV0JykuZm9yRWFjaChmdW5jdGlvbihpKXtib2R5W2kuZGF0YXNldC5rXT1OdW1iZXIoaS52YWx1ZSl9KTsKICAgIHZhciByPWF3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShib2R5KX0pOwogICAgaWYoci5vayl7JCgnc2V0JykuaW5uZXJIVE1MPScnO2xvYWQoKTt0aGlzLnRleHRDb250ZW50PSdTYXZlZCDinJMnO3ZhciBiPXRoaXM7c2V0VGltZW91dChmdW5jdGlvbigpe2IudGV4dENvbnRlbnQ9J1NhdmUgcnVsZXMnfSwxNTAwKX0KICB9OwogIGZ1bmN0aW9uIHNob3dOZXdDb2RlRm9ybSgpewogICAgaWYoJCgnbmV3Q29kZUZvcm0nKSlyZXR1cm47CiAgICAkKCduZXdDb2RlU2xvdCcpLmFwcGVuZENoaWxkKGRvY3VtZW50LmltcG9ydE5vZGUoJCgnbmV3Q29kZVRwbCcpLmNvbnRlbnQsdHJ1ZSkpOwogICQoJ25ld0V5ZScpLm9uY2xpY2s9ZnVuY3Rpb24oKXt2YXIgYz0kKCduZXdDb2RlJyksc2hvdz1jLnR5cGU9PT0ncGFzc3dvcmQnO2MudHlwZT1zaG93Pyd0ZXh0JzoncGFzc3dvcmQnO3RoaXMudGV4dENvbnRlbnQ9c2hvdz8nSGlkZSc6J1Nob3cnO2MuZm9jdXMoKX07CiAgICAkKCduZXdDb2RlRm9ybScpLm9uc3VibWl0PWFzeW5jIGZ1bmN0aW9uKGUpewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7dmFyIGM9JCgnbmV3Q29kZScpLnZhbHVlLG09JCgnbmV3TXNnJyk7bS5zdHlsZS5jb2xvcj0ndmFyKC0tYXNoKSc7CiAgICAgIGlmKGMubGVuZ3RoPDEyKXttLnN0eWxlLmNvbG9yPSd2YXIoLS1kb3duKSc7bS50ZXh0Q29udGVudD0nVXNlIGF0IGxlYXN0IDEyIGNoYXJhY3RlcnMuJztyZXR1cm4gZmFsc2V9CiAgICAgIG0udGV4dENvbnRlbnQ9J1NhdmluZ+KApic7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL293bmVyLWNvZGUnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2NvZGU6Y30pfSk7CiAgICAgIGlmKHIub2spe20uc3R5bGUuY29sb3I9J3ZhcigtLW1pbnQpJzttLnRleHRDb250ZW50PXIuc2F2ZWQ/J1NhdmVkIOKckyBVc2UgdGhpcyBjb2RlIG5leHQgdGltZS4nOidTYXZlZCB1bnRpbCB0aGUgbmV4dCByZXN0YXJ0ICh0aGUgc2VydmVyIGhhcyBubyBzYXZlZCBzdG9yYWdlKS4nfQogICAgICBlbHNle20uc3R5bGUuY29sb3I9J3ZhcigtLWRvd24pJzttLnRleHRDb250ZW50PXIuZXJyb3J8fCdOb3Qgc2F2ZWQuIFRyeSBhZ2Fpbi4nfQogICAgICByZXR1cm4gZmFsc2U7CiAgICB9OwogIH0KCiAgdmFyIFBSRVNFVFM9ewogICAgZGVmZW5zZTp7c2xvdHM6MTAsdHBQY3Q6NjAsdHAxU2VsbFBjdDo3MCxzbFBjdDoyMCx0cmFpbFBjdDoyMCx0cmFpbEF0NXg6MTIsdHJhaWxBdDEweDo4LGRhaWx5U3RvcFBjdDoxNSxtYXhMb3NzU3RyZWFrOjMscGF1c2VNaW46MTgwLGNhc2hPdXRNY2FwOjgwMDAwLG1pblByb2dyZXNzOjgsbWF4VG9wMTBQY3Q6MzAsbWF4VG9wMVBjdDoxMCxtYXhEZXZQY3Q6NSxmYXN0TGFuZTowLG1heEhvbGRNaW46MjAsbGVhcm46MSxsYWJGaWx0ZXI6MSxsYWJNaW5MaWZ0OjEuMixsYWJCb29zdDoxLjUsbW9tZW50dW06MSxtb21CdXllcnM2MDoxMCxtb21CdXlTaGFyZTo2NSxtb21OZXRTb2w6Myxtb21SaXNlMm06MjAsbW9tTWF4TWNhcDozMDAwMCxncmFkT246MSxncmFkU2w6MTIsZ3JhZE1heE9wZW46Mixjb3B5T246MH0sCiAgICBiYWxhbmNlZDp7c2xvdHM6MTAsdHBQY3Q6MTAwLHRwMVNlbGxQY3Q6NTAsc2xQY3Q6MzAsdHJhaWxQY3Q6MjUsdHJhaWxBdDV4OjE1LHRyYWlsQXQxMHg6MTAsZGFpbHlTdG9wUGN0OjMwLG1heExvc3NTdHJlYWs6NSxwYXVzZU1pbjoxMjAsY2FzaE91dE1jYXA6MTAwMDAwLG1pblByb2dyZXNzOjUsbWF4VG9wMTBQY3Q6MzUsbWF4VG9wMVBjdDoxMixtYXhEZXZQY3Q6OCxmYXN0TGFuZTowLG1heEhvbGRNaW46MzAsbGVhcm46MSxsYWJGaWx0ZXI6MCxsYWJNaW5MaWZ0OjEsbGFiQm9vc3Q6MS41LG1vbWVudHVtOjEsbW9tQnV5ZXJzNjA6OCxtb21CdXlTaGFyZTo2MCxtb21OZXRTb2w6Mixtb21SaXNlMm06MTUsbW9tTWF4TWNhcDo0MDAwMCxncmFkT246MSxncmFkU2w6MTUsZ3JhZE1heE9wZW46Myxjb3B5T246MH0sCiAgICBvZmZlbnNlOntzbG90czo2LHRwUGN0OjE1MCx0cDFTZWxsUGN0OjQwLHNsUGN0OjM1LHRyYWlsUGN0OjMwLHRyYWlsQXQ1eDoxOCx0cmFpbEF0MTB4OjEyLGRhaWx5U3RvcFBjdDo0MCxtYXhMb3NzU3RyZWFrOjcscGF1c2VNaW46NjAsY2FzaE91dE1jYXA6MTAwMDAwLG1pblByb2dyZXNzOjQsbWF4VG9wMTBQY3Q6NDAsbWF4VG9wMVBjdDoxNSxtYXhEZXZQY3Q6MTAsZmFzdExhbmU6MSxtYXhIb2xkTWluOjQ1LGxlYXJuOjEsbGFiRmlsdGVyOjAsbGFiTWluTGlmdDoxLGxhYkJvb3N0OjIsbW9tZW50dW06MSxtb21CdXllcnM2MDo2LG1vbUJ1eVNoYXJlOjU1LG1vbU5ldFNvbDoxLjUsbW9tUmlzZTJtOjEwLG1vbU1heE1jYXA6NjAwMDAsZ3JhZE9uOjEsZ3JhZFNsOjE4LGdyYWRNYXhPcGVuOjQsY29weU9uOjF9fTsKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdbZGF0YS1wcmVzZXRdJykuZm9yRWFjaChmdW5jdGlvbihiKXtiLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXsKICAgIHZhciBrPXRoaXMuZGF0YXNldC5wcmVzZXQscj1hd2FpdCBhcGkoJy9hcGkvbXAvc2V0dGluZ3MnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoUFJFU0VUU1trXSl9KTsKICAgICQoJ3ByZXNldE5vdGUnKS5pbm5lckhUTUw9ci5vaz8n4pyFIDxiPicray5jaGFyQXQoMCkudG9VcHBlckNhc2UoKStrLnNsaWNlKDEpKyc8L2I+IGlzIG9uLiBJdCBhcHBsaWVzIHRvIHRoZSBuZXh0IGxhdW5jaC4gWW91IGNhbiBzdGlsbCBmaW5lLXR1bmUgYW55IG51bWJlciBpbiBSdWxlcyBiZWxvdy4nOidOb3Qgc2F2ZWQ6ICcrZXNjKHIuZXJyb3J8fCd0cnkgYWdhaW4nKTsKICAgIGlmKHIub2speyQoJ3NldCcpLmlubmVySFRNTD0nJztsb2FkKCl9fX0pOwogIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJyxhc3luYyBmdW5jdGlvbihlKXtpZighZS50YXJnZXQuY2xvc2VzdCgnW2RhdGEtcmVzdW1lXScpKXJldHVybjsKICAgIGF3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7cmVzdW1lOnRydWV9KX0pO2xvYWQoKX0pOwogICQoJ3N3QXBwbHknKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7dmFyIGI9dGhpcztiLmRpc2FibGVkPXRydWU7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL3N3ZWV0c3BvdC9hcHBseScse21ldGhvZDonUE9TVCcsYm9keTone30nfSk7Yi5kaXNhYmxlZD1mYWxzZTsKICAgICQoJ3N3Tm90ZScpLnRleHRDb250ZW50PXIub2s/J+KchSBTd2VldCBzcG90IGlzIG9uLiBJdCBhcHBsaWVzIHRvIHRoZSBuZXh0IGxhdW5jaC4nOihyLmVycm9yfHwnTm90IGFwcGxpZWQuIFRyeSBhZ2Fpbi4nKTtpZihyLm9rKXskKCdzZXQnKS5pbm5lckhUTUw9Jyc7bG9hZCgpfX07CiAgJCgnZGF0YURsJykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3ZhciBiPXRoaXM7Yi50ZXh0Q29udGVudD0nUHJlcGFyaW5n4oCmJzsKICAgIHRyeXt2YXIgcj1hd2FpdCBmZXRjaChBUEkrJy9hcGkvbXAvZGF0YS5jc3YnLHtoZWFkZXJzOntBdXRob3JpemF0aW9uOidCZWFyZXIgJytwYXNzfX0pO2lmKCFyLm9rKXRocm93IDA7dmFyIGJsPWF3YWl0IHIuYmxvYigpLHU9VVJMLmNyZWF0ZU9iamVjdFVSTChibCksYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7CiAgICAgIGEuaHJlZj11O2EuZG93bmxvYWQ9J2Fsa2FpZC1kYXRhLScrbmV3IERhdGUoKS50b0lTT1N0cmluZygpLnNsaWNlKDAsMTApKycuY3N2Jztkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpO2EuY2xpY2soKTthLnJlbW92ZSgpO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtVUkwucmV2b2tlT2JqZWN0VVJMKHUpfSw0MDAwKTtiLnRleHRDb250ZW50PSdEb3dubG9hZGVkIOKckyd9CiAgICBjYXRjaChlKXtiLnRleHRDb250ZW50PSdDb3VsZG5cJ3QgZG93bmxvYWQuIFRyeSBhZ2Fpbid9c2V0VGltZW91dChmdW5jdGlvbigpe2IudGV4dENvbnRlbnQ9J0Rvd25sb2FkIGFsbCB0aGUgZGF0YSAoc3ByZWFkc2hlZXQpJ30sMjUwMCl9OwogIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJyxhc3luYyBmdW5jdGlvbihlKXt2YXIgYj1lLnRhcmdldC5jbG9zZXN0KCdbZGF0YS1maXhdJyk7aWYoIWIpcmV0dXJuO3ZhciBmeDt0cnl7Zng9SlNPTi5wYXJzZShiLmdldEF0dHJpYnV0ZSgnZGF0YS1maXgnKSl9Y2F0Y2goXyl7cmV0dXJufQogICAgYi5kaXNhYmxlZD10cnVlO3ZhciByPWF3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShmeCl9KTtiLnRleHRDb250ZW50PXIub2s/J+KchSBGaXhlZC4gQXBwbGllcyB0byB0aGUgbmV4dCBsYXVuY2guJzonTm90IHNhdmVkOiAnKyhyLmVycm9yfHwndHJ5IGFnYWluJyk7aWYoci5vayl7JCgnc2V0JykuaW5uZXJIVE1MPScnO2xvYWQoKX19KTsKCiAgZnVuY3Rpb24gYnVpbGRKdW1wKCl7dmFyIG5hdj0kKCdqdW1wJyk7aWYoIW5hdnx8bmF2LmRhdGFzZXQuYnVpbHQpcmV0dXJuO25hdi5kYXRhc2V0LmJ1aWx0PScxJzsKICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ3NlY3Rpb24ucGFuZWwnKS5mb3JFYWNoKGZ1bmN0aW9uKHNlYyxpKXt2YXIgcGg9c2VjLnF1ZXJ5U2VsZWN0b3IoJy5waCcpO2lmKCFwaClyZXR1cm47CiAgICAgIHZhciBsYWI9KChwaC5maXJzdEVsZW1lbnRDaGlsZHx8cGgpLnRleHRDb250ZW50fHwnJykucmVwbGFjZSgvXHMrL2csJyAnKS50cmltKCkuc2xpY2UoMCwyMCk7aWYoIWxhYnx8IS9BdXRvcGlsb3R8Q3VzdG9keXxsb3Npbmd8TElWRXxXaW5uZXJ8U3dlZXR8RXhwZXJpbWVudHN8VG9wIDEwMHxPcGVuIHBhcGVyfENsb3NlZCBwYXBlcnxDb25uZWN0aW9uc3xSdWxlc3xHcmFkdWF0ZS9pLnRlc3QobGFiKSlyZXR1cm47CiAgICAgIHNlYy5pZD1zZWMuaWR8fCgnc2VjJytpKTt2YXIgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7YS5jbGFzc05hbWU9J2NoaXAnO2EuaHJlZj0nIycrc2VjLmlkO2EudGV4dENvbnRlbnQ9bGFiOwogICAgICBhLm9uY2xpY2s9ZnVuY3Rpb24oZSl7ZS5wcmV2ZW50RGVmYXVsdCgpO3NlYy5zY3JvbGxJbnRvVmlldyh7YmVoYXZpb3I6J3Ntb290aCcsYmxvY2s6J3N0YXJ0J30pfTtuYXYuYXBwZW5kQ2hpbGQoYSl9KX0KICB2YXIgY29ubkNoZWNrZWQ9ZmFsc2U7JCgndGdQYWdlJykuaHJlZj1BUEkrJy9hbGthaWQvdGVsZWdyYW0nOwogIGZ1bmN0aW9uIHNob3dDb25uKHIpe2lmKCFyfHxyLl9zPj00MDB8fCFyLnJwYylyZXR1cm47dmFyIFJwPXIucnBjLFRnPXIudGVsZWdyYW07CiAgICAkKCdjb25uUnBjJykuaW5uZXJIVE1MPShScC5vd24/J+KchSBVc2luZyA8Yj55b3VyIG93bjwvYj4gY29ubmVjdGlvbiAoPGI+Jytlc2MoUnAudXNpbmcpKyc8L2I+KSc6J1VzaW5nIHRoZSBmcmVlIHB1YmxpYyBjb25uZWN0aW9uICg8Yj4nK2VzYyhScC51c2luZykrJzwvYj4pLiBBIEhlbGl1cyBrZXkgbWFrZXMgZXZlcnl0aGluZyBmYXN0ZXIuJykrJzxicj5DYWxscyB0b2RheSA8Yj4nK1JwLnRvZGF5LnRvTG9jYWxlU3RyaW5nKCkrJzwvYj4nKyhScC5jYXA/JyBvZiB5b3VyIGNhcCAnK1JwLmNhcC50b0xvY2FsZVN0cmluZygpOicnKSsnIMK3IHRoaXMgbW9udGggPGI+JytScC5tb250aC50b0xvY2FsZVN0cmluZygpKyc8L2I+JysoUnAuY2FwSGl0PycgPGIgY2xhc3M9ImRvd24iPsK3IGNhcCByZWFjaGVkOiBiYWNrZ3JvdW5kIHJlc2VhcmNoIHBhdXNlZCwgdHJhZGluZyBjb250aW51ZXM8L2I+JzonJykrKFJwLnRvcC5sZW5ndGg/Jzxicj48c21hbGw+YnVzaWVzdDogJytScC50b3AubWFwKGZ1bmN0aW9uKHgpe3JldHVybiBlc2MoeC5tKSsnICcreC5ufSkuam9pbignIMK3ICcpKyc8L3NtYWxsPic6JycpOwogICAgJCgnY29ublRnJykuaW5uZXJIVE1MPVRnLnNldD8oKFRnLm9uPyfinIUgQ29ubmVjdGVkIHRvIDxiPkAnK2VzYyhUZy5ib3R8fCd5b3VyIGJvdCcpKyc8L2I+Jzon4pqg77iPIFRoZSBib3QgaXNuXCd0IGFuc3dlcmluZyB5ZXQnKSsnIMK3IHBob25lcyBwYWlyZWQ6IDxiPicrVGcucGFpcmVkKyc8L2I+IMK3IGFsZXJ0cyAnKyhUZy5hbGVydHM/J29uJzonb2ZmJykrKFRnLmVycm9yPyc8YnI+PGIgY2xhc3M9ImRvd24iPicrZXNjKFRnLmVycm9yKSsnPC9iPic6JycpKTonTm90IHNldCB1cCB5ZXQuIEluIFRlbGVncmFtLCBtZXNzYWdlIDxiPkBCb3RGYXRoZXI8L2I+LCBzZW5kIC9uZXdib3QsIGFuZCBwYXN0ZSB0aGUgdG9rZW4gaXQgZ2l2ZXMgeW91IGhlcmUuJzsKICAgIGlmKFRnLmNvZGUpeyQoJ3RnQ29kZScpLmhpZGRlbj1mYWxzZTskKCd0Z0NvZGUnKS5pbm5lckhUTUw9KFRnLmxpbms/JzxhIGNsYXNzPSJidG4gbWludCIgdGFyZ2V0PSJfYmxhbmsiIHJlbD0ibm9vcGVuZXIiIGhyZWY9IicrZXNjKFRnLmxpbmspKyciIHN0eWxlPSJkaXNwbGF5OmlubGluZS1mbGV4O21hcmdpbi1ib3R0b206MTBweCI+T3BlbiBUZWxlZ3JhbSBhbmQgY29ubmVjdDwvYT48YnI+JzonJykrJ1RhcCB0aGUgZ3JlZW4gYnV0dG9uLCB0aGVuIHRhcCA8Yj5TVEFSVDwvYj4gaW4gVGVsZWdyYW0uIChPciBzZW5kIHlvdXIgYm90IHRoaXMgYnkgaGFuZDogPGIgc3R5bGU9ImZvbnQ6ODAwIDE1cHggdmFyKC0tbW9ubykiPi9zdGFydCAnK2VzYyhUZy5jb2RlKSsnPC9iPik8YnI+PHNtYWxsPm9uZS10aW1lIGNvZGUsIGdvb2QgZm9yIDE1IG1pbnV0ZXM8L3NtYWxsPid9ZWxzZSAkKCd0Z0NvZGUnKS5oaWRkZW49dHJ1ZX0KICB2YXIgcG9zdENvbm49YXN5bmMgZnVuY3Rpb24oYm9keSxtc2dJZCl7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL2Nvbm5lY3Rpb25zJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KGJvZHkpfSk7CiAgICAkKG1zZ0lkKS50ZXh0Q29udGVudD1yLm9rPyhtc2dJZD09PSd0Z01zZycmJnIudGVsZWdyYW0mJnIudGVsZWdyYW0uZXJyb3I/J+KaoO+4jyBTYXZlZCwgYnV0OiAnK3IudGVsZWdyYW0uZXJyb3I6bXNnSWQ9PT0ndGdNc2cnJiZyLnRlbGVncmFtJiZyLnRlbGVncmFtLm9uJiZyLnRlbGVncmFtLnBhaXJlZD09PTA/J+KchSBTYXZlZCBhbmQgY29ubmVjdGVkIHRvIEAnK3IudGVsZWdyYW0uYm90KycuIE5vdyB0YXAgTWFrZSBhIHBhaXJpbmcgY29kZS4nOihyLnJlc3RhcnQ/J+KchSBTYXZlZC4gVGhlIHNlcnZlciBpcyByZXN0YXJ0aW5nIHRvIHVzZSBpdCAoYWJvdXQgMTUgc2Vjb25kcyksIHRoZW4gdGhpcyBwYWdlIHJlY29ubmVjdHMuJzon4pyFIFNhdmVkLicpKTooci5lcnJvcnx8J05vdCBzYXZlZC4gVHJ5IGFnYWluLicpOwogICAgaWYoci5vayl7c2hvd0Nvbm4ocik7aWYoci5yZXN0YXJ0KXNldFRpbWVvdXQoZnVuY3Rpb24oKXtjb25uQ2hlY2tlZD1mYWxzZTtsb2FkKCl9LDE2MDAwKX1yZXR1cm4gcn07CiAgJCgncnBjU2F2ZScpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXt2YXIgdj0kKCdycGNVcmwnKS52YWx1ZS50cmltKCksYz0kKCdycGNDYXAnKS52YWx1ZTtpZighdiYmYz09PScnKXJldHVybjt2YXIgYj17fTtpZih2KWIucnBjVXJsPXY7aWYoYyE9PScnKWIucnBjRGFpbHlDYXA9TnVtYmVyKGMpO3ZhciByPWF3YWl0IHBvc3RDb25uKGIsJ3JwY01zZycpO2lmKHIub2speyQoJ3JwY1VybCcpLnZhbHVlPScnfX07CiAgJCgncnBjUmVzZXQnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7aWYoIWNvbmZpcm0oJ0dvIGJhY2sgdG8gdGhlIGZyZWUgcHVibGljIGNvbm5lY3Rpb24/IFRoZSBzZXJ2ZXIgcmVzdGFydHMuJykpcmV0dXJuO2F3YWl0IHBvc3RDb25uKHtycGNVcmw6Jyd9LCdycGNNc2cnKX07CiAgJCgndGdTYXZlJykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3ZhciB2PSQoJ3RnVG9rZW4nKS52YWx1ZS50cmltKCk7aWYoIXYpcmV0dXJuO3ZhciByPWF3YWl0IHBvc3RDb25uKHt0Z1Rva2VuOnZ9LCd0Z01zZycpO2lmKHIub2spJCgndGdUb2tlbicpLnZhbHVlPScnfTsKICAkKCd0Z0NvZGVCdG4nKS5vbmNsaWNrPWZ1bmN0aW9uKCl7cG9zdENvbm4oe3RnTmV3Q29kZTp0cnVlfSwndGdNc2cnKX07CiAgJCgndGdUZXN0Jykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3ZhciByPWF3YWl0IGFwaSgnL2FwaS9tcC9jb25uZWN0aW9ucycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7dGdUZXN0OnRydWV9KX0pOwogICAgJCgndGdNc2cnKS50ZXh0Q29udGVudD1yLm9rPyfinIUgVGVzdCBzZW50LiBDaGVjayBUZWxlZ3JhbSAoJytyLnNlbnQrJyBwaG9uZScrKHIuc2VudD09PTE/Jyc6J3MnKSsnKS4nOign4pqg77iPICcrKHIuZXJyb3J8fCdDb3VsZG5cJ3Qgc2VuZC4nKSk7aWYoci5ycGMpc2hvd0Nvbm4ocil9OwogICQoJ3RnVW5wYWlyJykub25jbGljaz1mdW5jdGlvbigpe2lmKGNvbmZpcm0oJ1VucGFpciBhbGwgcGhvbmVzPycpKXBvc3RDb25uKHt0Z1VucGFpcjp0cnVlfSwndGdNc2cnKX07CiAgJCgndGdSZW1vdmUnKS5vbmNsaWNrPWZ1bmN0aW9uKCl7aWYoY29uZmlybSgnUmVtb3ZlIHRoZSBUZWxlZ3JhbSBib3QgYW5kIGl0cyB0b2tlbj8nKSlwb3N0Q29ubih7dGdSZW1vdmU6dHJ1ZX0sJ3RnTXNnJyl9OwogIHZhciBtb3ZlQ2FzaD1hc3luYyBmdW5jdGlvbihhbGwpe3ZhciB2PWFsbD8xZTk6cGFyc2VGbG9hdCgkKCd2MmNBbXQnKS52YWx1ZSk7aWYoISh2PjApKXskKCd2MmNNc2cnKS50ZXh0Q29udGVudD0nVHlwZSBhbiBhbW91bnQgZmlyc3QuJztyZXR1cm59CiAgICB2YXIgcj1hd2FpdCBhcGkoJy9hcGkvbXAvc2V0dGluZ3MnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe3ZhdWx0VG9DYXNoOnZ9KX0pOyQoJ3YyY01zZycpLnRleHRDb250ZW50PXIub2s/J+KchSBNb3ZlZC4gSXQgc2hvd3MgaW4gVHJhZGluZyBiYWxhbmNlIG5vdy4nOihyLmVycm9yfHwnTm90IG1vdmVkLicpO2lmKHIub2speyQoJ3YyY0FtdCcpLnZhbHVlPScnO2xvYWQoKX19OwogICQoJ3YyYycpLm9uY2xpY2s9ZnVuY3Rpb24oKXttb3ZlQ2FzaChmYWxzZSl9OyQoJ3YyY0FsbCcpLm9uY2xpY2s9ZnVuY3Rpb24oKXttb3ZlQ2FzaCh0cnVlKX07CiAgJCgndjEwQnRuJykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe2lmKCFjb25maXJtKCdTdGFydCB0aGUgVjEuMCB0ZXN0PyBBIGZyZXNoICQxLDAwMCBwYXBlciBhY2NvdW50IHdpdGggMSUgYmV0cywgYXQgbW9zdCAzIHBvc2l0aW9ucywgYSAzJSBkYWlseSBsb3NzIGxpbWl0LCBzdHJpY3Qgc2FmZXR5IGNoZWNrcyBhbmQgc3RhZ2VkIGV4aXRzLiBUaGUgb2xkIHJ1biBpcyBzYXZlZCBhcyBhIHN1bW1hcnkuJykpcmV0dXJuOwogICAgdmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtwcm9maWxlOid2MTAnfSl9KTskKCdmcmVzaE1zZycpLnRleHRDb250ZW50PXIub2s/J+KchSBWMS4wIHRlc3Qgc3RhcnRlZDogYSBmcmVzaCAkMSwwMDAgcGFwZXIgYWNjb3VudC4nOihyLmVycm9yfHwnTm90IGRvbmUuIFRyeSBhZ2Fpbi4nKTtpZihyLm9rKXskKCdzZXQnKS5pbm5lckhUTUw9Jyc7bG9hZCgpfX07CiAgJCgnZnJlc2hCdG4nKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7aWYoIWNvbmZpcm0oJ1N0YXJ0IGEgZnJlc2ggcGFwZXIgYWNjb3VudCBvbiB0aGUgc2FmZSBwcm9maWxlPyBUaGUgb2xkIHJ1biBpcyBzYXZlZCBhcyBhIHN1bW1hcnkuJykpcmV0dXJuOwogICAgdmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtyZXNldDp0cnVlLHNhZmU6dHJ1ZX0pfSk7JCgnZnJlc2hNc2cnKS50ZXh0Q29udGVudD1yLm9rPyfinIUgRnJlc2ggc3RhcnQ6IGEgbmV3IHBhcGVyIGFjY291bnQgb24gdGhlIHNhZmUgcHJvZmlsZS4nOihyLmVycm9yfHwnTm90IGRvbmUuIFRyeSBhZ2Fpbi4nKTtpZihyLm9rKXskKCdzZXQnKS5pbm5lckhUTUw9Jyc7bG9hZCgpfX07CiAgdmFyIG93bmVyRm9ybVNob3duPWZhbHNlOwogICQoJ3NhdlNhdmUnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtzYXZpbmdzV2FsbGV0OiQoJ3NhdncnKS52YWx1ZS50cmltKCl9KX0pOwogICAgdGhpcy50ZXh0Q29udGVudD1yLm9rPydTYXZlZCDinJMnOihyLmVycm9yfHwnTm90IHNhdmVkJyk7dmFyIGI9dGhpcztzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nU2F2ZSB3YWxsZXQnfSwxODAwKTtsb2FkKCl9OwogICQoJ3NlbmROb3cnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtzZW5kVmF1bHQ6dHJ1ZX0pfSk7dGhpcy50ZXh0Q29udGVudD0nU2VudCDinJMnO3ZhciBiPXRoaXM7c2V0VGltZW91dChmdW5jdGlvbigpe2IudGV4dENvbnRlbnQ9J1NlbmQgdmF1bHQgdG8gbXkgd2FsbGV0IG5vdyd9LDE4MDApO2xvYWQoKX07CiAgJCgncmVzZXQnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7aWYoIWNvbmZpcm0oJ0NsZWFyIGFsbCBwYXBlciByZXN1bHRzIGFuZCBzdGFydCBmcmVzaD8nKSlyZXR1cm47YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtyZXNldDp0cnVlfSl9KTtsb2FkKCl9OwogICQoJ3RvZ2dsZScpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXtpZighc3RhdGUpcmV0dXJuO2F3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7b246IXN0YXRlLm9ufSl9KTtsb2FkKCl9Owp9KSgpOwo8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg==";
/*ALKAID_EMBED_END*/
