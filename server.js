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
  auto: { log: [], typeAt: {}, eqPeak: 0, dd: 0, lastPause: 0, lastDefense: 0 },
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
    for (const k of ["bank", "closed", "report", "skips", "events", "startedAt", "seen", "outcomes", "auto"]) if (d[k] != null) MP[k] = d[k];
    if (!MP.bank || !Number.isFinite(MP.bank.cash)) MP.bank = mpNewBank(MP.settings.startUsd);
    if (MP.bank.pauseWhy === "daily stop") { MP.bank.pausedUntil = 0; MP.bank.pauseWhy = null; MP.bank.dayPnl = 0; }   // the old daily stop misfired
  }
} catch (e) { log("error", `loading ALKAID: ${e.message}`); }
setInterval(() => {
  if (!MP_FILE) return;
  try { const tmp = MP_FILE + ".tmp";
    nodeFs.writeFileSync(tmp, JSON.stringify({ settings: MP.settings, bank: MP.bank, closed: MP.closed, report: MP.report, skips: MP.skips,
      events: MP.events, startedAt: MP.startedAt, seen: MP.seen, outcomes: MP.outcomes.slice(-600), auto: MP.auto }));
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
    if (sr.impactPct > 12) { mpSkipGrad(w, `selling just $100 would move the price ${sr.impactPct}%`); continue; }
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
    if (ch >= R.tpPct) { if (R.tp1SellPct >= 100) { sell(1); why = "take profit"; } else { sell(R.tp1SellPct / 100); sp.moon = true; sp.mh = px; } }
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
function mpEquity() {
  const B = MP.bank, S = MP.settings;
  return B.cash + B.vault + (B.sent || 0) + MP.positions.reduce((a, p) => a + (p.tokensLeft == null ? p.tokens : p.tokensLeft) * p.last * (1 - S.feePct / 100), 0);
}
function mpAuto(text, kind) { MP.auto.log.unshift({ at: Date.now(), text, kind }); if (MP.auto.log.length > 60) MP.auto.log.length = 60; mpEvent("Autopilot: " + text); }
const mpEntryType = (x) => x.entryType || (x.fast ? "launch shot" : "at 90s");
function mpAutopilot(now = Date.now()) {
  const S = MP.settings; if (!S.autopilot || !MP.bank) return;
  const A = MP.auto, B = MP.bank, eq = mpEquity();
  A.eqPeak = Math.max(A.eqPeak || 0, eq, 0.01); A.dd = +Math.max(0, (1 - eq / A.eqPeak) * 100).toFixed(1);
  // 1) drawdown brakes
  if (A.dd >= S.ddBrake2Pct && now - (A.lastPause || 0) > 12 * 3600e3) {
    Object.assign(S, PROVEN_V2); B.pausedUntil = now + 8 * 3600e3; B.pauseWhy = "drawdown brake"; A.lastPause = A.lastDefense = now;
    mpAuto(`down ${Math.round(A.dd)}% from its peak: paused new trades for 8 hours and switched to the safest settings`, "brake"); A.eqPeak = eq;
  } else if (A.dd >= S.ddBrake1Pct && now - (A.lastDefense || 0) > 12 * 3600e3) {
    Object.assign(S, PROVEN_V2); A.lastDefense = now;
    mpAuto(`down ${Math.round(A.dd)}% from its peak: switched to the safest settings`, "brake");
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
function mpAutoPublic() {
  const S = MP.settings, A = MP.auto, eq = MP.bank ? mpEquity() : 0, b = MP.bank || {};
  return { on: !!S.autopilot, equity: +eq.toFixed(2), peak: +(A.eqPeak || 0).toFixed(2), ddPct: A.dd || 0, brake1: S.ddBrake1Pct, brake2: S.ddBrake2Pct, slots: S.slots, autoSlots: !!S.autoSlots, slotsNote: A.slotsNote || null,
    paused: b.pausedUntil > Date.now() ? b.pauseWhy : null, log: A.log.slice(0, 12) };
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
function mpOnTrade(tr) {
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
    buys5: +m5.buys || 0, sells5: +m5.sells || 0, vol5: +vol.m5 || 0, pair: p.pairAddress || null, createdAt: p.pairCreatedAt || null };
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
      if (ch >= R.tpPct) {                           // offense: lock the win, keep a free ride
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
 * VIEW-ONLY SHARING. The owner creates a secret link; whoever opens it can WATCH the dashboard
 * (trades, balance, decisions, rules) but every change stays owner-only. Turning the link off,
 * or making a new one, instantly locks out the old link and every pass it handed out.
 * Only the link's fingerprint is stored, on the server's disk.
 */
const SHARE_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "cannon-share.json") : "";
let shareInfo = null;                       // { id, hash, at }
try { if (SHARE_FILE && nodeFs.existsSync(SHARE_FILE)) shareInfo = JSON.parse(nodeFs.readFileSync(SHARE_FILE, "utf8")); } catch {}
function saveShare() {
  if (!SHARE_FILE) return;
  try { if (shareInfo) { const t = SHARE_FILE + ".tmp"; nodeFs.writeFileSync(t, JSON.stringify(shareInfo), { mode: 0o600 }); nodeFs.renameSync(t, SHARE_FILE); }
        else if (nodeFs.existsSync(SHARE_FILE)) nodeFs.unlinkSync(SHARE_FILE); } catch (e) { log("error", `saving share link: ${e.message}`); }
}
/**
 * Wallets that may WATCH ALKAID by signing in with their own wallet (no tokens needed).
 * View-only: every change stays owner-only. Add a public wallet address, upload, done.
 */
const VIEWER_WALLETS = [];
/** Pure-ish: who is this pass? "owner", "viewer", or null. */
function cannonRole(p) {
  if (!p) return null;
  if (MY_WALLET && p.w === MY_WALLET) return "owner";
  if (VIEWER_WALLETS.includes(p.w)) return "viewer";
  if (shareInfo && p.w === "viewer:" + shareInfo.id) return "viewer";
  return null;
}
function requireReader(req, res) {
  const role = cannonRole(readPass(String(req.headers.authorization || "").replace(/^Bearer\s+/i, "")));
  if (!role) { res.status(403).json({ error: "This link was turned off or has expired. Ask the owner for a new one." }); return null; }
  return role;
}
/** Owner: turn the share link on (a fresh one each time) or off, or see whether it's on. */
app.get("/api/mp/share", (req, res) => { if (!requireOwner(req, res)) return; res.json({ on: !!shareInfo, since: shareInfo ? shareInfo.at : null }); });
app.post("/api/mp/share", (req, res) => {
  if (!requireOwner(req, res)) return;
  if ((req.body || {}).action === "off") { shareInfo = null; saveShare(); log("access", "share link turned off"); return res.json({ on: false }); }
  const token = crypto.randomBytes(24).toString("base64url");
  shareInfo = { id: crypto.randomBytes(6).toString("hex"), hash: crypto.createHash("sha256").update(token).digest("hex"), at: Date.now() };
  saveShare(); log("access", "new view-only share link created");
  res.json({ on: true, token, since: shareInfo.at });
});
/** Anyone with the link: trade it for a 7-day view-only pass. */
app.post("/api/mp/view", rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Too many tries. Wait a minute." } }), (req, res) => {
  const t = (req.body || {}).token;
  if (!shareInfo || typeof t !== "string" || t.length > 100) return res.status(403).json({ error: "This link was turned off. Ask the owner for a new one." });
  const a = Buffer.from(crypto.createHash("sha256").update(t).digest("hex")), b = Buffer.from(shareInfo.hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).json({ error: "This link isn't valid anymore. Ask the owner for a new one." });
  res.json({ pass: issuePass("viewer:" + shareInfo.id, 7 * 24 * 3600e3), role: "viewer" });
});

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
  if (role === "viewer") {                     // watchers never get the owner's wallet addresses
    bank.savingsWallet = null; bank.sends = (bank.sends || []).map((x) => ({ at: x.at, usd: x.usd, why: x.why, paper: x.paper }));
  }
  const settingsOut = role === "viewer" ? { ...MP.settings, savingsWallet: undefined } : MP.settings;
  res.json({ role, mode: "paper", on: MP.on, fast, startedAt: MP.startedAt, solUsd: sol, settings: settingsOut,
    feed: { ...MP.feed, subId: undefined, perMin: MP.launchTimes.filter((t) => Date.now() - t < 60000).length }, tape: MP.tape.slice(0, 30), seen: MP.seen, queued: MP.queue.length,
    stats: { trades: done.length, wins, winRate: done.length ? Math.round((wins / done.length) * 100) : null, pnlSol: +pnl.toFixed(4), pnlUsd: sol ? +(pnl * sol).toFixed(2) : null,
             best: done.length ? Math.max(...done.map((x) => x.pnlPct)) : null, worst: done.length ? Math.min(...done.map((x) => x.pnlPct)) : null },
    skips: MP.skips, open, closed: done.slice(0, 60), evaluated: MP.evaluated.slice(0, 60),
    bank, events: MP.events.slice(0, 20), learned: mpLearned(done, MP.settings.learnMin), filterReport,
    scorecard: mpScorecard(done.filter((x) => x.pnlUsd != null), MP.bank.start), lab: labPublic(),
    graduate: gradPublic(), copy: copyPublic(), experiments: expPublic(), grid: gridPublic(), top100: topPublic(), autopilot: mpAutoPublic(),
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
  clamp("autopilot", 0, 1); clamp("autoSlots", 0, 1); clamp("ddBrake1Pct", 5, 90); clamp("ddBrake2Pct", 10, 95); clamp("killAvgPct", -90, -1); clamp("killMinTrades", 5, 100);
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
  if (b.reset === true) { MP.closed = []; MP.positions = []; MP.evaluated = []; MP.skips = {}; MP.seen = 0; MP.startedAt = Date.now();
    MP.bank = mpNewBank(S.startUsd); MP.report = {}; MP.outcomes = []; MP.events = []; MP.auto = { log: [], typeAt: {}, eqPeak: 0, dd: 0, lastPause: 0, lastDefense: 0 }; mpEvent(`Started fresh with $${S.startUsd}`); }
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
  [{ text: "📰 Morning report", callback_data: "report" }],
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
  if (cmd === "/pause" || cmd === "/resume" || cmd === "/defense" || cmd === "/balanced" || cmd === "/offense") return tgCallback(chat, "ask:" + cmd.slice(1));
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
  { command: "vault", description: "Vault and savings" }, { command: "report", description: "24-hour report" }, { command: "pause", description: "Stop new trades" },
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
    engine: { running: MP.on && MP.feed.connected, tradesRead: MP.feed.trades || 0, graduationsSeen: MP.feed.grads || 0, telegram: TG.on },   // details are owner-only (/api/mp/state)
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
const ALKAID_EMBED = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgaHR0cC1lcXVpdj0iQ29udGVudC1TZWN1cml0eS1Qb2xpY3kiIGNvbnRlbnQ9ImRlZmF1bHQtc3JjICdzZWxmJzsgc2NyaXB0LXNyYyAnc2VsZicgJ3Vuc2FmZS1pbmxpbmUnOyBzdHlsZS1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyBodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tOyBmb250LXNyYyBodHRwczovL2ZvbnRzLmdzdGF0aWMuY29tOyBpbWctc3JjICdzZWxmJyBkYXRhOjsgY29ubmVjdC1zcmMgJ3NlbGYnIGh0dHBzOi8vc2xhcGJvdC1iYWNrZW5kLXByb2R1Y3Rpb24udXAucmFpbHdheS5hcHA7IG9iamVjdC1zcmMgJ25vbmUnOyBiYXNlLXVyaSAnbm9uZSc7IGZvcm0tYWN0aW9uICdub25lJzsgdXBncmFkZS1pbnNlY3VyZS1yZXF1ZXN0cyI+CjxtZXRhIG5hbWU9InJlZmVycmVyIiBjb250ZW50PSJuby1yZWZlcnJlciI+CjxtZXRhIG5hbWU9InJvYm90cyIgY29udGVudD0ibm9pbmRleCwgbm9mb2xsb3ciPgo8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHZpZXdwb3J0LWZpdD1jb3ZlciI+Cjx0aXRsZT5BTEtBSUQ8L3RpdGxlPgo8bWV0YSBuYW1lPSJ0aGVtZS1jb2xvciIgY29udGVudD0iIzA3MDYwRCI+CjxsaW5rIHJlbD0icHJlY29ubmVjdCIgaHJlZj0iaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbSI+CjxsaW5rIHJlbD0icHJlY29ubmVjdCIgaHJlZj0iaHR0cHM6Ly9mb250cy5nc3RhdGljLmNvbSIgY3Jvc3NvcmlnaW4+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9U3BhY2UrR3JvdGVzazp3Z2h0QDUwMDs3MDAmZmFtaWx5PUpldEJyYWlucytNb25vOndnaHRANTAwOzcwMDs4MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQiPgo8c3R5bGU+Cjpyb290ey0tYmc6IzA0MDkxMjstLXBhbmVsOnJnYmEoOCwxNywzMiwuNzQpOy0tcGFuZWwyOnJnYmEoMTQsMjgsNTIsLjc4KTstLWxpbmU6cmdiYSg3NywyMjQsMTI1LC4yMCk7LS1saW5lMjpyZ2JhKDc3LDIyNCwxMjUsLjQyKTsKICAtLWluazojRUFGNEZGOy0tYXNoOiM5M0E5QzY7LS1kaW06IzVDNzM5MTstLXZpbzojM0ZEMDdBOy0tbWludDojNTVGMDhGOy0tZ29sZDojRjJDMTRFOy0tdXA6IzNEREM5NzstLWRvd246I0ZGNUE2RTsKICAtLWhlYWQ6J1NwYWNlIEdyb3Rlc2snLHN5c3RlbS11aSxzYW5zLXNlcmlmOy0tbW9ubzonSmV0QnJhaW5zIE1vbm8nLHVpLW1vbm9zcGFjZSxNZW5sbyxtb25vc3BhY2V9Cip7Ym94LXNpemluZzpib3JkZXItYm94O21hcmdpbjowO3BhZGRpbmc6MH0KaHRtbCxib2R5e2JhY2tncm91bmQ6dmFyKC0tYmcpO2NvbG9yOnZhcigtLWluayk7Zm9udC1mYW1pbHk6dmFyKC0taGVhZCk7LXdlYmtpdC10ZXh0LXNpemUtYWRqdXN0OjEwMCV9CmJvZHl7bWluLWhlaWdodDoxMDB2aDtiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudCg3MCUgNDUlIGF0IDg1JSAwJSxyZ2JhKDc3LDIyNCwxMjUsLjIwKSx0cmFuc3BhcmVudCA2NSUpLHJhZGlhbC1ncmFkaWVudCg2MCUgNDAlIGF0IDAlIDIwJSxyZ2JhKDYxLDI0MiwxNjMsLjEwKSx0cmFuc3BhcmVudCA2NSUpLHJhZGlhbC1ncmFkaWVudCg1MCUgMzUlIGF0IDUwJSAxMDAlLHJnYmEoNzcsMjI0LDEyNSwuMTApLHRyYW5zcGFyZW50IDcwJSksdmFyKC0tYmcpfQouYnJhbmRyb3d7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweH0KLmJyYW5kcm93IGltZ3t3aWR0aDo0NHB4O2hlaWdodDo0NHB4O2JvcmRlci1yYWRpdXM6NTAlO29iamVjdC1maXQ6Y292ZXI7Ym94LXNoYWRvdzowIDAgMCAxcHggcmdiYSg3NywyMjQsMTI1LC41KSwwIDAgMjJweCByZ2JhKDc3LDIyNCwxMjUsLjM1KX0KLmdhdGUgLmVtYmxlbXtkaXNwbGF5OmJsb2NrO3dpZHRoOm1pbig4NnZ3LDQ0MHB4KTthc3BlY3QtcmF0aW86MS8xO21hcmdpbjowIGF1dG87Ym9yZGVyLXJhZGl1czoyMnB4O2JveC1zaGFkb3c6MCAwIDAgMXB4IHJnYmEoNzcsMjI0LDEyNSwuNSksMCAyMHB4IDYwcHggLTEwcHggcmdiYSg3NywyMjQsMTI1LC41KSwwIDAgODBweCByZ2JhKDYxLDI0MiwxNjMsLjE0KX0KLmdhdGV7bWF4LXdpZHRoOjUyMHB4IWltcG9ydGFudH0KLnRva257Zm9udDo2MDAgMTJweCB2YXIoLS1oZWFkKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbi1sZWZ0OjZweH0KLmNhe2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweDttYXJnaW4tdG9wOjRweH0KLmNhIGNvZGV7Zm9udDo2MDAgMTAuNXB4IHZhcigtLW1vbm8pO2NvbG9yOiNCN0NDRTY7d29yZC1icmVhazpicmVhay1hbGw7LXdlYmtpdC11c2VyLXNlbGVjdDphbGw7dXNlci1zZWxlY3Q6YWxsfQouY2EgYnV0dG9ue2ZsZXg6bm9uZTtmb250OjgwMCAxMC41cHggdmFyKC0tbW9ubyk7cGFkZGluZzozcHggOHB4O2JvcmRlci1yYWRpdXM6N3B4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKTtjb2xvcjp2YXIoLS1pbmspO2N1cnNvcjpwb2ludGVyfQouY2EgYXtmbGV4Om5vbmU7Zm9udDo4MDAgMTAuNXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLW1pbnQpO3RleHQtZGVjb3JhdGlvbjpub25lfQphe2NvbG9yOmluaGVyaXR9YnV0dG9uLGlucHV0e2ZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0fQo6Zm9jdXMtdmlzaWJsZXtvdXRsaW5lOjJweCBzb2xpZCB2YXIoLS1taW50KTtvdXRsaW5lLW9mZnNldDoycHh9Ci53cmFwe21heC13aWR0aDoxMTAwcHg7bWFyZ2luOjAgYXV0bztwYWRkaW5nOjE0cHg7cG9zaXRpb246cmVsYXRpdmU7ei1pbmRleDoxfQovKiBBbGthaWQgd2F0ZXJtYXJrOiBzZWUtdGhyb3VnaCwgZmFkZXMgb3V0IGF0IHRoZSBlZGdlcywgc2l0cyBiZWhpbmQgZXZlcnl0aGluZywgY2FuJ3QgYmUgY2xpY2tlZCAqLwouYWxrLXdte3Bvc2l0aW9uOmZpeGVkO2xlZnQ6NTAlO3RvcDo1NCU7d2lkdGg6bWluKDk2dncsNzAwcHgpO2FzcGVjdC1yYXRpbzoxLzE7dHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO3otaW5kZXg6MDtwb2ludGVyLWV2ZW50czpub25lOwogIGJhY2tncm91bmQ6dXJsKCJkYXRhOmltYWdlL2pwZWc7YmFzZTY0LC85ai80QUFRU2taSlJnQUJBUUFBQVFBQkFBRC8yd0JEQUEwSkNnc0tDQTBMQ2dzT0RnMFBFeUFWRXhJU0V5Y2NIaGNnTGlreE1DNHBMU3d6T2tvK016WkdOeXd0UUZkQlJreE9VbE5TTWo1YVlWcFFZRXBSVWsvLzJ3QkRBUTRPRGhNUkV5WVZGU1pQTlMwMVQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMC8vd2dBUkNBSXdBakFEQVNJQUFoRUJBeEVCLzhRQUdnQUFBd0VCQVFFQUFBQUFBQUFBQUFBQUFBSURCQUVGQnYvRUFCZ0JBUUVCQVFFQUFBQUFBQUFBQUFBQUFBQUJBZ01FLzlvQURBTUJBQUlRQXhBQUFBSDVnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU9uQ3JtYzFDWlRSTlpuZUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQllpZWxyazhmVjZDcENvRDlqTkxyblJkSmxEVTJNTnk1T2wwbnc3azFYWHlUMTVIbWxvMmdBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFkMnBpMStwV1ROYnVaTGM4M0t2cTU4SFZ2THJIWWJjZ3VudXdaSldUeVRVaXpHcldkMDZXZkx5Tm5NdFRTUlpFeTdXWEFhTTlvQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT0pxMzc1blBmbm5wdXcrYXEwbGZRdU91eGpNOXhKVTR4NXpSMksrcWZVOC9UaHVYaHN5SEdJcnlqeUdXbkNTMzRaM2RDajV1bWpzMlNVZGd1TVpiUUFBQUFBQUFBQUFBQUFBQTUwQUFBQUFBOU5NM3RVV1piTGk4OWJSdHRYSnJzNkoxd1hqOEY0M1F3ZWo0cHpmazFycHo2Y0V5MHJRbWR1ZW5OYmxLaXJTRHVuQ2RGT2RCVG9JdEFnenFVN0NoYUZHTVJzeDJnQUFBQUFBQUFBQUFBQUFBQUFCMDl4SitnWkptdmtaaHJWSmRwM1ZDS2J1NHJsdUhSZWQ0Y3NyR0x6YndYVHNocVRubTdNTW11R25QbkZMNU5ldFplT3QxSFZsc3FkcEVwd0FEb28vU2ZLb0p4WjFXbVo0dmJQMHpjOVB6YTRBb0FBQUFBQUFCem9BQUFBZFBaUjlhNUpsOGVmMVY4dlp0a1k4WHM5UEMzdGdYMTVlWHFSMjBoTzJlaHBqbzh3eGRXeTZ0bWVpWXN6cko2R1habHp6anJ5YU5kR2hxeVdvTWk2WnN5VHJRWG5ad0x4Z282RGlPekNkcUNkV1pmVGtZemM5UHpLQUZBQUFBQUFBQUFBQTJwbzlMa3BsUEU5U2ErWUhiZFBwK0oyVDZKUEozcFdkMFBOeWUzSmZKdVoxOVczaVZUMmZHdmxGMTV0eTNqcTg5bFp2T1QwOHVqTm5FdFVLWFZJVlM2bEtrOWFyYks4V3p6VTZvMUs3T0s3a2NKektUWHB6bHBEMHJBdFRQY3dHbk5hQUFBQUFBQUFBQlgzcytpWlBEMFlsdjdubTNUelorejVCemo5V2ZXZVJ2UTh0VTl4UE0yMDJmYWkrVFAxc3k0aGxLZWhqM28zbGJ2T2t0T2lGMHJFb2p4UzlNK2hjcVdsZExQdks0M2FpVW9TSEVRYVp3RGppMGZPYzBSMUttZGxHcEdwczgrMnM4c0MwQUFBQUFBRGJqOTJTMmEzaXBQUm95TDZNNnVqWkcySjVzNjBreThxbHRjZm81SklkWmJxMjd5dUh0ejgvYWN5K2dobjJJeGd5T2hkSzhORVhtSU1ITkVpUnBhSTJ3cmZoemlSS3pRTzlValJDNnB4bXpuRHQ3YVJlQ3IzdmFWdVVDMldrTms5VHpLQUZBQUFBT20vd0JGT3pPUHpLVVhYalBRUmRQa2VvTk91WXBoOVRDalBtYVRUbDJ6bWNhVmJYVE10VldmS29WMitaeFBhejVBaGFQb0VIemJDSEZWYmNaRWVmQTBrWWxvekY2RGlkNHh4dTJtYXkxeG1NOWtqZGF1a0ZSRHQwSFNxU3ZsQzAyaXp4MkhsZ1dnQUFCc3grekpiRnM4Vk9iOHV4Y20yTVU0K3p6RDJEUGNob2wweG1uTWphOGVtWlNQYnJYSG9oZFoyMDVWYUhkUmlOdWNUMDVKWmkzWTlNc28yaWFZMnpscDFtSW15aGlyM05WVWR3YmpTT3l3em5UbHZub3RIWmRKbGVhOTZjQzZNUlRvUHpwVHZKb3BqOUx6YUFGQUMzcjRkc3pIeTlFMTBYU2ljdytqbnJSazV0anpQVDh5cTdvWDRqNXUya2hiTlpsRnNpemVEWFU3THhhWkthVXk2NFpsOWp5Nlp5NmFzQmVGNDFlRk94MithWnJ4cmNuWGpDZHRNNU5hbmJUYVlWK3FYeld5WFM5T3FDNkJzOVlDdXIwZENCbDZhc05kQjU0Rm9EbnFVV2N6NXRvK2lxNkc2bHJZWUc3UGttVXlNcTdiK2I2Q0xRZ05EWmpSM2c4UG11bHRzM2FpektLbWlNVHN0b2pZOUtpeHJ4WlhuVXp2U1k4SDlJek4zemlsTzV4Nzl6R2lLaWQyeTRKSTZ2ZWQ0VXRDUld1YnBwU0xoeHdSamgzVmsxbm1uZVdtalB0VFprMWVkSm9URzYxbjFpSnBZeUcxakMyN3BpMDZXU2EzRE8xbFRBelRYdFpkSTYwZ2Q3b3pMVW5SSmFFMEdUVDUvcHhoU2s2dDFvQ1diMHhNM2ZNQ3N0S3hlTzBoRURycHJIeTI0bWRxOFdTMjRSNVVxUlFKajhYblRnM1U0bDZTSXBsMzRLUFE4LzBvcjVtL0lGcVVTWGE5SjA1TXNaME5iZWVpYjE4L2k3WlplRnBjRjdhUG9wbnY2VVRMaDE1QzZ3M0dZYlFSMDloSkRSMmNrMHRNMFk5ZWN2V0NXNStWNWRQRytjMUl2QmVhQXpsSkhXUUt0SHFWN0ppZ25CaFJlcjFpZmFjRUhEbkhtYS9QOUR6Njc2UG4rakNxWVRjdVFUU2tRYmpFTDN2RXIyTlVqelJOWmxlVzgwWmtYZEdkVE91NE0yamtqWTNtM1M4YVZrd1gxTEpmejdjemhwNjBtSWpKZHhucE5iek5XZDF3VkxYVHJFdTE0TDBVWmVkRHZXVG5XN0l5cHdVWVZlOVVZUXB4UXB4WFhWNTNvK2RUZWg1L29RbUhmSm5OVFRiTXlOb1puR2JDTVp0REh6YUdSOUU2VHVmbDNvbnhyWlRzaXlLOUlsd20vZW9xTTBJN3RNODBwZm53MnkyUnZrOHlHdlBQWkNlaWZUdElvdDBxdVd6S0JQbE9Dc09MeW5CTzhFZnV1Mk9mbkhvOFR6K2VnTDU1dkREemVIbjg5Q2R1WHRaM1ZzTzNGclhkMkhiQTg4eWJ1Wm5IbFYweWQyTEdYdDFxWE84VTRBcXZ4VUg2Y29xRnVaK2xFZXBLd3FWTTZTYWVKV1RsWGhqbnVta3B6YVQzMTF5OUlhM2RjdE5hN0s3TG1vOGluSWhWTzlKOHJ3V2t3MHRsN002Vmt5SnpUTlpGZ200aTBKTFZTVlZ0ajJZcU51SFpENGR1UW9jYWs2NUN0emhSODZtNHhNbWxaTUV0REdOZGtGbFZMcHpzVVc2T2hMVkJ4NlEySktOQ1R2RWFTc3V5TldiUmpxN3JtYTFTbHlxUzBRVzFKSWFFejJSWjY0RXk3TG1yVlVPb3BaWmNXbkpnM09kT0RBdlFydEZJMDROMkdqVmwwRjVVaEpXY3FLaHA2WmU2VXFUY1VmaUVNdldwTEZJWExTUjNxc2d5MlhtZG5xc082bzBLZWNuTkdhcXJvaFdRa3kxb2cvRGljRnFuSFJHNHl5ck5oQmxPOEJHcEdnVHZKVjczaDNxQTNCaEMzYWdYV0VaVU5VYVNOT0xaam90RjExVGZrekR2S0xIdFVydGNyR3ZpUmpzeHFkaTBFdXhSZWQ2Y2ExWklMZkhhWFZGcnBUR2NLV0VhS0ZlbkVBVlNzTEhaem9MMnNodWM2TktpalBLMGtlYllzNTJPWFZPOEJPdHhaMFZEVXNXcnFDUjNqZHBXNzBySFJLSHkyamFkNEd0cFVtWVB3VnVkQmFjQkk5NVhhOFlmdlpTY25XMGtMcWtqb25MZXB5bDBQTmlkZVJMU3JyRnhYa2pJM0laS1Rybzhsb3RFSjFKbEo5b1RkUVYrY0xObnBNMmt6U1FiUk1tbzJ0TE4rck5sS3RHaEM5NTBMVHVSZU5US0JhQUZMNWRVaEswVVk0eXRGNFVPdFFxalNMSVUwNStkTFRxU0wycUpuZGt1Mm10U2V1Y1RSRmFUS3ZVa0ovVStWbmw1a3JTMTE3Snk2ck41VlZOV09aNmpGMzNxY0t6ZnFkNVNreXNOZVE1b3o4VitLMXZlQXZFb2dVazV4bFlheW9rMjdDM2dDZ0FYZ3lhQWVTRHB4VTV5aXMzSFRzK3pSZWRGRzdwazRWeHN0eExyQnJSQ1lYWE9qSE5VYVRDMVVrdjlCODE2ZU9Fdk4rcStZYWozcHZ1aWFzOVVwbjB5Wk9WbnJYTzhGYnJPa3FjU1RkQmRVeGhYWkc3ajNoYTNlQnp2VlZPc2xQMVdqUmwwNXg4OUoyZ0FBQUFhR2hhVHViVm1PMDR3ZDdNNHZlb3Q2eW1hUUZYVG1zU0pxaHdqeHRHdFpMM21yOXpzang2dWM2WjFXWjErM1B3ODhlNTA5UnZ6K2ZUOForYmo5VDVOdmtBYjczUmx0UkxNUWRwbXpLMU01UzY5VE5mT1c2OHJhSk1iV2xkSjA3YUkzVm5zalF6T3EwZ0NnQUFBQUY0TVhaR21adUl2ZVRzbEVtU0FwYjF1Mmt0anV5WmRhd3V0V2VhanB3VXRLcHhLVG1kYTlYT0VYbkxXM1lOOHpsSm90dVNwYkowcmRrcXdxclNGbzBlbFVIUjlPWHVjY2pzekxNRFdxNk1STTNoU1NzeWFicXVHa3dreTJnQUFBQUFBQUZLWjdKYlBTa21UdkdVNXpwMjcwbVVFbmJWSnF0RTUwNGRVYm5DbXJPa2RsZUV6cVZsbVk4QzY3dXc3czR3by9OYldpdVN0QzF2STFSVHZPZ2NZWHZlSFdsMHZUTTB6VFBwbVM0ZHV1ZE9vMnA4QnpuWjJnQ2dBQUFBQUFBQjNnWDdHaVVoYTBrK3hWWFZDbTRkam5SUmxhOVo5Rmtpc0tWbWNEODdiNkhtK3A1bWM2Tzg3TXJHNzYxeGNtbVNHdkpwdDdHMFlodXliYmNlM0RySDBlTFZLWnZYODYyTGRtMVRpc0tNSE84NFY0blR1NHlwTlJGT0JhQUFBQUFBQUFBQUFBNkJaNHNqUzBjaVBlY3J2S1hNMmxZR3VPY0cwWnRVbDluaU5NNzhlL3dBNDlieS9RelJObmtqeUkzVnJLU0hlWmJka1lYRjFaTkJtMll0eGcwYXJJbmxQSzZvUzZycDFoVzV3Zml2UzZxNTRJQ2dvV2dBQUFBQUFBQUFBQUFBQURvRm5pNldWYXlRbjNxcU1Wem9CenBCenFqTWpneXNuZW5jNWh6dk5hN3F6YXM1eXF5M1hYU3B4WGxYT2lxd2NPT3JBSFJlUHlrWm1oTi9jQ1VpSXB3TFFBQUFBQUFBQUFBQUFBQUFBQUFaUXIyVHBvU2J5SVhrS2Q1YUFSempLY2VkS084SXZ6cXpFdUJkZDJZOXVjWXVNdDEyMGRKR2JMYjFIUlc1MVJtNTBBY1I3MlJGenlEZ2x2ZUFvQUFBQUFBQWNPZ0FBQUFIT2dBQUFBQUFBQXp5NlVyQnBMelN5U0xjSkszRm02c2RPOEhaSG1JZ05OdHhicGpDckxkTnB6YVV5cjNsMjAzVTZjYXV2ZWtTMFpzeWFzdk9XOVhnb0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFkNEZDZlVla3VtanVma2xFYXhGZElaNlVhVEdXVzFkdVhYbkdGYTl1cDBvOVl1YTJYSG9ybU5IY1FVbWN0N3hlSGVBb0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFEZFFLRStvNHZUdmVkS05Fa3YzT0YwbUhWQzBPY0dFNFB4UlFBQUFBQUFBQUFBQUFBQUFBQUFBUC9FQUM0UUFBSUJBd0lHQVFNRkFRRUJBUUFBQUFFQ0FBTVFFUkl4QkJNZ0lTSXlNeU13UVJSQVEwUlFORUlrWVAvYUFBZ0JBUUFCQlFML0FQUzRNNWJ6a1ZaK25yVDlQV25JcXpsdVA5dGFidEJ3cndjTlRFMFVGbXBST2M4NTFTY3g1ekhuTWVjMnBPZlZuNmg1ekVNeHd4bklvbUhoS2thbTZmNlMwMmFMdzBDSXN5ZW5VczFyT1lzNWl6bUxOYXpVc3lPamFDdlVFTFVuaG9JMGFrNmY1cWNPelJhS0owR29naHJ3MW1NTHNZcStOcUM1cVJoa1dYZGdWT296V1pyRXlMaDJFT2g0MUUvNU5QaDJhTFNSSWJOV1JZM0VNWVdKdGd6VE5IZXY0aFJrNlpUWENWamhRY2gxdytJUkc4a0V4TVd5Uk5jemZJTWFuL2kwcUxWSWxGRWhoSUVmaVFJOVJuc0ZncHpSTk14S1lsUTZtcGl4N1NzY3ZSUGhVMmgycHcrTFRFeE1URmcwRFg3Tkdwa2Y0S3FXbExoZ3Q2bkVnUm5aempNRk9CSnA2YXAwVTRvN0lQSW5Fd1hhajJjMzJOUVppOU9KaXdPSURiT0lWVjR5bFQrOXBVV3FGRVduYXJXVkpVcXM4eG1MVGdTWW1PbFJLNXl3M0VYc2xZK1BEZk1kOTQvdEczWHVwOFQxNHNEZlBaNmVQM2xEaDh6R0FTQUt2RTVzcVppcEFKanF4RzhReHlhZGpLcHkzRC85RXArcjdSb2g3dUl2MmNUYUEyREZZMU1OKzVBektIRDZiVkhWQWFuT1p1R2FBYVNySjlrVGlHOFpUSGFuN0UyNFg1MjlrOXJIYWJnaUEvWnhNQVFOWUhCS2lzTnYyd0dUUW9oQksxWVU0ekZqZ3hYWklPSURUbEk0ME9rRlZvS3FtYjlBaDJxdGw0SXZwV1BqT0UrZDkxczQ3MlNHZm5veE1Uc0lXQWhiTndiYlFnVndSZy9zd01taFJGTVNyVjB4dUdjZ1Vqa0xpTlNEUnFiTEFTc1RpWjlPcERTbU1RT3dncVJlOEVxTmhZdnRES3A4NXduejFQWVJkbjlZMjRPRENJTW1hWmdXMUNGNFd2aTJuTXhpMjBJRmRmMlc4b1VkQWxhcm9GT3JvWkt5UEQzbW14R1k5QVJnVnNsZGhGcUk4Tk1Rb1JLVzUyNGhyVTVUSGxtR0NjSjg5VDJpWE5sMmlqc1NCTmNMUXRtK0xBWm5ZUXdtWm04QklMcnprL1k4TlJ0VnFhSTJjMnAxblNKV1IrZ3FESG96R0xKV1pZdFpUTUNFNWpIVVlteTlrcW54SHFKd2Z6MVBhVlBrajcyWGVGakMwSnZpd1VtZGhNelZNM1hKc3JGR3JvR1g3L0QwdFJqdUthOFA1SGlxZlNsWmxpVmxhMkxNZ2FOVEl1cnNzTmJLUWJpSHRLcHl5YnpoUG5xZTYrem42Z2o3VDh3dkNiNHNGSm5ZVE9ZVENiNEFFeG9VOWpLYjZHcjA5RGZkUk5iS3VoU1FCVnFhMm91YWJkbUZSTkQ5R01SS3JMRXFxMWlMUFRCaklSMFU5Nlk4aVlUS1h2S2U3ZTFMNUR1dHowWW1JRkpuaUlUTXpQUjZXcENaaDdsVGFrUTZ1cFJ2dVVLZWhaeE5USkF5VlFZb05pVmsxcmZFSGVZN1JhakxGcXExc1RFYW1EQ0NMVXgyVDFxbkNHVWZraWVyKzFMNUl0bTNPeHRpQlNaZ0NFNW1adjBLQ1prSlpWTE0wYTR0VUhPcGZiNGVucWFWbjBLd0lOTVFTb0RFYld0U21OUnBrQzVIYTYxV1dMVlZyRVFpTlRpanNSaVZqNXhMYkIrNEZoQnMyMHhGUW1ZVVFrbWFwbTY5MWlKcUxOZ1dVYUVQWVhBTnFUOHQrSXA2SCt5QmswMTBKbVBVTFZPSVhVdE5zRVcrT29Sa1pOTnZCNHlsVEtZeWg2VnFzc1dvcld4RUhrWXh5WWZHaUY4eWZyRHVpK2huOGEyQ2t6Q2lFa3d0aUU1NlUrTlZ6SGJ0YW1uY25KUGMzUGlxbXlmVnBmWjRaTGNTK0JLRFpWMTB0UmJJakRVdEpwV1hJRVYrMmdHVWZrUFd0UmxpMUZhMVZzSkZYVWF4ODZmZGgzcjA5OWsvOEg0eFl3c0JDeFBXaS9UY3hVWnBvUllHN3ZHNkZFWTVNRVZpcmNVdmwxZ1pLRFNwT0E1MU1xOWtPbHF5NmtVNlNyWkVxREJVNmhVWFNZREVxRFZXVFMwQzZnYmFlaGFoV1ZIMTJvRENzY3NuYWpTK1JUaDZoaVEyMVlCWW00N3pHTEFac0YwZ2ZIcVVSbkxXVDZhSG9FYnNMTGFuOVNsMThPdVduRU4yVVpLeHhocURaV291bHFUNlRaZnB1dzFDN3NWY3FHZ3lDUXJxOU1yYlVERFQ3WXVveWFuaFRqK05DbDhrZnVxN3R2RFlLVE5LckM4RTBnUXhWd1NkSi9odFNYVVdiVVQzTngyQjZVYlEvRXBwcTlWSmRLUjIxTWdnbFlSRHBhcXVwWlNmSWpycVdtMm9WRnZVOVprTkY3SExVMndsU01wRUJLRU9yUnFVS0djTWs0Z3hSbHVJUGVsOGtIZWxQeGlDZ3htaEVqVmJCWm5FV0wzSmZ0RDhNM2plQ3NlaFJITU1GeFkvVTRYcHBqTHlzMkVIY3FJSTR5a3BObGFxNFlIU1EyUkc4VzNoQUIwd1lLTXBFL0dvNGJ6VGVDckdwOWlJbFJrZ1pYaUhBcW5MMEI1MVRtcFMrU1VvZXhYYW5oUTlhRTVnVW1kbG5rNTJqSEFtTW5TRWhKYWN2RVhTb1BRSjZnMkYvd0F5Z2NWSFhTL1J3NHRYYkxKQmRxTENVenBkMTFMS1RZTU1UeFpobVowa01EUEpabFkzWW8ybG5YUzI4OGtJZEtrZW1SWktwRnFQYW5LWHlSUGFwN0tZelpzRXhDOFNtWGpzRkNEQ2s5MTdEWDJDWW5NQ3hBYWoxRGt0MEtJeHlaanI0b1pQUlRHRTJCM1dDQllGbTBxY3ByVlY3eW0yUkhHUWphaFVGZ3hFOFRDTXJCNTA1dkNzU295VFNsUU1wV3plUERvdW8wZmtBeTBxYlJVSmhJV2R6S2RHVmFtSW8xRnpGWFVUaGpyQ3pOdmpwazlDaU4yV2VNeEN2Vjc4SmRmYllWRGltQVNVb3p4RTF3MVlheXcxNGF6UXN4c0RnZzVFUGcyOFlZTmgyTlFZWlcwbXFMYndpYkZhb01hak9JbEFTajhsUDVXSGw3VThLc1p5WXFGaWxJTEsxVEZ2UllQQ25la3NKeWR6ZlhOUm1abVptb3pWTzF2ek9HOXoyTnFJODVXUGNWRldHdERWYUVrOVdscG9hVXdSYmNVNDY1Rng1SktSMURHazNJbkQ1MTF6bXJUR21qU3p6RjdWS205T05uVlRwRXhRRmxhcml5RHU1eWFTNWFvMm8yVUZtZkVib3g5ak16TTJwblRVNGthYTlxRnFwODVnelEwNVpuTG5MRTBDWUZ0NXkzbWlZU2VNSnphcGpObE9scXE5eDJOVHpUb285Z2U3VmZHbFM5NC9kRTlnUHE0bGFycHUzaW83bHZCTDA4S3R1MHdKcG1rOUdKaVltSmk0OVp4WGU5TDFqYnIwQlNaeTJtaFo0VE0xdENacldHcUlheG5NZVpObDcyNUZRZ0E2RDJsSnNGMTBOYytQRFVWelY0aVV2ZjhBSzk2Y1B0VnJhYm9NQW5KcExHeXgwbm96TlJtcVptYlpOdkdZbWs5UTJsVHZ3dGs5VHNLYnRCVHhNSlBHYXpDekdhaE9ZczVzMXNZU2V2R1pRcHNDRFRweHVJQWpjUm1Gc21mSlRWV01GQnB5VVdWM0JIRENWdTlTbVBNanZUamRtRERITEJuTE1DbkxtZmsxRGdOTlluYU5rbjdPYjVNelBHWUUwekJCZzc4TEJ1UFYvVmR0U3ptQ2N5YTJtZWhXRVpjZEtxV25MUlp6VVdOV2N3a215b3pRY094bklwck9aU1NIaVREV3FHYndVSE1SZVduNXBqeXhFOW5USkttMm96WE1xWnBFMFRCdnFtUk1kT0lLWmh4OWtibVVlNlFiL2gvWHAwOUtOcGpKTkpta3phRmliQkdNRkthS1ltdW1zTmN3MVhNM2dvdVlLRTBVMW5OUlp6NFhZd0NJUElpMm96WE5TbWFWTUtUU2JaTTFUSU13SnBtTDZUTkJtaWFnSVdKNk1USFNOenZ3L3RGM2piV0NrekNpYThUVzAxTk5iVFcwMXZOVFFPNG5OZUI2aG1XbXJFTldHb1pxYnBCS3ptUERVWTlBRVVTbW5kMHhERE1YMUdaUFYzbVptWUV4TVRFeE1URXhNVEV4YkUwekVVUnQrSCtVN3J2RE1wRmVqT1pSTTFVSnFvVFZSbXFqTlZHYXFNMVVacW96VlNqTlR3WGFhb0RQT0UxUk9hODVyem12T2JVbk9xVG0xSnpha05Sak9ZMER0QTV3SE1WektWWEVxMU13dVlXTUx0TmJZMW1hMm5NYWN4cHJhYTJtdHByYWFtbm5POHpNek1UaUhWZjFiejlYVW42dXBQMWRTZnE2ay9WdlAxYno5VzgvVlBQMVR4dUlZem1reC9iaC9tTzY3eHR0VSttWm9RemttRlhIUm43R1ROWm1zR1lRemx3b3dzRHBQTm1wR21oVE9XWnBZUVFSRzdsb1laeTNNNWN3Z2hZVFhmUTAwQ2VJbXFhdWdIRTVyVG52T2JtRmUzUmdtYURNTFBHYW8vdHcvd0F6YmplR0J6T1pOWW1SQXhFMVptS1ptaFp5bWhCSFZtZUpuTE1La1d5UkJVSW5OQm4wek9YQ2pDQ0NvMEZXZG1BbFAySjdyM1kxQWtOV0Z5YmFHbWllQW5NbW8zQ3Nab25pSm5veE5MUlN3SlhJMGllSW1xYWpiTXpBZTcrM0QvS2R4dU5wK1ppWW5lYW1tdWFoTXpXMHlETUpPWERUWWRJY3pVcG1sVE9YT1diTDJRVlRPWXBtbEdqTHBsS0hzMU0rY1NWRDVMVHlQcExPYUpyeVhFQXpCU2Fjb0NmVEUxd3NUMGlteG5MbUVFMVltbzJ6TXpQU1BadmFoN1dYYUgyRFRJNmNURTd6VVpyRTFDWm1venhqQlJGQlk4ckViRmhtTXhNVWFqVWFVMXllVUpVVlVoNzAwUGsrOVAzaTlrM05Yc01URmgzSDVETmc1c21tY29HTXBVaFZuak5SbVRNek16Ty8yTXhPN25lbDYyWGFZWFZvQmhwa1RUTzh5WnFtUjA0bUlvT0llaFJITnZSQU5SUmNDcFUwV3A5MUVmMXArOGJzdFAzcUh1SnZiYU4xaXh6MTVtWm1kNWlhVE5NcDR6QjI0ZXlXcVRVWUhtdk04VE5JaHB6Uk5Nd1ozbWJLdVNZeDZSMlV4QjNZNU5KWlVxYUp2YW51ZmJkS2Z1dmRxaGxPSHVlZ1FqQkVQU0xFWU51OXNUVE5FMGdUS3pWQzFrK09QMm9XU3orb21tYlRVWnJnYWFvU3VDMWdMYlJqMDhzNGMyUGlLYTVMdG9GbFNGZ0krNnluN3I3dnVPeWVMUXJqcFBjV05NNHVMYmk0YWExbXN3bVptZWphaks5MTNoOVJmVE1RRE0yakhOaFpmRUh0MEpUTFR3V05uSmlqRTltTGN0YzVpcVduaWtMRTIzVVJQWWRqSDJnYVlCbTF4Q0lJdW9US1BHcGxiaXhzUjBFWTZxa1VaYXFjMUxpMnpkR3dZOW9MS013bkpzaU01OEVoTFBOV0lkZ01scDZEdXhDZ1F2TzVLVWNROXl1MFgyaSt6N29JUmJWTk45eE16SWFBdFRuZzhaR1NDRzJ4aHZ1T2hCbDNPV3BiOUM3Ujk3aUdIdllXTU13WnBWSVhacDJFSnpZd2RnRGlhWVd4TXhLUmFaU2xHY3ZZZHJMdkZoM1gwek1ac0RpZG1oR0xOY05pYWN4YWhVYVVlWU50N2Zpd01ZZENkbG0xTG9TeDdyZjhNYkFXSFlHZmxxdHFmdkF1WmpNRTNPUXNKZ0JKQ0trYXFUWVRFNWJhY1FibVp3c1Bxb3lXVW8weFlOT3h2aVlJbEw1TExWeER2RFkzM0Y2bmlrcTlJc0pzWUlUWVdFTVBSVDN3Qk1aalBrUW13U2E4WFVhalV4cUcxSmtxMCtJb2Nza1hFZTN5MCtrR0VSVzdZd0tRSE5QVnRZM05rR3A2amFuVGNuSjZWczl2d1QwbnBwenhweG1MRVdDNW1RSVRub1h3UWR5dTFPb1VaSFdzbkVVQ2hJc3U3V1JpclZWSFNSaUEyVmlwVFN6dU1QaTR0djFDTDQwb2UxUHFXd241WTJGdGgwQVptakFEZlRzbTJrSkdZdDBBR0tNbHprMHZrRzRuREt4ZXN5clRhd2dVR25hbVJobEs5QWFGSS9acFQ5M2J5MDVoWHBQZnBVYW1ySHlIY3VjdDFpejJGaDBwVExRdXFUSk0vaGlxV21RbE82MG5hWXBwQzVhREFXVWZsL05Da2FqRXBScDFhcHFOTk14RjdRaTVNOFRDcHVHS2toYWlrRUZQYXBNelhtRk5VSXdibnRZaTFQd3B6WmZzS2JMM21PNHNZYktwWTRTbkdkbk8xdjRsWHN6NWpla0ZBNHpUU016TllRN3lqOHY1VjZkT2pWcW1vMDRNS1RpbE5OS2FhVTR6VFlidHZOamtHYUxBK0FmSTBZSitXeXNWT3RXRDB5c0ZoZGFlcDZ6Wk1ZL2FGbUdSTnJMM21nTEdxRzJiQVFoYWFNeFlnRnB5d0p6ZE1KeWN6TUc4YTFINVptLzlmTTFUVkR0RTlvZHd4blkyMVFBVEJFcHRwTlJRMVJ4M3VqbFQ0UEtpbFRONElQcFVwc1B0Q3luQkl3WVRGY3FOK2hWTFRVRm1obm1pbWtOUTJ5Sms5TGJTaDh0eFA2eHUzckV0K2JkNW13WXpzWS9zR0ZSV1VxZWcxQ1V0U1RMVkgxdEQ5d0d3OGczYXdtYmhlMmwzSDAwalZHYTJSTWs5WDQvOHloOHZSL1d1MjBIcDE1c0NSQVJrZUlaTzNTcWwycXNGRVAzaFpocldHNlU0WFVSbUxXek4rbkVGaDZpZm1oODM0djhBMXJ0dFAvUC9BSmhtSm5wemJPSXRUQllkSitoVC9ZQ3dPQ3l6ODhyRTFLa0pKT1pucUFncHpTRmxWZThFY1lvSGVoOHE3MXQwVXNXY1V4bjZFb2pBckR1KzBiL25QcFF4eXVla1hrVnBWcG1tMHoxN1RJTTAyUUNrckVrL3NRYksySVRwRXoxaFl0T2VDVG15cWNMVEhNb3hkNjMvQUN0dncveXJIQloyT2luUDRaVU9sRU91ayt5N3YvenR0UytDQ1Z6cW9kakNMWit4VFVhYWptbzBQN0lHeXRpT3VPb0tZS2VKclJZYWpHMUVaYjZMR2p5RWJpVTBWWnhQL08yMUg1Vmp0aVUyN3V1ay93QUZJZHlhUklOSVNydW01LzVtOXFYd1JGTEhpZkNuTXpJbUxaNk1TbFQ4YWxRMUcvYWcyVnNSa3hjSVROS3JEVWhPZWpVRnBXcVZGcWNQQzFOcVgwNVQwYTBsUTJWZ1YvaVlnSlluTk5aa2NuODBXUUlGNGVjNmxTRHVYYm96MENKVEFGV29haC9iZzJWdE0wQnBsVmhjbjdvbFA1QjYzL2h1ZGg2d1E5ZUppMlp2RnByUkR1MVJ2M0lOZ2NRaGFreGcvWkZ4RStSZlcvOEFCZHRqc2JHNDZzUlVaMnluRGdrc2YzZWI2ZzBaTlAzVStWZlcvd0RYdTJ6WE8vWGlMUzdQVzdmNEtzVm5pMEl4OXRmZGZXLzllNWgzdCtla0NKVExITk9sSHFOVVArRG00ZWFRWVJqcUYvd3ZyZjhBcjNPMC9OakJiRVJDMHhUcHlwWFovd0RKRG1ZVXdxUjBDNDJYMHY4QTE3dDhkeGRLVHRQbzA0OWQySCtSbm9Ec0pyVXpTcGpVMmd1TjE5Yi9BTmU1UGhiZUpRcUdjdWtzNXlwR2RuL3pjOUlZaWM0elZUTTAwek9WT1c0SExhYUROSm1QL24wTk9XODVMemt6UlNFMVVWbjZob3pzM1JtWi93QTdNejFaTTF2T2JVbk9xVG5WSnpxazVqeko2dTB6L3FabVptZHZzOXBtWm1mM24vL0VBQ1FSQUFJQkJBRUVBd0VCQUFBQUFBQUFBQUVSQUJBZ01FQUNJVEZCVUFNU0V5SXkvOW9BQ0FFREFRRS9BZlh1UEM5ZDBXKzZMMEt3K2ZSK1lOaDRoMzNsYVA4QVVPb1lNUnFwNWcwamE2RDBTZ1BYT1k2QVlUQmVlODdaVFFZemVZWURtTkJwck12WEhFYkhSOVk0TkUzdU83cEhIUHZBZEp3bU9PT09pdk01eHpoQmdKTVpqTVpqTUJNRmlpc1dFaWZuQkJnUWlzV0ZXTzlRWE94ZTBjR1F4NmJvc3lvOWdtRDVJRFVXT2VZdEYwN1dHbk1UNHpSMk9uWXg1Qlk0c0NQSXcveUorazQ4bWNIYVBJWXFpN3pGT1Urc1Z4SFdDaWcxZk5PV0ZRYXdoNzBOVERGQWRjd2lDQ3BxWVk0QnVuMFozWFlhY3ZRbW5LcjMxRkZvL3dEL3hBQWZFUUFDQWdJQkJRQUFBQUFBQUFBQUFBQUJFUUJRTUVBZ0VDRmdjSUQvMmdBSUFRSUJBVDhCK1JCNzdjY2NCMDN3ZlJjekRPeWd3dmtOSWlLQVlWc3EvZVozenhLamQ0b1lvc0tnMXo0RUtjMFpvelJtaldsLy84UUFPaEFBQVFJRUF3VUZCd1FCQkFNQUFBQUFBUUFSQWhBaE1SSWdVU0l3UVdGeEF6SkFnWkV6UWxCU2txR3hFeU55Z21KRFUyREJZOUhoLzlvQUNBRUJBQVkvQXY4QWszY2k5RjdPTDBYczRsN09KZXppOUZXR0wwK04waEtxUUZ0Ums5RjNINnJaN09FTGdQSmQ1ZDRydkZkNHJ2bGQ1VkVKOGx0ZGpBcXdSUTlDdG50VzZyWnd4ZEN0cUVqNGxaYlJWQm11RmZMZFh5VVYzNnJiN0x6aFg3WGFlUlZZZmhyOEZxcVVuZFVFcmxHS0tkYkN1V3U0dXRxRmpxRThKZjRTNW9GWnp6bmQraXBSVkw1R1FnRStzZ2NqN3JhQzJmZzJwazVMTFlEcXB6NGtUTnRKZE1qYnphVksvQWFKNDc2TGxKb0s4MDVPNWFmUk9xWFRaWDN1aFZmSDdOOVphbFYzVHB0SjlaUWRVNmZ3VFJWQ2NWSGpNVVZrd3NuS2FDZzEzcnpBMFRhS0RxaU03YjdGMmZwNHJGSDZTZUwwVzNFd1R3bkVGdFE3dHRaOUU1bEQxOE00VHcwai9QaUhpdkxXSk9UTFpMSnUwaFR3RlUreXJWYUtsZHoxVGF5ZzY1MjhCUmFkcCtVeDhLNXZMREJXTXA4VGxWRTZwd1Z0aFVWSlhWUW5rVGtBMFhTVUhWSHd0Si8rUWZmd21LSzhtSGUvQ2U2dlZWblZiTkZXVzFXVkpNdXF3NUNUT0ZIZDBwdU5jcmhZNGUrTGp3V0tLVENzUnNxM25xRm9jbFZzcXN0UXRKa3pmVk5xb3Vrb1VaRnM5OXhybXBKd3YxWUxjUjRCeXVTY285b2F4TEdNdW9XaHlWVkt6b1V6VnlBYUxvb3Vrb0VVRkYxelV6NjV0cjBsaDRtOCtSdXFkMDIzekpnbktkUHc0cnFteTFXb1hQZGt5OGpKNVE5ZDVxcTV2OHZ4TEdlSDVUbkorbEh4c2pDZDYvR1dFU1pmcHhjRnpHVnZSUExVTFE1S1pIMVRheUV1c2h1dm16MHV0bStzbUNZV0diR08vRGZlUEtseXF6eFEzQ2RQVnVTZTQxeVJOeU9UVUxUSlNUYUp0SlBwSUJBN25WVnl4Y3A0WWJhNnoveWkvR2QrSEZVN3BxTjB5WlZXSkR0QW1uL2pFbVZGOHAreVlpVVE1YnR6TWY1SUJCRUtJcDBlcy84QXRhcXVlTmNsaGg3czNpc0xwemxhWjdQM2hXSGRZakxDSkdBcGszR1RMQ2JoUEpqVWFMWXJ5VGEwM2ZXVUtiUlBvSkVLTHF1aWg5ZDVFWXJMVGxvcUJiVVQ4b1UzWnc0ZnlzT2wrcWJKWGhrRVE0SVJ3OTJQY2dJa3B6SjFpQ2NKeExHTGhPdVV4anZxanBLbDUwemtvbE9oSnZQYzF5UEg1QkdLTXN0bUYrY1MyakxGeE5zemV1V0xzdU40ZHc4c09URHBKalBEd05rMlI5VnNlaWRPVnlWRnRqekNlR295TW1FZ0VKQTVxTGFQa0V3b0piVXJQRm92bWoxUk45cWRiRE0rWVJhSnhhS3U1Sm1Dbm14dUoxdUU4NFRMYXZxc0VYRk5kYk5DcXFoVzFRenhGTWdFQWhsb3EwVmJxbEpPYUJOQ0UraWQyQTRwb2JmbVVQV2VEMXpOcG41OW51RzF5R1RhTHFuVHl4anpsVk9tTTJXSVhDcGROMmdUd1ZFOUNpRVUraUtFaUo0b2xTVkZxVlJZWWFsTUpNRnRWT2tuak9IOHJHQjBkT2NyK200WTJpb2pEcGxlWFRMU3NtazNDZUErVXFMYSt5Y1ZoVGloMFhKY2l1VXRsTkZRcmxLdFpSUlNFaGwydlJNSllJUE5ZcFl2Uk5CUlBHY0svYkRjK01xV0ZzM0xjdzlvUGVHWjgxYUtvZnBKNU54bHprODYwV0hpSk54R1N0UW5ndXF5QVRJSnBBeWV3V3pKNGxoaGt5WlhhRUxZSG5OdmVpdm02eTAzRVE0d0Y4M1dWWlVDckUwcUNWVEp3bmsvQTVYVkxKMWpISEpSWWUwVHcyUUNKUVFtNXJrd3czeWN6a3h4V0gzVG5MUlh5WFZSbE1IekRNQXFmWldsVTVyU3JQQ2NyY1JMQVV4eXR3UjVKL05Ca0pHVlZSWVlieWMyRXEyeU1FSUliUS9kTjRDRTgxRm50TytidXFzY0t2RVYzZlVxdzlKVU0zVGppblFqRjhzVVVtOGtKUGthRzgybGgxeVA3eCswN0xpcmhXM3NFZXNPNm9DVlZoMUtySDZCV0pWSVlWZFZWMVpVQ3Zsc3NFWVl5YmdWeXlkVUVBaFhKQ1UwTjU0dlNXSXA5NVlMaXI3bUE2RnNyaUdpckZDUE5kNG5vRlNEMUtvQU9nVlNWZVZwVk80YzBDb3FLejlVNWx6Q3BDVlZndHFML3BBUWxFb3F5c3laRlZWREprd2szREk1MzFncks2b1JPTWFGNWhHVjVXVjhyRVVUaW9PV2dXM0dPZ1d4REtwbFNFcXBBVzNFdGtlaW9QVmQ3MGxadXErKzdvYzlNejJHcFd1NzdVY3QvcURjSjRhd3F5c3JKbmxRS3BDclZVQ29GZVZtNnFzWG9xajFLcDlsUUsrYTA3NzJwQVd5UE1xcGZlUkQvSFBSVkw5RnNnQlhWMWRYVnlybFVpS3VxT3RxSlhLLzlEUFNWVG10OEM4c3RZUHV2Wkg2bDdNL1V2WlJmVXZZeGZVdlpSZlV2WlJmVXZZeGVxOWpGOVM5akY5UzlqRjZyMk1YcXRuc3lEMVZaWFZJMXhYZVYxM2wzbDNsM2wzbGRHdDBGZFhWMDZLdXJxNnVpcnE2dXJxNnVycTh1OWtZWWZSZTc2TDNmUmU3NkwzZlJlNzZMM2ZwWHUvU3ZkK2xlNzlLdEQ5S3REOUtab2ZTUVJ5VkFQa3F3ZWhWSW1XeVFWVUhmVmxRcTA3S3JMaUZRaFZHZXlyRjZLM3FxWk5PcXZLbVdrci9BR1cwQVFzVU5SbHNxMFZTckxoSUk1YWlkQ3F3Z3J1a2RGU1AxVks5RlVacWdGWFpVcXJaTm9MUlVJVnR3QXRPbVN5cVZaVXlXVlN1SlZLWlhZclpUc3hWWWx4S29BcjV2TGMzbGFkMVdFTGlGU0lLMmFveXVaYlFWTWdvOGlaUEZFdGVxb3E1Tm9yVlVBVjh0bFdJTGlWUWJvSW9ubGxPNXZrb3ExNnJ1K2lvNllCMXRSUWhVTHp2SnA4MDh4a2JJMG1jejJuOGxzeHduN0ppcWtydStxb3czd1JYYUhsbExxaEc5Yzd4aGVSR1ZrTXorR3FaeDVSTFJjQ3VJVkQ0RjlKT3FYemlST1p2QlZPV0l5SE03dWhWV2xUSmg5VTJYRndUU1lTWVhudFVUUStBeENvek42WktoVUVxNWh6TW9ZZEJsTzh4Y2VHWGxxdGdZanFWaWlOWlBKaGVYSlV2cnVHblRPOEsyaGhPb1QzR295NHZYZUNIUUlJK0E1Wk5rTDV6OWs4UllMWlRTWmMxcXExbmlqVDdxcXBOcE9xME9xNi9kZkpGOWx0RGZBSWxFNlozM1RDVEM1VzNVL0tGaEZCb0ZxVlhJL0ZQRW1FNlZLcjRCNThscytpYThPaFd3V1B5bE1SV1RicUtPWFh3RDhUTm9SaEdUa2poRnA4NVVXM2ZSTUtESmlhbWU3Smpsb3F5clF5RTJpR0lLa245ZHpERDV5RU9tNGJQVzJZOUZXK2l4UmxnbUZCcGtlS2dUUVVtQUUwTmhTVE4xQ2NkM1A4QTVRL2NiaG9xaFBEdFFxRnRiYjRCRXJvbjNENTJHYUxEZGxYYWkwVG1iMkNwbHhjVFFUY0w4aE9PN21jTEZEM1lzdFowVUpGQzlrUkZtYk9ZdU1WSmRkeXliTDF6YlJZZmNxUEFHbkYwVzNmNWN0a3lwWVdVUFdidzBaSEY2WklqeEJuZ2lzZnNxNUdOUXNVTlJNZFUwVzBGKzN0RFJQRGxmSzJxd2kwTzh4Ymw3RFVwdXo5U25LUFdWRnNYSnZrZHFhbGZPZnNtNGFCSFcwb2VzdVdxNUp6a1BNWkF0RnJPaUJGSXRFeFFSNVJTMnIvTUU5T3FyazVaRDJua0pQdThKNDUyQVcxdFJaQjFXS0tnL0tZVUdpaEVuaklnSE5iRUxuV0piUmZMRDFrQ0xKekk0MjgxYUJlNHZjVU9GdkxOdEJiTlpGTkhVYThRZ1JXSFZSalY1MFRSaE9LdzZpYlRBV0VXaDN6NVg3VDZVd29OQXFxazRjVll0RTVUQUw5Mkp1UVg3VU9IbnhUblBEMVJ5RCtXNXJWVVByS3RWc3ppd1hleWZYSlFxbXhGOWlxaHBjNVl2ZWl0NERsT2w5Y3pRZXFHRWNGdG5FZEFtaDJSeTNVUFZSWlA3Wklla2p1ZEU2YU8vd0F5cmx3bTAzUGNDZndESE84VkIrVlFZWUY4NSt5cmJTV3VjVGg2cUxJUDVaSWVtOTBURVlvVThOWWN6QzYvU2dzTDgvQk9MaVRUeFIwSE5VR0k2bFZNcWJveWg2cUxJUDVaSWVrZ2p2WGh0bGIvQUZJdnQ0TndzY012M0RoL0svYmg4eXFsOTA2RVdzaXV6T3NvZXMyQ3d3ZXFIOHBHTThFSXRWRDBsNXJxVkVTQVdYc2dtdzRTbU82MmdxVmwrckZmM1FuUGhkaGdOZDNVcllDRUtNUEVUN0tVUFZGQUJOQjVtUS9sSVFCWWRGRDBsNXFGUnpnajNuNnZhMjRjMDU4TnlUaTJlcXBWWGFUNkxhaUsyWXk2NUdzdXpsRDFSWFZNVnlRL2tzV2ljdXRsM3k5cEpoZFE5bnUvMU8xN241VmZJZUk1TEZEYkp0RmJJVmNqQTFuQzUyNFpRQ0kyQy84QXFERDdvend4TCt5WVRyZVFoZXNvaEVicnZmZGZ0UXVVOFY5MStwMjNkNERWVnR3SGkzaFZLNzhLTEovYklPbmdNZmExaTRRcDR2R1VWS1JKanZnb3NuOXNrUFJEZTRZUTYyZHJ0TmRFNXY0OW8vVmFqZXdxTElQNVpJT205eFJuQkFzSFpEREQrZmdkS0ZWM2NLaXlmMnlRZE4zc2p6WCs1SDlrOFIrQzdWUXRnK1NydW9zbjlza1A4ZHpzaDErNUZpaStVSnU3RG9QaE5hcWhaVkc0aXlmMnlROU03c3cxS3FmMUQ5azNkR2crRzBLMm9mUmJNWHFyWlk4bjlzZ25SZDF1cS9jN1IrVUsvYTdNRG1WdEYvaVZDdG9BcXNKSFJVamJxcVJRbEdsMTNTckZjVTNIRXJGZDBydXFzVUk4MXRkcDZLa0JpNnJaRU1QUmJVUlB4cTY3eFhlWGVYZVhlSzc1Vnovd2Evd0QvOFFBS3hBQUFnRURCQUVEQXdVQkFRQUFBQUFBQUFFUklURkJFRkZoY1lHUm9iRWcwZkF3UU1IaDhWQmcvOW9BQ0FFQkFBRS9JZjhBMHFaWk5pZlpua0p0amY1eC9uRFRjenNGMncwMWRmOEFhdXNIdnZaN0VDQldqOWd2aXNSVzhBZTVQOTQvMHovWElyZXFKV1ovUEFkL3VsQXdvTzkrQ2tPV1NIdkhML3BXYjFFSlp2SGloRXpkenE0VjNBMFg5WVorWDJPNzBPejBPYjJPSVQyVDFPbnFtN2tQZ1V4UzJxTE5KOUJ2d04rbzNYL01TYnNXdEc3QnpRbUZDUTQwZEZMb2I1NnFMKytXSnBkSXVIckU5cVZ1ZEtrTzB5aUZzaEwxRnlHbkJVUk5jU0JpWGxpelFKd25XZXR0bzJlaUFRVUpmY2FhY05SL3gwbTdJVytRWXBweXZzR2J2cFRxZ3RGZTRmeTdzVkU0VGltaVhZeXN4YUFpcDd5L3dSNlYyem13bU9TSkFMSG1yaVN0YUdMTUZ1UWtkdEUyblJqUmlia3l2SzJHbW5EL0FPSTJvcUs3d2hYYm1kdlFadTRwZ0p1eVNVamRqYXMrTUZXTmVnbFFsS0ZZcnR2QjdLR1VTTFcxQlR0aWVPNFdWZXdoUTE5NG5TUXRERERNTkRGUVErTkpnY0VKNUVFMFArQ3doRElPeC9KaEpKSkxKRGFTbHVFc3M5d1N4TUV4TllUWEl4SXNFRUVEVTBKaEwyODZSQlVIRktpSTM3RkdwTE1adWJOQkpUVzRsRk5FM05sTWdRR3BHMzBRTU1Sc05DWG9tYWhhQmdDZnZySWhaYndMSVQ1TktMNFVNYTZZV0VKbW9iZ3RYRnBRUVFRUlBnUnY0TVdTZ2tqM1FRUjNGam1Gc1RCYmhJN0NLTzQ5QjRFZlNLcWxmVEEwTVJGaUVUblJLNGY4QXhmTy91MHBjSW82UHk2RWlFcEpnYW1RbGRqcFQrb1pWamJoS1JzaUVFZlFneXEyVldNYTJSS3RpS2VGR2htQUhjR21Hd3N6MkpMVXlEaTZFeWthSDlEcjZHaGlyRzdvNHBiWVd2eWZ1YkdoQ0VTWmVQdUozSldkWk1kRHNleUVWQzRDbE1IS1RENUV2bzZXc1N4TTRSUVpOVVpBVW9idFVRVDJNbDFidm9WRWg0N0RWMFdjUEJVd2hPdnVSRWkvUm16S1pBNHdYR1RFTXR3TG9OTm1tb2EvYk9pUWxLbkZQSFk5MklZb3l5Mkg5NXRpaW1CNUxRcWhkcERzQjlSNVNBcFl2WVVCejJFMVV5SFk5Vk1ONmttOEtpTHNXRWhJWjVhQ0RrREVKZkdKbUh1UVQzMGRIQTkvSVdTMzBJYndURVhrWmdCNGJrU0dKaWNpYmFXaG9vMkVCakVRMSswWkFoQVh2U2VPU1JqUmZBS0FtM2tUaTVNV2tGb285eTBxYmp5VW53T1dUbENqbUU4VVk5WHlObXltYms3RWJCQllWUWxUMjNHTElRa2NLQ1p1RUN1S1QzQTBNZVliQ1QwRm9RRDFGb0xBdDdFcXlHb3ZSY2pSYXB2UHdoajQwU2tVQ0JOMDNHa0pTeE9STnRLY05FNlVKQWFhY05RMSt5U2JRcmlrVk1FVGxsZTZ3OTBGSzhsTVVOakVTUlVOMWFxMkZjUllvT1ZxYkRTRmdscHl2VW90SDNFTUpycGpXd3VTcHdOSElVRlVXeXJHSmRraXpaVlk0N0NvODF5OUh2ejNXalZYTkIyTE9DM1JwNjBHcUVmSXVqOEliWUJlOHNab2lSYVcyVzNJNW5zTTNkaVVUbVJNSVRJYUZ4TWVTL1pVSS9BMlFGc29WdGU2ZGFKUEF6TWNER2s3ald4T0JUQ1NoNnI2QnRRa2FVT2VCbDNjK1JzYzUzTDUwU09kV01TRUZrM0lJRjNDdmRxOTlIdXozeEFpU2R4TXBNU0pibDFBaDdOeE9IdU9LdEFsV0dPNzFXL1N3VzNkaU9aelliTzdHaXRVYlBWV09Fd3BFNVFvWGtRanE4VC9BR0dERWpDU29nOCtKYmtIU3BIUlVnbzc2UVJwVDU0R1E2bmdZNjNHeXNOWUZWQTl3YTdhYk1ucURVMFNVUWxCSUNwUFFlVWJ1SWVPNDl3TEtOMmoxQXl6b1Nlb2gwWVROc01kM3FnbEJXVmJkMkV1ZnpZYlhNU3JESHE1cTUyMFB5Vjl1b3ZpbWtoRE91dTM2emtJSVI1aHFaQ1ZSbTJ3dGlZcjZCcUM2cEI3c01DUkJCRlJzMEpCVDU0R1VlWTJNWnNEUlVZaDdtSGxmUWt6Rk5ObFZrU1oyVE52Yzk1SHNJcFpNSWFXYjNLdWdQVzkyTmIwR2l6all2a21tcWtLQlhVcWJ1d2x5K2JESGNPTmhzNzZ3MjRWeHBYd3diYmN0MUZxVnlyVnVISnRrdDFZMVF3UFJndFhkbUpKaHI5UktYQ0VTN3JhVlNvcjhzcEE1TllZMlN6b3hPd0s1QkdoSHovaUJWOEV5aGIzd01wajZHTkpqMkQzRmNvTDZ0TGdvZmNqVEJxa0ZQYVNJS1piaWpzT2sxNFl4c0YxSXNTM0toc0VwRUs2cmJ1d3VXNXNNdWRocmdjaHJTUmdra3RZYUVOT2YyNktWNWpxbTNybmthWENJTER5dE9ybm12MUt3c2h2eHNVM1pJWVVsVUpoUUxnb1B2WWxDaU04RzlCRXNOd3NRUUtVMDFkQ1creHBQNTVHdEpLVFBBek9TMlk0ZHh1Qkx1aittUW9pZzJpWGdHUzU3Y2lkQkxjNC9zcERTeVVON0R6QVdldGRMeXdxbTdzTG0rYkZ3ZjBORlliTzVKSWt0eFJUMTBadEpYYnNoTExxK1g5TmFuaDlBNExXc2F3U1FtU2ljQ0p2MHFPVWhBSmRqUkp1eFpPQW5SQ0xaYXFWdFppVUY3Q3ZmMU1RNXNrK21qK1RaajMzMkpJa3lEYzVPSU5EV2tsSW1Wc3pPdzltTWUwb1pzcXNiNUdTRDNjbVJPUTArRHNNRW5sWjF3U2N4UVhyY0tqTjBROWZZWlBVb3J0WVZsWHpZcURXOWhGbFJ2MHZoZkkrdDBTN0U0YWU3M2VrRlNscjhTSHV6RGFsMmR3NnZVU2QvRW9XL1JrY0ZGcEFacXZSVnA0R3ZmQlYxdnZvdGpqMmo2TXV0RGxENTM4YkRxWGZKZjhBc29YazlTRUdob2FHdGFaZGJNNFI3RW5jMGFSeFpveWtTeUY2L0dnNFAzQ1BEcjVMaFNqZHYrQTFTWnFNM2QyT1VmMWdrS1UwcWZJMkVvNElML3RiNE54dXozTEtjcitvZUhGeW1xM0RZQzBld3E5bFRIVkxscWpTaTh3d2xXb256K2hFSWhUdGlMYVNHdXVNbmZrZXBjQ2xYMThEVTRCQzgyakVjNXloQ1V5VzI0UkF4eDZVTzIvbmNhMWVkR3RKN0hqY1JwdzFESUtsTlhRMFJwVG01WEpJVVVTMG1Yd2MyTXJQelRUUkQ1SUZUZGg2dGJqTzAyMFpzNXFqYUVtMk5MbGRsbzJ6R1JwS2k5UlNQdlA5Q3RwU1NvVWQ0Tjl1ejJMMHZnYkU4Qys4YUZKZHpwWVNXUDBhOWgxWkExWTBxeXo5Q3FpeUd5TkZkNnZRRnNTZk5TUmIvQkxyR0RhUit6MWVWaVRvZEhYUkRpa1FsVTdNcU4yZnQzR1RTNkZDeHVWQlYzRlpsb2U2RlJRTUx3VzRoc3JyVmkweXgxc2kwN21sOTlOa3BFYUVZdWg5TGVON01ITlE4U0ViY0lWUlU5allRMHk3YmV4REhLeVlMN2pjc05zMG1laWRLclJXYkt6WllXeUhvWVd0MktwdUxkaml2cG1TNDVKa0tac3o2bGNnZVMxWFpITmoxbER3RWJoa3I2dXFqSzNBeWhaVmlpN0prbnpJalJKNFJrZERUaDk1TnlLV0NkVGdzUFlnUy9DT1lXQ1dSRkxUbXdRVjkwSldxTmNxNFJWVzV5YzJNbThnK1o4RHVWaTJFNmpxckpOd2piNEx4K1J5NGM2TERndVBhay9rSVpCK3JFbHQzUHNrUjNJQkUwUmx2Mlk2bENOMmVpVW9SU0xlL3dCcEFveXhXMGUyaFVqYjVmU2JkRjdMMitxT1NPRlpGSlhvRURCbzVCZ1JYVjZDdkt3Y2xNQ291ZEpxQktSWlRHQ3J0RTRoRFc2L0tEU2VJZDlpcTRkbXJIdytDTE1zY01wK2FJdWFOeFNybHVKY3ZnUEM5aGhSeXRtV3JyR08vQjBLaE54RG9ORDVud080MVFTVmJHQVJwbDdJYTZVOURMaTB1M3NSODQ3RmhkdU5KcjVSc1F1MHZ5Uk51aUpJWE9LWk1yd1g4c2VLZWtpbFJOc3ZBbEVZcEpNc2E3QzdsNk9nc3VSZHF3WWYwTFMwWGhpUXgxbEgwMzlOQlhBU3BZV1FrM1JGV1dIQkNUYXpKUExBeXJydEVsTllZNENGeUpxcU9VV2REMyt3YVRQSm02Zlp3RjRNU21ycW92QVd1NnhSWWR4T1V4UTNuSy9mY2gwS0ZTSFZ5eFpqOGd1NVBuZkE3ang2UWtkeUNyR2NFS3RFSXFldXdwUVVXTUQrWFk5WklrbXU3ZEVraEsrN29KcUZGM2k3OGxGQ2JaZmdkSjJWZjZIemhzVEh0ZzB1TmhhWFpPeTBXVVE2c2w5T0VKdE5OWFFxeHZlK21MNUprMklkdnNMRnlxdzUzMG9WNWRoRTNtOUQ5UktLVklZYk1aWDFudnBWRlpZcU9jbU1Kam1VMmliS2U2dDZFcFE2cWF5dEs1eXFuczBKcERhS0owR09hSXlRMGhJMDVZME1qUXFTZkwrQmtTN1lxRlFXOENXWGF4SEYyK1NXeEI5b0VybnkxZ3BObGxtTjZiRGtvTFlhVkZoRTk5WC9BRU5tNWJsNmVDZUNJbHlMUnZHaGgzK0l1UlBhSU8xZEJyUkMyMDhZSFgwTEtGaGJVSnp3S1RReEthZXhMTFBSUlk4bjhLVkJHemI4SDlpTTVTOEYwV1R1UFVDVkpwWStRY0lkR3lSTWFOY0ZXdVZSRXA1STJyRngwSnc1RXNoek5ERXNDYTNKV215dy93QTVTOFEzdm55Q0JoS2hrU3RGL2IreHBRcFpDcWJzcTJjbnRvc3QzVi93aVpjbDEvbU42cXFpY2U3Q0dNZlZ1V3h1b0ltQlJkamhiNVkydVd4UFRBV0FmNENyTUVFaDNHbHF6MEpJbmRVMW1RZWtGc1U5RFk5UXptQzZEODZ5U0pOMlRKTWhPd1RzcWFOU0o1R2FtNHRDVktQUml6OHhhSlpiZGhzMjhpd25JMW94dEt5V2pnRkI0RXhBeUhrZHVQY1dFZmdkVUV6SjFLallKSVF1VGs5dEovN1FaUXFWaTVVY1kxU0ZTM1FaSkhOdXl4OEJhTlNTSWYxU3lRdEYxaG5DQWhPRzUxVzc0TWt6RlJQeUU3QXN6UWx5RWNPRUpWa2hKQ1dDbm9Uc2wzUXBzUE1rVitvb0pXMC9JYkQ2RDVFcW9lK3NJSXNRTTBKZENLdzF4RmhPVU1UOEN3emM4dG5zNGhYUkNtZ3NIa05DOGlJVGtVRlF1TGs5dEZWd3JqSlN1M3V4SEFpQzB2VXg2eWNzUzRhVGlFL0JIOVp6b2NBYWN2R3NFQ0dwSWg2ZTM5TFN3VTZsY3hhQ1F0UFk4UjlnaUlMSGtaQ2ZLY0VWWmVKK1NWUk5MaWdqTDFHdjdERFptQUliaTNYYlpJd2h0d2xMRklKRnczVWFabEZwRWtWbUVpc3JhVEFuSjVDZkp3VlZIK2NvaWdQbFBKWmVCVWZRbEx1UlBOZXhNNlZ6MTkya0tTZGxFOUM0MEVEcGdra3NzNURvSkNHNTBjeEt6OFJHeENPUFdiRmVtTk5YVFgwSXZMVHRscW9VYUhmQTlsUGRnZjhBeXA4RVYvQ1BrbGNuNDRJQ3k2THlRM1JEM0d4N0JpUXZCbG5xTmtrL1FtYUVteWYwbDA4aWF5ZUMvRXZjbVhkaFJqMEU5bnAxRlk4RHQzdUZ3NzFFK1JKNEszSEEzV29QaEV2NEdKcGsyTXdvbUZUUkE2aitRYWJReGlsSE93dUxDc3VoUlV4aUZKQnFFeTVVNVVlU2VZMjM5U1pLSWVHU3pvU3RFakxPVFBCMnJwbXk2N1J5SGtWWVRoNmRTTkZnOXNNVUl5eUw3QjRrMk44SU4yd2JPN0oxUVZVMlZkRVpPd21NZ2pSbERtTElnUlk4aGxTNkQwdVU4SHpSU1hMZmcrM0Z5eVg1U1prbDRFTjh0bTFXOUJNcHROcXFDN01SR1pIc3NVQmtpaENlUFFzUTU5U1dVWkNKL3dEUWJZYVkwWFQwbGlZa3VpRHVMRWtpZ3FIVjZnaERxb1V2dTZGU1NTZGlXUzlpZExaY3pzczlMWXJPaHhKSk9rTVRab1FscFVncUUxNm9JS3paWjdjTTVCelBRaDN6N1FpazBiWTB2S053dmNWN2Zad1lINFJodmt1TCtLRld5MlhMMmgvVGhHSlVudHdOblpYWmRhTnRLbXdWM05SMEdyUHFjL1FPNDkwTzA5bWJQcUdqR2tXUk9aeVJQYWhMRFEyV05KWW1WUzl6aDl4Yk03azNhL3hvTzVjM0pKS0thc05Fc2tsRnN2bGU4YjZDMFFKRENFa1diTnZ2SnBDWHFYb3VjY3M1ZXBjM29EbG1YZkxHOVFsZVd5SzNQSXFaU1VnelplbzNYYktrY0VQWWpnZlM3VEVyUHNYSitDc3VjWEVyY2lWSksyZzEwU1pXMEZxSU9xQjdsYThITHAzSUlJSUpRVDdFSGMyTkVoTVRKa3llbVpJaDdFZGlXQnNybVRSdDhzVU5xVVFPU28rb0NGMkJxUTQ5a0YrZ1FER0pBQVArcEozYjdjaGdwY2tsblhSL29vWlR3cWNnNVp5am1ISTFrZzV0S25rRXBwc1VMSW55S0FNYko4akdhYjdFMjZoVmlWT3dkQllOcmFia1NoYUh5em5uT09Sb09ZTGxIZERsNkJwdWRTWXRxZ3Q1SEQ2SndlaWNYb25CNlorQlRoOUE0ZlNPSDBqajlJL3lSZFBUQ1VsQk9GV2g3Qm52dFJncHIxSVJjRitHUjN4MlIvQ3JMYUNYdXlYdVM5eVc1TDNaTDNaTDNaSXhyUklzeElNVFBhTUduVEhzZk5Db1RqaXVqNUVMZU1SNUl4dkJVYXJqMkhjZ3d4RXRTYXcyaFZFMHQzUTQzdU9ZNVlUdzhJYk95THN6Q0ZrWHNFRi9TamludGxPenFnMkcyODZ6cUlFdXo5amhlZ2xSMUtDK2ZsWGVrazZLeVkzQzdFZVhvbGJPK3lVMFNlTkQyRFBkYVNzV2lQSWdKK1lFektMa3J5ZmFxREk3QWIvNGtEd2t2S1M3QyttV3JPRDg0aUxUZGlTNUM1TVZGYVBRdDA5cVNMTDhHTjg3dWhkbmdacXphRU15YjZhNkp0MDN1TU00eEhrWmMxNEtvczNVc2lYVVR1aThzeVVGVzkySjJ6dWdsWDhLTzkyNUhDejBvTncyM2Q2V1JpaTJqOGlEaVhUV0dTNDlTaFpia2dsSXVKdWxnaXNlS2tZZ29zaHR5MGh2cFkwN0xoOGd1YURVREVFaHJzY1Ntd2l2RE9ZVDhpVERFalB6VXpQN0RiajN5RHYrNkNLWnRicW85SUUyckNhaHVVSzBUZFIyUGFNV29ZdGFkY2NDanNmZWlNNUhUSHNxeWhvbGVTc1dnRGRiUndlMGdrZmlncE1TY0pWT0NYS1JvVUxIVkRBSklkZWFNWTBJYU5valZtUTQyeGR2b2NGamVDaTA5eksrQWhacnlOK1k2TDNJTEpFbmhFdmNnZ2dXVWFhblpQb3JsalNqc0VaazVpbWtFRFhZNHRpYTJDVmRTYjBvVE1paGRIUnhPcVJwN3g3RjRTMmFKUW0yUkwwUzNMOUVLdDdsRUNiVm1PcW14ZmFDbTR5U09HalRGS1RuYnNQRnNJRUxiM01od1RXOGpWTjNJL0kyVWk5Q2xxZWR4cUlNd2lLMmlQTTEyZFJBOFE2dmNnRERIVk1qWklwdFBzUmZBUTJYYmZZMFdTSnhSSWg1WkJHa0VVS0RUU25udUtQcG1iS3hHWmk0SWtpbk9seVdsSzMxYUlFbFpsU0tZNUc0VWpTNmlaT2t6TUMwWGtkV01CWlJQOEkyMjVicU1JME1ybHNPNFJIa2QzYndlT1NRczhWU2FPeUdnb2cwSnlrV1ZFUmREbzlKSkhycEVwVml1NUFsOUVORXRFaE13UVZoQ1N0WVdsWTNhV3IwMHViZ2d2VWVyTmhaRUUzbDdoTllZeFhVRERZZ0pVVHR4R2xDbUVxdDdEVFpRbFpFblgwM3cwc25rdG9tR29Ta2YwamJhWG8wZHlsaE9od1dKRWhLMGtpN3FmeEI1V0lUZ3V0SEZBR0Z6OUxDNXM3bEE5T2RHNHBCSWhpZGljVG1FRUZrMlBha2hqdTJ5U253dEtIeWF2V05GbFhzeXBEVEZCcGhJRW1WcGM4RzhDVW1taHJzZ2RTSmFPbUgrakFHOVlGVmxHRTU2MENxNFE2U1ZXRi81QWJiY3QxMGJkb2JaWWxnaGNDVU1lNkdoQnZrTjZSby9VbE5iN2pLcnJkYTMwdXNpWmRGVmVkWTdJMWJTT1lncmpVb3FtUjJHVUtqN0hnaERYY2NDV2lSRUlzdVRTaldIalFrbzQraTB4UWJJYXhDb0pIR2k1MFRrUHd4b1NQMzBnUnpSTGRxSkNkSGh5bmhGVks3VEJVeUpQd0tRUUJiTkx1VlJVM094MnR6K05jZEY3RFJVc2pWUjFmWlNtaDZkUjFzRS9ZYWJROUxqUXlKemhqRStkeXRqMjAxSDJoVlpocUlhMHFYT2xZSXphSVVaSjJpUWxvMFVrUkxrNm5UVlhHbFNLNDFNdHZvYWtTN0NDRytpU3hVSkZiS3NxRC9BTUc1YytnNnNoREgvQkYrTm5EN2tCQ2JiZUVORWhJM2VSNFR5S0FQZ1UzM0VxR1daVTR0dGdlN0NWRlZpMGxvc0R5N21WTWhGc2R4S2VLakNaT1NNVGFFalVCNWVuVlhHa2xDT0dqNDBmeU1xT25raEczN2o3RHlJTnVTaGlRSngwN2pWQ2FZWTloSTBRcmVVUkQweHA2L001TVpRN1pKRzVjL1E4NkZwM0MxUWIwR2xPaVFoS1drc2pKTGF2eXg4RTBJYndJVjk1RDVZdFNsaHRIVDdTR05MU0s0MHVTN2QyWEd1QW5kVnFjWlloSUlXdzJkekZ3dHlKQ20ycThZR3FqREpaSGRpM2ZnYVdaUXpGZ05MQnFCb201Y1p5VzRuQW4zQzBkUmRycDJJVnozYlhKaGp4UTYzbTM0WkZMeVREMFZIc0ozR3BxTENJSEpFNU1hSlNleWxwTSs3L1MxVEFzdkZSYTJHRFROcDdjY0RRaWNoN21VN1hmYjB0Y0p2MjBZa3R4dVkzVkhOSkxZa3V0a05QaXlYQ3J1R3NnU1N5cHZPd0svQXJTNHFnYWxsblo2S1JjeEpEblNoRUtXbWtzc2ZMeUozSHNMREVOVktCYkJxSEJUUk96STd4SHIyUFI4RWs0ZDEweGszcWpFNlZyZCtKTGlUb2hXZGpJaFVUWnlWMUYyTkRSaDlMVkU1UThNYW4wVkdiUkplaXB1YkZ4cGNzYWZveGQ1eWY0VkZFdGs4OUZJK0VSQ2oxTm5TbEw4ektjRU44c25SOTFOd2htd0dIUElub1pFeVJFYkkyNE5aN2FEVlJvU3FHd0pqdTQ2L2hnZENZSlR1TlFKeFlsb3lsT3hIQzRkdWh2T2JzNDcyR0dVN2hkOUZ4T0dOU3BaMjBTczZKNUxwRWJZcXJOaUJiM2FvbW16OVQwMFNVbDZlbGhNeFZFb0VtM0N1T0ZGaGU0K0I2cFM2Q3VJbTludEVZUG9GMlNCbHNWdDBVd3BHMng2U281Wmk2N3NZMHR5L29yZndsV1NnVjJYRUt6Nm9lS2RoZFExbnNSRDBHbDZJVjVDVFcvTGpnYTBsbEdNYUVxTVZMcmJTY05CU1RHNFBvY2pRMHhzdnZxd3hVVDhkbHV6c2RHSXVqNG5oZzBidSt1MFBTTFRmSWs2bU5SSTBYaytBM0NIcXhxQ1dUeFhzRk1nMFhMcnVXNzBXcjE5UzZyMlA1R0ZjV1Nzdm9hVGFhRU5XbDJMNmQwRW5xYVNpSlFYTWpqS2RGdTBOQ1hNTDU2RWFQTS9uM1lZNmhNeDlGS1ArSG9nVW5MdDJMTHpYVDJJamd5NGVPbUtKdHR4N2tpZFNMcksxVmRLRzVYMGFsYUllaGNoTUxCQWxBNmhVK3REeWl6TmpOeHVXSm9tWFpEYzFaTXVSMUlNTXkya0lJSmY1VUpNanJsaWhRNVZlejBiUW5id2lUbE1EK285VnNJZEJDdnZIUUxiRXRrUWgycXZvNFdkRkZZVVZSTGpaYVdXNDZPNld4RTZLRVdqc3hhRE1qbFJzTlhGTGRDU2xVYnJXWVBER21LMXNZMUlhYXdlN1JVdWN2REV5c0pIVG42ait4S1FmUlovWWZFa01zTlpFNGNpU3BkWXdaTktvdTlGT2JKMFg2TUQwZ2pzQnNvUFFxdURZckliQTZJcjVNU1U5TENLaWZTV0JwWFZZMjI2bHVaL2dUVTdPL1FnUmNJYndKSW14OGxDZmcvSjEwTlphSlZpNHAxUWw2QnRmRlpiSjRkTFltU0MwSW9QekVjUHNPSDJDcTltNURMZWlsTGhYMks1RXorU0ljcXNHbXJsQTJjaWtMMkFTZGt4MFE4eVQzMWtETk1WS0hLRmt5Y0ZkQm9hVkt6OWpMVHV0SEljK3dwTzNJU2x3VE9GWmZwUFF0VXBlNnZwWnkvZ2JoQ1NrdUZwN0wvME1LTkdSbG9YeVd4UXRHTnBKRkF0Yml1L3NNREpZK2xOOEYyaUMzbVFvUnlWREpCdDdzYUliUGdvUjZieGFRcmRmNUd4SWo1dnhyTVdudXRFa083TDVaVU9SY3hzSEtlektxS0dKbGRSREhlSWJTczdwMll3TTcvSjBGWDBTYnVXR1JYanMvaEJXQjJHV1RoOEc0YVRoOEZwTlRMdCttME1WVWRBN2t1L0RrbVcyeVJqMVNtOGtWay9Wa3BXcTl5K2ppbGxkdXlJdVRQMjdDU1dTQitKbnNqeExiKy9SbzVHemdqVmlVc1I3TVkvR1I2c08veG9ray9LNTB6YVgwUVNsSmxDVE5ORXIxWEp0MUR1Y1hVZm53dFY5eEdzck5XZjBTSWpwUzA0MFVweWhicWRWL1lZOTdZV3lGVWVYK3RjMnd5VE5aMDNPeUt0VjFXenYwS0ZHYjI4aS9GUVFRM1JSRU45YmpWYXIySGNXSTBzSjZadUMrajJZeCtNNm9mdWZnZXY0M09sTE0zNFFoMFFuTmlDSktxekk1cHAwbXpHWlhld3pxSng5aUtWemJkL1VvTHFGRm01M2FQQ2o5VlVHa3M1RWR4TGZTaGFuUkFzVCszSTJuMEY5QnZlTzJQYW5samJ1YzYySjJKUkpkcDdESzRjRDBWOEg4ajBSOG40SHIrZHpvNklNdmdTTGg1YUpUNEdRUkZuQkxLSlFuc1pVTE4zcEtaTzRGMGYwSkVJbGl2SFNZVS9ydEFuSTRoVDJNcllodUNxeE9rcFhhL29GdkR2Wk9uTnV5Q0hPMURzalNTUnJKaEl5VmtSS1cwV3B4SlFhTXFhL1hQSHlWcWVxeHV5UFdQQ3JQZFBnWWkxcUVVRFlKK2Jka1N4WXNGQ0JISkJsY0ZlNTZFV011MERUNjI0MEpseVRKR2tFdEV5SnRwVGcva0NIVEx3NEVpRnN2OEE3alcyVzlHNWY3SWs3cDNROU1XTUxrN2pFdGthdG9sc1l4ckkzTFpEZTBITEtnTnQzWjMvQUtHV2VhRlA1NDBtZ3pWOFBrNWtmQWlBcFBZWFo4ejRLdHdpYTNaSU5ld2I4KzRrcU4rSEpZY1RwOGpOS1Zja2xWeVJZWTFhSmtUT2tFRlVTZENrV216TGpiNDF0bzM3UXNIVnJvdnFYeUxWdUNXeG9Va3hTNUhZWit3cGloc2lUaElha2VGL2c2TG1LUTdmQk9Rc0FUaHlNb1YrVUxBOEFlZlI4ajFhVnhCY0psa3VzZkkrQ3JhM3lMMmZZOXFtM1lrSzhOVTBiWGY4bHppaDhyNEZjU2x5MWgxUHkwU0oxa2t2UWVhSUV5SlQrdzY2TUxWZ2xrSjVRbDRGbzMrMkxWcVd1amVQeEpLc3hoaGs3SWhvaGNzZTBzMnlTcEJSRTJ2b21kZkp2cGJTbG5BNlloczNlbWVRMEx4K1JEYWh6b3h0amtkRjdmQXR2bDVqVkNwVUZyWk5BVlc4bDJlN0ZGMTJKVmZ4OEU5V2NqbzZXSVpVa1RLcjFJVHNOQ2JHVHVXZmVTSmJRbGl5MGIvY0RHcGJLSHRySzJNWkwwS2RNTFpGU0NQclQwdXV0SHZUMmkrUjZJeDdmQTlWZ1NRSmh6c1dHQWlSVmVrRk5IQXJvU2xDVlNESDRkU2NVdjRHTi91aHJ5ME0vd0FGc2JSRU1qOUJsMmlMajN4N0ZmSTlFT3o4V0hyK1p5VUtMQkZ3aDZMRldkVlozVXVJVkVud0pvb1o4QTh2bHNza2IvZElUb2xJK3NrTXFYYitnOWNvVHFKNmg3TmZJOUVQOEhBOUVMK0RjdkhxS3d4SHVkK21xb2wwUlAzQTdzUW4zUTg2R3h2OTRtSjZXUzJ4RlhyakdoSUkrbDIxZWoxT1QyYStSNkl3L05oNklxWDQzWThzTzRoM0dCWCtocjRSZTF5c2gyN1hzaXNVL2pSdi9nTFZRaE93dmZJR05DUXlOWHBacXN0ajJhK1I2SXgvTmg2SXV2eFVkOVMwV0ZSUDBNNGZ6d01SS3FQQnJOLzhKTVQxaFFzT1JaYzJaODhJZ2RoM0xOYmlQYXI1SG9qSDgySG9qOFRuVnVtaGlaVG5qQThoc29RTDZMcTMvd0FaQk9kZHBEK1NqSGVxQk90YTRxSkZ5QmpqNFh5UFJHUDVzUFJFNk5oaUxJUnRpSEJ2UVRiZ01vT3hqNnZ3eHEzQTMveVV3bW45RnpFTENQS1BuS1A0S0NlWjg0SlJyNE1mOWFmNHdwcmVnYndTYmtlQ1Q3UW5XOU1YRzdZMmoxOGJ4Nml2azVEVlJid1BrdytpSFkyZi9ObURtUStwSXN5OGlWOTg1cCtSSDVFTnhOOS9WRys3dlAweEZ5ZXhQRkNmK21tM09hSWJNbmNVM1JIUkRJWkRJWkhLS2JDZHhEWTRwRXQvM24vLzJnQU1Bd0VBQWdBREFBQUFFQUFBQUFBQUFBQUFBQUFBQUFBUkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFDdXlOWktNQ0JUZ3lBQUFBQUFBQUFBQUFBQUFBQUFBQUFRMGVKaC83dkNtUFFpdTNqQUFBQUFBQUFBQUFBQUFBQUFDNVN3enMzOWxLOURobG9wN3Y3aUFBQUFBQUFBQUNBQUFEYmEwNnptbXJnanhGRXAxaXFxdXBnaUFBQUFBQUFBQUFBQ1FZdHJybUdwRXB5dnNXVWxuc3Jpc1N6aFFBQUFBQUlBQUZUVW5NNnQwUDRHb0tFOGhNdjlodWc5aWdvZ1FBQUFBQUFCYWV4ZVZkZTNxM1lxWlZEcDFLc3ZkVHFxbnVxaUFBQUFBQkRPbzJlanZvWUJtdzUyNzc2bGliUXlRUlVTajgwZ0FBQUFEdkJtOFFYVUxKRUFMRlF6NkJwZDB3WnpEeitzWmN1UUFBQkZGeTExaGRGVi9ucFVKd2ZvR0s3eTdyeFllaDhZVzZpQUFDbFBvdzRJRmFhY0d1cG9iajhydHZaU1FuU0hnMXQxVWlRQUd5dHdTdHV4d2JIaXU0a3R1ZXJ1dzhwb1FKTnpzcVoxMGdBREdwaU9sdDZ5ZWhyNXBqZmV1aCt2OEE5eUJFY2NZSTZhWm9CRWRzZlBZSVBSay9PT0tjdkptd3RmdnQrYVdZNWtueVJXNEZJNzhwUXkyRDF0ZVJPOXdiY3Q4ZFBlNnE3WW5tMmJxWllZRklyVTJaZW5jRVBKWjZqN2hEZ0F1YUx1Zk1QMXhnN2IwMDRGcG01MjVKb1Q1bG9QWmxxQzAyTlJJN3BlOXUyb0ZKcEtndTNaTURXKzFqaXBxczY1QmN4Tk1pNmdLb01kTUo3bnljYVQ0bTVxR3UrWXRlZHIzckxzVmV2UW41M01wbGphT0ZJN3VjazRsVXQ2cVNqUFZaQnRaMXBNN0tWeUF2S29wSFVJK3ZlMGFjNkVDKzkybnJWNjNHYjBkS05MblNyYmFaWjRYSDM1L1EvVzNhQURzNVA0RlhsZ1BNcU05ckg2MmpiYmFvcUNwWnY0VmErTEtBQ3Y4QStCWmJadzBCeXZ5bnlpVXlBVldXZkJVWGhhUHpLRGRBQVZEL0FLaGdkQW9DeTB2bFNLZjV2RHFibUhpOGlXWmlkdGlBQUVCL2c0ckFjRnJwWW5KMFJQOEE3dWZEa2pZQ0ZPU2RZNlVBQUFBQjlhaGRuS1VBbWJaTi9ubVVYYVZJN3dJN0RXK3FxQUFBQUFDMU50Sy9UNnBkSGFRd3RQak14cnFJSzdOTnFPdmtBQUFBQUJCeWxibXVNVWJiVTY3RjJWN0ljMEZidjdiSjI4QUFBQUFBQUJEd0tFa0VrY3NHck9PTHBjTWRjUnBackg1SUFBQUFBQUFBQUJCQU90VTB1NEtDSjNjNHFXNWErc1dhZGVBQUFBQUFBQUFBQUFBWDI4RWFwblpSeTJlaXRPZVByTWZVQUFBQUFRQUFBZ0FBQUJDRHJNdDlPUG1vRDkxcC9tNHV6Z0FBQUFBQUFBQUFBQUFBQUFCQld6ZThKTHdSdDN2T09BRUFBQUFBQUFBQUFBQUFBQUFBQUFBQkREWDFCZWpzZ1ZtQ0FBQUFBQUFBQUFBRC84UUFJQkVBQXdBREFRQURBUUVCQUFBQUFBQUFBQUVSRUNFeElEQkJVV0ZBY2YvYUFBZ0JBd0VCUHhEL0FBVXFML3Rnb3JJUWhDR3l2L09iZ3h0aUVSckRlTGpSQ1l2K04vZzJ4WVh3eXJndlV3bjg3Y0c2SVdGOExveWw2K0dGbnl0dzJ4S0c4VHdoakVlSUlZdlV3dmliaDFuTUV6VEdtdUYvY2R3OE1lTVhtWXBjcC9BM0RvdFBESVVUSlQrQkllVUhRdjNLV0tYS1owNThEVVQ3SHNUdzNDNFRMZkQ3T2lEOEN4U21rWENHSkRGNllTT3JEUW1YU3BvZmJSTVFvM1dMUFJQWWl0NWd0VVRiNlZDV1lMeTlpMGpqSGx4dyt4NGhCandrVFF2RFFUVWpac3loK1dFR1BhRTZzTVQraFZCV0U2TEZIdGo3aFlXc3REYjZLUDhBQktlbG5vWE1JNHg0UXBvWVNjeFNVU1B2QzZRNWw0Sy9RbVY0WGZGS1FnaDRXaC9aQzhYOVBxK1Z2RDJLRHVZVDArQ0lhS2lsR3lqMkxmbDhIclJSY0xvU0hsaTBVcGZTd1EyVTNqV0VpR2hXS2owUU4zZ3cyR0UvM0N4UllwU3JOS0lXRXpVVWEreElKTWFLYkd2MGJEZjZRNDJ5S09ZbUpyRy9EZy80Ui9aUzR1RU0wY0czZy80UCtEL2t2OEU2K0NVU1M4d2FEdUMyN3VsVEJlbWhCbjh6K0ovRS9pVThHZDJMb3lYSlA0UkVSR2RFTjRuNE5Nb0pLSk5GQ1dabHFqTFRncGlNUWtGMFl2RXdoc28wUXRteDdHa2JHdDRwc1NwQlllaEl5NGpJSjQreERQczJVdmlpSjRnMW9hSUxoUE13bjRwVFo5aUg0bVhqZy95VSs0N2lmQlM0TDluUlB4UEN3eGVHZjNEYjZMdzRVcGNYd3hqYTRMMWZoaS9QU1NRM0dKdHZORzRhS2JJeWhSOEdlSmhzbUowTkdMV3ZTeXgvdnBvaGJlQ2R3eHJvZjRLNk5hMkppb2Fqb25od05KckFxT2kzNFhsby9HYjlqWjhFRm9qZlRtR3RDUTN2QUpzUlg0TmhCY0Z3bzlrYU9zbEt3dnN2aWF4VTBmMFFiL0JQMGhNTVEwRUVFaEtQb1JDRU9wRGZUdzc0SzBvL2k1bDBTSjRaZGpFRjJJZWJtRG9wYWVlL0N4YTE2cFd0bHlVNGhCcjZGYkJ0bzRIK1N5MzVoMFMrSm92MC9Fd2ExMHViTkJyWWxvUVNwTmliT0JzK0VrVHhmbGFMTzR2bHJRK2lIMkliMkxFODlFdm1aSndUOVBvanNRK2k4dGt2ZjhUUnRFZVN3UStpelRvbC9rZzBUOE5sR0tqcENhTlhEYklRbitpRUlRUVFURStiLzhRQUlSRUFBd0FDQXdFQkFRQURBQUFBQUFBQUFBRVJFQ0FoTVVBd1FWRlFZWEgvMmdBSUFRSUJBVDhRL3dBZlM2ek5MNTdpRXkzaTZURjhiZUo4RnRNWHdkaytGTDZ1ZDJNL1JDOGp6Y2RrM1haK2k5VnhOVXVSL0pmSjhpUXhFSHdYRnk4ZnBDY2lGdXRGczlHSnRkblovQk0zQzAvZDBYd05md1Q1M2Z3WW1kaVh4WXNmbWlmNE5jbktGOUc4SmZONVdqUStoTW12NzhHY2k4YlF0TDhaODN2Zmd4bFB3dmdlMTJXV3hzYkV4UGVsS3RMbDZYRUUwVlpwemh0REREeEV4TmIvQVBEa3BjWExLTmlsTGduY0pyTXJYNllvV3pHeUt5c3JLeE5sWERJUWhDSWlKdkJwNE9oQVZKc3lDWWhDWmVzSnBjc2lHTllKSFpCWVluY3dueXU4MWE0SGhiVHlzTFNhZGFPaUhZdkRUc1MxcGZnMGRDZlBoU1dFOUdOOEZDZHd4UFJ2a1E2Rng0R3pzNktMRFkvNE54aWNZbUpqNEZpbloweFlKL1pzU09qc1dHaEliNUlTRlluemhGR2RZaFdpL3BmbXlFSC9BS0VpYUlhNUVFRWh3MmFFL3dBSU1jUHE2eVltbjZmdVN3OW1oVmVTNFIrNGVhUG9hRS9PeHJDRDdFdUJpSU5ER3hMMVBDT3doaTg4Mlk4ZGhEN0Z0UEZNWFI0N0NIM3RQTkRrbzhkaEVMaWV5RUlJVHdmL3hBQXJFQUVBQWdFREF3TUVBZ01CQVFBQUFBQUJBQkVoTVVGUllYR0JrYUd4RU1IUjhPSHhJREJBVUdELzJnQUlBUUVBQVQ4US93RHBLbnR1Q3oybUpmZFJnMms2V3MrWDlSbnRTajdUVkE3bGYrMVhVanVsSHF5cFRPOXZhYXp4cUIrVXJMSGxXRjVvMGF2MmpoZU1FZnM5Q2lMNnpNVFZLUkJvejl3Wlpqa2E1NjZkaWFxenZjSHJOVno5ZHd5Nk1WK2pINjZpdGV1bi9vZ3JRWml3S1grc2F3YU5YUzY5dGZpYWVMbXEvTExXQWROWXJVTHJFcmIxblRNWVlPNStsSVhZOWhpR2pUdW5DeTZ3aTNkNWdmWTdpUTFEaXhOVHpLNkVUdkhyWHJLbHdkQ1pUVWI3bHZTWllWYmRQckxoOGdIcWYrWTdSVmhObHV2SHEvRnlzVXg3WVBYWDRoYUJ3Q3IrN0V1VnNRY3N2N0w0UDlJT3hIcS9zVFRoL1RXYXRJQjQ2UXZWRmJvWmx6Q3VvRVhldEQxcWJxRnRhUjVqQk5ONHNJeU5NcUFOTjJsTnVzWXQwMGVab0hyUVdoZUppRVR0bWFTbnRIdWVrVG1ZdDN1Q2M2dGNNVWRBOFE2VWpVVC9BTWQya1dIZ3Q2STl0M3hEbEliV0R0bzliaU50V28wRnJRYXVrc1JUMnlQWFNXZ2Z6cWwyRjFYS1V5QVJXc2UrcWFScVNqTmIvcmJNQkEvU2FDNkoyL2srMFZscXZCS04yWCsrWU9Eak0rOFpZTkdIRVVVdkhUcHI5bUgxdDQ5Tnhac2tRMHpOT1ZjUy9TN21KcjQ3YWZTMUlQUmxYSFNNa3dwZVpxUmtDSnFQL2hnclJyRk9QV01keCsyc0ZORDJjSHB1N3NRdHE5WXJFZFVxZW1tWjROV0lFemJSNklDWWlXYkNNN0w3VFhLSVBaZThyZFFKVmo2eDNQNElaK2kxMEJwR3JyNlJOQXpBVWRDN25WOTVlbHhpUzdldURzeXNaN0NXdG94bVpXY0N6OTdmRXVpdGZ0TGpTZHpCZHZTRDI2TW8yOHpZWm1YS25ETU92bHBNUDhRU3NhNmsxdzFvTlNXRE9VMVAvQkhxVmFLTHQ2Y3djdjVMSjNiZGoxbGhwWmhRZGlLekV5bFZMOExIOUkzbDVidGVoMk5vOFVXNDJoZmFDQ3dDYVJseks4UGlZYlE0ajVsemNHc0YxVmRQTFg4ZUk1d1FnT2tjMFVMOGZ6VXNab0s3eTZ6U2pkbUFBelhMTnlDbUprMU1KQUhEZ2NRamxFWTVheWRtWDJyZncraVJOb3h5SHBMTVlZczFabUd2eEIrRjVtSmNGWFRabG8wNXRtWUZuWjJmKzdFS1BBTzUrMnNCMlVVdlYyNEo3L0VUYkI3Mm5kMm14M280OEVxZ1ZqdE9mUWdlQWRJUnRWY3dCblhxelIrWit0cGZZb2pVdlgzZ1hDelB1N2Z2U1ZpMkRQZEtvNnhnQ3RDSHVoRHNhKzlTak92eElIT0gwcGl3TVhyMFlWTFpjdGtNWnhaZ3NlNkVtYlQ0L2JsNU0yeDFpQVRES2lNZlNWK2tRL3hMVGF1U1dkWXZKTmNSOEhTSG85T0pwT2dnODlrdlJmczI3LzhBV2dBcTZFWXBkVXJYOXQvUzVwVlVHaCtYckFKNVNOUk5HZ2RIWTRJcTV5c2N1OWNUT2loOTRCZ0FiY3pCeGZyTU9rcEVxTmJGOXBTNWNRcnVLWFMrZjkrWnFxdTJYOFdHc1dYM2xXT2hMdnErOHdyVEQ4eXp4QUVGczF1eWRVdS9EL055aE92eGh3WUwxbE5TckhsZmFVaDFNTVZrNGRPalBYNk1yc25mMUpYOXhCMTlaL1pDU1dDM0VCQVIzK2x3UXJWYU1BbkpuZU8wUkZ4WC9RQkczNGdRRUxUZnJ3T204dTVYUS9IU2FyTHBmcDVoRU4yQVgvSjFaWUJzaXN4cUVielprOE1jcGMyTmYzTVZtKzhERjZITXFuQktEVnFaWDNLalc3ZlFNRWIybzh3b1p1RVpHQzArMFVzNnJzUDUrbWdVeTlJS1RZWDhmelV5Tm9NRzVXV2ZXRy8zYU1YbVFxTHdhOWY1bHdtaVppTGFpcUNsVzBVQVhtbWUrOFJKeEF6Nm1HWTIrdHhJNHl6RHBFNlNyZFVjdWtjeGw0TUVESWVGd1FXTmtQVWlPQ0JYdDlrY3Npa2RUL21FSGErMEV1bVJlb2M4RVRkaXJuTzhvTUM2UFUvaWFqSmwrT2hIb0pEaWRhQU5ueExmL2VIcHQ0bE1WdUduNUkrdFBKV2VrcDYzblZLS3g2TUhtQlVEbzRqd3ZFUWE0bDlQWE1GNWRXSUU2NU8yMzVsWE4raEVDazVaU3EyNWwvQVVuWXkrOWVrd1J6VTlqTEhlSmRaK3FZSzc3TEt6azlwcHJvdUFHd2E5WmlDL3Fud2o3eWxZUUhNV09zcmNabmNxWGNOSW1HOGgybXlDc0doRHdaWnBnODVZdFkrWFdJclZXSTlKV21BYklSWWl4TnBwb3ZZUDc2UnNDcVIxSC9rTkhsbHdSbEo2blhnMmpsZXE4emdPaHIzdlhwREF5WXFyZWp2S3RrNkpDNFBKQmxQVGZ1WXkydTA2U3FoYnFvbUdnclRmU08wdDY2RHVTMlJQRGgvRXI2RzhNQXBwNC9LSmFUcU14V0hZR2FKd2J2QnZFMGxxaDdCOUZWaXd6RHBXT3hMdlUxYzcrN0tKZUFIZmVaSm42RGlDdTgra2QxTDhQODNNaHU3SXVzRkY1SnhDT2UyOFROYmZTdlE3cDFib0UwUTdzRTJ6a3dta1Y4dUQ4ekduc2hNTU5Pa1c0dlFRQnpFUSt3QWIyZzh3UzJHclZEMmhIcnVRYTVGaWFrWURsUm9IOS9hak5TS1IxUDhBaU1tcWFBaGxDWlE5M3B4enJGWjFIT2RZYkFROUhQZmljbDVhbnpBYURiOWVqdktjVTRkb3kzNnhwOVlUVUltbzZ3YkRiV1dKMmVETGVlRHMrWUFLaWJNSks3dkxqMVM5UXZmSm1Vdmh5SDNtZHQ1WkV2M3BwNk0wN3JoNE5aWU4wZWJhS1lrMzBnTkY2OXdmcEttaXN1c2V5Y2x2bUNIOS9FUHJJWWJuNmgyOTRib21IREVVV28xRFplR0VvdWNuMjlvRGJqV1VZRGJMTkRWN2o2NkViZ0J6cStzR3JidjM3d0tsbzRNUzRMUkNNdVdhRVBVQU5VMEhtR2xPc2xEeHY1aU42V213UnpHV0dhOW9Zc3c3a1lraXhJMklQQnQ1UDNwS3IvZzNnbVVOQmJ2SDU5SlkyNWZtT0F0ME9hNi9pSjc4WGNXWExUSktSQVBEMmRvUUJkMzY5SGVZUUdOT2tVQzE5SFVpTTVEd2tkQVRaemNRWDgyTldGd2txb0VMeUgzbGFkQjBlR0FpVUd3WWxxcWg2QitzVnptT2h0OUZlWmV4bXBqWXkrOWVrcmpXcndaWVMwQzZPbEQ4L1IrbjBZUFdUSnFVcUJoUnNtSTFIUnpBcFE1T1VXSlVsb2E4dzcwQnd6UmR1REJBRU45ZHB3NXhGZ0xwTjZBeGlFcUtHclVQTU5qMXNCNDNqTjZXbkI0aGxadmFPNWZFYzZ5b2RaZ3VnYXdManpIRHJZNU9HZEdJdlcvNEVQZVZwb2MvdThLQTZOQndUTUF1T2R4RGZkd2Nla2M0WUp6ekF6RDZCWjBnNHFXN3AyWWozSi9EQUNnTXRMMmU4QXVpUFdLQVg1ang2d0RKSERUaDYvU21HZTZKbThiSWJLM2k0blV4bTJoa2JRZStyN3pDOUJUdnZMS0xwbmd2N1RWQnRJRzk4eCtyK1pabVFYdkFWNlQxWXJaeXM3TXlIZDlHS05OWlFpYW1TQmt6YnJ0RTdaaXpWeEZjc0RRUUJBRHFsRHpOaTZvbytOWHpHaHVEd0IwTnB5ajRpZHI0bFNwbFlGWlllN3dlN0RMS2V0VXR3YmZlK0lnazMxSUlsOHgyNzJka0JuVXBaeHgvdUtCUzgxOFFnQ3pVYzhkaVZCUlo0ajVXSEhFL01JRTM0b29xOVVJNERWYTVQOEFMMEVPOGVwUnNrQkZVMzlPek1BdGJ0ZWp2QVZURURjY0xBVkgzK21nc1Y2Zys4SlVkSmE3Q015WGIyalA0bGc3QzB4RVhLVjh6Skg5cG15WFdJdlQxY2ZlTnFSU3dVM2Y1cGZjMUgxWmFoZGJpd1JOc3hMbHFxWWNPVWFObHk0blpBMGF3cHBEVnFIbWJOMXhSN0dyNWk0MlZwc0hiaUhobDEybXRzY0VxWUdBQU5tZ05ZaDRQVTd1WDRqTlNtMVhMQVFGVXhqYU94cTlvNlFpeDNlWTZmUUZSZk0xeHJJVHAvUDhBc1lBVldnSVR5V1crWDdIbU9kSW12dk05RHNSeUhsaU02WlM4ZGU4V3BXZnJnWHJjZFhTQnNPRWg5QmcyMW9QMDd3RmJRQk85L2lPR3NVRHFqcDJZMkpkcjlsZ3RWaWJ0dXpDeUFPWUpxZlpqbGVibUxpVmRadUJ2c2djN0dYN1RFTldIamVXVUlyUFNvdmNTRmxRVy93QkVQeXpONEZ4ODZMUGIrcG1FczFaZm1MVU5FdVZPd2U4UGdqMGhOQkROUzJGSUFkV29lWm9RRHVLUGpWOHhDN3Rob0hZMmhzWlB0SEpEVVl2QkdGSTZFZTdGUm1LTFE2Zm42UnpCUHRhbDllTHV0L0o5cW5DUnI5Q1dFbUEzSmtSRkVic2hVaFRTZXQrOWY5bXA1dmNHNzl2TXNxZ0FBT0RZbVdmYmVXTVdHcEdXaks1UmhvYXh4Wk10bXppWTdid25EeEUrNmFCdjFOeUFVV296OWp3OUdOWXdzTklJOVlYZ0NIR2FUd3FLUnNZV3d6RlAyZUdVSS9wTllNQXY1Z09SdzZ3dExuZTVuYjA4b0xCazJKVkxpZTdyN3N4QnhWNWYwbDNCcFdpZWVoNzFOdzk1WlJYeU9VcnlyNWl0TDNhOVphMGRScGdwVEZiOHk0NFo4TXNLMVVHU25lYmptRnFRZFdvZVpzZFc0UStOWHpNcFlHaG9kZ2FRcmRIY3ZvSHRBTXBGVzQwUHV4OXBUU3NyR0RsWmRDWUtxL0IwZXMybnpBdFl3T2Q3MStMNW5kTm9OM2VWRXhtT3NGQzJGZ1ltbzl3S2FoenROSzQvMWFwQ3dBbEFMME5qNytZejFIYndONVlKb1BFRGdnejRHSEd6OXBXVTMxYnN6RUNEZ29UcHlmcCsvRTBDZlpCV1hvbW9PRTBUdk1IajE5SjNlM2FLQUxOSnFjbkpIcG1JY3FkbW41UGVaZm8wUnMrZ2tWUGN1dk13aDFacjVnRkI5WlFVck9KWlIyWjRNeXRVNVQzaVA2c3BvTzBvR2wxMmFTM1ozK0VIOHl1RHI3Z3pyUnA5eUNtR2plTGZ4Q0lORGZuZUhHWTlNRis1S3dMMWZ2ZVZ1TFVvOVlJOHpJanJpajQxZk1kTEd3cWpzTkNZNVc2VERMUnhMbHdPWmJ0RldQS0g5ZUl5cGVwZG5nNWVrZUJ1Mmw1NWpkNDRpUzNFM1h1RXBYYnVZN0JhdXRnMkRwVXkydzRKVURFREdhUjBqUk94c2ZmMGxHRmpDcHFGanZ6K3VZaWtTazFIYi9TYjJBdnh4NWZ2RlZ1OHJyTFZacDJkaUY2ek1aUlE4T3N2R3l3OG16RGQ5bnMyWWNjY3pEaUpoNGRtS2NPQ25WSmhQRm5xUkpCUVBSZTdWZG9LMWpMcGZ3Nm5wQXBHQ3ZrUG1vNWgxTmY4QWFPMHFieWt0WCtoRGF1L1ZQM2doUWNKVDJsd1hrOUc4VzJKYUtTbkFaZlpodUtFQngrNGx3NGcrSDNsYzNaYUhnWjIwczhQOHhwTm4yeWhyYnIyblEvdlI5akVLYzRtQTVaZ0JjMG90MElJMDlqU081VU9EU1h2OUQ2R1paRnBRMURWaTRQekZoQUNzQUQ5M2QxamxndGRBN3JpQ3NmRDI4ckhwY3NLSnhUNW1uaW9ZWlFXWHpONzFwNjh4dzNIV0NvRVd6V0d4WXU1MDh4dzZqYkM2UlFzWkdySGZwQnowR3R0eC9vUTNkcUVZcG9ENDlENW1FQnl6TGNsdlRwS2RXUmlhdGp5Y201TW9RM2ZLbVY1V1RrNGlXWTlzWHBkZnRRRmYwbjRtZkVPanQwWlp1b3gwNlJSQVJwTWliUzk2RkE5ajVhd3ZVakZXYzA4UFNKWkF0S3pyY0hrZVlxY0dvNmtjc2pGTlVUWGNkelVsUGFNYVNtNkRpMGhCbzh3aTZEV3ZqZjd4T0ZFZkVZaVVnbDhsdnUrMHpYdjhNNG1hUG5FU3VLdE85aFZTeE95QVIyRFIwemYzZ3d3RXRja1h6UTRKZjB0bUd3UXloZThydTZTcmwwakdwYUVDTFZkVnY0aFJMWllZZXQ0K1h2SDdxK3lRS1Z3OUNLMXRlczc3RHpjYk1Yb0hCNDBQRVZ3WU9DWldWZjBPZkRRNndibmlaUmFzQ0xTNW5IMWxGcC9nRHg4ckVyMW1SVW9zbDVoTStPeDVOVDk1aUlvbEp0L21GWGV0MlAwSWl0NVZtdlYvRGpBU25SaldWc0tNSG1XeXQwRHVvd0pubnNsODJmSDZhU3E1am5DRmIzTDFaYlRzOGZ2U0FnYTZQREF1Q3FhZThJcVI0bDVJYVN4Nm04RnptdFcwN3RuVFh2TmRFOWVrSERJc3ZTUytEcHRUdVJBR0RvbVl0MjUwK1RlSmxWdVJ1bUlrMEpydjFUUWhRSHdTczlweGhCNWNwODM0WTJKT1krY1UrcCtadzRNclNhYWtHWEljSDBacDA1MmpuT1g2WEZKdlZlN3ZBUUt1Z0dXRStBdUR1L1lpVU5GWUFLcnNTckhtVTJkZjQrdkVFclRhNWZweTY2Y1RLbWNXdVg1aWtxOGNmUUxhaDBRYXNacTBZNGpRbUVRQ2FRdXZZakNwMnVkbjU4UjZiYlZ5c045c3JTSlFITUdnazVWeDZtNUNTeDNuWFgzK2Y4QUlLQUxXYVV6OW44MzZSUU9BTHRqSzhnY0cweDN6RGdPWmllMlh6SHYrSFpNSjNqUE1GVFZCemJtekZSWE1CRGpNK0diSVlIZnZBVk5OS0h2TEFVeHp0REptSlhwZFgwSDdzTEFqU04zQjdSd3BOZTNmdnIzZ085TjUyUFozR1g3Wnh2Y2hpK0RlZjNQeEZEZUR6MlpkSmJYaDdrSG9KczEvaUFLRkRwa0ptaFRraWxRSHE3c3R0WTlBWUppL1RIdHZLVzZvNzZRL3U1UVpkNTFiWSs1TlpIMHdxRjNCb1FoWURneWxPMVZzdHY4UWRORXFyV0NMQm9wbnNOL2lHZHRDaHZ1UDJKU0VOSExnZHBhL2ZCdm9ic00wZHFqZjZHaGlKd3VGWVBqd0Q4L1JSMW1iRXNFNjdlR3IxN1RFb0NLaTJhc2RRQzEwNndLWkxSZWR6OXZFVnF3NHZuNlZZa1c2SjBsMXZZTy93RGZiL0p5bW56R2dOTUE3R2t0a3BhZHQ1UTk1VUVITjhTaXBvdndsS3VaTXZJdmMybHVPOEJ0eVRYclhyMGhmSWFCNWkxNWxRTWFFM09ZSmlnZXBNS0kvdW01TWxSN3VQSnI1UXM2dFNMM1ZaclRkWTRJQUlIV1Zyc3h5azF6cm5kNmZtRE55Mjdlb2NSaFEwUWU1OTVsR0RrR0xtbXI4Zm4rSlNpMmM4bmFJS1VnNVVvSEk1aUhVK3AwZTBIbXJ6Mzd6SE5NWGlPMUxGZkxnK1dXNjdGVHhENmZ5VFY3c3VSb2crbjl6ckFpdExiTXFBV3daVUpiR0hxejVmeEg3VjlPSTJtQTFHanVZR3NyaU1PeHYzZlNEVEZXcWhMTzZlN3dkSXdOaFFtL1BsS2k1VndSUlJtQUxWdkRMSStpSG9mQm50SFJhRkFvRGdJSXd1V0l2c2ZsVXN1MEN4cjI3WXcra2UwRmJWZDJXdHZRaXBiTW8zanYzL1VyTDRQZEpRVnUvUUtBWlZNM2hBNnd4cTQzVE9rMTBYL3hVOGdXZDlEN3l6RlN4VEE5Vzh2c3cxMVFncUJlY3k3emZUV2VONG1pckNtWVZCamxjTU5LVWxSYnZMNk1NdHNCZ3ZBa1ZySzFYSkNXdEdrdWlzMFNvcDRTdzkvd3FJZ1lOUENINWltRFVxYlBjSFU3UHJCc0ZDM2tZUW5BZSswNERsWER1UUs2VTk0ellHNDZQY2dCc1EvbDltQXRPbGFkemFCNmpraEpZZWk2bm5lTlRJcmJDNUZoNkQ4c1ZSYXJjL2E2cHFkMlh6WmJlWmxPQXdPSWF4TlBBUUtBVldnRFdiR0c1azd1M2JXWUFEUUJROFFMYWMzN1JkUUpnZmlCZ0FwMDduN2Vzc3RCdEwzQ241SHhMa0pxUzlmN0NpVXdsMFJaZFB5cUF0dHBybm5UdzlZY0Z1MjBlVlhnMWc0RU9wMVRsNnJtVmgwMVFZZ2FUSlZwRUFETHBEejhQaDU4dVk5R0ZncGlGUk13aVdReTNoaUpVbG5lR2hqcjBHdjcwL3dCV2lVQU1xL0JnKzhTcG96R2F1VmJDQW96bVhwVHJIZDBNb0MzaXBXSHZtcFJtcm9LaUtPU0FvWFdwZEJ5ZEdEbVp5K3k1bGJ4VGFudEh4QlBid09zd0lhVHF6ckZsT3Y1aURFK2gydSt6eDZUS1dVeXpjQjk1cVV4alBnZmhnb0t0VTlJNnZEdVEyM1ZFS2s5ekoyWWdMVmRIeWZjbC9QRGg3TVhPWnhnUTkzTExIcFpMb0FYQitqbERkWWdMaVZaaEl3elMvbVVIVXdBb25tN0c4b1VtaGJuNTJPaEVFTE9nVFI3aER0dzBlMkVwVzBaNEExaHFEUlhnMkp2c2F2QktLa0N3dFRvYnNyK3JsN2JlR2VzWktUS3JheTdhM1pwbkY3bHRuZDE3VnpNK2F0SU9kWUdKdE41YWpVVlJvcU9tNTg2ZXNCZUttNE5TdFI1Qy9lSjdaMk15YVJSbWo5Qnd3NlF5T1I5eHI5LzhLanczQW9kaCt2TXFRNVI0Yi9FcFRXc0dGbHU2K1lNYXhzYjkyb0hTdXJ2NHFPQ0dOMFBoRW14NktMZnpKb1krbjVSSEJjTGlkcUl4a2ZYcEhSd21uRTc2RWJubEtQRHpMSFJFeEZZT2hDS01VSTdTMHVGby9FUFlIdzhSODZEQTVONE9Ta0NQWmdvMnFTSHhiaWJURXhnYUl5NHNjY2VUN3l1dDJjNURvN3pPUlFEVDJKa2U0RjkzNEpjWFg0TW9nYy9CbFgyV3p6Rm8xVEJjODREcDhmMGlxejM2ZmFVSnFkV1dJSEt5bGttQTloMW04QlRzLzFQTC9FVTYxV0E0ejZRaTZ3ZnBzZGJiYy9zZWd4OUt4RzdFc2VJSTBRaHRBWlRvTC9URXNDUFZnZXRNcTZqNGhmaFJndHc2NWhmUWVxaTZWbkNSWmtiT2tLRlpnaUhyMk44MWo3eDlSQ3ZIMUZ5V0NYOC9hSmRYTUMrNE12R1grSU5RNWFuckhXMlhselFUMkU5M2FHcGYxTlNYWWhvSmJBTzdBd0N0alpsNDk0VndUVkJGOFBhQWdGT3AwWlpPQkdERlA0SjNpVlRWVk5JNDlHNTk1clh2cjFncUVhU0diMFRVaHBwTjhJckRDOWd1aDdzTTQzUWZFSldVdnFzSHhEa1FYYm9NVEdnbFhQTTY1d2dYb254TEdxRklnQlVDYUZRYjhDSDZ6SE9yQ1lMcFVkMngrN0RHVWJadGVXYlpaVTdTMUdCZ2NHeDlibFRBUWdCd1UwWCtnNkV2cnVNQVFqYUhFYk9ZbnFNcE5SL3hDMFdHOW1VN0k5Sm95MzBZcUJ1UkFXcXI3YVFSQ3FIem42K0hYdlIrWXQwbmE3WG9RdG9MTkE5Q2JBTzdGNkwzbG9zZWFJQU5WZVdHTVhUU0I0bHJRSmVwbjBYQUxSOHNQdlV4K0xFL1lud0JmbmNOQnJsUFlVUWFsRWJLajMxaXJLcnZNaHJZTUdYRzJBYzlvQlZhd25NY21rc1liR0dpY2JuaUt5NEtyR29mVzNJTElhR2doNEZ2ek54S2ZLeGxEZjJQNmd6cHppdTBVd29iWHJLczRQeW11Y1llc3dBSWJoQUFtUVRpZnZNVlZWdFlFQXROQnpDRExyVHl2alR4QkdveDZFWFpOanpHcm5XSDBRODZKdlRsN3VoNWlaNlRSWUhVTVUxSjNKRmRPNUJsM1hkMnZtWmF3NXlJbE5JanduMFJ1RVUyajFwM3hmSk9oSGdaVEZZNnFsNHhNeGJBOXorL3JtK2FQYS92TWhpdjNLc3dzRXdtTjVXOFFyZERHOFdlR0ZXQlUwaC9qTlpZek9UM2hvaHYvMFI3SDNnL1Q5MjMzTThVekI2RUJrenFvNXBleFlESHBSUG5sbVhwWU9oVVo5Y2JneDFaUzZrQ0ZKb0JiTFJMcEZObVJQNk43eEZFcEdrZ3F1em5aajB1NTI4UWdsWnJERnVPWTd0dmVLL2lBVkxTL1lMajlRTGVZblVGOWVrYXBiNzhvTW5hNHNidXZpQWFKajRZQ3ZhS0Q5NWlsYTJ1N0tseGdjOXpmdytlMHpob1lJQ0dDL0hFV1dMV3UzYU5XaTlvSzlJRWxySlpadEZMYXF1c05FWG1CY3U1QnVvOFlpdFJQZUs0UFZCM1hwS2NXVGhMaStzZVF0N1N6NEtNVjBmQkk4RHRHSStzRmZRSlVBd2VGY3VhWXo0VFA4QUgwQzJEdUZmdDlwMDZVWGRsSjZuRVAyblRMNkJobk1jRDdsOW9hOHJ1ejdVaDdjMGZWdGdHSDRYWHBINWRRZW5ZSDVnZm5ZdWZTUWo4TkF2bVBYR0Z1VktaZEVjQmJLNGdVWVFjTjRpVVBOVzMxZ3llNXZ4RlJGYk5CNlIySGJyb2czK3hGREgrYitZbmJ6RFNyMW1WSjZ0dlFpZTFON0ErN0ExWERzTVVFdGNhQTkzUHdUQWRGVHhHTGc3bytVSWczQWFSWXV4VnlvYlhmckdtTERXdE5NeTZXZVNHTSttTlB2RHpYTkdCdXdSREJSd1B6R0JhaHRNN2F1alY3ekUybmFBWUM5TU1VTnhHd0g3YzNsbVdJaktnUUtoY1hlQzZsUW90SHBjcjFUeVZEbDZHZDQ3a3UzQ1RRaW1mdk5QaVdqUFVmbGx2NkgxSmF2UTZ2dkdGWUVHc2ZRODhSN2ZUSU9zeER1OTFsRkcrUGVJRVZWdXh4VSs3NGdmd1VYb082czRnNkFUWFo3dHlodE11YWhHVnVYb2RRZnN5dm01WHU4SnM5SUhpVytpc3hVdE5hME83dE14V2J0dnJERUhxSnJORDFpZnFETG1WSjVNUFdhSkx6WjdRRUpKdFlmdXd0Rnp2WStTeDVUR3luc2d0S1cyRDJuS3Z5eWpicHVoOTh6UEFDNk9oN2U4cFl5cmJFYUp0UjBoaWxzc1daZ1M0Y2VzdmNnVWp2TGRXbk9VcFdMSDBoajVubERTOUpqbzRlcFUxcUhhb0crNFUrODAwZU1TNEJvcEE0Y2swa25JQjZNUlZJa0VhbHdIRXMzSURSVW8raDE5NGIrTGpkMTdWRHNhdm4wbEJsakVEdVFHNnZNTmhIdVRvUFdkWWtzWFVqU2h3dWtGRjFTRENYb3UxL1RPR0o4RDRsRkRkSUs4NWgzUzNFekxPcktGc0UwUm1Md1JGMGx1WXEwWkkxVDdKc3pXSmRESzRObjUyZ21pZUdQOHVpNjdHMWxIaVk2M1E0SGd4T2tHdWp5bEhxeEw0a3RlMEN0Ym9IME0rODV2TjczMVlvUUhWcjdURkNPTUh0RG52akxDQnBPN1BsbUFGaDFML2RxWlVIcjlvcUM2UFFSNnh6ekR0Z3RNcllVTXQyamlDV3cyYXhya0s4cHZBdXlKNjNzdVlPQjdvTFJ2cExJQ1dScTdDcHIxemt6S1J4aUhLOTh3emtyc3o3akZlOFEybnNianZEMm1wTHZMaFZTNDRnSUNub2h3UFQrWTVubXlFOWd6RERxdGdmVFFlYm5EOExYWDRsK0pacVNsdkVNVnRIa1FDSFRGREpOaTR1ZTRuYWtqTkhzelk4VEl1djJZNVJPSmRpdDZOSmwzL1N2UjZYUEdhRk82NWlybCtoUDZvZ01UNmZTLzVKZUxiWE9zdXkrb253elZvY2xIcmNiQUt5WGZRWmhxeHNnUFRMSFVma0ErdXNWdGI1U3N3ZExneEVXekJPNzBuV2Vrdnk5SmllVldjVE1GdThrMEExb3dpT2dydWJkNHJvNkRtT3FtQ3JiaUlLYjFxRll3cmd0dUlpdFN0dUpvamZUck1TN0dyR01EZFhVQ0ZORjFpQjFYazdWQUNoUHZGdFY5STJyYlY2UzNFdHhMY1BwTFh2NlEwaXpjTHhObkh1UzdjUFJnOWtaUnQ3UlFNNlU2VTZIMEZjVGdnTTVZVTNET2tacHBJeTRhTU5QeEhpNEh0RFQ0WDVud011SVNTd3Y0bVgvYld6RUxNNy94REZWTmdlbFJXOTJYNGgvTXZ4UDc5K0ovZnZ4UDdIK0ovYnZ4UDdKK0ovZGZ4UDNyN1NrS05rbmhKb2hUcXpsQ0I3b2ZhTHNIcFpmaVpSUTV3ZTBiZm9HVFFpQkFxM2VrNnoyanlaZExSQlVhOUE1dUNBM0dzR2MzbUJWeUlkQ0JObDFXaHhVdWkxR2RDVk9pWGdRMDBYblpCaE9KS3d0UzI2UkIxQUZlSlFYVWJNR3VrYUYwMHdIb2hPdStxWXA5TGxOOEZhRWVDV2xxTHUvdWw3cDZIN3MzeWE1YmlOazk0VzJJUi9yUlJYbFlSNWx6OURvdWwvaHRFQVAyajdSVFZmMjRtRC9iOUpYWVdwajFKcVZ3Ui9xYlQzejVud1FjUml4cVcrMFFLL3BmSlRLR1I1czl2eW1XU2RueDVMajhLTittcys0eEVkUTdzNnoxblhlczZqMW45eFA3aVA4QU1SWEsrWUw2eWpOTTBtcXA1ajF0UGJFS0lmWVB2ckRudjZZWnlUb2JmaURXVGxnOXBXc3JtTFZaTG1iUzZnVFFwZTArcEVsdXprRDN6QnZHdVh2TWdNNXF6MW5VbGFTbHFPSzVscHNwMStsazF2eEFhTWRGN3loa2ZRSzljRVMycndmb1ZCMEJPRCtaY1VlWXFpNnVkSUMwRmVETTFWWjNSOG9DdTduTjdzZGdybTcySTFWZzRGSW5wMW1xSitnSTVQREZaQlBXTTJKNGZpSDZCOFJ6N05TcjdpR0dFdE83ajBYMzBqaCtwYnROY25pRmRrZFUzcjI3ajZ6Rlh4TVF6dTM1VFVPQW42VGllNmZNVkRzeFdPMzJoWDEvRVcxQWRKVHErR0ZhdTRtZ3BOQUxqUjZNYVBVN3ZVcUludXR0ZXN5Z25SL2ROVHpRNFJwYnFWL2d5M2JMcEt1T3FCYjFJUHlmR1o2eXBmSFU1OUlwUk81RUdveldrNlhITGFYa3d3d3c3RDNheDFzbjlLZnpGWjZEay9IdkFMNnNGbnFSZk1IRFV3S080bEhrVndhUkRTbEl6Q2JSUit3bGhZZWRIdEFmWkVhdnREcXZ0Q3RydnI3eG1WVjNiWlpIcFlpVXMrb3dxMUhsL2RNMGZhNzNaZVNqL1pSaUdLcU9BRDJqelZGN2htYW9QZGdMb0wyaW51SSsyWmxqdEM5V2tYV0c2UHZyTXVWV0Z3VGc3cERaWDJNcnpSMUJaNmtyRU9nMjQ2a0lYcHBmY08zYWZHOERSTTZ0RXhWNHUvbUUwMGNEWHhIcStZanJhSTJGZ0RRV0pvKzBPTHdudEZhY3JOS1hKMEptSGVHcWNTNHpFTGhFN2todi9hR2pCMmdkR096T005NGpJUFpnNENuR0QzajZ5UXQ3UlhVZEVFZFFHeGRlOHZBRG92YUNta3BpWEdFTFNTM0RnYy9NeGdIbzE3YVJQanhxOTQ2VzdPU0FGeFJyY3NDeHJpWFc3UmFVMzhzdDFFdlpwSWlBRjZUNzZ3eVhmZDluOHpHbHRHcTlwNkxFWERYWjVoSUt5MHVIZW5uVm0wZ3p3VWQzK0JpY2FnaXdDTEw5T2JjRXJWSWIvQ01UR200QWZhREd3Y2ZtRW9wU2syR1dKTDRXcmllY1FGWURxMU5EK0g3c0RBam1yWUJUSnhGWDZpdUZ2UWhGM1c2VVFPZlF4dDdRMWgrMUlBUUhxbUFWcmJDb3FyU3ZLeDFBajFtS2FCM2l2RHRNdFZnS1BvNnpKOHgrcE81cEhXT2k5WXZpam9kRWhyVmRMNWdjQWU4RjJuZUZocEh0S2psT01SRFJ3UE0zTU9zMGI3SUpvZ05RZk9JMVZWeXFsaFRMZ2Y1UXR6M2R6MmJoMTlNSHlRQ3c2QmF4RGJKL1pEM2o0YzR2YXpNc2hMeGNzQ05MRjZaR2h0SzFZSmI0UDNFMm9EVTJPRHhHQlRFQjIxQnJxYlBjeTdtMEQ5bWQ0WWdyWUNvam1XR3JOSW00SVhoU2xsWTk3d01IM2lXVFB5b3hqVk9qZ0tsU3lOTm9sUTNPYS9XS3daSE14QWhvWEdMWFk3N3kxMVZnWVIyQlR1TTFaZWY4RDNqNUpacDRuYUxIOHNPZWMyK3hLRmRnWkxuenhacUFpWldzVXd1M3FLYWtyM2hocEFoQmttQVpKc0wwaEJtMzRsZzVVZlRhZXQvVlhoek5SaEVtYVJDekpLbmdMcDlHcHJBZFdMc1hPRlNyV254QTd2aGcyNmR5QzZGOHlwVmtCMUJseHBYYWJqSXh2czBmYzlpR3pjR25XS3lzckVOR1dqTE5Td2dCWjBQdkZsS0UrWTJQSDNuTVZiaEFyTVBHTE1IeVk2VXB0VjFsZ3U3N2tRSGNaUWh1R2Q0MTRZeHRjYm15dk9GZUtqMVdmTzcvQUN5dzdLL2pNbzAzcWQ0aXMyZzRHdThxWWdEYmJtRVdXalBibU9rbXVRd0dYNWltS0Q0aTNtRURjT3pGZVZNTVowWUVDNDBhb2VZanZLVlFNNENXdDJDNmpOOFNwOXdoVzF2YlNvdDU1aXRkVGZiNjZEcGNOTzhzSFV1bU9qQUJvZFo2S3c0aWVwcXA5cDhBS0gybW42RmRQb3pXUWRTSWFTM3BOUUtlWTZ4OVlRUTd3Sm0xTjBTQ2pBcURZbHZHalQ4eGhENkN6UXN6RzIwSmozcWQzWWpWRGRQcXlxRGxsaGhSZytUSENLcmF1LzBaU25DR3Z5M0xucUVaaExuRlBTQWFSRERuRzhyamt3S3VOZytjdnhFU3ZMTkVSV2F5enJSS1lRMnlPaDlwY2JOUjZUSlVMQWdmU29ZWmdMaUJRM2lIU0xmeU9WdzVsWUk3d2VaWi9FdjFYNkl2YU8xajdNWG1Pb1Rsd1JBOXF1ZWdKY1c2WWwwOVVEKytZNlJiZXV2SDExRFRKQnhPMEQ2bjhTdjVZek9TWlpFNnpYMis4UmhqM2lqa09nMTdRVDNXajZrVUp0Z1JHT1VCOVdKV1ZWNW1RM1pTMEFyZEFid2hvTGR2bmgyUG1MVzQ1ZTB6WWxRSUtOcXI4blhpM2xhRGFCTElyUVJXTW01dTdzWVVZSmhvc3dmSmp0eW0xZDV2RkE1c24yRzNkbGNtOFpMM2Q1VUhjcVhDZDVpUFg0alVieTVQY1lpallWTGhyZDE5ajRtbmE0dGY1aGRFL2N2aURCUnNsaDY4VEk0aEtSZ1grU1VNTk9GcUQxK00xSXNpU3BVMDZNenBIeUY5eDVtWUlkUnJ0QndsRWlyQTg2TW9DcFhBcUowQjBKcWkrWWswWEZPa3l5M1dJUmliVXQ0RTNJcTlSZTcvQUY5YUNEaVYzcmtlTXpqQ0lPMFpxdEVjbmtoWU1ReExZWXQzbUZOR0Q2V3R0SUZTaFZhSmRqZjdDRHpOamxqcks1YXdNd2hRZDBmcXVlaG1POFJOYzkzejZUQk16SmtYRHgyaXRYZVhPOVowY3NGS212dERnQ2pBN2RXTVhWTnE3eTJvQnppSDVlaE1GOWc1OE51K3NkZGgxemxsSTV4T2FPcWFRWGlIVDYvRXAyWFM0bG5kMWlJTWRLUEJBZFRhWmtlNUJybGI3dnhLZzAvTUYxTVN3V2F6eTB4TXIySGlWSkVrelZ2a09wdVFMUU4rcWE3bnBEU0VPVmI1MmVqRWhpTEdhSjFOU0NnTlZvY1BQbjVpdlBFeEpTdCtzR0xNc1EwT3NacXljeXJabnpBQnhwQWx4UnUxRGN0b2U3S04zRncyRFlxZVBxNk1xZVVZQzlMekZYM1ZENlZpV3dtU05XQ1lacjhQcGh0b0tZS2hxdER0MzdkMk94QndHZzRJamJUOVAwaUJpRnV3T1YwRHZOMkhzVTd6cjRVZDRZTGdZMERnUHRGRGk0WEw4N0hRbFdhNm94bkY2dkJ2TVlOWW9PRGFDYlFXbkhlVVlaTEdzeVp3emozZC9IcktzV2hSUlFkamFDZ3JNcjRBdTIwd2RWaUhFemZlWXdlOThRWjk1ZndxM2lYRTRJUmREaStKYVVpTmlqSzFpUE9qK0pqc3ZyMThjekk4SmpNMUs5WlJOelI0ZG9XS09FMWhZcmNqU1FMaWNGaDdQdVMzMWh0UXZobkxWb052bTE5eDJobGpTMXFEa1RDUzVycEwxbWptWDJ5d29ja3ZzeXp5RVYxd2x1dG1EVEZDTC9KSm9ZR0Y0bGVxSE1zRFFmdVRoNUs3YVFHb241Um1XcTIvNFl6ak11VUMyNTdtSmxDYk11Ymc1WFI4UlZXKzBDMm9OWHJFSUtxZzVoTnNaTS9TalNZNitZQjA5QXRaazYzWldld2RpM3RHUUp3NnQxNWVyT21EOXVyN2Q1Zkl1c3EyWEJsaU10NVhiSDBPUE1zT1UwY2RXSWJnZm94NWpreWFoMTd1ODFsNGlkbkpVRmlCcldoM1prUFJrR0JNM3ZMaTFyR3Jwb3NPYnY4QUVGZDVtYnBIM1B4T3ZET3Frb2xTcklPakFPWEVkYVRBWFp3d05pMDNOVDh6S0QwVXVXeXlodmp1anZEdkREeFVQYW1rVnI4UFVpTmV3T2hEZEhjOTRtQkdvMzRjUFVnR1VkeDdMMmFZN2pGQ21vOE9zR1RycStIanpDaTBiM2dKeTBpS3AxaWpIcU5FNlNvR1RtZktCTEFiTWZLVjUzOUpvWWpibXlPeC9qUlIzeE5iU21HdnRieDRPbUlUZUxnMHY0bHpYUTErbUMyck5wcXVoWFMzZnhBdVBCQUFXcGR0YXdNSWxKcFBVZTJrdGd0UDRCVFdWaUU1MHZITExBNU5yUnU3QjArWjU4TVRZd2NuQVFzZDBtZkJ0RjNMNjVoaHFiQkM2K3Vaazd6OWRYdTd5czJ0UUlyaWtnMWlSTmFwd3NXYlNoTDFudW1MTFpYNGdaZzllWUp3ZE9rZDRBOVBTVGliNjd5OHRYRzF2TlEwNW1pQzQyZnhOK0xGUDVpT3RTVm81aXh5QS91c1pDcThqcVBaM2phVGNQVVNmQ1dqQzhBaG9ucUhiVHBIaXByeVZONE1mUmo3SUVRYkUxcHFRaU40ckhybzdReDlEMkFUcGM4N3BBUURWMGhLTVp1LytOUm1RTjh3TXVqaEk2R3pCaHRtVmo0RVZWdWE1b1Fqcmtlcmc4eFdxUHRMMTdiRXZNUG9WWUtsWWRxbkhGc2NIZDlpSTdWNGhucFBIWFR2RnBodGlhdks3dlgwcVZ2VU9xNjhSMmpRY3hWYzZ6QnV1bG5vRVF0Nnc2L050RnFydkJZZEZtRHJDdEZSVGhyNU5zeEZCeVV5a2lMVDJkdUdJTDBaTTI0ZnpFR1puMExDNnowQlVvblVlN0R2MytIYVd3ZzlHSitUSStSazVJaXRTdGhMMzJsZ091RDFJWWQvcWVwYlB0R0JsZERWd04zVTlZNjJoYVpPenY4QU1GSTYvVWFiZzB1WjZyTkVkemlheXM3WEpEVzVVZ1VjY1FaV2tHZ05Kb3VXdHlQUTEvRTZpcU94QWRzV1kyckZmK1Z0SjFKdk85emFEaXlMVWJ2eE5MME1RS0FoQ2pTQVN0WUNNRlh1Y3VaYmpwditJODE5QWpBQ0tPd1FSbFVNRXNXQ2FGdCtyZDZHT2VJdFh1bmJwMDdSQ29rb2ROL0VaeXhBZ2luUzdITDBnaTNScGw5b2tVbTYvVUk4SHJkRS9ROHNBQXRLQ1VWY1hIcG5vSnd3dVFxVm5WK1RyRVJyUHdHV0lLZ0U5SWl2T1lSMTZleTlIbzlJUWprSG51K3o3VjlRTHIwbVRoOXBid2RVMHhaaitFTUwwNW1UWlZPTEU0VGNtTENaVHZidHV6NnhpTEphWjF4amVWOWxqb05HSjlLTU1FSllhdHQyL0JnMFJ3TUk3UUJFeXVCWTZ4UjBmU1VTM1RLV2JjM2gzWThUQmFKN2Y1K0Ztc0dpaHgwWVNoU3M5SnRtcjdFcVZzNnNKcnRyMC9sOFF1cG9UQXkydXJ6OUFsYUhkZER2QnRqTEx0MmRoM3hLTCtCMDNkbGZZYWFScnI1N0VxTVY3cWpHNkQ4eXRVMTRTdlh0MjE3UWlzb1VDZzREYjZWS2lJRkZvWUwwbGY4QWJRdWgxbFYwQjJtL25MNWxSNStTT21jekpVY3gySGl1T3R4M3FMdUhHSzBTeGxROTRWTDBYcnNmZW8waGlDb05GZnFiUFJpbW5Tc1pMT3NTVkRFcUs5b3VudWJkdEltSHlZWVh3TnZpWVRvZ2Rrdjd3Y3o5WnlSa0NxeE01VTdoazdkSUZnR1IwZXRHdmNnM2daSitxZFluMHdWR2UzM2s1L01IQk1NYTdUU0twckgwZHVzWnRjOTk1Uzg1YUJ3djgxVFpLeTlwZENha0JqQUd1aEpZTEw4dmlCaUczMXc1ZUlpV3p2TlV1dGlLME9pQXRoOER6YnZRZ3VzSXBaWGsyZVlvSld5bDMrWTB6V2EzYVQ3eExaV3hRV2pRY3JzUnV6YnFjSG8xMTE3UnFxMnhsWmpPbjZ0VDVaWDNRMnNmblY4VkxKZGtROGZkaXZHaWNtcjdlV09XV2RoQWJUbVV5MlZWcDBPc05LR0lHcis3T215RFFjRXl4dHRHNFV5OTRDSDdlNFNxMllRYkJ5eWpKeGF0dlNhaWVJOUlzT25xUUlZaEJ1aGpjNFRjbGE3dDJLK0haem80amd5cFJTVEJQMnNneW0zelExN2o2eEFVaU5pTkpDNEIwd251YWZLTWJ6bnJ2Ry92aUxHQnFKQnRNSFZITWFtM1BTQ0RubDZPazA3dEpWaDVQb1FQdEhYZC9lSXF0cXEvNm93d0RISlo2eEluQThPMGRuU05NQlZiUU5ESzRJaWo4ODdzdWFQZWFUZVdSYXpXZ2Nyc1FWUnNIM3QzMk84T0RJYUtnZEF3VFl2R09EdTd5d0s0cUkxVjZBKzhyRnR3OEErK2tjUkcyYm5WZDM5S2pGamQ2MytJSlVGZUFsUW9aSDJHcGdHcUxaczhmbmNIcURRZERzYUV5VVM0c0hySGdoUGJvVmwweWE0dUQycVlIc08vTVpZMmdhRGlMVVYxZzZGWGUxeGtscGtZaThpOUE1T1BvRmgxanRIQlV5d1BVekM4aUR3eDBDdmJmTTBaRzVvbmlJMEVZaURiOWVIN1Jld0ZCN0R1ZEgyaU9DZG01MGVIb3hxdlR6bVI3bnZLZm9NT054aDB0TkRxdXh0NHgwaGpSSm1Pend3SmE1TWhFSGlBajFvUExtQWhDWUVkb1p6RWh5czlHN05LM3EyWGRpQ04yRVBGbitrYWJodGI3ZHBsQTFnRnhoKzh1c2t4MGYwL2xEczMyaXBTd0xaMXhCcSsvRHZucEtDQTQwTzY2cjFZTk0reWJ2WVJwUzV1WHV3aUlGV2dDMVpTQUN5MXBacTNjZmRHcHB2d2NkRHBDS0ZzTGlncWdHVG85dk5SRlZ1NWVYQjRpWmIxUzE4emZyZUNhVGhEM1NHc09RUlIwdlJGazZQaEtWWGlONHJabzIvMk1hY1M1dWVrVHA2UzRxdFlydlVabU9JN2JyRmZReEJBSWVtNDdPc1ZPSjlMMGRIMmdwb2g0U0ZGTWMzVDZ4STZvc1QvQURHVzRnOVlzQnJEcVI4a0xLY3JlcjM1clh2TVFGQlE0ZHoxdU9HWENQa0Y0VEljSnZCQlRON202TzdvNGdzWWRoVk15amZHYzlmNFJBVzBQbVdKZ0tQYy9la1psbmcvMW5DbnRFV0UxY0hFSGlXNW10L0FSU0RLM2M3QkRjOXhCMDQ3NndIUjdqanl6NWNHUEJGVXFxdTc5RllRQzNVUEt4ZnRzVTVTbkEyZTcwMGlKTXhkaTFmeERNVWQvQjMvQUF1S2FwalNYdnFZQzNVMzIzQitaaE5IU0c3Nk9DQ252bVdkQjlEcDVYNkI4STh5NHN4ZjNOc1dmbzFURDlHcjZDamhJWlNLbzhzQ05vRnAwRG1JNUp0MGdJWVczNWF3R1ZMN084V0lMRHJreE5DbFVXdXpYZmJPdmVIQ01MUlk4anVSaExoWFNXZHJkVnZTUEhTRG1JYWFSTXFWNyt2Nm1Pd1k5SUlMVzZhc3kreGcvd0JselRnam1VWnFHVzU0bGtsQnBIYVZCZDhneFhRYkJvZlFMbFk3Z0hvUHU0Z0VadDVVSGxPcjE5SUd3SmJ1QitXWXRiNEdqeCtZQXZCeU5Fdzl1YlQrVXhDcmdhUUVxTmFvS3RIME04cW5vMUt1T0dHTVRJNWZBZkNMbU9acmxQME5NM3h1Yno5M3ErbldEaURoRzR3WEJVdWI0aUd2UnZNR2NCS1hOZTV0Q3lqM0drdXl4czVJSlEzM0JBelBmVXFreXNzblZiUDZ3dFhsWVV2Z2JQc3h4TCtoSG1YREZvL011RFBZL3JqOTBqTUoxZGY5cXRjRVZ2Qm9HRWxZc1dEWitZNjBTd2NNdmVFSE1JTlJVVVBYZDJScXJTcW9jVWZ2NlMrUFhRMk94b1JvTEFPV0NicjlNUksyN29FQ0thbUxkRXNTME9ac2N3Sm4rM0ovRUp5TW9hUkRmWnlzblI4SlM4SXdpQnpIOURqTmJFbFd3L3Q1UzR0TnR6Ryt3UFUveEdoVUErOFlBR0dXTU9ZWWcwNFpvby9tTnYzQkZLMFVBKzFCTkc0M21PZUdJZ0FsTEFjSTZrc0NscVhCOTV2OVdVeGE0Q0xDTmRQUjcvdTBYUFdJOW9SVmJmOEFkYTFsQVNEa3llOEhwNWNqOFNxQlRRQzFoaGt5TEoyL0tLWVFjSGhORDNpZGgxUzJPb1l1QjduV1VyYXQ2L1JVUUdZdHdST1hMU0tqVmRrSDl4OHd0RGxLRkY3ZXBLcWVsUFEvekNNR0FRTGNjdzBybnRrT3p2OEFIRzIrSFk1bUhaaThBTjE2UVpoZHdXY3YyTm9OTHJlMksyYVJJL2MreDVob05qbnYvVW9sTUFpRGhqVlJlc1ZQa2ZRL21DMzR0Q3RBeGtsRkdnOGZqTEptMkF2dFdHVkJOWkJvT1NVTVF6aDNnYWcwOFIzT3NUR2NFYzdNZHB1TWtBTVMrSmNqTkxrN0w1SW1BOVlkeVgydWhEWTlXYjlVc1dPMW5WMm1ZME52K0JqRXNRVFNOcDZKTnlQaHRTT2J3cnA0aTFWS3U3dkJOTXNkMVJDS2dNQnJySFFSTXd4UXNqZ0I1ekdvVzdSa1g3RWRYTm1idm4zK0pXR1FwN1pQdVFVdzRuUzNxSWVyZzRQTXNUd2hhZWo4Y0c3S0pYQUx5dlNLSEp5Tlh5bXh3YmQ0M1lxdldWVGZwU1VFTFZvT1dIbkFMWnYrc0Q5TkxQdVM0UDFsS0YxZ09QS0hXeEg2bitKODM0SmVmZUNsUUlpYk1vSFhRakdwbjNJN1FlR0NhWWlKTUpxZFlGZGVzY2VkWlIxMGpmTlVRZXBBdXVHQ2lOaE55TndMNWorUWZ1a2NQTGdOQndSWmJnMC80dHB6TE84UnBhT0NFVnB1SFJoUE1DVkEzWEhRWFVaMGw0dDJxaUNVb2I2ZXJlT3NqMHo4c1FSbnB3OS80TFpRYWFyTEJVTGxqelZ3ZUtEU2JYcWV0eW9HbzNBNkFVblp0R0x5MDlFWlA5NHhlOGt2dGx0NmVlOG8yem5iOGQ0b2grbFlHZ0RpK1g0MTlJclM3aXA4UmtnQ2pJZkVUN0JISkhxNGp0TjM3a3pEWUhvSVh3ZkJDb2x0QTBQM2FGSVVWN0JWK3F4Szd3Q2pEaDBqb2R1U0lsdGtXYXpBYW5EQjJjVjZvdEd4N1NyaFZlM1BMTEpQZVQ0T256TVNoVUdrbG0yZjhaaGxtSHo5RVNER1hSaGkyL1hub1lrRGRsdlJwR2F0QWVBT3N5dDZ0SDhFNnZhVzR2YVpRY29jUTZiWHIrSVlsY3B5R3EybzBmc3djek5Ud05RRlZwRGlHT3I4UkNrVVV1THhVRkM0Qkw0eWoyZzZNSWVVWXBiY0oxKzBDQzdBck5IQ0dkUXpWMnV2MlBFY3hJT0NaQzk2L01WUk41Q05seVpNV3gzR0FTMmxORkVJRU9Eb29xVkFxOSs2NThFc09HMTRpMlJtTUdheWx3MHphSjFhTWRaOE1jYVNDSzFJTnNyYm1FN1F6cExzVnhPQncwRDBpMU9QL2xHdEpncGc0dVgzSmFtaVJ5Lzkvd0JKUXlseVVnMVBFWmF4cExPcks4UURpVjlLcDcvUzZselgwdW05eVRXanhIVS82YmhOVTMraC9VNFRmTCtocjV0N3NKWGRZZG5MTkNPZ2RZa3FvcHRtcG5kcUY5cU9kNG13SHZFcGJnbHF0ZXNzT1M0VXhkbldDQ0ZOQVp1Q3hQbjdrT2VPR3c0Q0tvN3Avd0Era3pVd1JNTXVzQ0NYVGNHTFJRYkpIUlVyNlZLK2lhUEU2dzB4VjlPcFBNWHJ4RFhid1czSHhJTXcxK2daK3Y0emZLZ1pJYTYvM3A0cEZuMXhBMU5JdTRmYVlrTFVzMFpaeVlJVU5HQ0YzVDRFUlhYbVhOQmJBRDExUXgxZENJbTRxbnhuWDk2UjhMTGR5SXFLL3dEVlU1OVlXeVFjaWFrSzJEWWdOYlpvZjNFb1RFcjYxOU5wdFlOSjlQd1NndkRQTkdmcHVNMVN2b0hxZmpOYjlOUkxTNSs1SGljVFNkVzRIMGNMK0k3YWdVclk1aFE0TFRYVTlrdkZCamlCdXM4NXRNc1N0YXI3WVIyVC9sbDIrbEVzL3dDeW50TFRXL29rM3Rhckl4TGFjblI3UzJKZG9xcmxmV29NdW4wSEF4WXZoanF5cC9DNC93QnJaRm1ETlVUMTN4K3ZXUTVPaGI2RXRBNEl1a3k3MGNBSmxlQmJtM29TelQySUNtVEVBc09vNlN2UFhYRjVQMWpOZ045MzdzdWwyalE3RGFkWlNSVi83aFRUNlFqM2c5Y3hTazlZZVlEUTN2cUV0QjdFYWFaNnl2b2N2V09zQ21JMVNQcE5Zc1JxcCs4NFRWQ2E0bnF2ajlPODFFRmNUN2t5WGVMbFhhQ2hNMktyOUlLSE15MzlJd0hBNVphYWJyUjlvN2RWdVlPN01DUnhnbm5tWEZDY1AvaEtkU0M2ZW04R1hUWTBtOHdtNDlYckViOVAvV1ordzIzUFNOdEhNRzdVbUNuendzM2pqNG1mbFQ5SndtcjYzM254bXVieldSVW0rSHVtckJ5dkxLSFI2dzVtYlRDd1o3RUdBYnkvZG1hZ3YwQTlYZVhGTkVLbGQ5L3BkU21Ldi9pb2E1ZzZFZStzNmJ6MUppVTZISkJWRUxyaVpRYXk3UHlqOUZ6WW82UXA0bCtTRkxFM21rNUpnWFQ0SnFoTmNYMTN4ano5Rm1NenNRL2ZNVkN5bk8wcHVnZEF1WDYzSzAvTWJnUzJMZldCcWl1djNWalE4YWZTNE1LOVAvSkFVNUp1bGQvb2ZSNzA1anl2TENidU9iQ1ZtMU8wWGdCdFZiZ0R4QXNIUnVGMThWcFRxUG5QeUVpQkZZcVpyQyswZEkvbk5jSG9qTi9ZRW93QTZrZlZzdDk1b2ZOR3NmRU84c0xIRjZBNGVrN1Q1bFZyZzVZaHBjWURiai96UmFGSUxRREJkMDd3enBUMmxKckwrdnQ5SW1qaEFYM2EvRUEzZWlkY2RoTUZWMkErMDFrZWM5OWhNOGZVRjBuSUR2RXQzc3hIWUVLVzFYLzB4NktvTFlZUHFIWmwzSHVRdkxMUlhtZEk5WjBwMEoydldZYWg1bU9zYXQ3Mklub251eFd3aStxbC93RFgvOWs9IikgY2VudGVyL2NvbnRhaW4gbm8tcmVwZWF0O29wYWNpdHk6LjI4O21peC1ibGVuZC1tb2RlOnNjcmVlbjsKICAtd2Via2l0LW1hc2staW1hZ2U6cmFkaWFsLWdyYWRpZW50KGVsbGlwc2UgNjAlIDYyJSBhdCA1MCUgNTIlLCMwMDAgNDAlLHRyYW5zcGFyZW50IDc4JSk7bWFzay1pbWFnZTpyYWRpYWwtZ3JhZGllbnQoZWxsaXBzZSA2MCUgNjIlIGF0IDUwJSA1MiUsIzAwMCA0MCUsdHJhbnNwYXJlbnQgNzglKX0KLmNpY29ue3dpZHRoOjIycHg7aGVpZ2h0OjIycHg7Ym9yZGVyLXJhZGl1czo1MCU7b2JqZWN0LWZpdDpjb3Zlcjt2ZXJ0aWNhbC1hbGlnbjotNnB4O21hcmdpbi1yaWdodDo2cHg7Ym94LXNoYWRvdzowIDAgMCAxcHggcmdiYSg3NywyMjQsMTI1LC41KX0KLnVwe2NvbG9yOnZhcigtLXVwKX0uZG93bntjb2xvcjp2YXIoLS1kb3duKX0uYXNoe2NvbG9yOnZhcigtLWFzaCl9CgpoZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDtmbGV4LXdyYXA6d3JhcDtwYWRkaW5nOjZweCAwIDE2cHh9Ci5sb2dve2ZvbnQtc2l6ZToyOHB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzotLjAyZW19Ci5sb2dvIHNwYW57YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsI0Q2RkZFNCwjNERGRjhGIDQ1JSwjMkVFMDZDKTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0O2JhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50fQouYmFkZ2V7Zm9udDo4MDAgMTFweCB2YXIoLS1tb25vKTtsZXR0ZXItc3BhY2luZzouMDhlbTtwYWRkaW5nOjVweCAxMHB4O2JvcmRlci1yYWRpdXM6OTk5cHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMil9Ci5iYWRnZS5wYXBlcntjb2xvcjp2YXIoLS1nb2xkKTtib3JkZXItY29sb3I6cmdiYSgyNDIsMTkzLDc4LC41KTtiYWNrZ3JvdW5kOnJnYmEoMjQyLDE5Myw3OCwuMDgpfQouZmVlZHtkaXNwbGF5OmlubGluZS1mbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4O2ZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKX0KLmZlZWQgaXt3aWR0aDo4cHg7aGVpZ2h0OjhweDtib3JkZXItcmFkaXVzOjUwJTtiYWNrZ3JvdW5kOnZhcigtLWRpbSl9Ci5mZWVkLm9uIGl7YmFja2dyb3VuZDp2YXIoLS1taW50KTtib3gtc2hhZG93OjAgMCAxMHB4IHZhcigtLW1pbnQpO2FuaW1hdGlvbjpiIDEuNHMgaW5maW5pdGV9CkBrZXlmcmFtZXMgYns1MCV7b3BhY2l0eTouMzV9fQouc3B7ZmxleDoxfQouYnRue2Rpc3BsYXk6aW5saW5lLWZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Z2FwOjZweDtmb250OjcwMCAxM3B4IHZhcigtLWhlYWQpO3BhZGRpbmc6MTBweCAxNnB4O2JvcmRlci1yYWRpdXM6MTJweDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtiYWNrZ3JvdW5kOnZhcigtLXBhbmVsMik7Y3Vyc29yOnBvaW50ZXI7dGV4dC1kZWNvcmF0aW9uOm5vbmV9Ci5idG4ucHJpe2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjNUNGMDhGLCMxRkE1NTUpO2JvcmRlci1jb2xvcjp0cmFuc3BhcmVudDtjb2xvcjojMDMxMDFGfQouYnRuLm1pbnR7YmFja2dyb3VuZDp2YXIoLS1taW50KTtjb2xvcjojMDQxNDBEO2JvcmRlci1jb2xvcjp0cmFuc3BhcmVudH0KLmJ0bi53YXJue2JvcmRlci1jb2xvcjpyZ2JhKDI1NSw5MCwxMTAsLjUpO2NvbG9yOiNGRkIzQkR9CgouYmFua3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmciAxZnI7Z2FwOjEwcHg7bWFyZ2luLWJvdHRvbToxMHB4fQpAbWVkaWEobWluLXdpZHRoOjc2MHB4KXsuYmFua3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6MS40ZnIgMWZyIDFmciAxZnIgMWZyfX0KLmJre2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTZweDtwYWRkaW5nOjE0cHg7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTgwZGVnLHJnYmEoMTYsMzIsNTgsLjgwKSxyZ2JhKDgsMTcsMzIsLjgwKSl9Ci5iay5tYWlue2dyaWQtY29sdW1uOjEvLTE7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLHJnYmEoNzcsMjI0LDEyNSwuMjYpLHJnYmEoNjEsMjQyLDE2MywuMTIpKSxyZ2JhKDgsMTcsMzIsLjkpfQpAbWVkaWEobWluLXdpZHRoOjc2MHB4KXsuYmsubWFpbntncmlkLWNvbHVtbjphdXRvfX0KLmJrLnZhdWx0e2JvcmRlci1jb2xvcjpyZ2JhKDYxLDI0MiwxNjMsLjUpO2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZyxyZ2JhKDYxLDI0MiwxNjMsLjEyKSxyZ2JhKDgsMTcsMzIsLjkyKSl9Ci5iayBzbWFsbHtkaXNwbGF5OmJsb2NrO2ZvbnQ6NzAwIDEwLjVweCB2YXIoLS1tb25vKTtsZXR0ZXItc3BhY2luZzouMDVlbTtjb2xvcjp2YXIoLS1hc2gpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmJrIGJ7ZGlzcGxheTpibG9jaztmb250OjgwMCAyNHB4IHZhcigtLW1vbm8pO21hcmdpbi10b3A6NnB4O2ZvbnQtdmFyaWFudC1udW1lcmljOnRhYnVsYXItbnVtc30KLmJrLm1haW4gYntmb250LXNpemU6MzJweH0KLmJrIGVte2ZvbnQtc3R5bGU6bm9ybWFsO2ZvbnQ6NjAwIDExLjVweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpfQoucGlsbHtkaXNwbGF5OmlubGluZS1ibG9jaztmb250OjgwMCAxMXB4IHZhcigtLW1vbm8pO3BhZGRpbmc6M3B4IDlweDtib3JkZXItcmFkaXVzOjk5OXB4fQoucGlsbC5vbntiYWNrZ3JvdW5kOnJnYmEoNzgsMjQwLDE4MSwuMTQpO2NvbG9yOnZhcigtLW1pbnQpfS5waWxsLm9mZntiYWNrZ3JvdW5kOnJnYmEoMjU1LDkwLDExMCwuMTQpO2NvbG9yOiNGRkIzQkR9Ci5jYXJkc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLDFmcik7Z2FwOjEwcHh9CkBtZWRpYShtaW4td2lkdGg6NzYwcHgpey5jYXJkc3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDYsMWZyKX19Ci5jYXJke2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZyx2YXIoLS1wYW5lbDIpLHZhcigtLXBhbmVsKSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjE2cHg7cGFkZGluZzoxNHB4fQouY2FyZCBzbWFsbHtkaXNwbGF5OmJsb2NrO2ZvbnQ6NzAwIDEwLjVweCB2YXIoLS1tb25vKTtsZXR0ZXItc3BhY2luZzouMDZlbTtjb2xvcjp2YXIoLS1hc2gpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KLmNhcmQgYntkaXNwbGF5OmJsb2NrO2ZvbnQ6ODAwIDIycHggdmFyKC0tbW9ubyk7bWFyZ2luLXRvcDo2cHg7Zm9udC12YXJpYW50LW51bWVyaWM6dGFidWxhci1udW1zfQouY2FyZCBlbXtmb250LXN0eWxlOm5vcm1hbDtmb250OjUwMCAxMXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWRpbSl9CgouZ3JpZHtkaXNwbGF5OmdyaWQ7Z2FwOjEycHg7bWFyZ2luLXRvcDoxMnB4fQpAbWVkaWEobWluLXdpZHRoOjkwMHB4KXsuZ3JpZHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MS4yNWZyIDFmcn19Ci5wYW5lbHtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxODBkZWcsdmFyKC0tcGFuZWwyKSx2YXIoLS1wYW5lbCkpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxOHB4O292ZXJmbG93OmhpZGRlbn0KLnBoe2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7cGFkZGluZzoxMnB4IDE0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSk7Zm9udC13ZWlnaHQ6NzAwfQoucGggc3Bhbntmb250OjUwMCAxMXB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCl9Ci5wYntwYWRkaW5nOjEwcHggMTRweH0KLnJvd3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmciBhdXRvO2dhcDo4cHg7YWxpZ24taXRlbXM6Y2VudGVyO3BhZGRpbmc6OXB4IDA7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgcmdiYSgxNjcsMTM5LDI1MCwuMDgpO2ZvbnQ6NTAwIDEyLjVweCB2YXIoLS1tb25vKX0KLnJvdzpsYXN0LWNoaWxke2JvcmRlci1ib3R0b206MH0KLnJvdyAuc3tmb250OjcwMCAxNHB4IHZhcigtLWhlYWQpfQoucm93IC5zIGF7dGV4dC1kZWNvcmF0aW9uOnVuZGVybGluZTt0ZXh0LXVuZGVybGluZS1vZmZzZXQ6M3B4fQoucm93IHNtYWxse2Rpc3BsYXk6YmxvY2s7Y29sb3I6dmFyKC0tYXNoKTtmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjJweH0KLnJvdyAucnt0ZXh0LWFsaWduOnJpZ2h0O2ZvbnQtd2VpZ2h0OjgwMH0KLnRhZ3tkaXNwbGF5OmlubGluZS1ibG9jaztmb250OjgwMCAxMC41cHggdmFyKC0tbW9ubyk7cGFkZGluZzoycHggOHB4O2JvcmRlci1yYWRpdXM6OTk5cHg7bWFyZ2luLWxlZnQ6NnB4O3ZlcnRpY2FsLWFsaWduOjFweH0KLnRhZy5idXl7YmFja2dyb3VuZDpyZ2JhKDc4LDI0MCwxODEsLjE0KTtjb2xvcjp2YXIoLS1taW50KX0udGFnLnNraXB7YmFja2dyb3VuZDpyZ2JhKDE1NCwxNDcsMTgxLC4xMik7Y29sb3I6dmFyKC0tYXNoKX0KLmJhcntoZWlnaHQ6OHB4O2JvcmRlci1yYWRpdXM6OTk5cHg7YmFja2dyb3VuZDpyZ2JhKDE2NywxMzksMjUwLC4xMik7b3ZlcmZsb3c6aGlkZGVuO21hcmdpbi10b3A6NHB4fQouYmFyIGl7ZGlzcGxheTpibG9jaztoZWlnaHQ6MTAwJTtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS12aW8pLHZhcigtLW1pbnQpKX0KLmVtcHR5e2NvbG9yOnZhcigtLWRpbSk7Zm9udDo1MDAgMTJweCB2YXIoLS1tb25vKTtwYWRkaW5nOjE0cHggMDt0ZXh0LWFsaWduOmNlbnRlcn0KCi5zZXR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dhcDoxMHB4fQouc2V0IGxhYmVse2ZvbnQ6NzAwIDExcHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTtsZXR0ZXItc3BhY2luZzouMDNlbX0KLnNldCBpbnB1dHtkaXNwbGF5OmJsb2NrO3dpZHRoOjEwMCU7bWFyZ2luLXRvcDo0cHg7YmFja2dyb3VuZDojMEIwQTE0O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjlweCAxMHB4O2ZvbnQ6NzAwIDE0cHggdmFyKC0tbW9ubyl9Ci5ub3Rle2ZvbnQ6NTAwIDExLjVweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1kaW0pO21hcmdpbi10b3A6MTBweDtsaW5lLWhlaWdodDoxLjU1fQoKLmdhdGV7bWF4LXdpZHRoOjQyMHB4O21hcmdpbjoxMnZoIGF1dG87dGV4dC1hbGlnbjpjZW50ZXJ9Ci5nYXRlIGgxe2ZvbnQtc2l6ZTo0NHB4O2xldHRlci1zcGFjaW5nOi0uMDNlbX0KLmdhdGUgaW5wdXR7d2lkdGg6MTAwJTttYXJnaW46MThweCAwIDEwcHg7YmFja2dyb3VuZDojMEIwQTE0O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEzcHggMTRweDtmb250OjcwMCAxNnB4IHZhcigtLW1vbm8pO3RleHQtYWxpZ246Y2VudGVyfQoub3J7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweDtjb2xvcjp2YXIoLS1kaW0pO2ZvbnQ6NjAwIDExcHggdmFyKC0tbW9ubyk7bWFyZ2luOjIycHggMCA0cHh9Ci5vcjo6YmVmb3JlLC5vcjo6YWZ0ZXJ7Y29udGVudDoiIjtmbGV4OjE7aGVpZ2h0OjFweDtiYWNrZ3JvdW5kOnZhcigtLWxpbmUyKX0KLnB3e3Bvc2l0aW9uOnJlbGF0aXZlO21hcmdpbjoxMnB4IDAgMTBweH0KLnB3IGlucHV0e21hcmdpbjowIWltcG9ydGFudDtwYWRkaW5nLXJpZ2h0Ojc0cHghaW1wb3J0YW50fQoucHcgYnV0dG9ue3Bvc2l0aW9uOmFic29sdXRlO3JpZ2h0OjZweDt0b3A6NTAlO3RyYW5zZm9ybTp0cmFuc2xhdGVZKC01MCUpO2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjdweCAxMHB4O2ZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y3Vyc29yOnBvaW50ZXJ9Ci5yZW17ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2dhcDo4cHg7Zm9udDo2MDAgMTNweCB2YXIoLS1oZWFkKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjo0cHggMCAxNHB4fQoucmVtIGlucHV0e3dpZHRoOjE4cHg7aGVpZ2h0OjE4cHg7YWNjZW50LWNvbG9yOnZhcigtLW1pbnQpfQoudmh7cG9zaXRpb246YWJzb2x1dGU7d2lkdGg6MXB4O2hlaWdodDoxcHg7b3BhY2l0eTowO3BvaW50ZXItZXZlbnRzOm5vbmV9Ci5tc2d7bWluLWhlaWdodDoxLjRlbTtmb250OjcwMCAxM3B4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWRvd24pO21hcmdpbi10b3A6OHB4fQpmb290ZXJ7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tZGltKTtmb250OjUwMCAxMXB4IHZhcigtLW1vbm8pO3BhZGRpbmc6MjRweCAwIDQwcHh9Ci52aWV3ZXIgLm93bntkaXNwbGF5Om5vbmUhaW1wb3J0YW50fQoudGFnLndhdGNoe2JhY2tncm91bmQ6cmdiYSgyNDIsMTkzLDc4LC4xNCk7Y29sb3I6dmFyKC0tZ29sZCl9Ci52YmFkZ2V7ZGlzcGxheTpub25lO2ZvbnQ6ODAwIDExcHggdmFyKC0tbW9ubyk7bGV0dGVyLXNwYWNpbmc6LjA4ZW07cGFkZGluZzo1cHggMTBweDtib3JkZXItcmFkaXVzOjk5OXB4O2NvbG9yOiNDRkZGRTA7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDE1OSwyMDksMjU1LC41KTtiYWNrZ3JvdW5kOnJnYmEoNzcsMjI0LDEyNSwuMSl9Ci52aWV3ZXIgLnZiYWRnZXtkaXNwbGF5OmlubGluZS1ibG9ja30KLnNoYXJlYm94e2Rpc3BsYXk6ZmxleDtnYXA6NnB4O2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW4tdG9wOjEwcHg7ZmxleC13cmFwOndyYXB9Ci5zaGFyZWJveCBjb2Rle2ZsZXg6MSAxIDEwMCU7Zm9udDo2MDAgMTFweCB2YXIoLS1tb25vKTtjb2xvcjojQjdDQ0U2O3dvcmQtYnJlYWs6YnJlYWstYWxsO2JhY2tncm91bmQ6IzA3MTAxRTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUyKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzo5cHh9CltoaWRkZW5de2Rpc3BsYXk6bm9uZSFpbXBvcnRhbnR9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CjxkaXYgY2xhc3M9ImFsay13bSIgYXJpYS1oaWRkZW49InRydWUiPjwvZGl2Pgo8ZGl2IGNsYXNzPSJ3cmFwIj4KCiAgPHNlY3Rpb24gY2xhc3M9ImdhdGUiIGlkPSJnYXRlIj4KICAgIDxpbWcgY2xhc3M9ImVtYmxlbSIgc3JjPSJkYXRhOmltYWdlL2pwZWc7YmFzZTY0LC85ai80QUFRU2taSlJnQUJBUUFBQVFBQkFBRC8yd0JEQUFZRUJBVUVCQVlGQlFVR0JnWUhDUTRKQ1FnSUNSSU5EUW9PRlJJV0ZoVVNGQlFYR2lFY0Z4Z2ZHUlFVSFNjZEh5SWpKU1VsRmh3cExDZ2tLeUVrSlNULzJ3QkRBUVlHQmdrSUNSRUpDUkVrR0JRWUpDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1Qvd2dBUkNBS0FBb0FEQVNJQUFoRUJBeEVCLzhRQUd3QUFBZ01CQVFFQUFBQUFBQUFBQUFBQUFBUUNBd1VCQmdmL3hBQVpBUUVCQVFFQkFRQUFBQUFBQUFBQUFBQUFBUUlEQkFYLzJnQU1Bd0VBQWhBREVBQUFBZmxRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFkT0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFIVGcvdFNlV3M5dzR6NDNSM0tKRmI0eFJtU0VJMU81QlpyeHlZUzY5V1h3MEtrK1cyNWI3cDVHUHU2cnJ4SjZ2R1hOTzh0QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFlUkZuMWV4blBtdGx1TEJUM0xqUTU1N051dldwZVY1YjZTaFdtR2FVcDJ2dHN1VE9SbWVyOHF2WnBsMW9Uam1KdFdZRWpjNWxzU09QNWMwMGtxZ3kxdlVVM1huUjFLMEFVQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFMaWw3MDNvYzR3OW9wbUpRd2ZPMitxeE1heTc1QjF3eUx0cTB4NTY4MGo1YjBHSXJ6VmpzanVCdWVSVDBpZkhVd3lWclNkc0g2eXV4Y1ZLdlFpWjgyYXl4ak9pYTVuTlNOeHI2Wnl1OVZiakYxTjBBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBSGJ2WnpPSjdGbU9lZks4bnlGdm92TTBPWGFiV3UrWkxyODBWa3h5U2t0QmQyQ3FlYXRVMWJ0L1FSMXBqUDhudlNremZRNEcyWnNXMDdxcWNrcmJldlpJN3lYSWp5ZkNxcGpsSndkcldoeFdzMGhKcVJsUzJSaTgzOGE2cEF0QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFEVGI5ek1LdFN5TTRlOGZsTGEyTVBiUzUraTVObW15enNsWGJJa09TZ0hPc2g1UDBuaWxyM2NqYnRmWWd2bkdNN2xhM1BsbmFHZXhicFkremw3NjhSY1cxcDFlR2hKbnNKTlhVamhIT1NFaHljU0VMUVZyYnJ0bGNqY010SjlrWFE5QlJiakFYUUFBQUFBQUFBQUFBQUFBQUFBQUIwUFQyK3N6emlIakpsN3lkYnV1bXd6NXltVGNsSFlTdDdMejA5TnpFZEhZODZRQUpzd0U4N2dNSzNiK3FycXlOWTJ6NW1aVTN2UGVtNThNWXNXWGVWbGR2dGsxMkd0cDYyUTdYVjMweXpzSkhZOW5GWXhPazVPVkZISUlxNnBSMGs4a0srMGpaTXQrZjM3YmZOZ1hRQUFBQUFBQUFBQUFBQUFBQWQ5VlQ2L1BPeXVQakpuUVp3UFZXK2YwOXRWRXN6YnVYd0VQZTRGMVR2OEFpb251TXpKMzVuTHYzRXlyV3dkcFdjZlg4bW1Sd3V1OW5WeWRuT0tmSzdlRk04OVY1ajFYUGhpSTZDR3R2NkdScTY2WjlUYVd0cmRsQzYxS2k2WlNmNjFiWEpkWWNXejFScFdzYTUyMjRyczZ5aWx6Vk1rWVJWWFFaenJrZjg3Nkd1M0NBdWdBQUFBQUFBQUFBQUFBMmt2b1djWFJNQ1lRODU5QzhGZDBuSjYxcWVwOEozT1BwbFhqZlJ6TFVXS2pQOC82dUYxNFE5WGdYVWQzekhFOTVMdzJ6TTczaTlyQ1d2UVEycnA5c296endwS001elQ2dnlmcWNjTXJQZVV1OUNSVFpmbDZtZHYwVlVNSzYyMjVsdW80aW9xTXE4NDBFN2lGM1cwVWF1cGtuVlNxTkt3Rk9OTG5IK3lzNXE0MWh6TTlkNWk2b0FVQUFBQUFBQUFBQW5IMU1tdG84Vnp4VThUT3pYWDNlYWg2MlkrWVc2bWMxSGx4VkhMYjg1dTlMNC9rbjBDcnl1M1RGRDFKaFluc2w3cnlIZGpMdW9kT0U5N0kzNU5QRTJQTVRDTDJkcFNLNjJUcUM5TXEwMFZyME00MWxiemZYTVh2cjEwaXRhdXN1RnRWM1dPeUpPWDBKWlZTdkY2OFNUZ1NJTXNKSEs0Yld0WFo4a3BJdklXM1RXNWlNTTR2UFNlYnVnQlFBQUFBQUFBNlArL3k5UFBMbmk5bkJYTzlEbGVodXJaMlowenRlSzlxcE1lWjdzSmlmTG8zYzRYVzgrT1R5VU45WHQ3eU1qM2RYbHR4TEZ0S2hmTjUvcms3cFBjVDFtVS9LYm5uNDdvNXI5VTdHUnJxaXUwa09LMlV5UHRvdVRLRkxpbXRvU1lldXM5NXFoSjAwcXcwdlZ5UzZ4YlJ6alBoWlpkVTZWdVBVNnVtdE51WG9TTFZFN3VNYk9GMTFmVTN2TXRiU2VTQXV3QUFBQUFBTmpKOTNNdlV6ODFNWW5xL0c3ZDNsZWxXelU5YlBsa21UdTUwVXltZER6V2M2MmZQVW1NallYWnpqQnBjcDYraFN0cUNyOHNnUGJua3c5dlg1dmFrYnVxclR6K2RLVjFhNHppR2xLL1BMdXF2QzNPTXlWTTV6RExkVjBidTFkZEJYa3FlTElqSkR2T2hwb2JPT1dhOFpza2VhdGx1WG9YUXRVU3RYMzFuMDZjdXBmRTZxNHJvYUdaWXlabnNQSDNRQW9BQUFCMDJQWVpiK2VVUEI3dUhkT0w3U2kraThwcDJ6TU4zdy9xclhjblZqTTM0MHRhUExXRVVlM2ZMYWVPQ0srd25lbEtURzl2cjVYbWloYlRXNHdaSXhSSzdma2lGMVBvS1k4eHJaaHY1T2doQ3V6ZzdCbnZadWlLV1U5UnpQaFcwY0hMVkxYRXprSnVJcll4ZG5FTlplN241NFZadGQzS3MxZDlHTXUvT3VvUzVOb2oyZHJGVFdZbFZzTDdlTXFzU2FTTmU0bmtnTHNBQUFIMFBVek8xWFBGbVBPT0k3VjI5VmZjejVuMTNrdG95SmJ2bTE5bnpEMjVFMk81bzdqK2h5cGhSdGFZeEIzTHpoNFZZVUo0dStuVTlybDBzeGtDM0s3dDhubS9hWjd0bmtuTXIwRFNQRkhUTzFNeDBUZVg2ZHFhMVpQUGFPMWdXdDVpdGkxTjMxRi9hYlpKdjVrTWNKT0pQeVprZTM3NlExTE11cTFTZDZIZTFuZEpkZ1VTdXBMTE9TRHBFdjJNZ1JWYjAzbWJvQVVBTFBiZVc5Ym5IZkgrazhoVE93aHBsOWtMWlBQdzlYbVc2WG1kTytaOHo2VHpsdDE2YXVmSkV0RFBlVFBZbmxZNTdOVk4yZWF5T2dyMDc4Nm5yYTFtODR5cnVlczVKbE1hK0xkYmxHRmFsSHBmUGVnanplbm5hTnVkZFRJMEVOVExrMDYwbGJaeFpaV1BGZFZFcjNjb3ZRYVRocDZtR2ViTVowem01ZmlidHFPWXlqcnRPWEpMR1ZlalYyZTBsSlJ5OHVpWEpJYzZFdTg2YmZsUFNaUm5nWFFIVDBXd20xbmxsWUQ4THRuUWJhbWE5VFBwVGZxOHdxZWlXODZxcnVkRHQxcTdIay9RbzFuNkZNam1Ld3pNNDlpODdkRGl2YzVYSHNyZlRYek5QT2tZcHFjWE4ybEU2MHNWM1lreUphdm0xWnZZVkVaU1pXekxma2lHakhQVzlkNzAxWjFjL01rdFpaWXIxRW5vcjRqMllsempsdWlreG1sTW8yWFhhNWRMOUhLVUhHTXlacVN5K2oxTUxFcUw0TEdjSkhOYkczRHlvRjBYVXZ5ZW5qSktjOHZUOHlYZTJ0bmRMcWJMVldIckV6ZWE5eGhTOUJNd0h0SmlUc0d4bkkwbUtUUHp2UTRjaHlIYnBsVG1vWTIxaGFTb3p2WEhPS3RJc3RwMFcrZzhiNmZDem5mdzlmTEVkakoyVE1henRKY2pjWTI5V09TZVlrSlExTHVPWFk4am1NL21uZXg2VDlDbjJaWHo5T0NxU1k1YW5XNVdMY2I0cW94d283WndoMDRUN1VETnlGd3h1NGVpejUvajZGMmJPTnZUT3JtdlpVemthQ3V0ZFJZazNNcURza1M2L01WbkdzWW5tVkp1dzgvUkw2S256Vlp2TFl2THJTWFZGMHAwK21ZODYxN05JOHFqdjRGMXU0dHowbWYzZ3JMT2Z2ek9WMUgwa3ppMDFzUWxyWnJzem5QUk5hMCtvNGV0OWlkdTdyMnNkTzc2bFlqWHJ4a3pPdUxFK3FpdXpRNmFFa0pzdTlWbVc4ckZsRHZTZ2FqUy9HQlYrTTBsZlpkTFFxTlR6L3BQTjJuby9PK2trdnp0SEptZFZqR3JOMmpEcE4ybkZEVXBRN0RFSWRtVzE3V3M0eklUanZwRGxuTHFKYzdibmEwa1k5Tkh4OFUzTTlaKzNQNzZKcVo4eDZpR2JKcXRlUHFUMTJVcHA1emdlMnBxeHl3SDE5UEdNaWJkTVdaWG9GT3ZWQzNpbStyVWMvdXR0SU5YTG5talhTMW5LVmNFZXBkWEtaVkxzWkprSlNTa01aeFgxK2laUTd6bStsbmFlTk1kbzdWMWl3alVWK0t6VGRUV3o1cjAvbUxaZWs4NzZHTGZPK2d3MFdseXlJZGFaempQWlpYbWV4NFNBZEM2a3JRWFh2bWJJeHZ0ejZkYnV1dU0zTmJXOUMzRGpKdW9vU0oxVDVheHBaRjJjNzF2bXVaeHZyNU04NGM3VzF4NDNhZFhvdWZ5L05LK2t4SmN1bHhQdDlQczFLKzNmUXBSNXJwY3RPT3RRNzB0bmFzRE1WK2s2NTJDOWx2SW5Pb25OcUhESE5jWTZxL2JpU29zNWJUQnJxcGRkaGF2eStxMWl0eEs2Mi9NZW04enJWbm9QUDdwY3F6Vm5uVHBWY3podUNTbWVlMzN6NGVnTUNVYnBoOXMzRENJM0k0c0xiS29MOWZTL2RqeXQxVjFtWllGdkNFb0xEM2M3cG9kb2VtVTVQVXpOVnROV2M2ak9Renc4M29QVStEMXNmSTIvTlN6NXNXZ3QxK3RaR3E3dDNYSEk2Mm1TVDFwa1ZMV0N1NksrWGNybHRGSTdTb0RGbERtYytrdHdiT1BpMm9ZNjY3L1BLODFyMWZQS0MrcTc1UGkrc1BMc3Bzb0xRdTNjcHhMZlhhODE2VHpldDJiZUZ0bCtlL2tJOHhoMkx0Mytmc2szSVpkN0xOWFpHZkhhaVk1cXdNd2FXdGpDY1Y1S3V0YktiV2pQbHBjRlcxMTAxakY2YUNkdXJKaXM2TU01aTdsS1RQbzE4ZmM1ODZuY25SeHhwaFh4ZEt4UEI2ZGQvTG9jMzFRcDJZNjNtdGRUdDBJNVlyaThtS1JqcDhNNWkxVXRyaDBKUjdKTHZXWkZtbTE1aTdQZEJhMk5kMWZKU0ZybEZFRlloU1hXZ3RmU214NXYwZm5EdXhqYXczbTZLY2lyU050clBLWm5hN3VpazcrRUxhNGpsdVh5Tmk3RG1tdFNyY2tVdEcyM0Rpd1JUUFRWbVJyR1oxdlZ6NEtFdGFyUE9PV2Vqazg5b1hZbWNWNjJmZEpRNG94SlE3bWFLVVFXMHRiRUZXTHFnc3F0ME14eXRYRzhTK3h4RmZpMmMwR2NjOFFhbnJhakxpeDI5V0E5U25FWWl1VzNRNTBqR2ZWcmxNU0ozaXlqemcrdTJuTTYzbnZRZWZ0TkhPY3QxSzU4emlFc1d5NjBsUjR5NDdQVXhwYXFxcno1VU1jVzRNeHFZV3FVOUZLMDc4MlN2c1pMUGgyenVpdEVWbFhwdFJXcTMwMEtvZWFtWW5PWFdwVGNobkwzSlVwUnE1R29aR3hsT0toYlRiYTFSRzRvWnBMVjc1MEZ5cmkwbk84RG5lQTcxZGhFNHZwM1JLVlpaeWtXNk1iVXA0N2NaY3RHSW5iTmN2NHIwMVVIa2swc0hheFdpK2lkdTEydVV4bFhkRnBwMGVLcmZUUldxemd2U2FWRmVhbHkvTFdyYmkrU3lNazJhbDV3VWwyOUtidFNPT2FlYzBwMDdNVHRXSHRLbkJUa1phRFNlbFhuSnA1czdKTFl4Q05sSFN4aUdjYUtuSGhLVnRCZlhHeTIxTzZaVGVvekoyalZZeHh3ZU0wNjZSWld0TFl5N2RVZDdJVVloVGRiRWN5MWxpZ1ZXMkVKTEh0a3lMVlR5TFNYMFVTUWxHNk84RjFiMFhaaWxaL09oanNaMnhoYndyYWtzVUxBdlhhN1VtN0NpWjRyWlhtVVQwNzVtdWFSTTI4Ujd2cFEwczVyYTc2OUJVemV1T29MNlFpN3ZZVWlEaXpjaTl0VjlLd3Ntck9hOHFNSzZpOVF1VGpGc1dlVlJaVjFRdVZrZm1qTE9OVHE5V2VhMGR5cFVxN082Mkx6N3JmRldDMWF5dnFzeGcyaUZzWnJ6cEpKUG92Sm1hR2U0dVFCZEFCZHFZK25NM0l1Um1hWlZ6dXUyVjNFYzY5UUxvTkwxaWh0bUtkaWttdExNcXhocTFGOFdyc2F0VlcyTXZXckttQzY3eFdzbE4xdUxxTXdtZVhGa3pSTFZlNThQTk15amVpdDFYZDlLNVZPMjExbWpNcDEyVkZNN2F0YlpxWHVydkxKd3IzbW5NNTduS000YXJaelUyREd1a2hLdVhUdEdjcVZLR3FMUzlhd3VxdVhMSnh0SFVOUEdTNnR2SVVBdWdBSGtiVTA3S3U1eWxiT3UyM2traW9pd3RreTFMYXBLek1LWlJVbEdaM1d6dGZQSlJtdk96TGl1cmZUcTk5MTFRMnBUYmZYSHNuYmE5WE9HRVlYWTViWDBmNU5yY3ZEZDV2Njc0V1R5Y0hGKzMwYUhGbWQ3U2xDUzdtRy9MUExMbHlIVHZiVnlkc1dxb1NNMnJ3bWRwWlRUNThPWkcvajYwdnlYTjlvMjFUSlRqMVk5STIwZHVYTHl1MDdkVHFKSEtuTlo1bDlGb0FvQUFCb1hJUHpOeUxkVXpValBsMzFya2tsZkd0T0xXVTVrZTltY2NkcXp6dHN5MzVqTGhLV3Vybk5MR3ppM1BsSGZYZ002MHZMYm5uR0pxZFF4ejVvSWFjelJmUjZIajU5ZmV0K2VaOFdTb3pIZjBWYnJJZE9ra05qTHFPeGpjMXVkR3dwcmFBeFRkZGZRbEk0dTA3bmxpMlJuZGVoUmF3OGNYRW5XTHZETkJMZlNYT1dMMm50bXRRcm5OVmJJaFBhcFJTbGltS3FnWFFBQUFBSGRET3VSNjZtVXpsc00wck8ydTFJclcxeVJyWmR6bURlZFZuTW9TcTFxV2dqc1RPYzRxb2orYzI5ZDRtaG9KNjB4QkdoV1pxTXBHcWRXTVhhMlRzYytMUDBMNW5QSGx1eFlSdmZmOVQ1cHpIbDJLOHNZMC9CK2s4dHYwcWQ1YjZQYzJ2WlJkVzJWeksxbXJSSFNYaG5HaWt0cTV4UFAyY3lZUmx6bSsyeFpoenpqa3RhaU0wYVUzMGwza043bFd6c2xPRmZVdHVld3ZhQUtBQUFBQWQ0RDEyZTlNdG96WlpYaEdscm16aFc0dytuMk5TcjUyNjdiTnJPSGMrMXVZeGRTek0zMTA4Nk5DMzAwZFVKRlNaVmNraXM2am5ER3ZqNi9QaW1veXBkRTZyRDBlRnVlZjU4T2NxajE5RGk5eTlzRzFIcnVDckttdGN0aEsyN2xWY01NSjJJM1ZWZk1hVjJjcmpqeWpleXJ0VTd6ZldUaUJuUHBQT3hFTGErNzZOUHNlZGprdUwyd0F1Z0FBQUFBQUFBWlc2bWpZdFpKYmw3ZWJJdGJ5RnNpTWllaGMxbm5WeGRaVzFJVjNUVks4cll5NkFRaVNsQ1JOMVJxU1NiNmVPZmRqSDJzOHMxVnhMWFVuQ1o2THorOWhjK0M4YmVkZlJjczRtY2Z6M3JxQ0xxbHRrTE9WM3RmWloxMkJYWnlCYmFwWWo3T1ZQT0djN1RWRkFON09nRzZ0WklrcUYxQ2dMb0FBQUFBQUFBQUFBSnVJWEkwNGwzT2FhdDJvcnRRcnErcW1Dc1Zja1JsTGdGWXB4clVUTTBXYkptWG5YZERPY05pbTNXdlIrYjliNVBseHIyOFRkbk8zenZvY1hYVG1tWU4xdDVUK2RuRjNwY3RiV29KYnVHUTNjbmF0eGRITTA3dlJzOHZYTWVzOGw2ZlBUQmswdnZ0WjFheFp4bnlLcFRqWFpWQ09SWGxFWHVieUsrZWxHM2xIWVhRQW9BQUFBQUFBQUFBQUFCZmVpd2pEdWZLWlY1cjVTOTczaDNrSkVUU1pFdE5GQTJjNU9KYjZQR2N6aS8xZmlOdkhIQU5yQjEwOXQ0L3dCWDUzUFBOMkVXQnRSbkN1dFRON3FOU3pINXpEV2NyVHJmb3ZOdXJMZHE0K3ZNNG10a2JXdDQvTk5pWkllbitmVE1yRVpiN00wY3R0WG5mVVRrdEl1ajJaUkpuZk9lYklJVWxiUUJhQUFBQUFBQUFBQUFBQUFBZDRERnFkeU12WjBwbGVXeFFSbmxjVnBUc3JheTBJU2tRd3Z6ckpLRURaejZyTXpYVlQ2emF3aTNqblBNY1MxdnJhYzdyV1ZieXNjNitCMDZ6bGJSSmZkQlZZdUpTdDE3ZlB6bWJhT1N1dXd1bGF0eGdLTE93TEl4RGpyZWhKZDVtTWFLU3U2QUZBQUFBQUFBQUFBQUFBQUFBQUFBQXZ1U3NScDdPbE0zcU9NeVpSYkcyUFFYaDBPY2x3S2JxVXN0b3ZYazRTU2JGREhQakZEUVF1dVRqSnJaeU5yR3h4cER2VHU1UXpET0lMV1ZiNmRqWlhieTJIU3U2cTA2U0RuUU9GenFJYXptQkpvWXBDMlZQSXRBRm9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQkpoWHFOOW90azBZSld6TU9QMTBrV1JhajBEbFY5SkJoVmxUcHhMN3FPWTVNSXZJRXBRbXU5aDd1SHo0MGgzcjMwSVRoakNVSlI2OXAxVzBGc0oxMU95TW9rU3ZLcjlnWmtwalVuZWNxdXAxY0ZBRkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQW5BR1pLV0l4ZXJLWjA0WjlrektMczF6YTMxTHBWaWkwczUzaEloYm5td2craElXMTJMNkRCM3NIbnhwN3lYWHUvQWpuQ2xjNGRPMXE5MVJaQ2VrSXNhc0VZamdWREMvT1c5aENLOTRDZ0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBSGJLZ1o2cllseEN5UmxyTDdNNk51UklkVWFZVEhZMEpTS29ibkpNV2V4S0xjSDF1Ym5sNStXM3pwM3l1YS9Fd25IMTdwd3hJTHY1YWhRZGdzdVZRdG5BRkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFPOEN5ZEFqWFZKREJWSkpCMENSSnc3MGlkSWlTNWJFN0U3MkVhdEY0cmZHb1h2QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEvL0VBRE1RQUFJQ0FnRURBZ1FHQXdFQUFRVUFBQUVDQUFNRUVSSVFFeUVGTVJRZ0lqSVZJeVF3TXpSQVFWQTFKUVpDUTBSdy85b0FDQUVCQUFFRkF2OEErZnFqUEsvUzh1eUo2RGRGOUd4bGd3ZlMwbmI5TVNkM0NXZkYwQ2ZIVno0K3VmRzQ1bmZ3R2hIcEx3NFhwTHcrall6eHYvcC9KbHZwbVpUQ0NQOEF0NjNLOEs2eVYralJNVEVwbmY0dzNXR0haNkdhL2FCS3hNN0pybjRtWGhUMHZJamVpTFpML1RzckgvNjFlUFpaS2ZTREs4V2ltQmlJZXIySWtiTW9XSDFGSTNxQmh6M2h6TFpTOStRL3crVEdweVZIeE5rK0tzbnhiVDRxREpRenZWbWIzOGxlZmtWUnJzYkpqK21JOHR4N0tmOEFvMDRsbDdVZWtKWEZDMXozNk95SkxQVWFGaitxT1krVGJaTjlNS2p1dmsyZHkwTHVkc3owNnJ0VXM0UlRNaXJoZHduR1VnV1ZFRUh6TmtRWHNJTWlDMUc2KzBYS2VQajQ5MHR4TEt2K2JSaVczdGora1YxUWFSWWZBdTlTcHJsM3FkenhuWno1Z1F3VW1MUkRUR0h3dUhLcS9IYmpMd1gxRjlDaHU1VGwxelU0eXR1M1ptVmNXVUFqaE9FNHpSZ2NyRnZnZFc2cmFWalYxWHl6SGV2L0FKS1ZOWk1YMGJqRkMxckxMRnFXL3dCWEFsMlRiZWZlQ3NtTGo3aTQwRkFFN1FFNHlpdnVXK3AyODdGWGs2cm9ZNmNyUzNJNVZuY3U5T2ZkZHE4MEhSeHB4K2RRaDROcWNZVmhXRklVbmtSYlNJdG9icXJrUjZLN1paVTFaLzRnQmFZWHBqNUVvb3F4UVl6QkZ5UFZ3SmJjOXphM0VvSmlZMFdrQ2NKcnBxTUlvRlZOam14OGRkblVwWGpWZS9icUNzN1liZHU3MmxpOGJKYVBHTTMxNUtmVldkanJxYW5HRlpveGJDc1d3SHFIQkZ1SDQvNFZkVFdIRDlLU29iOFRLOVRyb2wrVlprTjd4TWNtVjQwV29DY0pyVTFOVFhTdXZrM3FWdXF6TVpkS0k0NEQxQnZIcEM2emJOY2xia21RUEVieW9PaXc3aUE4RytiVUt3ck5FUmJOUU52b3JsWTFkZVZMS21xYi9QeE1HekpmR3hLOFFTNjVLRnkvVkh2bnZLNkM4cXhkUmF3SnhtcHFhbXV1akI5SzU5bk8vV3pXTkRISE8wdHliSWJ1WGVsLytpZk14VzJyRGtzQmg4Tmp0dGIwMDFUZnNhbW9WbmxZdG5VV0phdVRpTmovQU9kZ2VuTmtHcEVwVGN6TSt2Rm1SZGJlNEd6VGl5dWtDQkpyWHllM1R4UGVLbXprMjl1dHZNcEczV1UvVFRZL2JxSGllamplZS9peWs4YlQ3MnJ4c2x2M1ZQeGV4ZVFJMFFlUS9ZMUNKclVISVFFSHBUa2NKbFlQRmY4QUtBM1BUL1RPNUFBQk0zMWJoTzRlVlhxVmRpL2gyTmtCc2JKeHBYbU9zVExwYURSR3ZsMUZFKzFQVXJZWmlyQkxCeFhOZnd4OGVqRDlkZjhBY3AzQTNKY2dmVExQdGlOeVN4WXA0bjV0Ym5FemdUTzJCRFlxeHJpMFZ5Q3JjdW1Qa05RY3JDVjAvd0FqVzU2YjZieTZFK1BVUFV1NzBxeHk4c29lb3E3SWFQVjNXS2NYTmorbkdkdXlsbHk3UkZ6YXpGc1I0VFBNSG1MTEQ1dnM3dGhsQzZUSFRsYVR5Tjc4N2ZlZWlEOWZrZmVoODFIYWtiSHRENUVvUGsrWXl4VHNkQXBNN1U0Q0ZkUXVvajN4ckNlbkdhZzhSWDMweDcyeDN6TU5MYS84ZjAzMDdsTndzRkQyV2VwdmI2UFM2L2h6MGxLK0k0N2wzcHdlV1ZQVVI0TkhxZHRjcXphTWdQaDF0TE1heEp4aTIySkZ5WUZnK2tabG5ieHpGRzJUMngvcHF0YnQxTjRDejBRZnI4bitUL2RMYU11R3JJM2hnZUpqQ0JTV0ZBZ1VMTmJoWkZqWEdQZEdjdDBBM0FtdW1wMkl3WFNuWFRIeVd4M3pzUldUL0Y5TjlQTnA5b1RNL1A4QWlHeFBVYk1hWS9xRk9SMGFnVFdwcVBVcmpJOU8xR0JReWpPdXBsUHFOVmthcExJMklZMVpXWXo4NjdmRTlRczVXbVVENnhHK2hjMS9EZVNzOUQvdjVYOHNyZ094ZU5yTFBlVkhhU3BQSjBzYklFZTB0R3ZFTEZ1bXR3SjFGTTVCT2oyQVF1VEVmZlRFeVd4bjlRd2hWL2llbllSeUxBQXF6MUROTjN5WS9xTjFFeDg2bkk2Y0o3UStaYmpwYUw4RjYrdE9UYlFhZlUwYUIxc1dvTFU5bG5GV1l1VE1aZkdPbk8wbmsxNzg3YmdPMHM5RC92WmY4czRENFdzeHZJLzIvbFpTZFA3SHZFUjMxR3VoTytxcEFPblpJbklKMGEwQ0Z5ZW9nMk9tSGtxa3o4TTRsdjhBZzQyT2IzcXJHUFhNN0k3cnJoMXJpM1ZtcXlhNjQvcUYxRW96NmJ1aHJFOGlFUzdGUzJYWXoxZFVzYXMxZXBUTXlVZW5wV3VseDE0MTJ2MjZ2YU41eFJQUXordnl2NXY5M2ZUVWgwWmFOUDFOcTZhOG1FOVFzQ2dkQlJxY3drTU5vRVppM1ZLZVFtSlNITnhOcksyK21NNlpkTjFMMFdmdnFwZHNIR0dQVk0vTStHVG1RK0xrREpwOVV4TzZtb0JOVFUxMHg4NjJpVVp0VjNRckQ0akx1WDRZYVBXMWZ5MWprNlFqZ3VlM2hwLytrSmdXdFRkZTNLMFRMOWtPNFBNdUgweHZ1aE96MEEzQXZRWTVnY0pDWWJRSVdMZE5kRXJBRnR4c2lLenRicXRiRzRoVG8rODlwYW40cGkvdittWWU0elMrOFVWWFd0ZFpSVnpOREhCdis0WitMMkxSTlRVMUY0a0ZPSjFLYzI2bVZaOWQzUXBDc2FzR1c0Y1pTaDZZdzg0NjhyUzNNNVQ4N3ZlSjV3aE1jZmwzZUhFemY1Rk1yTWJ5UGFXUW5RbnZBa0VYSE1EaE9oZlVMRnV1NXJ3S2xvV3l4ckdtTXZ3OVh0R1BJNmlOcnBqM05qVytxNHFqOTdEb04xb1VWclBVY252Mkt2STQ2YWoxQzJ2MC9KMnVUVUw2dUpSdFRVMU5RcnpwdittY3VsT1hiVktjMnE3b1VqRFVzclZoYmlrUXpIWFNZNDQxMlAyNm1NRXJmamp4UnhyeVI1VXkrdzIyZjdxYUdXalRFYkI4a0pBc1hHSW5JVjlEWUJDMitncjU5VVhrVHh4WXpsek1YSDc5bDFuZGUwL0lqZFBUN1ZzWElvYkh1L2JBMmZUNk94VlBVOHJ0MTVXSTJQTWJXMEdnUEV5YTJyYW0wWFY1Q01oV3FuSmoxTlcydWxCMCtTaDdSV2E2MVpsbFVxeks3ZWhTRVN5aGJJcThRNDRMbnZwREJMaHdxUlM3TTI3bi9Nb1dOMGRlM2J2YTNEYXpoRnhTSnlXdUdOWUJDNU0zTjlNQWJ5aks2bXRaM1RFWG9Cc3VQaHFXUEZmazRCYWdkejJtV1BqOEw5djAvSDd0a2UwVlYyMm0yeXZXZGdrRkd4YmU2azFLdjBlUjRJeUU3TnRlWnRXeGd5Nm5HWkE1NGhFSW1wcnJUbVdWU3JMcXQ2RkpWWHUxenlPWlp6dW1OWDNiV0l0ejhOZnpWTzgzR094aGpXU24xVlZyenN1YmxkV1lSdUxqRVFXS25SclZXTllXK2JBOFpOZFRXczF5NDljMUs2TExqalY5Z0U3ak56Ym9aVFh5T1EvSTF0MHdNajRlL3dCUXhQaE1uOWxSeWJFcEZOTTlVeU50UFRyKzFkNmxqOFh4N094WUNDSmsxQzZyRHlPNG1WVDNVOWlqbEc3dFY4c3gycmlmVmhNSVJOUWlhK1NuTXNxbFdYWGIwc3M0SVR1VkRrK0hYMnFGWTg4VWNhOFU4c3JHT3JsR3JxVDllTU9PVkttOHd4cmxXUGF6L09CTUNubFk3amh4WjJYQWNEbGkxUkh0ekh2c0R0WTJnT3FqWi9qcVk3UHRGT3hMQjhmNmIrejZkUjNMU1pkYjJLWFl1MUZXd0FWTlJHWmkySWEzd2NpYjZaQ21pMnR4WU15amdZREtjaHFwaWlySVMxQ2pSS2U4ckRSMUFuS0ZkZkpWbVBYTWpMRnRjcFV0Wm5zSzhjVEkvTHhjSCt3cmNMTG43WVU2YXdsVHVLZkw1QVdQY3ovSXRiUENBT2lJV2hBRXBvMk1UbmsyTjhLa09aWUFUUExFL3BjY25ROXowUG1VcHMzV2NqTlNzNk13TW40Yko5U3h2aGNyNS9lWVZYYXBucWQrMlFjalVzeWs0MituM2NMZlVhWnZSeHJ1OVhHQVlZekhIdWNCeFluYmJwZ3RxL3VxWmRRYTRqRkdhdXZLUzdGYW1FYmd1SW53NjJoNjJUNWZUYWR6MUN6bFpXbk4vVTM4WVA4QVlQdTM1bU5QdXE5b0k1MjNTdkZzZUhzVXg3V3NJQkpGS3JITXFwVkE4cHNhd2IxQ1NlbUhVb0ZqdFk5amNqMEoxRVdXZmwxMkh5dlErSjdpWkkrTjlMK2ZEcTdsdWdJN2l0TEhMdGpyRThETFRkUU9pakRJcHRxTlQ0OXZZc0RBajJHVFYzRnhyKzlYbFY4aHJYVEhPcnNrYXZxdGFvbWxMcGkyY1dzeWJNZTQwVlpJc3JhcytWTmVhR2pZcXVyWTdDTXBFUlN6Y094VGUvT3pBWGQrZTI3OEgrd2ZmRjgxSHdhVDRZUXhhckxKWDZleGhPUGp5M0llM29sQmFjbHJpQThhTnZhenJXWHNMSEdPcXVsTlp0c3lYRXNiaUFPbzhtcFFKWTVhR0w3ZEVQVDB1MExkazBuSHYrYjB5dmlzOVN0MHFqa2FsMEJIWG1zd0xOTm4wY2xtRGY1OTV1UHZIdDNzWFY4U1ZLbER4Zk1UNnB2eDNGdmxvK0t4MUoybVlsb3R3akdTSlk5TFY1ZGQwZWlZbE5hNU9mWndXZW1ycXV4dWRtRC9BRG4zeERxeklYamJVZE5aNG1MaXFWdHlLcXBmbU5aTjdsZFRXa0xYVk9iM09GK3E1eE8vcXRwV2pXczVXbWlWMFdXaEI4Smo3MFB1UFErVFdzdlBFTjBIWDJNQjRuMWRSYVBsUmVUVkRoVk11M3UyMEw1UVJZSmN2RzFXNGxYRmlaTlhhczlwajNkMnVPb1pjWnloZGRyemF1S3RkczdsbFE0VlhUaVVadHEyUGQycmNxdnQyY1JZSzdiY1VoNk02WFlqMVFycVU1TmxFcXlLcjU2aSsxZy9Jd0pnL3dCZys5UjR2bUw1V2FEUy9OTFFzV252RXh3a3N1OFZVUGtHNnhhUWk5bW90eU5JZ3grTWZLOFU0OWw4L1RZOG9MNUp0dE4xbHJiZzZFeXRZdjVhc2VnOXg4Zzlwamo0cjA3NWNLdm5ZZmZKZnQwSDNwSGhaL29JV2h3cTdSYjZUY2t3MzR6THI3bFpsTnZaZFRzVElyT3FiTzdYZW5JQXl2SlpRMWRkczdyS0xSM0svY1VuNGluUlJocHc5V3BUNmc5Y2ZIcXlGdHBhdHY4QWJ1enhGNXQ2azNHdVlQOEFZUHZMZnpNY1N4enFWMEY1M0VwQnNMVEZ3Qzh5OGxhaGoxOXg4bXpreWdzYlQyWlhUYmtIOGpIbDJWWmRFVTJOa2tVSTc4VjY2NUd0SmUreWRtZGxwdzE4cSs4OU10N1dabjBmRDVmeWVuSm9UMUY0bzJheUJGQk1ycGxkVStsSWNxcFpkWjN1bVZWMjJNdzd1dS9ocnBlbkZnWURCY2RBMW85dGZaZXQrMVptVjhsQmdJWVBYdUF2UzFXWFhldDJBUkdHcDZldkxJOVJmbGZUU0xLY0grd0Y1V1dKMjdLRHlxOW9pTmN5MDEwaTY4dVVSckd4c0lWek16ZTJQZU5xaXNuY3gwN1ZhbWxaYmt2Yk45TVFmRFZFd25rM1FuY3JTYjdWV290cFFkMUROSzBOY0tmSWZmWkI5WkhkSHlZeThhaDc1cjg3c2ZHZTAxNFFybTZrbnhCRWZLaloxS3h2VVljKzB4c2kxdW5LYmxOM2RTV29MRXhyWll2SmRjRzNBWWZNdEhlbzNNT3pjc3JOTm05UUhsQ3U0OWNweXJNYzZvemhpWXJZN1hOenVxWGpnWUIvVVYvMk10ZFdZNStvNDRMMlhoRlp5OHg4UnJUVmpwVU0zTTdmVEdYakxYNUhIcTcxbVhhQ2V1TFFjaTIrM3UyV3RCMEpnMEljalVMRW5rWjNETzRKeUJnZGhPNlp5UXdyRDdlNncvbitqZGFodHdPS2s4Vm80RnZqa1VIUGpadHBqV3UvWGZ5YVl3VldHWTlkaVB1R1hEUlJnNHlLdGdkY2QrTDMxZHF3TnhOdytLeGdkZ0hVQjVRaU1rMFVJc1lZTXlsN1dKaGNoa0FsTE1vYldwdFBsN1VCU3h4c0tLQW96Y3p0ZEVRMlBlNFZaV1Boc2NuWjZzdnd1T3pjUUlPaEIzb3pSK2ZrWnpNNVFQRU8rbnBmNWtQanJpTHlzSm1VMnFDZk81dWFZd1ZPWjhNOEdHMEdJSU1WSUtLeEFnRTEwU2kxNThMYUoySzV4eHhOSUo3eTVPMi9ReXdmRVk4d3J1MitYVDJMb0RxQTc2TXU1NmkzYnhzTk9lVDZrK3FzTWZua2VmNU1lVy9YUmcwcVYxcVp1WjJ1dEs5dXF4dVp3Nk82K1hiM0g2NE5ZV094ZHZFNFZ6dExPeTBLc091cHhFNENjSnduRXpSK1NrL1dmQjlPczdlWm5WOXJMNllBK296T1AwS05sS2xnUUNBZklQTUdKZVI4TnFjTWRaeXBFK0paWTF0anp4RGRXc2JPcUViMUdIT3RNTjd0Rk8raG1KYnhzeXFlMVlJbjZ2R0hnd0hVRGJtT3ZQSTlWYmQzcGRmMStwTnl2d3lPOGRieHZOZGk4YktmcXE5Ti9qemMzdFQzNlUxZHg4aTNjUmViUCtSUXgyZXZlYWQ5cDNwM0ZNMkpxY21XRnlaK1hPRlpuYU1OVGo1dFRpSUYwWDkwYmkvclM2eSttRU5MTTQrYWhzcVBDVnU4R0pkT3pXcy9UQ2QxRm54VjBKTFFzcXc1RlloekFJY3g0Y213d3VXbS9seE9CdHI5S2RtcXdhY2VaTmVIWk1yZ2F5SmpYZG16T3ExQjBRTVRoMDJJY3ArNWtlblY4Y2E4OXkzRUI3ejc1WXArckxYVm1NZlBLeXBXM3ZwcnNWRTdPTWlWeXkwVzJBVm1OamlMU3ZPemp6K1VHQXpabktjaDBHeE80MDJwbXF6TzBET3paQ0NPaGorMDlVK3ZINllvL0xqS3R1UXFZdGNGL0dOZmE4MURZaXc1S0NmR1E1ZGtOenQwN0pWRENadjVOUlVMR3IwMTJsYTQyR0xQV2dKWjZvN1I4cTJ6cHNpSnlzT1BUYWFhL1MxbmJ3c2VQNnBTb2YxTzF1amZwOFlDWXFyM0dVYnErbDh4ZkFKV0RJTStJUXpoUzhTcGEzdUR0UElubm9ISWd1SW5lQmhDdERXZmsxTlR6TmtRTUp4MlQ0TzV1Ym14MUZ0Z25kbktzeHRjSmtmWDZSMG84VnptcTJuS1dITGFISXNNTEV6YzMwMFpycFZlMUpzclN5c2lhbXVpVnM4V3ZIcm40Z3RZZk11ZUVrOUZSM2lZRnhpZW1WaWNNQ2lONnJXZ2YxTzR4NzdiSUpYaTNXeXYwc3l2QW9xbWE0N2FyTVFIdVdJZVhIeVFIVnNWSTJLMGF0bDZjbUVGelR2cVorVThOSWhwYUVFZFE1RTVnelFNMTAzQTByWHVIczAxUjd6T00xUE0zT1U4ZFBNOHpjSG1xTDlYcEVYN3F2NDViOTNYVVd0bWd4WG5hWVR0V3pzWFQ0YTJmRFd5cGI2WGZEYStEQnlKK0g1TVBwK1RMS2I5bkh0RVdxeHl1RThYRXFFRFkxVWIxQ0hPdGpYV1dkS3FMTDRucDBYQngwSGRwb2orb3BENmphWWIzZUR6RVdVVmZXOWVveXg1M0dFK0lhZkVBemFQRFNrTkJFSzZNNU1KM1RCZFBvYWRvVHRtRUVkRkc0SzFncVdCYWE0MlE3Q2Vac3pjOFRXNXduRTlQTTMwci9qbUw1OVBpZmZYL0hMaDUxQUlsRHZBS0tvY3UzWGNzTTVQT1R6azg1UE9UemJUYkNkNjB3V1dNZUYwMGsrS0ZVc3pXZUhJc01MTzNUVTFPSm1vR1pZTDdoR3RkNW83QTNOVGlRVVdVcHM0Mk9TYjZPRXNFY2VTUEJFSU8vOEFYSmhPYmROVFUxTlRVOGljekJaUHBNNENjRE5UaE8zTzJaMjUyNXduQ2R1Y1ROTk9NN1VOWkUxNVZkSk1Eemp5djcwK3lNMWZGV3dSS3JmVFZqWCtuV1RsNlhPZnBVNStsem42WE9mcGM1K2x6bjZaTzU2WE81NlpPNTZaRGI2Wkd5bkU3OEZnYWZYT1dVSWNySVdmRzN6NDYrZkg1RStQeUorSVpFL0VNbWZpR1RQeERKajVkMWtHWGJ6WElzQStJc0krSmNzbVErcU1oZzJKbDl1WmVVV05sN3g4aXpmeERnTmtQbzVWaFkzUHgrS3RBK0x1bnhkMCtMdW54VnMrSnRueE5zK0lzbmZzaXZjMC9ObTV5RTV4TEdCSHJsMC9IYlorTzJ6OGV1bjQ3ZFB4MjZmanQwL0hMcCtPV3o4Y3RuNDViUHh1eVA2dzVINGdlVFhkOFQwLytPSjl5ZlpLMlNkckZlZkIxR0gwKzRRMTNWenVPSjNHbmNhZHhwM1duZGFkMTUzWG5kZUd4akN4TUk2QnlJTDJneXB1bXlIR1F3NHJ4a0s5YVhyU0I4WXcwMFBEaGlmQzJyUElnTVV4RzFNZTA4N0xZeGpReFVheWZDV1FZOVFqTFVzWnFveDJlaTFzOCtHTTdWWW5OVWpYa3p1R2IzMEdvbGxheGNxc1Q0eXVkL0hlVzBsQk56YzNOemNBWXdZMWhuWlFUOGtSR0RDZW4vWkUrNnY3SWJSV3kzb1lHQm50QmtXaWQxV2hxeFdud1NtTmczcENwWDlqYVR0SzBOTml6WFFNVmd5SGk1bXB2SHNoeGF6R3hMUkNDczJWaTVGaXhNd1FaU05PM1U4c3E3VURUSFlkd3Y1TFJNZXZpZXhWTE0wUnNxTmRZWnVKVzd3WWpUc1ZMTzdWWEh5UzBOckdiMzAwVEJqMlRnaXdrZGR6YzNLcjJxSnFXOGFNRkZqVDRmVTQwTE80b25mc2hKUFRZbEoyc3dQNFl2dlg5a3lQdVZRWjJvTzRJTDdCQmxDQzlET1FNREZUOFRaQzlUUTA0elQ0TW1QaldwOG1wcUxhNlFaVzUrbnNud29hTmpPc05iRG9HWll1VFlKVmUxaTZ4N0kyR2hqWWxvaEJFVjJXUDlkUWFZbkkydVc1S09aeTdlSzhvbGRsc0dCWlBoS2xnN1NtM0lZUTN1WVdKbWlZS0xHZ3dyRFBoNmtuT2xJMlEwTEZ2bEJNVkxYZ3FRRHQwckJhaVQ0aDR6czNUWW5NVHVUa3htdHpVeC80cGkvVGh3U3I3WmsrMWZUVTFPTUtDY0lHc1dmRU5Ca0xCYXBudkE3Sk8reG41RHc0OVpqWWQwZEdUcnFjaUltVVJCZXJUalMwdGFvUlFYYTV4VFdQSkF0U0xmYUlsd3ZCSEZxVHV2Mm1NUWI5aVkzMzVoODRhL1Zkbk5zNU5waFptaW5pYkFMYXg3MC9EbUc2aEkyY1kxN1AwMGVvUm1ndzdZTWV0WituU2QvVWEyeHVtNXpFN2s1TlBKbXBxYTZhNlZlTVdWL1Q2YjBwUDB6Skg1WTVDZHhoTzlPNnM1QS9KcWNad21pSjNMQkJrR0M5REE2bnAzckpkWjNEU3FNMjhPdVczY3hLNnVVc2JRM01aT0MyUHpiRXA1RmExbVZmWGpqSHMvT3lQRm1PMHUrbXpFL21iZkxIOFZYTnl0eGh4eHlkc0YzQ3MxS1g0bTVPTEF6UVlGZVBTbkxhdGU3aVdTNWF3MU5uQ05kWVo3elluTVEyVG14bmt6ak9NMU5mSnlFNVRsTm1lMkpIK24wenBRZWxuMksxUkhhcWFOaU5EUVlhak5FVG00bmRNN29uTmZsNGlWMGR4anhFdWJ4OGlqa3pmU3JIWnFUdVBrV3ltdm0xTmZBWldTS0F4TE1wNHRrK1ZvYlQ1TXhmTnA5eDlOTXNQYng0RHFmY0NPbSs2bnRGTWNiK1VRSFkwREdRcTJwcWE2N0U1Q2M1c21lWnhNN1Jnb000SUp5UVMveFhNMzZjUHBRZk1JNUR6QmF3aVg2SXlHTTdpTk9GYlE0cGhvaHBuYU00RVQ2aEE3YjZjZXlydHhEZkxTdm01OW1Jb3FxOHUyTFZ3R1JsQ2hXWXVlbjM0Nm5VdCtxdkYvbCs1c2h0TFd2T3pLYmZVSFUrN29wMGJsZ2dPd1JvL0luUXIzRkhRc1FmcU00bWNEQlNZTWNtREdtcWxuZFVRM05DKzV5aWdzK1lmelI1UHFaL002VkhSZ1BsaHhzMXVHcWVSQmN3Z3ZFVjUzM25jUXkyeXBZMXhQUkYxMHBIQmR4bTVIcnFWMFBjMzhkWk81U25KcjdPUnhLTm5JdkdPck1XTXJyZTByVlhUTzczVDdFSGRPS2RXcWZ6c2d6Rys0V3J0cUFZZGd6Mm52MFU3VWppUVlLKzQ5bEQwdHJxT201YXNXTXU1N1JidFJiYWRHOFEzT1lXbk9jajAxT014VjVaTnpjcmNaZVYyYzNQSjZMN3FkaVpBL05Yb1J1TlZDTmRLbGZST2dXNUdJTjlLcSs0MWpjelkyNDNWSzJzWVkxV1BIdWUxYjIyMm9meVVxVHVOWmN1TWpNWE90eGNYakxNZ0tyT1hsSjA5bzA0T2x4LzVSNGV4dVQwalZaT3lybFlHVzBOU1Y2Ym52QjRMamtvZzhpcktaRitHcHlJOVRJZWlIb0RxRmUyMGRma0tiWG9GZ0hYQ0hIcGdqOHhqeWJyV2ZwbVFOMXA4akR4WFhDWmEzbUFiSUd1amZscTdhQjhDQVJjTVZqNHNpY1ZxaHVZcWZNb1hVYjh4K1F4a1ppeHJ4eTQ3aVVCN2kwU3RyRGZqZkQxRHhMdmIzRkg4cDl6SCtpci9kbE04ckZ1SWhWTEl5bE9xSFJzWGlWT29MdFExYkM1bklIRUZvSzlCOVN6WGNVUS9hUnJvSWpjVGFtaUlCOG44ZUZGL0x3dmtvUFFqa2lmTDdCMjRyMFJkZEsveWxnK29ueWFzSm1VNU5lUE9MUERkeEVzTVVjell3VlYxUW9WN21DMTFSN3lUN3pHd251bk9qQ0dUYTJRMDk2eEt2NUQ5eXJ5YklNUWJheCtNS2hvVjFBU3NTNkdyYzl1bjNwUDlLeFU4a3VqSzlMREtyeUpiZ3NxcDlKZGRIMmorWi9zamwxRUgxMSt6ZjY2YTNNNDZhWmg0VS9KV2RHS2ZMcjI3ZXFDTWZMdHlNUWRLazVzejhtZHBSalBaVjNLTWFXM3ZjMWVoV3pGekFDQVlnNHJ2ejJ0Rjd2REV0SzZtdE5lTFRqQzdPWnB1RWJBRThpYWxYM045MUkrcTA3ZWdmWGNmcUJNMkRDazlvcmxaeUZrWk5SVExCNUUwUkJLN1NzeUt4VGJYZTlMZDZqSmwySzZVeFRvc09CSHN5K09pTnhhMWRIb0ppcHp5TEg3bGxLOHJjcCtkM3lEd1VQaVhqYWc5ZlpiRzhSUnN6V3kzMHF6YTZOYzdKMEhqREFKUEJLb0tEY0FtMklMemtLNHprOUtjVFlPV3RTc3hjd1ZzeXBNUERiS3R6dlMzd3lVZ1BFdDdxL0FlNXh4cVA3NFMxV3RZbmJmZXA0YUZkZEZzSW1nMDE0LzJheWk5bmwwenY1dWlYMlZnZWVnK3NEb3k2NkF6N2wvMklJdjVPRktQb1Q1cVc2QWMxSFJJN1FuWmlqUWlmbHFmRVk3K1VKdkU1enQxNHN0dWExdGNWWitsZExXVGxUUkh0YXc3NkFUSS9KcFQzd2Nwc0xJVTFaZEhxUHA1eFdaWVJOVFVYeFUzdURMaDhaam1ibktlRzZBNml1RExGbE43VW50SmtEa0xKbnJxejVQY1IvcUFqZXg4R0E2akRVRUFMSFBZYzVrSHQxZk1oMGY5S2RHOWVOaysxYkczMFJmRXJYbEMzSXNkdy9JbzhkbDdzZjRoY2FFeXRTenNTWWxiV013cnFqMk13K1RFQVNNNWRnQ0k1bUJudml1clZabFBxSHB6WXJPc1BSL0N3VEd2TkZtWlFLbjExNVJheS9SV01FVmlKM2t5Sm4xdldPSFA1Rk1NVThTVjRON3h4c1FHZjZUek1NYWpNV2FsZVQzUHpzK2VzK0lSM0tVOHl4dWlqZlFEY2FNZFEvSlZTV0pxcm9PYmE5bGZ0MHcvRnRXTnlXMjRhK1FDQVRJL0tXVytLZmRVRTlIVzNublBVbU5aREFQSkFMWmxBb3lPbUt3dnJzUnF6MUJJSU5lUkZxYWk5MTROQjd0YTllUHdwdmxpZlZaVzFaNkR6MEgxZ2RIWG9JUGZML1QwVGZicC9ZcmJYUkc0dFl2YmRqc2diZ0hRZlFQYWU4TTFOU3ZFRkN2bUhROHpOOEdBRXlxdGNTbTYxN1c2MDQ5dDdMaDBVU3k4T3VPZ1FzZGtTOGZwMThqMDdBYkpMUFZoMDUyYStWWWZNNFFMb2tlY244eFNPbS9ObGg0bEszajFNbnlWNUdseThZdk5RVDdraVpSNHFnZGJNZlExQjRoNk45WUVNSTBaZ1ZBdmRhYnJGSEpzaCtUZnNBeERzVFhlcGlEb3F3bmtXT3kzanBSaHZjTy9UaXhtZTF2Q1RlNW1uOVJUUTFwN3lVQm0xaTlLTUMrOEJNUEdsbVpiYXNYM2M2NkxMLzYvcHVGOFhhN1ZZVkdkbnZsMkZwNmJpTG1YZmdWVS9BcXArQlZRK2hWVEpUdDJtSjVhMzNpc3lUOHA0Mk93NnJjeVYvbFpjYXRxbXVjb21Rb1c2QTZsZWI1ZkdydkRvVUtRaUszQXNPQkVJM0FoTFptc2JIZ1BiVDlxdHRkRWJnMTlYRmhCNWpHTWRSUks2YkwyQXg4YVg1YjNRTEMvaUlOdGJRRGJia2xodU9Td1QwMWd2ZXhzYVhYMjVCaHQxSzJMRVM3M0VXWkg5ZXJJZkV0emZVYk14eTIrbUU3WXRINDlrVDhleUorUFpFUHIyUkw3RFk4cEczYzdabkt3V1Z2Q2hBREZUM0ZhR2psRkgwQ1ZaQVpjekhJb1ljNnVxdXlFWmFaSXR3bnFEcjRpblk4d1REVUxMYkRiWUJ5TnJjbS9iUnVsWkRxUndiN0YzTjhqMks2NnJjb3VvVXRPUVNiMzBWU3hwU3ZHc3liM3Z0U3A3VDhDbEUrTkZRWjJjdzJUeTAxRThOTGZLaUxMLzYxMzNibTRKWC9BT1l4bktjcFQ5VnplOHhoNWxoK3FLNzFudkszVDJndG5hUjRWWkNNaHE2S2tyeVM0S241S2NxeWhsK0h5MVBndy9VS0VOejU5eWpvVHdYOXhUQWRqMmpxdG9KNUYyZ215eDhMQzVQV21oN2liMG9HSlZiWloyTVhIajU5bXA3UTJ6eTN5ZjdZYUpHNnhGbVIvVnUrN29zci93RE1icmkvMkc5NVQ0cmovZU9oRTFPWkVCQjZMY3duSmJGS3VoZklyeXhiUzlUSDVOOUJCNElBOU54WUl6Y2orN1czU3ArRFpGZmI2L1lPdFZBMTJyOHBRdUxqUzNMdHRBOHc4Vmh1bnY4QUlXZzZIeUY4cWZkWmtmMWJ2dTZMSy84QXpXOXoweHY1ejA5cVYrNFFDQm9PbW9Wbk1pY2dlaTJzc0Jyc0NNMWEzWS9GZm13S0ZBeUwyeWJZNS9mRVZ0OUtuREMyczFNb2g4bnBqWWpSOG1sR3R5TEwraFpWaHNZelh5Y3BvdEdYakY2RCtLcnkxZzB5ekkvclgvZDBFci84MXZmcGpEODgrOHNPZ3ZzQkQ5cXJ1RWFnZWJCaG1vVm4xQ0JoMFd4a2xlVVZsdFIzOG1GaW5LdHo4c1hOQ2VJL3dGT29Ec1FheWEyVTF3QWtyZ0ZRTDZjZVdXUGEyNTNBSnNtYStUbE5Gb2xCTVRHMEFpYTRHdDRuMldLRTlMdUgxSk1qK3RWNGovZmo0N1pEWFpLNHlvLy9BTWVaVFgzcmJRdHk0by9VTUlpN2JLL28rMlA2VWl2ZFptWWxUVjVucDFremZTME5iTHJvSDFON211aEU4aWN1aXNWUE5YaG84YWxHTzE5bWJjbVBWMEoyZjhGV252QWRRZHZLbnhYYWhZdENRSVhudk5kZmFjcHhKaVVFeXZGaGVpbVVYdGNlL3dEcXZVTWZpWlY5MlNQL0FJTzN5cVRKMThNcGxkVFgzWDNKUlg1SlQraVpnZ1ZwajVINmtwd3ptbEErdksvb1dlS3ZTUDU4bitkSjZWbE10MmJVbFdVMVVLNm50QTg1Ym11bkdhZ1BRRWlWYnZlNnhmVEtqMFk3L3dBUkc2S3hVc295VkxIcHJydlU1R0JTWlhqa3dZNlZoc3V0SlprV1d6Y1NsbHgwOUt5V2lZVDJlbnN1aW5oczRjZlIyL2lVeTl2MCs1ZGVLYTExbDFhMFYvb2NTelhVczFQNGZkRzVLTnlpWlA4QVF1OS9TZjdHUi9PazlOcUp6UFZtQnpBNUU1Z3dvR2hYWFRsQm96VU0xQ3NyRFdOeVQwbXBtTEdFL3dDTXJkRllxWHJYTEgybWJBbkltTFdXbGVJVFB5YUkyYTBaeXg1VGN3cXU1Yms1VHJhdWJrQ2VtK3BXcmsrc1kvWXk1bGM3L1RQaE1qaU1MSUV5QVVyM0xQdnFzN2JYb0xhMFA2TEZUVXN2Wm43dGt4cmp6dlhoWlg0cnlQT0MvbXowcitlN0F5V3VwOUx5bmpkajBuR3RjMlB1Y3B1QnpQcE1aTmRPWm01cUxXMXJudCtrVnN4Wm9UL2tCdWlzVkpDWlljTXBXb3RGeHdnK0lxU1daTDJUYzh6VTR6VXF5R282OHBrWjl1V2tIcUZxMC9FTXhOcmJ5RzVWMjJtdGlkOUtiM3FnODRiWkRkdm9nK3UyMDJUL0FQSDhRemdTakliR1A0cmJQeFhKNDJXRnlKb1RqT0JubWNvR213WndtcGkxVzVEMlhWZW1JekZqQ2Y4QUtEZEI0aXVsOHZleWtsaTNUVTE4NTZMMEVIdS8zVy94WlAzZFYvb25yamo4Ny9kbmdlMFdIMkhSb0JCUEFudk5hbW9WRTBaN1RDd3JNdzM1dGVOWDBKL3pGYnJYa0RqZGk4SUpyOXBlbis1WkxQNDhuNytnaWo5QWV1TC9BRGdiZTAvVTN0RzloMDl6TnpVMzExQ05USDlPQVRMOVJOeXpjSi96ZzAzdnBWYzFSTlZXVENDcC9aSHZEMFBsTGY0c3I3K2dpZjhBbnQxeFBPUldQcmMvVWVqeFlUQk5UYzhUYzFGVXRLYUh1WS9EZW16SXliY3A0VENmK0FEQTNUMmk1QWNQUVY2RWZLWWVwOW92MjJuOHZLL2s2Q0ovNXpkY1Ard3Z0RDd4L3VFTUh5S3U0S3h0Y0VWcmtlcG5oMEovNGdhZS9STEdyUEtxK1BROWMxTmRmOUg1YTRUTXIrVG9Jbi9uTjF3LzdEZUs1L3VlN2Y2Lys3b3Frd0tKWGcyTXIrb1VZZ3R0ZTU1dUUvOEFHRFFIZld1OTY1M0tiWTJPNG1wcm9laW54MFQ3bSs3Sy9rNkNWLzhBbk4wRXhQN0YvZ1FkQjdtTEFKV25LTGdNcW5QeDhVWFpGdVEzUW1iL0FPVHlnUFZMR1NES1Y1MmE3WStQWWtJaGkrM1YvZksvbDZDVi93RG5OMXhqcTdJTzNtcHI2VmhHNVQ2WGxYVDRiQ3hJM3FwVlhzZTF1aE0zL3dBMFBOL0ltUlpYUGkxZWRyRXRnd0hBYWl4SWVoOHJsL3k5QksvL0FEVzZxUE5ubGpLc1RKdGc5SXRBN1BwMlBENm90Y3R5Nzcva0oxT1gvUjVHY2g4b1lyRXpiMGc5UUpuZXczbjZKb2FhSG53SU0vRDNnOU9zMnVPM3duNGE4L0R3SjhOanJQMEtUNGpCV2ZpWENQNmpsUEdZdDh2SVFzVC9BTmJtWnpIVFg3RzV2OWpSbmdUbXNMbi9BTG15SjNET1luTlp0WjRtcHhNMFpvelJtcDRtMW5KWjNKM0ROLzhBQS8vRUFDY1JBQUlDQVFRQ0F3RUFBd0VCQUFBQUFBQUJBaEVRRWlBaE1RTXdFMEZSUUFRaVlUSlEvOW9BQ0FFREFRRS9BZjhBNjFtbzFNNXhXZVMyYWkvNjNJc28wbWtvckNLS0tLemY4N2xoUkt4WlloaUh2ckYveHQwTjJLSlZGN21PV2xDbHFWaTlTZjhBQTVIWW9sN2tQRTJRZnNUOTBwQ1JWRlpyYThlWG9qMXNYcFQ5a3BDUXl5eXpTY292WThlWjhIai9BUEpFVzJ0NmZxa3lpTHd5aXhQRkZDV1dlZm84ZlJCbjNsTE43MC9RM1dFcUdYZUdYaXhQTHd5VWJOUEJGY0gxc3Zhc0plcHNROGRDOGllT25SV0tMTEhob2VLb2lJdlkrQ3hPL1pKaUdkNTAyVzRrcGRNV3l0aUpENnpXeWN1RHMxZmdtM3VXMTlpd2g0WjJlU0gyUWwrN2F3aGREV0dMWkprK1JRT2lLOVRGbGk1eStDWEtJY281UXMyTWZXSHVaS05qL0RvWE9YdFdaRVI0dll5aXFJN2FIbENXMlJYNGFCTDBMWWk4VVVJZUdkbFZoWnVqdDR2Tml6cHdzMTZxSzJXV1dXTEwySWl4dkRZbHVzc3Ywc1F5eTgxbWlpL29zV1d4dWtKOERaWXNzc3ZaeHNzdktKZWhaNU5Kd2pVY3MwczRST2RqbWZJUmtMTjRyWXhNc3NzNEt3aDRacU5UTE5UTlJiRTVDYjJ1elN6U2lmQjV2OGhwMGVEemFpREVKYjJhMGZJaldqV2pXZkloU1JGMklrU1ZrbzJmR2ZFejRtZkN6NFdMeE1TMzJobmtSNS9GUFZxaWY0M2lrbmJJUkVKNzVEOFgvQmVKSHd4UGdSOEVUNFlrZkdrUVZDSGlqU2FTbmk5M0JwT2l6U2lVYUpRRkFqQnNVVWk4Vmk5dllreWpTYWNvZStqU1ZpeFNLS3d4b2E0S0hFNlJXMXlZbmlqVDZFUEZZdmJlK3NwRDlTZXl5OFVJVzZ0emthNzZGN1dhMnV4Uzl5M2RsbXY4S3NVZHRsK2x4S05mNkordG4zdGVOQTBYUkYzbXl4c2ZtVjBLWXNTbFNGTFpKajVJcTBhUHdXOWJINkpsTmk0THpJWEI1dkhmS1BCNXZwa1paWERyWkpEVFI0M3g3bDN0c2NyNlBzc1R0OENXR3pzbDJlYVZFWTY1V1JkR3NoSWNiSTRaZFBrWkZDZGRpa21KK3RsM2hzczB0OWlIVmxXUjR5eEluMmVUeE9jaVBqVVVlUlNiNE5Ia1BCR2FmK3g5Q3kxWTFSQm83Tkg0YXZwa1pYNitzU2pZbGgvOEZIbkZGWVlqeWRpUTBlTmNpaVZ5TVd4bytNaS8zRGpaR0duMko1ZGlXNW4yVDdSRWtqeDk0KzhJdlpRNEVmejNNVDN0aWRkNGllWHRFRHNpdVNYUFF1eHZrbDBhT0NEYWRQZFF4TDJORjdwZmlKcVJGMmlKTmNvZ2hrZUJKa1Z5TmNrdWpVcUljdXl2NUdoUGJReEkwb1pEb1pISDJJYU5DRXR0L3dBTFJkZCtpUkRvWkR2SDJMMFYvSFg0YXQwaUhSSThmZVB2ZFpYOHRGRmZoZjZYbVJEb1o0KzNoTC9iTmwvMmFTbWNqWkYwT1NQRytUVmkzaXY3NnpSUlg4Zi94QUFnRVFBQ0FRUUNBd0VBQUFBQUFBQUFBQUFBQVJFQ0VCSWdNRUFoTVVGUS85b0FDQUVDQVFFL0FmMTVKM2tudVRlQ040N2MyamRkMmJSd3R3SnoyMjdSeE1wZmFiNWFoZGx2bXJLZlFoZFoyWExXVStoUHV6d3dRUjJ2UXFyZlNONDBRdFhiM3lQYUNXaHY3eFBnYnRJdWw3S3FTbDlCc1lsYU9aNmVoaTlIcm5hNW53eFpjN3RINDBkaFhlcS9HWkpKUFVmQXRwdER0VlVaR1lxdVNkM2VTU1NTVHllVHp0REdpb1V0bmxNcEZ3TXlNa1pJa3lNaVVKelpqUTBZbUJnWUdCandTTXFLS25TeXFwMU1wUXVCanBNVEV3TVRFVkpTb3M3d1J4UmZFcXBNUlVpcEVqeGFPQ0NDQ09PQ05KMWRvSXRHc2szajl5U2VmSW5xeVpFQ1dzNkxab2d5RStuaVFTSjZTU1pDcXUySjZPMEVDNmJJdE4zWmlLWGRhTWdwNmszOWlWbXoyTXJQa0ZMZ3lLV1FLekpzaVlKNTVKSVloMlYySXFHWTNwMWRrN1lrbEw1V2lMTWpaRlFrTkNRcVNQSTlXakVUczZSS09ka2IvUmlHSzMzZ2FGMnFoV1Z2dDRGMjJNUkEwS3lFUlpraTdzRVdReGF4MTQ0V0laVGRkeWRtSVpUYjczbzFZaGxOdnY0RUVXWWhsT3NmaFFRUjAvL0VBRVlRQUFFQ0F3UUdCZ2NHQlFNRUF3RUFBQUVBQWdNUklSQVNNVkVnSWpKQllYRUVFMUtCa2FFak1ETkNZbkt4UUZDQ2tzSFJGRU5UYytFMG92QWtZNVB4QlZSd2cvL2FBQWdCQVFBR1B3TC9BUFA1TmFUeUM5aVI4MUY2U0xDWjVyMG5TejNCVjY1L2VxZEVMdVpWT2dRKzlVNkRBOEYvbytqK0MvMGZSL0JWNkJBOEZyZi9BQjdPNVY2Szl2SXFrU014ZWk2YzM4UVhvM3dvbklyV2dQN3FxUnA5K2JNdWFuRWYraTltSEhqVmFqUUFzVnY5VHUwS0Vqa3FSWGQ2bEhnUW9vNUtzSjhBNXRVK2k5S1pFNEdpMTRMcFppbys5cU5VNGxPZEZScy9KYWdEZVdock9BNzF0VDVLalhMMmZpc0dqdVcxNUs0MS9GZTFDbjFnSzJsaVBCWU5WV3JBcmEwS0ZVaVRHUlhwNEFCN1RWUG84WU80T1d1d2o3eGsxcG53VTR6cTVDcFhvMjNlTysyYm5Cdk5VbTdrdFJyVythcTkxdDV3MVcxVGphK0p2ZnFoQW5PeHd0ZERQTUlpM0ZWQy9mUWs3V0hGYXZvM0xDWXpIM2JkYTBrNUJUakd2WmFmMVZ5R0F4dVFzbWZOYXV1ZUMxWk1IQlRjU1R4MFpTeFV0NTBHUSt5UE5OWjNwcmtIMmc1SytOT3F4ME95NVpqUDdwb0ZlajZ2dys5L2hYSVRBd1pEZlplZTROSEZTZ3RueEs5SThuUXdzd3NtN1pDRE1xbTBUd0ZTcnhSS2N6S3FJMEpIZFJTUHFjdERWMUN0WWZjc2dyeG96dEhCZWpHdDJqaXFxODRob1VvQW44VGxlZTR1TmxWaHBTVXp2cjNJdU85VHNlN3Rhb1RpcEFUSzhyRDQyQXE3MmxQTmNmVVUwYnI2aFhvVlJsOXh5QVY2UFU5ajkxdWtQQVdYV2E3L0FDVTN1bnczQ3lxdzlUSWU5VHUwR003STgwR2Q2aGNUK2lEczBISU95c0lVd3FiOFBYMFhZaWZWWFhDWDNCSU5XclYvYS9heS9FY0doWFdhalBNMjRMTStvcXZtUkF3YlMwVHdGU2lTaW9QQXB3UkhlaUxTcnVTbm1ydnIrcmppWTdXU25pemNmdDE0MGFNVGtya01TSG1iQ051SmxrcjBRbWFrcW9UOVZKT2ZsaG9PZDJ0VUp6bE5RdWRuRFFCUUtrcHFmcTZLY3FXM1hpOURPNWRkQjFvZjArMmRaRW8zUDlrR3RBYTBZQWJyREQ2T2E3M3E5dlZ6cFVJSGlGZTZQRTdsUzlMaFVMWGJlNGhZM1Q4U21LOGJhMFZCYk5FOXliREhNMlRzYXpzanpUV2Q1c2hjL3dCTFFWUExRQjlYUlZQY3NOSE51OEwrSTZOVnZ2TnkrMWRiRjJmcndRQW9CZ0J1VmFETmRWQk1vZTg5cTJ1R2FtMGtIZ3BSUmY0akZVa1Q0RmVqZFBnVjd6Q3F5ZXF0TEZxdUJzeXRsdWFuUHp0RThCVW9rNGxPZDNXUWVhTmhIZXBhQmIzNmVObGFLbGVheDhGdzBhMlhtOTR6WDhUMGJEMzI1ZmFPc2kwYi93QW9oUUFEQVpJa2tCb3pYVnc1dGdERTVyVUpZVnIxR2FwWk5tcVZKd3NrNzBnNDRxN01UN0xscTZxd21NeFp0VDVyV0hmWmV5UnpkU3dDeDdzOVZPZGJDNXAzT3dXYzdDZ2JRQXFsVUZtTStTcHFyTTZldWJvODFKcmUvZXBHeTgzdkdhL2l1ajdCMmhsOW02eCtxQWcwQ1FHN0pUSmtCaXJqS1F4NXE3aTNKU0RycnNqWnEwV3NKTEJTTFpxY1B3VW5DUnNsTzgzSXF1bzdpcGtkNFdxWnFSRWxJNHRWM0pYT3paT3hqTWhWTlozMndrN25hQ3A1V0EyY3JDNWF4bHpXcUo4U3RkeTFWVXowcHZOMzZyVUV1TzlWdHJabXc0aENQQnJCZjVmWkFkeXVOd0dGaGh3L1pqRTlyUWxPODNJckc2N0kyVW9xMHMxaE5UYlVXNmp1NWVrRjNqdVdJY0ZlQXBrblJIYzFlT0pyWk5BYnNTcDcwNDl3VUdYRVdRazduWkNPK2JpaU85RUtWdk95VGRVS2JpcUt0dGJadjFSNXJVRXVPK3lsZEVCd2xaMU1Xc0orUEJTeFk2clQ5aWxLaXVESGZLeitFZ21ycU9QNkl3ZlBpaXc3dEdSTjV1UlVwM1haR3lsRlduR3o5Vm1NN1pzY1dxVVZ2ZUVHc2RPOWFFNStlcUU1M0N5Rjh6aFpDVHVkblJ4OEorcUZuUFFtVDNLbE5PY1EzQjVyMGJidkU0cWRsYlNTYnJSaWJERWllelpVOGVDTDNZcmpaL0J4dndPeVJodkVpUHNBYUVIYnpoKzlsMXUyN3lWNEd1S0R4anY1cnJXN1F4MDVUdk55S2xPNjdJMjFWVk1VS3I0NklzWXpJVFRXZDluL0FQVDlMT3NiaXdUVGp4c2dqL3RoYzBDcDVlcW5FTndlYTlHTHZIZXFxbWpmaXpETWhpNVpOR0RSZ0VHdEV5VU9qc013emFPYnRDYTZ3ZjZpSGo4WDJEckhpbSt3dmR1M0l2ZGlWWEJmOXQrSzRLWTJUbzNYanZ5VXJKVHZ0eUtsTzRjalpTaXFGVlRaVGdwRVN0SlRRY042bm1uSGNLV1JPRHhZNDlveVJzQXlZMzZXUzcxSlNVOUtjUTlYdzMrQzlHMjc4UnhVMVRSbVZmalkrN0R6NXE4NnpyenR1b3poeDBoRWIzaE42VkI5bkU4ajY0VW1nd2J0K1pzazNZYmdwSUs1NGMwWUQ5dHFMTis1WFRvM3Q3S0hrbVNwTmd0a0RlR1JVaWJyc2piVlNJVTI0V3ZmbnFoT2RsYkdHNDNiR0RoUHhRTmhjY2JCWnowWnhEMVk4ejNMMFRaZkVjYktWVmJKTXFjdERXazZOMmR6UDhxWkpKTyt5cGt3VmNjZ3IwcEFVQXlDdTZUdWlSZGlKaHdLZERkaVBXU0N2YjkxblZOMm5ZOGswbkFoWGJLSWRJaDdUY1VITjNveFdTcmlEV2E5RWVyaWRoeG9lUlYxN1MwNUcyUjJYYXBVR1lxQVcrQjBaVHZOeUtsTzY3STJVb3FoVnNZeklWNXByTTYydzJienJsTmJtWklORythbllEbllXSUZjclp4VDFZOHozTDBUYnZ4R3JsVlVyb3crZGdhMFRKd1Z5RWIwVGZFRzdsKzlza0lBMmpXSisybGUzN3JKaERwQTlyRG8vd0JaTlVvTnljOTJBUmU3RXE2ZHB0RmtRcDc5OXZWbjJiOENwRkZkWEdIV3cvTWNpcjhCM1dOeTk0ZDFzS0o4Um5wNWpJckc2Y2paUk5Cd3hLTHMwN2hTeHJkMjlBYnJ3YXA5Z0VvRElKN2VLbGxlK2lJeXFtdHpNazgvRWo0cVNuRlBWOE42OUUyNzhSeHN6MDI5L3dCRkp2ZWNrV1FzWENyOTV0a3hwY2pIaUFHUmswWmxUT0ozNklWTU1CYlhZZFJ5YzMzVFZ2TDFRQTNvY2ZwWjFJM1ZQT3dBN0w2THJRS094UWQ3dTlYaFd3amZ1VngyMnpGY1ZKQXRKQnpDOU1Mci93Q28wZlVLZUxUZzRZRlJXOWx6WGZwNm5HWXlLeVBHeHpzckx1ZEUrTVVEdm5OUkhIZVpLZWMwUm1vaC93QzI0cVdhSHc2M2hvNStwdllOYURNOXlrd1hZV1hiUEZieVNweG5NZ04rTTE4RnFNZEdPYjZOOEVHWGdHZGxvazFBTTJHVWFydWo4VC9wbzV4WUhtUFZUTmpuK0NKTlN1YWx2QzF1UjVvdE81ZFM3dVVyQjBobjRrSERBcStNRGJUQTRnNEZSMlE5UjdtN0ovUW9od2tSdXNOMDY0M1pxUkVqWklZNWFPTXdycmFaMk5EY1pxNE9WbEtYcStLYjNxOWtVNHluZWJkc3ZOM2kzaXNkQ1lGTXlxR2RuRE5TQzZ5SWJzTWVmSk9EQmRodFllVGFMV0xvc3NHc29CM3FVRU5ndCtEOTFQYVBHeTUvTWlDdkJxbXAyeVdRM291d3lGc3JBNDdKbzVPYU5rMWI2bmliQkNHRGNlZHM4MWMzTytxRVVkNm1OeW43Mi9oWmRJb1VZRGpRN0pSQjNxN2xiekJYVlJ3WE5GQTczbXE4Sk9ZY0hEQkJ3eENEajNGVHhiblpLS09zYjVoVGd2dmNEaXFqUk1VOGdwZDZhM015VFdqQWxONUZGQThMQnd0TnVGMFpsZjFYZVNxZTVTQW1WcjFQWkM0SVJJODVIWmFNWGY0UWlkSnAyWVF5L1FLTGcxb2h1azBidEIwZUlOVnZud1JlNnBLbG9obTkxVHB0aTR4SUZEeTlRRklZQ2ljODdrU2NUYUhaRlRDbm1FV2xYdDI5VEhPeWJkdHRRcDd4aXJ3eEZyVTd4Vk1EaTA0RlRnYlcrR2YwelhWbkE0YzBXdUY1aHFNMWZndUFWMXdrcHRWMk8yZnhCWG1TY013cUxKQm94TkVHRGtuTzRxZlpFMUxJSWNqWTV1UlVrUmJxdEpVM21YSmF1c1ZqU3k4N1ZiOVZkWVAzS3Z1N2xxc3Y4Q2k2Zld4ZDd6ZzNsbWk2YzNIZVYwaDN3Uzg3UTBDYUVGbXd6Zm1jOUtic0JpaTQ0blRNSit4RkYxUGhIM1RwMzdCREcrdG9SWm5ZWVozMUM2d2U3WjFUanl0RVZ1dzdGVEdDM0VGU0lJT1JRZGtacHJoZ1JMd3NCeW92U0c1RS9xWjgvd0IxTWJiTWxlaG02OWRYMGhzdUt2UXRZWkxpcHRNbEtLTGh6VzV3UWRMZ0U3Z0xIdnpNazUyWlE1SDZXU3pDS0ZsNXpabmlwYlhMQlMzV2FvNThGMjNabkJTYk1rNzExVERYM25xUXczSzQwU0cvaXBIRkJyUVhFNUowS1ljNXpoTWpDbGhMVzBHSjNLOS9NZlJ2QWJ6Wk8yVmdoNzhYYy9VVEdJVUhwYmY1Z2tlZWtBbWp2c2M3dzBUeHFnNFloQjI0b2pkdXM0NzdDMDcwWUxzUmhaZE9zenN1V3E2NmNuZnVyaEdHMDF3b1ZxRzQ3c3UzOTZ1UkFXem9ab3RPSVh3dXhWNGJMdnF1S3BWdVJWZFdJcTFiblpxbW1SWFllZ016T3pqZG40MkRrVVUwOFVEWUM3QlhSaGtNRld5Y1hIc2hYUktYWkdDNFpycW9QNG5LWjJuNDhsTkY1d2I1cS8wbDNWenJMM2ozSzVCYjFiUE04eXRVVUdMalFCZjEzK0RmOHEvRlBvbUNjaGdBaTQvK2xkMFRFTzdEaVZNNCtwalFQZVpydDB2SlVUajNEUzFnZWFuRDlJUE5HRTZoRlpLZThXVDNiMU1XQ0kzYVlnNVRVbEk2emNpcHdYVlB1T1hWeFczbTlsMklRaWIyMGRZWWI5b0s2Y1JaTnF1eGRZWnEvQmNCOUZKd2tiQmVNNVVRYm1aSnJCL3dXRGtVYko5OWwyeThkVnVaVW9kT084cVFWNStDNm1EM2tLYnRodFNqeHhVaGlVMkd6M04vRkVnRTV1UDdyK3UvL2FQM1dzNmd3QXdDa2gwWnU2citlV21HQ29iOVZJQlZWTkdWalo0TzFTb2tQZE9taVhjTEdzNzlHZ1dzNW9XcUhPOGxXRzBTMzc3T2RuVkh1dG43anZLeWRzbmpyR0RQRWQ2RjBrc2VKT0IzSXRRZWhIYjNxWXRtd3lWeU9BSitDbkQxaGxZMDltcXU5a0tLOGs2Z3B6UTVGQnVaVG01RkZxNUtUUk1xYnBSSGY3Uis2eG1wQlRkaXVxaEhXM25LeTVsanpVMFk1NU5WNTRNUi9aM0tST3FNR2lnRnY4UzdhTklZNDVxWjBpNzNqUWZ2WktRa3FpU29Sb3pzbU1WMGZwSS9tTnJvaXgzZ3FBcldrM21xVGR5V3ExbzgxcnhmTlVNK1FXcXhVa0ZXSTVZMlVYSGZZV2xkVzdGcWtydWdIKzgyaHNNRjNjaXp3VXhvWnR5S29aUDgwOHUzNEo3c3lqeEJjbThpbS9NcDVvak5GempUSVlxNDBBRElXVndWQWpEaG5XM25Ld3hjcU41cVdTRFVHTjJXMDBMdURjU2NncGdTWTBYV0RJSzZOQ3ExS2NWTWxZNkZIS29CVzhLaDBEbkJkb0JBWkJPT1NMb2tqelVnK21UVnF0VzRMV2VkUEFyWktudTMyU1FpTnhDQjNLOE1Sb1NPRHFGRWVDRGhpRjFyTnB1bE1VWFdQT3Rjblk0WkFOUXVpZUtCTkNETlRUU2hJcWltOVNDNnVIdDd6bFlHTnhLQVpnS0N5OTc3c05FUWY1a1RXZndHNEtmMkRGRVdSNEJ3ZXpROHJEeHBvWUZiSnNxNVltelpDd3QxSWIzY21yV3VNK1p5MXVrRDhEWnJaaVA1bVNOeGx3WlRzNEhRdis4Mnk2ZGx5cHN1MFpEZlJCZzNtU1lOMDVwck41TTAzV2wrcXhueFE1V1Q0VFU1V2RYRDI4OHJieDJuK1FzbnVWTm5BY3RBOUppQ2JXYkk3VGtYT015YWxWRTFnNGNpcVJQRUtranlLcTArdmg4YUtLMzRyWjk5alIzMllMRFJvcDlVNERqUmE4V0Uzdm45RldKRWY4clpMVmdUK2QwMXFCalBsYXRhSTQ5OWxYaFVtVnFzOFZqSlZNOUNXNXlwZ2FpeTZkb0s2Y1JvTTRheWF6c2hQZmtKS1dRVFppYW9KSWpJcHc0cVhjaU1sMWNQYjNuSzJ1eUtrckw5bEpYQnRQOEFwbzBOTnd5VzVWRm1Jc29TcWdIdVZXZUJWSE9ITUtqbUh2V3lmVUN4cnNqTlh1MjBHMDhyTzYzVVk1M0lMV2FHZk80QmEzU0dmZ0Jjc0l6KzhCYWtDRVBtMWxJUHUvTFJWSlBOVklDMmxSaFZBQXRzcXBKMHJyeTRBN3dKcldlME56RzlUa1BtY3RtYnMyMFVuUEFPNndPM2IwSXpkK051bzB1NUl2aU1MWjBFMDkzRkE5bzNrNTJhRW5TUm1iM0ZTekNCelRod1QrcmJ0SEhKVm5iZE9PTHYyVTFlaUVCWGpnc3JOWjExdWNwbzNKaHU2ZW5pdHl3V05sRmpQbXFzSGRSZThQTlVpTjc2TFpueVZSSzBHem9zWE5zcmUrd2g1TjNndFdBNTN6di9BR1hvNGNKbkppckZkNDJWY0Z2S28zeFc0S3JqWUhuWk85VTA1QUVxY1EzQXBpcFVtVTVMRHhLcTgyeUFKUEJYSXpDM210YUs2WEFMV3VmaU41U2hoenVWRnF0YTJ5WFpiS3dUbXRXY3VLQlhKVEZGVUFxby9WWUR1VjZjNVlCWjZHTmxmVlZDMWE4RktTeHN3ME5vcldZdzl5MkNPUlFsWkNQWmRLM3hzY1hLZ0pWQUZ0S3BucDBORGlEZ1Yxc0hEM205bi9HanFqdlhwb3Q3NFlmN3FVQ0NHTGFWVE96VmFUeVZRR2ZNVnJ4SEg1UXFoaCtZelVvYkQzVUMxUTFpMTRqajMyYXNOMHMxcnhHTjVWUWNBOTVHWm9nMEVFNG15Z1JualpJMXpDM2hVSUtxMDJVS3JKVkMzZDFGUStLcElxbzBLaFVPamRhMGs4RjZhSlhzTXFWS0UwUWh3eDhkUGZaaFliSW83TDdBbTZkQVNxaDNncVEzZUM5bS93QUY3Ti9ndlp2OEY3Ti9nZzVqSHpId3JySU1KelQ3MFBMbHdYc25MMlRsN0Z5dXVhL2dGN0ovNVZKckhIdVdzV001bFZjNTNLaW94bmZWVW1mSUxWazFhenliTlJzK0sxNHpCOHRWTWh6L0FKaklLblZNK1VWVkE1NTRxa21yV2NUYUpxbHUwVldSV1M5MDgxdkNvUVZXekUyN2xpVnVLcUxKVEFYdEdMMnJmTlZKaW5JVUN1aVRHZGx0UFd1czZVTyt3SnZLd2NyYUNtWndWWnhYY0tCWFdIcTI1TW90dDNpdHAzaXRwM2l0bytLMmo0ckUrS3hQaXNTcXVKNXFRRStRV3RjWjgwbFYxN2tKTFZwM3pWYnp1YXBSVkpObUN3V0ZsQ1F0dHkxbkU4MUxlYlpid3BvTFZFeWpTMG5LeVNtc1NzVDZyZDY3QlVXRmpyT2xENGJBbThyQmVFK1NyRGovQUp3cXdJMCtMbHJRK2svbUM5bjBqOHdYcytrZm1DOW4wajh3WHMra2ZtQzluMGo4d1hzK2tmbUM5bDBqOHdYc3VrZm1DOWwwajh3WHNvLzUxN0tQK1pTR3p3b3NsaXFSWmMxUjE3a1ZWeEMyMXRyYlcyVnRyYlcydHBDODdCQjA2amdpSitTYlhCRjA4Vks5NUlHZUN2VUtjN0FsYlNCdllKd25pcFQ4a1hURXp3VXBvQ2EybHRMYVcwdHBiUzJsdExWdkZhencxYlJObUZuc29INVY3S0IrUmV6Z2ZrWHM0SDVGN09CK1Jlemdma1hzNEg1RjdPQitSZXpnZmtYczRINUY3S0IrUmV5NlArUmV4NlAvQU9OVDZuby8valRqSm81V2RKK1N3SWNyQ0hRdzdtcXRpTTVWV3JIYjMwV3JyY3FxUkJzeFdLeFdLeFcwdHBiU3hXTnRDVm1xeld5M3VvdFZ4SE5VazdrVnJBdHROK0dITFlZdGlYeWxhc1Q4d1d6ZStXcXJvQ3F4ME5ScGR5V3RkWjh4Vlh1ZHlFbHNONzFzaFVFcmRWcEsxbk5iM3JGenZKVURmcXQraFdhOW1EekMvd0JQREsvMHNIelVuZEhEZUxEVlgybSt3KzhOT2dWYUxXaUR1V0RuSjBteXM2UjhsZ1FzcU1iS0d5VjhrWkdxMTRURHlvdmZaNXJVanNQT2luY21Nd3FnK29xMGppMWFrUUhuUmJKdG9WV3FyTlZhMmZDaW0ySVJ6Q29BL3dDVXFva3FMR2ZOVmI0S3BISnkyWmZLVUNIVEZnbk5Vd3NCaVBkTWlkMW9WSVRPYjZyYko1S2dXMVpxdEpXczVyZSthcVhPOGxxdGFPNmEzbm1Wa3NiS0JZUzVxc1NmeXFqZEttQnhCd0t2UU8rSHZITE5ZS2pTdGQ3UXNYT1dyREhlc1pjbFUydnM2U2Zoc0NGZzVXWXFqbFVLb1dLcFZVSkhKVmRlK1lUV3ZBYitFeVZIUFp6RTE2T0pEZjNxckRwVWNWcnRhVmdXbGFyZ2JNTEtFcXRWVVU0MVVyclFlQmtwc2lFZk1GUVh2bFVpQ0ZNRkhsT3dYUU85YTJLRGM2SXk1Q3pVWTUzSUxYTEdjeXF1Yzd5VW1OWlB4VXFsWkxHeWpiTmFKM0xWWlBtcWF2SlZPalFlU3BEQjdsNldFd2NuU1ZYRThscVE2NWtxa2h5Q3E0bXpHekRRaVdkSlBEUmFkT2hXS3FGaEpiVm1xNXc3MXJCaitZVllSYjhwV3JHbHdlRk5yUThmQ1pyV2FSb1pyRXFvQjVMR1hOU1lKOFVHakVxNDA0VS96WnFrcldhQ2kxdzdpaUZ5c2JOVXdVOGhOTmFuUElCdWpmbXJ0VDMwV1hKVk0xTUtuT3pXMVR4V3FDVnFnTlZTVG8wQktxTHZOYThZZmhWR09jZmlLMUdNYjNMYU9oVDFMalpHT1owUnpWTE5teWgwNkd5b3NvUlp0azgxZzBjZ3BQZmNHY3BxallrVThUZEN1aUhEWVBoRmxWS3pyRGlhQ3lhd1YwTkJlZkpWTzB1YUlzR3FISXpFdUNjN015UlY3TS9SVHowSktZd09qY2t4N2NudG10ZUM2R2M0YnYzWG8zM2h5a3RsaDRrTGJrT0doaDY1dkUyRDRuYUx1RlZWaEh5bFVpRHZvc1BDM2ZaVUJZRlk2VjBHWEZhdEdxNk8vUmtwWjJTOFZJZitoWkpTRlhueVV5WmxBb0ZCTktHdEpZelRPVjZ3REp1bEwxVlZJNldObUdsVjNncU5VTnZmWjBkbmZva1poVXNwTnF4RCtZV3N3amtWUjQvRlJUbDRhT09oYzk0N2Y3YWM3Wm5GMVR5c21wRGJSSk15YmU2enpRcE5VRXBwM2dtdHpLNTZkL3g5VkwzaGh4OVRWWXpWR0xFQlZNN0FNeXBaQ3hqT3kzU0k0MlV0eVdxNVZyelZXUzVGWWs4SktsTEoyZGFmd0taVTlHNnhwY2JadTJRcGVLbVZJVmZrcGt6SnNrMFRVM1NlN3lDTXpOU1JzQitKQUl1eUNMSGVhbXc5eWtSTFJrVkt5VXcyZThxNjlwYWRHYW1yNHdPUEEyY2JLZ09XK2VVbHFzOFZqTGtxblNid1RqeFRSeFQvQUEwcDUxdHFxS3RreWFLWlU5REpvcVRrc0pEY01sZDhkQU5hMGtuY0YvMUQ5WWZ5MlkrS3VNYjFjTEp1SGVwV1hmOEFrN0pEYVV5WnFpbkdwOEF4Vnhva095Rlcxd3M3MVJUek5zalg2cVkxaG96RzYzcTRqUkVoOWgzNktmUm42MzlKK1BjZDZMWE5JSTNHMlZsY0RpcnZublpQUW1OT0pFeUZoZDJRaWM5SU95MDVEY3BhRXQ2Nm9maVBGY2RDOTBsL1ZEYzMzajNMcStqTTZzR2xOcDNldlNWZDJSK3FKSm9NQnVzditDa0ZtOUVrelY1eHVOeks5SFQ0dmVLcFFLVFJOTm50dXNCMFpjTEpqZlpWVEZPS3FLWjZGTURoWmNlMit6Nks5Q040WmJ3cmtkdldzNDdRNzFlNk03clBoOTRhTjMzaHMvdHBjTlBqRU5rUjNhcHB1YjZ6clBlT3grOWs3T3NpRVFvZmFkdjVacVhSV1NQOVYrMTNaTHJJanBBKzhkNnV3aGRHZTgyQnFrRkljZ3IzdkhBSTd6dks3YnN6Z0ZPY3paV2dVaFYyUVY5M0lEUktBUVFRQ3BaUlNLMVBDMlZzd1pGYStvL3RidTlERUhFRUtYU21UUDhBVmJ0ZCthNnlHNFJvZmFidTU1YUY4ZDlrdERpTkVETXBrSVlNYlpDaGQ1OVFSNmlkbGRrVktuNUtTTHhJTjdSb0F2Umpyb25iY05VY2dyejNGeDRwMFFpY2lBRk1tZGw2VkxKN3lwNDVCWG94cjJRcm9vTWdxcVRSTlg0N3E1SzdEMUcrZnFKNUMwMlYwSzFWS2l5OW5vWFRyTjN0S2MwWWJsZVk0dFBCZWxiMVQrMndVN3dyMUhON1RhZzJjTjZsdTNjYko3L1VjR1ZUbjVsTkNQQ25xR3Y3dEdXaElMcXgzOFN1TmpXbHh1dHdHVnZPSitpa0tsYStzN3M3bDFzWjNWdzhKeXg0QUxnc2d0WHgzMjlaRk54bkZYZWp0bDhSVXlabXd2QW8zR3pxMjk1eVhhWWNIYUJrTWJDYkRDaTBMdGwyUlJhYUVZNlV4UlNOSnFxblNMQ08vTDlsNk16NGI3UHd0K2xybXRkSU9vUm5iYzMrN2J3dGxsYlBKT2Y3MFNnc2ZFeUduS3dzejBKN3RHOTd6c0xKNkxKa0J0OHpKN2xjaEFpZEo3eXZUQy9FM1E4dWFtNHpYMVdyWlFkNVdxT3NmMmpncHVNem9ONlB2Mm44OHJKaXJUdEROYm5zY3BpckRnZlVkZjhBellkSW5FWjZGTEtLcXZMVjd4dUt2ZEhvNytuK3k5TGoydDZabDFiYTkybjFtL0Ixa3RKckJpNHBzRnVEQlkySG5VK3F2REIxYlphRXpzakZUVXQyak0rQ2d5a0JyRW5jS3E3MGVydDhUZjNaV0FBVE9TcXJyUk1yRys3aGdwYnN0RXgzQ2tQQVpuY2lTWmtvRTcwRHdWS3RPTFZUWFk1VEZXSEE2QUZvZmlONHpDQlpXRS9XWWVHaFZHNkp5c3U0aXlpOU5SMzlRZnFvSnhhWVlFOXhXcCtYU3pHOWNNUnB2NlE3QmlMamlWNW9uMVV0N2NFTkdRVjBZRHpYSFJHcVhFN0xSdlU0eDZ5SjJHbWc1bFFHWUM1ZXVqREZVOGJMM1phVDVMckh1NnVIMmp2NUl3NExialBOM1BUYkFIdTFkODFrRGtmcWhZWE5wQzk3aW45ZHNta3M5QUE0VFQyRFpCcHl0UFJYKzlWaHlkL2xFT2JJalBRbURJclhreC9hM0htbTN4S3ZraTNJeXRoRUdsMFRCd0s5R2VwaWRrblZQSXE1R0JodjdTazRTMGJoL0RiTzJTWjBmZmk2d25lNzFjMFpZSERSbnZOazlBUmVsRzVrejNpaTJHT3JCeHpQTXFab0V4bVVOdGtnRkZmRkFjK2pibVhOVGVmOGFGMkd4eml2K29pM25kaUhYelZ5SERaRFprTi9lblJqaER3NTdyZWovS2ZxcEtacERHSlV6cXNidVY0NGJobG93M2I3c2ozYUFuV2RUTlVOdzhjRlhRNnQ0dnc4c3VTL2lJV3V4d21jMjg3WWJPM0JwNDJkVzhkWkQ3SjNjbEtFZXRaL1RkdERrcjdOWm4wNTJ6c3Y3eHRXU3RNWit4RHFuUE85QUtRd0hyTHZ2TncwSm5BS2FsYmVveUgybllLWFIyM24vd0JSMzZLWkpjNHJ0SHlzY01wRHlWTjJKT0FVb0cxdmlmdGtnTTNrMjNwWFdkdDFBdC9TWDhLTlZ5WVl6c01vTFpXOUcrVS9WU25KcmF1VXpxc2FwbWpkd3lzdUZ4YlNkRjdWL2d2YVBYdEhyMmowOWczR1ZnUUZsRnJDNGN3cGpXSEMxajJPazVwSVh1d292KzEzN0s2OFNJM0xvcmh1WlB6VHBZR290OUpVOW9iWCtWZWdrVHkvNWdwT0VpRkt5YXBzbkMwQ1NaMFZ1T0w3QzdlY1BXelY1dURyQUFyb3dGazFKalovb3F5alAvMmo5MVUwVTNtUTh5cENnc0hOUGpSamNoM2pMTjNKWEdpNURHRFJZeGpheWFyOGQ0Z3MrSmVnaGRZN3R4UDJVNGp5N2haUkdlajBiNVQ5VTJKRE1pQUZOMUFNR2pkYTdwTE5vT3VWV0VQd1g4dndYOHY4cS9sL2xUbkhFbWRwUWt0YlVPZTVUeEdZVXdaTFhiM2hUaG04bnRQT3dRK2tDK3pjZmVhb0RtbSt5NlJlSE5OTzl1cWRDWU1pZ3pwVFo1Ukc0aGRhd2lKQzdiZjFWNGI3TGgzNGNDcnB4c2QwcUpzc3c1b3ZkaWJKREFlc2xZWWJrV21pNG55dGE2TTZVNjNCdEg5bDFiUUdRK3cyelZxY3piSUNhYmZrK0xQWjNONXB6M3VuTlNZMHVVK2xSUTM0RzFjcGRHaENIOFJxVmVlNHVPWnNvcTJEUjZPZmhQMVhjTkNKL2RiOU5CZzQyejBKc01scnRrYzJxaEJVMXI2eTFIZDFrRXRQYWJMT3FJaGFybkNSaG45RklpbzBiME4wdjFSYUpRWWg5MzNTZUdTbFpQZU1VMkd6ZWgwYUZzUS9NMmNUNithRVRMRUtkdWFyVTVhRk1CaVRnRmRnWTc0bTg4c2tITllUSmVtZVlyaDdyUDNWMkVCQmI4R1BqWldpMVFxbjFQUnZsUDFYY05DSi9jYjlOQm5PMXhzT2hSVlZMSzZ3VjBHWEEyTjYramovQURSK3FrNGNpTUQ2aVlWNytkRncrRVd6K3djRmVic25DM2lkQy9FbUdiczNjbGRZMFE0SThGLzloLzhBdFYwbTYzc3RvTE5kM2NGcUM3OVZYVGFjd2piMGI1VDlWM0RRaWYzRy9UUVp6MHA2TktLdFZUenNsaU1pcEhVWFZ2YjFzRTdzdUlYV1F6ZmhaNWM5TTlMajBoc3crSW94SGY4QXF5WDJJdzM3SlJhVk00RFE2eUtHdFptOVRhREhmMm40ZUMxM0U4TjFtYXlIRDFRNEZTNFc5RitRL1ZmaEgwMEluOXh2MDBHYzdXaFBPVGRMSFE0VzBLeHU1NUZYbWdYZUdqTEJqZHAyU0VLRlNDelpHZGsvc25WdTJ4Z1ZjTkZJQ2F2ZEllSUxlT1BndituaFY3Y1NwVjU3aTQ4Yk0vVXpsZ3VxcGhXbFU1cDNXUEhJcUZFQUF3ckszbzN5SDZwMzRmb2p6VWhRQ3Jqa0YxVUFBY1pWNXFKL2NiOUxBd2IwNkMzY0tmb29mT3dLSFFlQ2Q4UkFUNXRhZFhlT0tMVEFCbFRZQ2srQkxqZFhYOUdONXVNcmFxbWhqYk5wa3ZTTjd3cnpUZUhDd1EyQ3BYOEgwZkFiYnN6OW5tZ1h6dkRHN3ZVdWpzNnJqN3ltVE0yMTlUVjB6a0VaTkRXRHpLNnozUlR1VElvd2NKR3lXWWtvSGQrcUJzNk44aCtxZCtINkp6UklieTQ0QUlRWU9HUFBpcHAvOXdmU3g4ZDNJSzg3MzB3akJ4bmJEN2xER1pKVHZsL1VKL00yZFI3cnNPYWV3VUdJOVRSVnNwaW1zdVgzT3dsaXVvaE9uSGR0dnkrMHpDdk05b01SbjZxYnlHaml2UnR2Y1RndFoxTWhaY1p0NzY3MVFNL09FWUVVRHJCaFdkZ09SVUp1VXJlai9LZnFqeWI5RjFjTVNtWm5pcFlQR0NrY1UvOEF1RDZJQVlsQ0ZDTFFCbVpMYWhmblRaeUwyVm9iQ1ZEN2swWk5UdmwvVUtKOHhzWWV6VXAzQUFXVkMxZEd1R2dHTmJNbFNiSjNTbmpIc0lrMUorMVRDdk1wRTNqTlNOTktwdkhKcTlHQXo2cWJqTTJ6bE83VlNodUlBeVh0bitLYUlzUnptdXBYY2lSc3YxaFpCYXhwY1pOd1VqQ2N2WkZRR3V4RFQ5VWVUZm9uYzFNTHJtWTcrSVQvQU80UG9qR082Z1JJY1F0dDNpcE9NMGNzUWlvWStWTzVvOHYxVHlJTHBYaWg2Tzd4Y1VhM29ydk5GempVNkZhckdXbDFjTUZ6aXJvay9wVGhqMkVYT015ZC93QnNtTVZ1YkYrcXVrU0lzbThnYzE2TnQ0NWxWZFRJYVVtZ1YwR05pWGRXeGpCZGsyaXdhc0FvSHkvcXFTT3EzNlc2c2s4NGVrSDBYVmlRRnJWVUNsaklabEp0aGN5VTViMXNRdkJTRG10NUJYbkVrNW5Ub3NMZXFodG1TakNnU2YwZzdUOGxNbVpQMjhOaVVjTUNwWFEwWmhUeDljYllQeS9xaDhvK21nLys0UHBvTTUyQUluMVZWWFFwU0dNWG5jdjRmb1g0b204L2NYVnhSZVo5RmZoNjdNL3NNSDVmMVErVnYwMEgvd0J4djAwR2MwUFZWVkZ4dG1mQmZ4SFRYZFhDN085eTZtQzNxb0l3YU4vM0pSWG9XcS9zcVRoWDE4RDVUOVVQbGI5TkNKL2NiOU5DSHpSNGVwb0ZuYlRETlhJTFM0NTVLWjlQMG5MYzFYNGpwbnlIM1BkakNmRlhvWnZOOWFWQitYOVYrRnYwMEluOXh2MDBJZnpKeDlYUUllOFR1QzZ6cGtUcW1ibTcxMVBSVzlUQzh6OTFhcFd0cU96WGFidzlYSkFaTDhMZnBvUlA3amZwb1EvbXRPblFLdFRrRmZqRVFJWEZYT2hNbTdmRmNyOFJ4YzdqOTIwUGNWckM0N05UYnJqZ3N2VUN6OExmcG9SUDdqZnBvUSthbGJYUmt4aGVWZjZURWJBWjVxWFE0VTNmMUhxOUVlWGZlT3FTcFJXQThWNktKM0ZWYjMrby9DMzZhRVQrNDM2SFFZZU9nYk9LMkxnemRSZW5qR0s3c3NSYjBXRXlDM1BlcnozRng0L2VOZEhWZVY2V0UxM0ZVaU9obmlwdzNzZnlLMW9aOExRdnd0K21oRS91TitoMDlTRTd3WHBvc09HT0pXdkZmSE9UVkxvM1I0Y1BpVjZTSTQ4UHZmSlUwSmd5VzNQbXZTUW1QV3RBTGZsVkh4R3FuU205NnAwaUVWdHcvRll3L0ZPZzZzeTRPbk5lMGhqdlZla1FSM3JXNlczdVh0WWorUVZPanVlZmlLOUZBaE1YdFNPVkZyRW5ub1ZXZjN6ajlqeFZCOS83SzNoWXJhQzNhT0syZ3RwYjFoOXhmLy9FQUNzUUFBSUJBd01EQlFBREFBTUJBQUFBQUFBQkVTRXhRVkZoY1JDQmthR3h3ZEh3SU9IeE1FQlFZUC9hQUFnQkFRQUJQeUgvQU8waitjZi9BQWp5VjZTRVBDZW9NVjdneGQ1c3RGME5DOVJWOW53T2tWdmUwaXQ0cC9sVEl2WVA2ekhsamY4QVo2djlmZzlPMFFzcFI4TE1KdFVoNkRXQnRvNmYrMm1hRXBaYjQrMHBKOUxiN0ZaU3JQMkNnalR5L292RVJrVmJkR25VZXdhUEJRN29mS0kyRVV0NFoySCtvTXBlYm9MN0ZwV0pYa1NvV1Zqa2xIcm9zU3JpUDlCZit0QXpKUExvaCtHdEgrTlJiRW5iOFlsaEIrWEtuVzVDV0VWUFZURms3U1JXNzVhUWhndVF6WVJpc0Z3aFQ2Y05tN0pJV1VtaElocnYzU1A4QUxPenNKNFRvN011aUJZQlBjaFk1NFo0SXlKdVpxRkxaelo2UWxZcmZuRU80M25Ibi8wRXBzTGpsc0pMSUJCZm1PeUZjTGhxbnlHMjB0eU5aRWtJM1FVV2wwUXZKOXlBb3ptMHd2UWJPcFhVdm9yTjNoRWFXVkVNRWhJdHp0S3IrQ3puQmVXVWRtUkxhNjZLREdQVzAxSHR1cUNRUk04NzFOTjdHVWdSbi9PaWNwbHA2b1VVcXpvVk9yeGhrazNEL3dETkVsc1lLaUJTL3dCRCtoeFJqRTg2anJTNDZtRWtzMkYzUHh2SktwL0srVGZBRFNWREF4a2tJWXVCZU5YN3Uzb084Q2EySmJ3SmpiYWZxWkdkN3pkcFZmQmFsTVVaRWp3T1k1UStCcUxEbzN1U29laG9iNkRNQmJtMGNyMExaMlBwNmxyY3JSbGVqZVJYWTJIL0FKTHBKMVhGaFVIdktGM1A0enkwVjVhOXgzM0dRZFQ4dDIvQktOaHg0S2pIbVpKTUxnS3lOQ3NrTHhCTDRSL3FBWkVKRDBxb3RmNFVoN2JqY3MwS21FU05zRzRwT0JKN0VodlVoY0gvQUlERzVxY0VOQ0JKdUp5b05DcDJEQVVhNjNMMTVXTDlLTGRhTXF2Rnd5RFFiNGYvQUlyU0NYb040RXEvb04zc2k5NnlPcmpRb3k0SFZOM2JjSW5mU1RzaHQxSVltRGRRaEVkdk11d2tXRkJIa2hmNGpaVWs5NWF6R2ZBdm5QSk42QkxDbzJLakliZkkvZ2d1OFF1V1N0TWVCcTVvblVPV2gxSVhaT2dvVXJod1FOaWx0eUdGYnVTN3VpNTNHdWo4aHZ5UFFhcUdyVWZVbHpjUDBMbHJFWVZuMUxpZm5JaUhIL2hTdGFDRWg2UDVmQTVJbENnb1VJMkgzblg5WWs0VjBvNk9XVDdhTE9CQ1RZajNRaEt0RDNMUFZuYXVCTHNPSitRWFVTOXhxRlZzaEU4MWIyeVN0Q2NGb2cxU3BSMGQ4VGxWa0tWN2hTTHkrNFZGS0lhbk5RK1NmakJNVGZFUFJjVlVMbXdTSzI3WkZZYTZ4K1JBOVBnMEtHdU90UTZoaXJiNkR0UVp5MEN5YWF1QTdTbnYvd0NBalBhNlUxZWlMVFIxamJiVHpjdlIyMElhRG5WN0U5TzNDOVZqYllxVVF0eUlvcTFaYk53WCtVSTYraHkvdERqSkxkRkFtVXMwRVQ5YUZ4a2xoUHFjbENpRFNnakxlMUlkbnprbXlkSmdiZytCaWIxVlJNN3RSN2ZSeFBRVzZxUVlGaUxESlBLcGNHMEJUbml6SjA2TWpTaHlpSjNJM2tjN2VHTTFTYUJLcXN2Ym9wYUF5RExLcy84QWRSUnE3VnQ5bnNKbVd1YnVySERka0kyTTZjaVVaaEtoSmJEb21Ua0NWdXdvUTZiQ1grZ2xHeUkyTzZHMEtzOHhOdENVSWlFelFXZ3NrZkVadExjdGtIdHFVZjRLM2JxM3lQNE5aVW9YSXlSNktJa08vd0JtWDI1RFRjNGZES0tpWXZXb251SkdvUk5sclBna2NrTWdYUWhDRlNlc0Z1alUzcVBvSnRVT3R5aEpLR00wd055cE05WEg3VC90c2FFcGJIdFZYZkp2VGR2Z29kMXN2N0U0WGNYRkhib2NmWWsxcnBsMUVSUnRGOEZLL0p5bDhvN29aSlJFZGd5Tm1ad0hRYWw3aVYzSmF3MDNmOGkyTGRqdlZ5VllTM1pMVU42ZzZmbjl1WEYrcURsd3BzMmJFcmZLcklrYy93QlJZRW5POXdrT3R5SXZCSnQzZmtrUzkrd1VpcDIyRllueTltOTBWV09nd3lYL0FDVFdJV3lUS0pIWVhDcGEwVDh2cFZ3Q2VRMFVMVTdwRW5LaS93RDJhWm9WWG9Rb0dsY2J0bytXU2trRWxGZ213cE0yU1ZWcUtCazJMRmwvMEliTlZIaUhBUXJLemFDRGdPTCt3Z2wzZEtKWHRDOERINkY2RGRLTnVvWWdqMWdxSENzL0tHMjJDU204Q1NlSUozeVAxeFRnWWNpOVJmMVJJZHI0Tk1rNGNJVGtlUWV6Rjg1QkEvWnQvZ1c2TjFVVTBQQlZMVkNJOVJSMkZoWHBkZzFJM0hLTU0xeUxWNEVXQkNTNlhjc0RuUWlqRlcxaFI1alowVE1VVkF6ZTVFaHE5RXlvbUNKZXBQcS82NlV1Z2lpYUw2dDZQa2MwaVFJUlpORVY2eU4ySXJYZjgvZ1FJNnMxVEhTeWxzZEdLVXZRTmFZUWliNWRiTW9GNzRZelEwMm1zcTVRMWZrcUp6SWE0elVtL2xGVTg0TlFzaFFhVkVzS042R1VvR203SE9DbTNGRDBRUnFJRldSZUhGMzhHdWtVNUtWQ0htWHN4WUFxU0oxaXo0Wlp4NUpaeHFFeElROUxkT1M3bFd1aVd4bUlvS1hIeFFzd0xFcEw1TnBYNmtKd1M2NThpS3RUckYyZllrWXdqRHB3RjdJdjREYXhGZVZ4SzhMR1hPSjNCRDJhaWM5Zit0VkRWVEZ2N1pFRVZPa3dGSk5CQ1dlQjhpMnFMWHF4SW9MWGlKU0Q5b2xOYzRKbGZISDlFbmprNEZSQzhpQWFWNUtpM3FKYkZZWlhzUUtFWEtUN1QwOGxMR3FvTVdxclk2TVp5MjNHSlpnWmE1bnlVNVphOHNZbTBrV2s4L0p5ZFJPNXJIQkJQSS9ZWHlDQnBvT3pydnlRRUxoQ2dSU3MwOWlKb0ttclpGd2drS1QvQU0wRVUwTkxJVW9rN3N2aDBKcUVhNGxCa2Vrb0Y0eTdDb09mY3Q5RFg5bVdDckhsYkVLT3hqUnh1NjVyelZNOVArb3pLcHJXM0wyRTVNZm8zdWJLMm92a3owTXZvZXBKTFJGQk1ZdjM4alVxMDBJcDF2YmdiOXBGdkphUlJEb0dENDUzSWFvMUJCVUNsbHFwa0lwK2dVUXcwcWlSekJ5b3ljRmxJY0xoTG9xZFF0MURYeEtwTnZjNUlldFBhUXF4RlpqMWFmUjY1K3g2Z05EUW9rbmNlcW91a0VUN0pFTm9vVk93bVFpeFFXbU9tMGpLcTJLYTQzcXllMk54clN6YkpGTEpSQllnVlk1a21xdXdsTC9YWCtnM2x2bVNpOXd6STY5R2FaSWJNMUtuSzZUR05JL1VlNWlLMC82U3VqUWRZenNSL1VyL0FHTGdjelh1UFFoTlVVQ1FxOVhtOVF2V0d3aENCVUlTSmxDKzZQREpwVXRLMm1HUDVSa3A3N2t3Mm9mWkJLdHFQQW5wUGdaM0xmNE9nc0hOV01KR0NKcHIwaHZOK1ovQnJTcU9TWXlRYXluUFI5TkgzK0J2S0ZZUW5xVFB1LzBTRFNqNFptR1RMNUNxbzFGUndKaTYzaTVTWXF2cU1ibHVXUG8xOVFjaTJVNyt3cVB5Si9yc05rL0phS3ZxeEljcExwc3R0M3NOVkYwZXVzZHczaXR6c3RpREQ2SGg5MUxydG9UT25IUC9BRUZneTJSQXBGbWxzRmRLVk5tb2trUkhCN2k1b3NUUVM2UGRJVUgvQUFEWlhwQmZtN01ld2tIWkNjVWUxaFhncm5BaDh1U1Q3TU5xYWVIUkNvTWlRbTZSckpNNWRmb1NrTTFEVWdTbGR2ZjBwQlF3bk5pTnJOMzZsYktOSjY4djVMZGhtdVJxdkpPbW9JV0czcUltR1QwYUVvU0ZrdEJKcVg3Zlo2aHRmNjlpbzIwN3NvVlErbHNqb3Bna05nZUFXMjQ3U2hVdG9ER0RFSkxJNjBmTEx4WXBLdStqSndrVGJKS05Wa1hoV0UwZjg2RjFLaWVHRjNKSEw5TURzcWVSNkRWNWFWOUtCUm1iV3ovQk5NVkdLWVowL3dDQVpudUN0L3NoekdWVVNJQ2dmbVIxUHNYMUpuU1Bmb2pJK1doYVNmS0ZOM1FscitReDJKU0xuRlU4RlZqbXZrMlZlcVFKa3hIdVA1VCt1aUxNUW5DcjlGQzdqbEdqZnBJM3dTVDJQa1JTeUphbFFTaUV6MFNkaEZWaUlTU1RURFg4ZllSd3B1VCt2WWJsdG01ZDI2eUwxTnk4SFBWM3l5RkJVdlgzR2hlNU1pWDZKYUxwaG1kZnErS0c0U3hzenQwUG9mU3VaRk5SYURpRTc4Zml2L010cUNhcHE4SWFkT1hxRE55cUUwazEzSHhoS0lrT1dOMkRLQm9wUEsvb2FwYW0zSmk2cVZGMVVTbHIvTTFuOGVDYndRWnR0ME5wN2xoTCswT0ZJQnkzSXAyb3hsQ1FoeVFqY2wwdDZHU1VwMGdpcFRxUzRvY1BjZndiUUtGQzg5THVWVzh1aEppWjEvVjdRUmRteUNwZlBRbjJVQ1locXc0ZkRLYVpLemFNa3lQUVJKY1FzQ0JhWlRVOFgyRlRlV2YxN0RkMjNYTFpyaHFNdlNLSGNlNlEyMlFhaGoyRzJXMXNLMlV4N3VYWFpnZGE4R3pxK2xKZ3UzQ1FTRzJ4WkV0SGNTNk5RNUZOUjBxVHFKZVRiNnJYL2tZaEV0MkYyRTVUYjVmd04rQ29VSjdQN0NxdVNjNlBLSkpsVitwU01zb0xJK2NRclVzcEpiUjZDY1hzV2h6RWxIOVlQUmpvb2JvaGpEUm9jdnVma0pVSm41YjlrREhBcVQwc0dQQ0pUVFhveE4zNER3UlVkOGlZdENVYVZPU3YwYXhOTGhEeXlrazJ6NUtMMEZOeEJkc2VnaHQ2dmdtN1ZvTFRHa2R4bFJzSmVndFdSVXFlYXhNaE5FSmxNTEpxZUw3Q2pMOUU0N0UyNWFYZVhrZWhlWFRxVllqUHZLMk5ydlFpSEZTemFiUDFzT3I2TWlYRVlEdTl2bVRqRXBxeUNCMWNGZXltZm91eEt5aVd5WkRUbEMxZWJKbGZxK2YrUjY3VlpQVFZrcFFraFVKb2kxbnpHdWlIZVMyUzEwWGxoanFxdWVCVTJ5Z1NwT1dXUTFNMytoNW5aTkovcUVRR1U3ajBIVk9vNUVFb2szSHRuRmg2aHQ0UnovSmRLR3RyVHloVDdkZFpjQ3BJMWlTSTFmaVpMdUdoRGwwRmljckdGVmtzWGFTa25RNG1kanU2NEQwZTBZR2Y2cFplck5FR0wwSmR4N2lFYWtXOE1iam9FUjQvVWN6UGNuU2FpdGJLZ3A3VEZ6OXZzN0M3M25qc09yYmRYbVMyVkZ5Sko2V0xsWjBsNmlPMWxMS0pOV3pGR0lJUjhMM3lPcHdKUzdNV1hMd0xmaCt2MlZ4cnQ4c2xzY1F1aUtWUzdHTGF1NG1DMzRDQ2hjaWR2WTVIS1U3MS93QVJ0NU5CU0txL25kajNJeHRQcWhKdXF3U0NpbzV3emFNYldaVWFpNm9VbXBNUFVSQWltczlmN0hiVEprbm90VkJLWUtpR3FaRFFrZmNCN25LcVJiSmE3OERFZjkvc3Q4RlRvUG9YcEd1bGlEVkdDUktkb1RVVS93QVI3Uzd1cklEZEVFWWJWT0VWbDFHOG5JWmNWZnEwUTdhbm9iWTJ2ay9meUlMeGFncm5YNEd5Umlxd081QzdKYUtpNFA4QWd1aTZEM3M2NGNWZVhzVjJvZE10VDhvV05hRlZzUW5oeU95b2w2TC9BTXA4c2pHRGxRRHQ4a3pIcFd2ZDFIUkx1NGtJUlpTVk1mb0hHWGtuU0tIMWlVM2Uvd0RqN2Y4QUZpeEtrNmF2d2JFS3lXaXdoTEdzV2FzY1ZJNWIxWXQwclFNYlVZUTY1cjdSUURid2ZPZmd1RTV2aENEWG9tdS9jZGZLSlJTWFVXZ3FFQkpUVHRLZVJDQ3FuTktsZWh5TWl2VlpXR3BOMFRQRFlhNWhGMDhER0NlcDJIczAxRFdCb2dtQ2x2WnNWMVZNTzVjK1ViR295QTFaR1RXbENqZW85RjdDRlRWOVNCcWxQU2F5TlE5eVFVVExzMTBSSXNXSUJST1kyckJhTCtDaDdoUVM3bEk1RVVJSlZwVVhheUk1cmJ5M2tSVmNpY3ZwK1VJNFZWS2FEeWJ6dVRGTzBlUXN1M2tjTnFVUHZjTGxzMnk3RmxWaUpDS0pYc3Uvc0xKTXpaRWlCcFFFMUhDcGJSRklLcWFDd2hLV1ZLT29KQ2UzTWhsN2MvOEFnU2JKSzdGVHZRN0svcjdFMWlTWUdRSTFDVWtrSmpXV1NRWjBhY0NhRld3VElaRGFVOUJLcEpXS0xYR21RaUd2Z25OTW5VRWx5cUJqbXl2cUlUSUxLU1pXU0ZTOURWYkNwTTNWdnA3RjNra1JaZFNpNkZ6bHRNY2tDR1dpbG44aExLUXZTVWFOT1ExMFJrWEQvcXJISXhRZG5WRC9BQW9LaVB5TkQxQTJVY1gzUW5XUjEyYUIxRFZKaHYwaXNGUmZZQW55MUZKdFNWa29sMkZKaGxrc2xaYmZLTGwvUk9vb2tza3FJUVdpcG92bzNlQk5GaFdyZjRic2ZqdzlsaDgzWTVxVjVMZytrN0JjeHF3SHF5NWJLQ3NoSVJFM0hzb0MwdHRZWHo0SklhQzFJRWxLRTZnekpRM1grUS8rQmtMRHB6Z2dyVEhDTENLeVZDMlMrU0N1UmFtbGpXYjBtTVJRYXFoSFpLS3k5ekVkWjZvYkZsMkpxaENyVFJ1TjhnM2ZnWHNJVkxFcFE2aDZGV0tpSHg4dVBLZ2dPRy9WVWJKcDBsSlR1aE8xTlh0UysvRDE1SjVzVlF3Tk1XTDVKYVRLeFB3UDh0N2pTVG1tcXluVkNsZW9YZFpKOHM4cHJnb3JUNUYxa2dKTk5qUTUwY0VYaTd2c3ZWbkZaSDR1aGM1SG1QOEFRU2JRNEoyczFJMjlpaXBNY3FsUXA1VFFJYU4wcGpoZ3VpcE1tczNmZ3NqVXBXNmE4akpESlJWYmRrYWt1cGl4eTloT1ZmcTNlNXZZWlJuSmRac1pLT1llUy9RN3ZvL2N6Y1FKelU1YU8vOEFBakVyc2lRaVlRcjJpUXRjN3R1NHd2eVgwTDBSS2d4TWdxRU1NdDhGd0dEbitjNHlyRk9YYjBrbFRSVXdLZnRUakF5RWdCYk5DRHNHaEp6R1QrOFF5YW0zY0c1RklSbjhFU0tPRlVmUmdWYWlWYkpaVHNXSldCUDlROWNGUER5VTZkS0hES0ErNFVlMFB1V0c2bXhLVFdOR095TU9EZnZ5TGRUWlpWL0luSzdHU01adkQraGRUNTZxL3dCa2owRTJyKzVIYlYyWlRuWnRWSGF1N0RFUGJTNTZTamc3RlUzOUgwV3Y4a29ia0ZTdUxTSlcrekZ5ajUwSVJ3YVpZYWdvNThNRFpwZFNDU1JjN2NtSVpvcmc4TFBjM1lZTGlnMjhHZXhHVk5GQ2FJa2xiVFo3NjhFMGxVdWV4WkpraElnUldwVlJhMVk3amM3cnRvbmNYbzk2bjRFdTQwWk5rTnVhTHBZT2loZlovUTdmSTlVaDFaWUxvN3E1R05SVFpLNUZrVTdLL2VuOHR6MlI0b2xTWE52UVRvVkNvM0hCRWttV3ZJbVdVU3pTNm9EcjRKUW9FTk52Z2JDdkxnSnQ1VGhyS0V6WTBUY2J3aTJpbFQ1ejBpbkZoS1RVUzQwN0VHdExmN2ZZdURoRWdsV2NhclZEeUp5VTRmWWJ1d0NsdHl4RjBNWlUwUHNZYnFjQjFhaHEvcjJCSFI3MzlrekRhNEx4Vkhsek8wTVUwNFhNRFc5M01SVXAzL1kvRUkvRjBQWEd5cUZOOGRLZ1p1OXEwaXVSTDkyNDhxL29TYndrMjNvVlllNnIzZVBjVFRJbHJMN0tkVVpNTTdxMlI3Q3JBaWRtSzczOERuc3lkNm01WVJGVHFVSXp4NGNza2VhM1NjKzZjV0paNnNPNlorSnArZlFOY0dnRWJKV3JZVUZFMlNzbUVpUkN3a0VFUzM2RVVoUEUreDlqYXNtNXQ2allzOFNqcXg1NDBMbVUvd0FudjUvbERyVm9OZWxNY1lHcWJzSzRubkZrYWxvRVlySVdsT1ZrZFVLZXhxbmlOaG5RR1VOYWxEYllnNWZFbXdpYWxQSTNVa0RtcGxDMEY3UGtwaFROeUJoWGlWYkh3OEVEcWFrNTBUc3h6a1hTeHd2SHNNU2U5TERHeVcvVVA4WTJsQjQ5VkU1SHZORVdLUit1L3NsaU1wZmtFZ3Z2Q1RWVnlWTmlnMk1TM1VndXptNmNMQ1B6OUQxVEVVR2NMN0ZMUlJEb3FqRTBxODl3c2xDSHYvcGRoM1lXRWhncFZnaGdncFRHMlFtQTlRMFhjWlVWcWdKYXBvSXFsV3AvbkJHQ0t1VVc3WTA2UGI1dlFRYTBwUnhJVWI1ZUI1U21EMW5Iczk1Rk1pK0JLYXNTTFZlQk5VSm1vVXNRMVdjck9UL2FDWFZ3Y0FtU21ZWTdpRjdGRDZpRERYcmx2VTBxVDRPMzhkcFBVNmZaTlNMYVhUTkFUbHFsQitxUWF3MklhM3NhL3dDa3kvQ0tKMktCUFRaV1JueU5FMEphMWIwZEVHWDlvUlFVWEZSbEJuVlBjMnAwSVNOV3RGNlc0cFZnR0g5dVJqZkg2UjZLc09xMVFtb1ZIY2hpaGxTMnE1UWxTYjF5WFV5ZDMwS0ovVWYyTWtuUGMwVVJtTWxZUW9NZ296L2dYOXVEQmxIMUtneW1KTW1IRGE4bWpVZlhPY240Z0Q4d1NGY2pJY1M5U09YSm1OQVg2QlMxRkpBdGVwOWRQYTNrWThxdGlrU3ZxYWltZkhTVUp5N3ZzSjFHc0h3dWlSYjRLejM0aGU1WGJOMjJUendJZ2tRaXd4d0g4Yy9tdlRYajRRWng2eklCdGtXQ0dtWkhTQXZrUVZCS3Bpa3VrUEpmNy9CS1hBcmZQMFZQc2VUVGRWTU9GMFFsS256STlMbVFac2ozUFVLdzJJaVdqZ3ZCUWhDY2o1Y0dPZkVseG5lQ1hNeU54UTFLSHFKVTNSYURCNVFOeHpUMDdsQzV5dWhzeHNXRUdLcUVWU3BxaUo2OTNYUWxXcFVOeTB5aGhiWDRDWmt5b3RkOUJXSFJqQ0tyY0V1ejdJYUhRbVdVYjhKeTJQWmV4SitpaEJwMisvUmFMU2lyVHVsOTlEZCt6NWVSdFh3UzVJTkp4RXFHeCtWSGNoTlZmN0x0OUZBV0RFQzVMQlhDUGNrbm9zU2lxN0t1eFU2L1FXK1MzM0JhZEtKZnZIdU9TRTVMajh3Mjh0aVhrTE5ERm9OR3FMNEpjaXRjWlF6SHlJVGRENEpLQlplZzZvVnF1czFjZm4vRGdWVFk4WDM3bGZhSTNJeU01dEIwcTZHRjZDbGQ3MExDK0ZGMlBjWlBSSkpJclIzWXNBVGNrckVrV1dnMWcvZlJ3SUxjaW5uMEQwRXh1VUxIamFHcmFvYzh3eVU5QmFrVUpqM1hUR05LRnBLN2lHVGtheHNyTkZVNmFYTnZnaHVsMnhDSENrdm54d1ZCZlRrU1p4dHoyWWpHSmx0U2Jod0tDU1d5dWxVSVVRaGNtYkQ5cU9wZjBJTEdYejZ2dVhjYWlHMjBHOTJWenFxdUVRalJDOHA4cjdDSCtBamN0M2ZVN0tVYlJCZFArYVJaaUJLZjZoSzBGeDBoa2xUZjh4RzBPNjZ4NjFhOVJNMjl5RDdCSXo2aXRIZHVqU2hscEx1TU9ndUI2NXBPemE1RWhXNUVJd2xvS0ozVmdsTFhiVDhDUmViTjkwQ1RhZkMwOUNhMjBtY2VTSlJjZk5Ha3hQcGNRYUthYjNIUnNyL2g0WldFenJaNkZ4alNoYS9BMFAxenBPNHZBaEZzaWFxcEp3cS9CdUVBdHFlWFhBWE9qM2hMZE9MN0ZTbjJnbnhOaVd4Rld5Y3Z6Y2JiY3VyNlllUzB2VmZleFZjV1JBdFpuUVRvWDVjbVJkRXlsaXIyRnhsa2xSdG1yR250cnVOL3lRbndFNFpoaFpUeWllalRRYk1EM0NHbzIxWFNpdy80UUtWQ0psTUpwOXlKbENUTmQ2OVk5dWZRYU9pVkVaL2FEeFFuZzFoWElxa0tZblVSb2xVOXFrVE5NckQxSnAyVlRoWGhhSVh5eFdhMnJQUW9GUmNPb1RydmJqU1ZaNldaa3RMalJvcTVGclRnaGhYNU1Rc3JwYjdGZXZCM0pqOHl4b0dUM1k1OW1UWW1LRFhSalNoQzB2b1JxS1Ric2NnUGRrbUdoZVgvQUVpRlhTN2lHcysxR1RNNE9tZytvU2VlbUJKOURma05ERjJnV3JjbS93Q080M0tYVmtGTGFFYkpFMXBYWVdNRU5RbVNDMlFqd0pSM0VKRUxKUlVpWGdDUmROeUpYOExOOHVVSjF2SjBLMFhjOVU4VlhWdVh6RkNiNHg3aXV2TXFsVlQrTUpzYlFoNHltMWtFcFczd0hXWmJGNVkzV1NWVnAwQWk2Z3hpZ1JYWW5WSHFDcXpqL1NJU3luVm8ra2k4NUpONmpZcEthS2w5QjdMblZwUFdLWmpyNFVsMnZMZ2YrMkwralpVUFhBWTZmNHFsUnZaSHhvTlVRZEtnUlFRKzRTay92cWxCRnJKMWtaZEdvbWlDMnNjUHYwUVFObG9zalZTcVhkRjM4RzdVVUphWjI0VlBzM1FOazhWZk5ZbWo4aVUyMHkwY3lLVE1Hd0Fpd0hMd05jYzNKRUlsR1c0bjBoL2RmSFlPbVhaR0t0NmpIVWFpU2VOQlJDam1pOWp1aHhGcmlTZUNhQmlHbC94VE4xb1k3ZVp0c1F5eEwvUWhNYTZhNE1iZzBTUjMxN2hxRFpGN2hTbFFicEdGVGtvTWxoVnFrWE8rbDZkWW40TDAvdm9vSnl6dHVYd2RYeDRnV1hEMCtYSlJuVnBRaHBkcXVwYUgzTE4yRU5sODRmdDJFWDc5eVd4cGROaGFyamthTEJneFA4RWlSb2tMRXB5aW95RE5wN3NVdURobCtTeHMzck1ZaWFLZzZ1Y2lzSkZrMVlTU0Y0c2xlMFNaYzBSK3JOWHRiN3hiME50R2hFWE5LM3RMRW0zdVJiYkgzLzYyU2lUbFoxaU9HVmRFd3lHMjVrNnZXUEpwSVQrc0lOWmNvT3BYZHdKTTE1aXpnUjBUeWIxWTAycWFlNDJ6cTVGUXN3MmJnWDQwSktNVXRVYWpvdXBDV0VKZ0xaNU8yUlZOQm9UNGNuc3plM1ptOUhKZXpMV0VFS0xSMUgvUlhzWlhkM3VJMDF0SjVGYzNYODdvcXRGRHkzU2FWMjRFL3BCaWlmcWFFV3lndWp5WkE3eVd4T3VJMkd4cWRoU2pkRDh0cGI3bHY4L3dCQmQxck5pWGNacHkrUU9OdHE3am1zZUJqTEczR29Ic1A5a2pmOVJwY3JtcXFGZVdKeXVMVmZ3VGJGb2k5STlHcFN5eGhvNkJoZkwyb29YbGpkZHNyL1E4WUZLY1hnaVlVT2gwS3NpaWMwbUtDRkxWV0ZIc0lGNWlrcmhpTHZ5SVc3d1c2ZGhvVitpVmpDUWgwYjFSQ0xUM0MvYXRrRi9Zc2J3eGNyb25GcFJsdWduN1RZMlY2Q2JXUk9JeWhxV1BoSkhXSWFmMmpzdlVnTnc5N200WTJrSVRRa0pZNGZrVVpua25JUjNMWGhtUzc3RDl1aXp5SGxTL1VrKzRUSlpWa21OWWViS1M4N1ppMjgrVFc4MG0reWY2Yy8wNG5LOGpaN0NCNklGMnVyMkRYMWszOVIvaVNFYnZRK0M1SjdpZEIyRFB2Zy9DS2p4eUhxWlU2MXhTVWNZTklOa2U5VUxrbnFSWFp3a05mZ0pQOWVweUVYc0gyTFpYVUVqa2psb3IyVXM5VGRrcUlTa2xGTnlPY1F0aExOU2pFOUNXVkxGYm9JN0UrQlhTZkVZcy93RGJKNndsQjBTUXlCV0JKTjBtVVlyN2s0cDdVSmJJNUd1ejdoZFJDRlBKWGMvMFgwTS9YOUJGUCsxSjNmWTRyQmgzMTdsVVNFRzlGUTEwRG1OV0NwS0NmUWJuQWtMNmNQWHM2ZXQ2Qk1UMEFnMWltWUZ2U1R1VlJ0QjdtN094Z29EdW05eC91RC9RSCt5UDlrZjZZLzFRbWswdHJNbjJCRUFUNkpiSUs5b2w0dVJWYzIzSHVTMDYrRzJmNjlCaExjd3RsTHN1aVJEMFpMVVQxZURjZUNXajhHYmpRc2crdFVFOUlPNGxxTWxzS0NUaWpFN2pxSllLV2lZa2dDcTNZcGY0cEd0S0QwdEJEWDFHd1NWWFluUVVxNGpVNFlrMEhLd05PV0NjU0pTbllHMjRWZDVaTG9sb1MzSmJpZHBzV1ZTYWtvMVY3RFFiUjNCUE5tSnlYUWtTSmt5UkhZMkpJdTVyRjJDbkNCa2pUcFVPL3dCeDlBL2lEc0lvZlFyaTRIOGFFSTJkaS9nY1ZHaW9JV1l4ZjhCaWdnaG13eFgrT0VyVDRwWktQZWhKVjJRa21xWXdRVGpXNFBvZGw5OTZEK0hlNlp2VGRpMUl1dmFmb2o4VUxhaVdoUU5BbFpoUm9RZzFpc1BvamxOVllYMEtpeUVSQ0VjYVpzRzNud1gwUDJtczBFTWFvYUVLSlhteU1xSVlSN1lhcFVaVDJSZXRHR2drK1p6Z2h5bFU2YmVtNTZmZUc1SjhqZUhzNEo5RE55L1FkTmZSalRrMmhKZm9oWlFWQ0djZlFsUDhBZjRFL3dBdWY0OC96NS9neHQrdU55OU1PSWxCNkNVcVYwV0VObjRlZXVjMDBacGw2czAvUXlqM0pmaGo5UHBsZE1lZjREbUFmQTdoeHl1dTM3SS9LRDgwajhFYnp3Ynp3SW9idEdZUjBJTEd1NG5lT1E5cUlGcGRHUkozRDBWOCtxRS92eFEybTZqcFl1aWN2QTl0dlJxQkRTVFVtN2EyaTlVT3ZVV3JCU1FqVDBmOElrWWdvMXlWR29QaDBKeHA2V1VjRWtWOTA5endqMlI1NVlqc2JzMnhLWWR3aEVrRFRwSjZPU0lmQk9UOURKWThERzNhWHFJWWJibXcyMmhjRGFwdHNrVjd1d1dxZDNVOXozVkovWis3N0RwSTVkaDVjQ1NuUkxVMGVqSEt2L0lGMUJaS1IxWS92OTdEVmxqd1JUS2xoMzZmdTU2ZXFHOEpOR01VamduSmxvNUxhUGhpYmFWUjZpYndoZW82SHY1L28xWDRTRGQ3ZlU5UlZWNWxGdVhZbitMR1MwM28rR1RhdG9zaStSYXFxR3l4MHJ6RUxZY3kyZ1hsQ3R5MmF2MEpPRlNleE14R3NucGNlUTV0R2hWRE5QWm1PY0FnMU1ucXdyaGpZbjNPZDVKVlJEaXFocnBlQlVjQ1hjNUVvMDMwa2dST3JZaUpVM3ArdFBRaVJBVmxTaDJudTJhSzRvTm5jWWVQUmhYdko0UjlaRkdqRHJXcDZtV0lzajdCdGN6NzlGU01mQTRwY2Vyd1BPT2lmSll4TGR5eVJQb1hRY3Bwb2hTVTZORDZ1cVVzYzdtaDZrMW1mVEFscjdxYXc3S0RIL2tPd2w0SUx1UGtkQjY0cUhwMG8vYmZwNm9mMWVpd0pCVTFLQTE4amt5bDJNOFJwWGtWeVhCaytlN29ORzJxR1RXb0xoL0U5RDArS0Q5VEIvVktScHE2am8wTU1XdUxrdGx1NklSOGtQMGx1dmd4aGRtR21ycGp5bTdsMExzSE56bzRpa0o2UUVsTmd5ZXFMUHJxMCtseGpLTkdoektUMktrdEM5S3Nocm9GSGhHU2lCcVROQ1l2RXVsaERaMWJiNUhrZHhDSlJOSkg0UjlDbExBck4zcVZuc1M2RnNhbG9YQm1LMFJmQVVTNFJnVGVpcGxibXlWSnNnZFN4OHZvcjFIR0ZRWEJpZ2YrUU1RWWF5dkFtdXlvTzAySkFNR2VxMHpnYXJvUGZZMndIa0VybjBVUDI2UHU4ZlRwY2gvQnNRdmxJc0ZicU5IZzBSSlhFV0ozM0Vtbm9qVjJETlFuY2xianh5cm9HYjliUGpabjVzUFVTVzRDQXdoem8xQXlPaFpmQmxIbzh5aEw3TUZjcDRpOEg0Q1laWkNFMlZDRzd5SnhDYWdHYTdxaXc1M1RDTU9DTlhBbWJXamdXRFBNUXRob2JyMFRjOHY3ckwzT0VLUkxVV2trbFMvTVRlM2NOVWVBdGhOTHNIbGJrTlNFcnVWSDBORlNUV2hIbzh4RjFYaUNyU0xpV09mS01jc1lOZEhNY1lobTJ1cndPUEFTUmVUVUEzOUF5OXhCVjYwbm8wV1JweTJQU0c0ZVJ2cUlSUmlvR3FQZ1RjbjA3Q2Zick13aVRZOTR0dzBKYXNkeGF2QmlmcXVSV1lRUU5VNkdqdWhyd1o2amwrb2xiS0k1UmRSM0U0ZEtjRWFoS0xGUzlTcTBtWUpFUGw5NkI5N1pYZ1VzWDUzSHk2a0QybWhGRWZsMEliUTdLc3Y0SFM0d01ReUlrTVlDcVQ5VEd1VG0wYWxpVmRFbnZhRWwzVWtuQXJXWlZxRHBXYzFoRWRodGlFN1ZmdWljNFZDVGJPK3drT1FRc29oR3hVTm1JM0JJanVRNW1oQ0s2R3lpTDVJc2JvQzhmWXFJZnJNaFMzbTZhRTEyaFF2UWJsTHE5eTVWSWE4endKd01CUWF6WnVFbWdndzFVU3FVeTBoSnlSaWlZM2lFaVVqZmRGNDM3bnJTallROXBUSlZDbHprbm94MmNlaS80SUVxUzFxRUpvSVlaanREVVR5aEpFc29KdGdvZG9aQkJBMllHTDFCdGhDTWhNQy9zaEFiRStzQUdYN0lKOWtQT0ZkdEVRSzFTSTlBd1FpaUtMN0plNWpST0t0czIzY2ljbkJJTU9oVjRSbEl5MHJXaENjUWE2bE1lR2J2K1EzTGI3bW9LRjNkZmtrZTBvVFV5SW1OQ3FOL1psV2FkR3VsQTZJa2JHS1JvV0R3bm5RY0w2NktCRkxBb3FOYXNHcTFSeXNIdGlHRTRUY0YyNmNtTytvZHhQazdha1pHMXRyODllc0NlQkc4YWhOSGRPeFFYWGtSSXpOVXkvcWN4NnBQaWYyWTBuQ0NKQ2ExcTloUXhEUmc0aE9jaW1VZllpcEExNSsybWc1ZDJHbjVldlZkSm1Za0V2eTZXbUsrQXZrY3VMc1RLdVgwTlphYnNmV1lsdDU2UU9VU29kVmRpNjBZOHIwZ01sTk5YTnFHS29Ra1FqdDZRRDFTaTVzZ1F4cUVwQnFHVlBEb3lTRTREeC9FSmpveE04RlBmR2FkT1NLVVJPUmt3bkRIUUVSTkMzSFF0VzJxUDNVekE0S000NURaN0drTVJRNkJFb1ZkMEk4TlBYM1VUdVFLemI5a1JXcVRIS3IrU0c1VEwyNTVNOU1JZGZBNmlSUmx4eWU0M3hNUXFHK0JsR1JJTnQzYlpHbGRrVU5XNWhIbDY4SWNWM0d5dU93M0pCSFJ0WEJZSlZlN0dOTWk0aks5OWhyWkNoVkNoeGx0RzdHTjZvYjZUbnRuUmNzVjhqZjZZcXVjaUcvUXlDYUpvaWVHUGwxZFZlU0R5aStGY3VoQmhOYVdNOWNWK3pFbEJsaDlFM1VpVW82Q25WMVllMXNldlRpbHhqWVJ0MWg5RFhSb2NpY3BCTW5CdzA1UWpUc2dxWkZvRTIxR3hqZkdNWWs0OGdYeGNpekp3UVRWZE83R2lzcEhpS3NVN2lGdjBhZkJVKzdIYzRTclIranE4S1FIQXlQWm9XZEZVMURNNTJHTkNReGNFb3pIR29oMkFjeHVrcVhZU2dvRGNEWmhNNmhxTk1TNjZJTUpDUlRoTWtTMlZSN3pVOTFpOVdYSTJHdjFNdmtwQ3lvU2JoVmJIU1V1cjdoNmNpa2hOMVJhYnNlWG1ibHRpWm9TVzdKWkYxamhiM0R4N2tFQ0xXZStwZG5ZakZyUWtYclVRMGQxNmxDY01lRnV3VTV0S3dUTzY3SW1HOHNwMTFveUN0SGdUMHFOTUVpeVJNSkdnWXU4UDJkRll0QlB2SG83dGpzUmFIV3g3RDNGNWt5SWFHdWxhUTZDM2FTVndnOXJPY3JCQlAwSHB0RnlJVEU1R09iYTZIUjFMakhjU0pDVmlvLzd4MUt6czFrNDNhZXFvVGNPa1paUVBRWFZEcVVrclZCVTR2Y1R3MlYrZWpvQlNRSk50SXBhaVN5T3BPMVZaMGRoNm91c1EzeUtqVzRnUzUxV0NmamNzYW5mWTV2Z3FGMDZ4UDhBZDhJaHpVRnFFN0RTYk9SVk9lbzd1V0VRNlNUTElrU0hkc2dnYjN1RmtWTU4zbCtGMktVQ1FsaGN6TGZDSnRJa29Dc01TRTRaZjVLQ2x5U3J2a1NsQ2drV1NSeUR4WDdpbWcyaTNkSGhnbG1URG9USlR2QWpsUWxGcU1DZEh3ZUNRaTlYN3RmS0hKVFZSUDBJZW9lN2VuYXoyR0p3MVZGakJ1aTU1UDNCNkRXYTNKZXdoaTRYVVpQQ21RVm14R0h4QkVmK0VkUnRSZUg3ei9IR1NiaEtWeU5VWFZLYUN4M3dJbXpaZFlPL1JhdlIyYWh1RTJ5WHA5anNoSmZOdmFMaGRPNVJ1RnZjSjFzMTExOE5SVEdIWGw1bjhJYkkwbkZXUFRlYkZpM0hZSGtsTjR4dVA1VGVaUkxsNEZNMFYvUkxQY3JJMUdOdHExWTBUNzBvdFQzTzRzMElvTEpDUmp6SFNzVDJaNnczdVpLazFja0NJRU1xN0ZFaDdEQ29RMVJyZE9xWXF1Q2VwK3cwM2FhYWF1bWlScmNYUW1PcWJDNDBpelYwYWZvVlZ3eHlodlBLYSs2WWduWTZLZXozRGl0ZjhTNGU3WXFXQ1cwcWpRbktvdWovQUxGWFljdDBYUTlMWjdEVkRvd2hJa2lia2pGQjNHYWdKZnlQVGtqbXNHaU0wNEVMcVNVV1J4NnQwcnk2SWthS3JzT2MxRlphRm9UdU5zbFNoUTM5d3pIZndncjM4REcrTXNLbGtZTzB1Zm9mV20xWTBTalE5V05NdDVKdDdQaENsT3BUekNTUTVTVjd2QWpBYlVrTktpU29Rc2FjeWdYQUpUZnFERmhpS1VjTVNya2tZRS9vcUlsVmszZ0lpRXA3a1oxYlVhR2NsYUVaSktMYW9iVzIraXVXUzNvWTNxWkN2cjBMWUUxellkdEdPTGJXSExScVJYWHVXSFpyZDQvT0NRc0JPOHJwUFNwYWlhb25aVGMyZ2VIZWNFOEhZSVRLMWl6NEt5aE9hQ0VtbW9wRGRvYjZEN0doRXl5WHpTaC9GNmhNcjBvV1pEbDFWOEVsU1M3RzYyWFFqaHpmcHh3a0prSWx1a0RwVDZKeTRSdHcya056cU9NVEloSkhvZW45aGJRMldTeWFFdkIwY3Y0UkZhbWo4RjZGS3hxM3NKTHEwMjhEWHZUeTkzMGJDdEJYZ2F0UFh1WlRYOXhqWTJ6TGRSUVd4dExTYkNTNDFJKzE3Q2FpYTUwUjZNaEsxc1hSaUhJSFdidXpnSTlIa2pvUmllTk9kblljbXQrRWVHSm1sRXFoMGZvUHM2WFh5UnBKYldKT1BSbzk5UksyYXJVVjZpb3ZvM0VVYjV1M3Ruc1FKUzlYZWdaSTVtbm91d2JvVHpqYjZkeG5LVVFOK0xFeFJjSm1BVHFyK3dWT2hUT2g2bWxtOXI5UFNyOUJjamMveWtRWnRFcHlQVm9rU1dYTUF5WjVFcGNGRzZlTE5xMUdTUzdJdUEraUVUcVZQQThpSy9NSHh3aTRWaEhUOTQ4ayt6UkN3a3RFc0NvblJ1djBNZmtlUm5ZU3ZRU0ZTcTdBNDFKOTl6QklucElsVnI3OVU3RjZ0aTBjalFxaDJYMlQ1UThOUDlSbGVML0hzeUJsWmo2RmR2UWE0WWloS29TUEY4V0kwU1FvOGFEVldoNk1hYXVNcVpsQnVMT1ZtT3JhalVNVXAwYUxnTHE1MTVmUEZ4MGt1UDFhKzQ1cTdRcFpoOUdLZ3JnNkZnK3hxTkpWSUpRRXlaSk1rczlSWWYyQkt3WmR6SlVhdi9BTW1VR0xaK3dHU2FIbFpNaGpvaFNkeENXZXE3dGh6MjhJbmFBOWVrQ0ljUEdUSEU5V3JoZEZmQmxGbHFqcys2NXExWkkvblRVeGpWSWdOdTBLTHVuWTQxNUtvd3Rrc3Y0SkVaVGpiTzIrZXd5TXhMYnlKVnFXYmxaV1JOdlU3K3lUd1FocCsyeFhrL3c3TWdZaGtiaEpIMExjbFlmWjEwTkRhdndEM1ZoaU9pWjBxUWpha1Mxa3NSRzBzVnVocW16VFFxYmoxWHd6emZrWitJdzFpTTFUOHUycEEra0FoWEl3SnFqTnk2bDFSY0lueWkzUXZIUTFMS3JGdGF6am45N2oyNVpMSS9SVkdsOWwvTk9HU3dJSmJkQ29taEdwN0l1VHBkaERIVlJ0anBKUDNOV3BHcGRZb1hTQkkwWUdxN3VCdVgvR0QwUWowYVlyTFlHMVJXOGlDdGVJUFVCSnBCNEpsaTdnMjh2elBpdytrRURIZ21wQkc3RjVXdjRWUEloWmVyL1dPcjBMUkpyY1diYmNmbFNJWk5pQ0xiRUpWSE14QW05alZQSDBFUUliS2xLWDR1TFBBOG81RFNaR1FRTFRDSFJxa0ZNZHUwZjYzSWdHME83ZTQ5OVdZVDBsem1xazVRNXV1ejhsK25rUjZIZnlOVGFzbGZuN1J1RUZvMXRxUjBvUU5FWmFIZHRIcDNLRzA2TmU0aGxuY1F4T2dwa2dxZFg3L2FET3pKZjhNbmdWU0h3T2NuZ1Zid1NJSWxIVGh1bXlHMGt1aVJXVGxURUU1RkFPc1U3c2ZZNGpVekovczBzSmNBMFZhU3Uwa0QxTU51aVNHa0Fxbkt2c3NWVlhFSllUUmFENlFjSWFWaG12TmJ2WXZVWjFYVzYyV1hrUkR1b2p5OW56MkdPYmN0MzNGcWZ0YytrVkhPY215S2ZGSVNlM0pPMkZvdXlFak1oR3hqVEl6WjZ0eWoyZ2lHNEUwSUlwR2FDcVR3a0JaMU5WYm9rSWNyUkQzM3RnV1NOSjRxanRjb3VYbFlOVkZ5VE5ldzNBdXFTTGU2WUg1eTY2Ry9xN2VCajJOVjNFUGFtQnh1TklTYUI2RW9XbnVXcFZZU25xSHhNa3BJSnFheVpDdEZvc0kzWU9CbGY4TURrcG42QnpJNTZhM3lYU0NnbEFwdDdudnNNWTEyTTBpS0VDSi9hRjZYWnIySFRoR05OcmhaRFhVQTIzTFpHbDZEN0oxTm42Z2hCM1NxRWxxRTZ0amZUdHFOVVA2dlhnMUM4U28rV01pcENDcnV5RHV5NVB0WDN1eU10RGY5dS9SNk42RFhxY09zRWx5UDB0WlB1aVVtZXhSb3ZDUzlsdVREZzQwKytneExDZVNWRkQ4QWY5T2ovUFIvaHhWWUo5VzNRbmREOFJkTHBwbzZvYStFWHdJcU9vSWF2UVZ4N2liVThPdjJjajdmZTlPQjlaZXF4Y1NpZG5Nd2J0dXFFTmFVT2NweFJhaHZoTm1lbWZGNC94dU9ybEEwOERVMUVUSW55VHN4TTlhSm43RFZsa0ZpOHMyNkphbVRHdCsvVUhRNGxQK014eTZISmxBcUN6Y01TQkc5UTJJaGZhUFVpYmxKdFpFN2pxcjBUZDRLeCtPL0xjakhpUVJyYVNDZUh0clBQU09hb1BYTTRuaFBtd3BwTmZhZXIzNlVLU3dhdHo4aW85OHRWOEs3RlFSR0duYjdGRUlzMWx3aHdybHBVTEpzRFEwVXlHTDBmbGF5eVFGaDBxbUlFR3luUkV5TmVCQkpVTlQ4SDVmMmZoL2NmNFBzL0UreTRtbWdaQWt5N0RtVzl5Mk5sWHd3TFZETnhFMlRhb2l3dWVQMEdvMUUwVnh5U3c0UzluOU5qUVBTcm92MFhwc3hiNUtDcVgzMFovV0tYWHl1c2lnMmpLR1VvVVE4Mm9oemxzTGJRS2FxaEJpSFUxY0NodEVJNGFGbHQ0VnhlclQ3ZzdhV3l4cUVMMkEvNDA0Y2szc0hVeUlXWTZvU2ZnVGcvekZDbHNaRTI5RWoyWGh1eVBqdWxqbDZ2a2s5RmR1eUZaUFJ1RU5tbHVXN3RpRk5obTRTV1NGOGJmTlh5ZXc5UTdPcjBFUmtlaWtWY2o5Q3gzUHpTL2hEK3didGxrNWRPUmFwV05zcTZQWWlTNDI2SHFoWTFYdXhvVDlVSDFQNEdvYW1NekhrS3BvUFYwcVdHNWJlcGFhSVNKZ1hQcEhlQ0UxS0RZVXRCdE5hRFhZdDJUZmp5dVJwcndZY3JHVXBLb2F6Y1R3cDRNNGI1cmkvSTB1S2cwOGZ3VGdtWWVJYXV0aldSN3F0VjN6TFppdGpYVkJvZi9BRjVhbDNxNS9Jc2UxZ2svS3gveXh2cEV0b1VhSUMxWG1HeUhXNVdoRFFhMHdrcVgybGwzTHpaV1NzdWtEQ2xTUkwwSjFiR0I3a29hbytBOVJKQXJtd25QQ1Yzczl5UjAvdWMzRGxzYWpMcmthQnl4M0dNU0k2SndqMGNraWlJZmJvdlEzNGN4NlAxUkQ2TVArYkllckd5UnJ1a3VkRUkyS3VRaEFsSWhYVlM4S3dUdVhGTzNTaThSL1kwMURiYW9WWk9xMHJJNnFmQ1JWTllYSzN1WjFLMUNkVThpUjBrbm9iR2xEeEE4V3JvZCtndVhaWC81NVZhanFWYnVRbUh3Yll1K2pjSzNId1MraVJDdmFzWDRjaVVOSEtVd3U3YnU5MklKbDdORTc1SUFkRy8wSk5DWGd1VUx1TWJhRnFHbTB0SkJIU0d3MHFUQnhkK2hJUERFaGtYby9YMWxyOVVSUFM0YjkyUmVFSTZmZStpcHJVclR5VkNFcERNMDRFVFV5UkJyYkpMS01pMFR1SzVROUF4WFYzUkYwQzk2U1YyaE5kZHhoaXF2SEZNTjlFdy9RZjhBRlVOR3htRjY5MFMwYWRLY2UvOEF6dERGSkhTdFg2TEY4N3A2b21iMUJqdHpkM2NRaUJwVzJFKzEyTW1qSEhZSFZFVnJFNFJFbHdjdEVVMUxhQ0VkSFFlZ1FKRU81WndRVnQxRjhrRzZtSmd2UXY2TXlLV3NmUzZ0RUg1MnJxUjBPdFJkd1FDMVFrdGFldE9tZ2p4cU14Z2dkVklxbndLb1hvaXI5WVEvc1RUZWR3MWVqRXk2U1dtR09LUE5SUks5R3RCaHB4cmxJejFTYmRDdnFydElKUXRmY0UxRTZqQTYvd0RRa0hLWkdWSlN1K1NhUTJUcWhhWVo0UW1YbWlwK0ExaWJUZUJXUTBhdXNVRHRxdlFkKzZhSVFnUTJsZWc5QW5DNmltVnRHcE9PdFpHU3k1NUhlRzBFRmVnK2tZWm01UXpkNUlqY2o5VFdQVlVUR0NZcjVSUXVsSnRyRk9KeVJ0dWV2c09pL1VocFkyaHB3M29zc2p1VFZDRlIvd0NDUlJyTTdpS05RVmU3STNNMFQzRkZFelNtckFsTEJ0QVBVdlBSWHNXUlNVNXBxbmtrRFVEcUpOQ1ZhdXh2SXFkd1NzQmFrYmttTGJGdkEvM1FkSkx6a0ptNHlTNXIyeTFaT0x6K1pmdUJrcFZZNlQvcFJjaWNKR01rdWhkZzFDVktUVlh2YnZnWXptWGJjdm9qSFpGYmdndWphRG5ZVEkxc2JZbG9LM1JyOXgzZ3FPa2xXV1pEdE5JMVg5RFFzdnEvbDhFWEowcFhJYjhhOFVxTkRnWkUzbEZkaTFHc3p1K3I0MEc1U29uNmNoeW1na244bjBQVXE2SDhDZm5BVmthcE1vLzdibFMvaFJRUWY5V1M0ZUdiYVcwbXdyQkRxYU1ab053SURWZXFJSlJ3VmJJdU5HcWtsV3doRXBqV1hhMUpsL1NocVE2cEs4SGI5djBNc3NmOVY0cWlSVU5EQXBJQk1pSUV0V0lSMGFCdXRRYzBMNmhiTUs2R3Z3QlZETzJSQWltcEs1RlZlNDRYN0hJbm93MHN0OUVoZ2ZieG0vejVGWEFyQ212OVRGQXZ2U0liYXY0UkVTVndlSDlNbTlUU09HdEJmdzVDWHVXUWlpc3JPRWo2QXJHSVppZEJ5S2RwSFpGdUxMelg1S0FGZjZLaUVUYVQya0laTzhlQmhSa1NPK2hCTFNQdzZKMWVxSHRQc1ZWbzl4RjJvaGxpaUx2QXdrL0NTeU5oZVlsay9lUmpiWWx0NUdUMFgvVnQwTVVzS2I0WlJNdEJodFRKYTlHUjBDSDFpK3BqdFJ1NFdxVFc0WUdHWmJsbWhGUkF0QjVIaGZ0QmdwM2J5ZVN3SUZZY1dVeXd5SXRQaTFYa1R3Sk1BVUJUa1hNREt2by9ZdWlFRFdsZlFkWElHTDd5MU1TSysxeWlqZm1RakdYV3VmVDNGYnQyU2ZUbFgwcXFXUnBVWUdrYWxOYlBRYWZpaEMrUDdCNW96RTFHbzhSeHpZSklkYzFyTjMrRVN6R3R0bFBRcTVUZ3NrU2JrYTV1TUVDUmR5SlhhNG1jSktXeFlvbm9LNWQ1Z243eU93dFMydTJOL3dEWTFReGVuUkRmQ0U3b0ZmQWYzcmhENndtTCs0anczZ0VVT1BoSWUyU3JVbmtRU2FDWnd0VGxFelYzZHh1Qk1yT0NlRXJXbFd3aVRRaU1vY2M2bXdzeWZoR05QWDdpSG9oc3J3SkRidTZpT1ZKcmdoQnFWTldWUWdxa0ZFcjFKNk9jVjVJTmFSQkVJaUNTdVRvcXVCcHJxSm1kb1ViaWE1WVg3eEdPN2J1eVd4WlkySWV1aG9EUzNFWHE3c1pVT0I2R21TUkwxZWJMZDZETlVrWTl2OWVSaGVZbHR1cll6VC83S2NkSzlyRE5wVGhvVXdlK1NyL1dSTTl4dEp0M2wzSWJ1UkVJSTZRTlVGWXNKSzU2V0p2SlNnc0gxTDNINWVqb2hDL3B5THhpSmlOV2RBTncyQ2hEdy9SaGRFU3E0TmluZGtWSExaTE1LaFhWSVhxeVJTUlk2a3UveWlTd3RKVCt3ejAxL2lmWk9Sc2wvd0MzSmpZbW1TT1YremtQV2JaWUs4Vi80Q3BRYWxkSHIwVDhrU1Z0TTllOXd2NnNPaTZLMytKRjR4SVh4eUpia25BdzZzUzNIVkhTOU5EQ0tsMk5uWlFLbVdFenRqY2hLc3pxWTViRkVnZmx5VVF1cXMydGhWUW83cmwwY1NUL0FMMGR4ZENYUFRLd3haUXlQWjhEMjBnMVNTUDVXSFJqOUdISTlDbVorNXFQeXRQOENmb3lMdWlGN0NWTFFTTXpIeUpGNkZxaVNwckZtMkxsYWtYT3JUQTlDN1lLcm1pRXlzYTVMZWkraGRxVmhlL2R4NTBVdlFYVmsvOEFBaEpsYzNFMjBwdFBZUnRxalZDeW85Q0U5dllZci94eEx4WFhTcGlacU5LdENWT2plNHNmcW4rQmZ6WmRTUFRoSTdjYm1wNktFNHdQUFlVcDhEMGduQWt0Mnh2ZnNoVnZRYThBb3BxMlN2MGlBdGdYWHNXUTJuNlJJNmRGdWY4QXdrNE8wSjRHeE5Pd0syN1N6RTB4b01RZVllakd5dVIwaW9XblJXWFJXUmM5ZzV6WVFXUHhUMFhTdjdzaTVqRWVqSGx0OUg2d21OeU1zYjhCY1NWZEhROTBoR2pNaU12WGRMOERlbXlpTlh3UzRqUFE0ZjhBanJGZXhoQ2MyTGpQSDJEME9MQ21SQ2FLa01TL3dWR0xmb3lKTTNTWnJ5TkFVT2ZrMi93L202aTlqNlBTU20yaXYwcUVwWXFGQ1d3bXBxT09TU3NTcGZSc2wxdGVnMHdmSytQeUppakUyWFlrbm90bi93Q1N0ZFNUYzc5R2NvY0M3aHE1ZEpUSE5LMFZKaElmWGVlQk9ISmJlcCtqYjF2R1BMMk1RdHc0Z3FieU9pWWc0TUsyT2drbTJ3UkRscW94a2x0NVVrYjRkYWVxRmtjLy9NVGcwRWlSMmM3Wi9oaHpvNmxqdGlqSkhFRmxENGdCYm4rYUNxWXF1bFpFZjRZZFhyME9OVmtpbDZqb2poWENWYWpXclR5NEwxSlp5SUV4UU9DRUlZWnBTeTBydWhlUDRJeUd6dFQvQU5GS3ZWQ2NFdGo0TEU5SE1wdG5CWW4yVkhxUkk5NWdvUnlxRzh5TFVIeWFOSi9RUVRacFJZcEk3N1NERGo0elNSZlk0QjFHdUFuN0Vrb01jbTh0OVdrbm9xMnFOUmNrTlZrTWgvNnFiV1dKVzRtM2xjRXAyVW1zRHAvR20zU1N6Nmt0U2RpbjhiN2kwQjVrN0RSY2ZJMXR3VFAvQUxhdEd4SjNOWk93bWgvdlJ0YVQxOGpnOG0wYlJ4ZVRlbmtvQm8xY0lqc21JWVh1UEM0NEc3dS8vQS8vMmdBTUF3RUFBZ0FEQUFBQUVMSExOTk1PUFBQUFBQTk5QTE9ETERHUFBITEJMUFBOT1BOSFBQUFBQUFBPUEhQUEtOUFBQUFBNcEV1T3VWbHNPMlBzUFBMRFBESEtQUE9QUFBQTENNTVBQUE9ER2Z3VmgzVTBrMmd1S014WjJGZkxQUE5QTk5MUFBQUFBQUFBQUERQTXB1WUQvR1RBL2phcTdIUDJRK3Y5UFBIUExQT09JUFBQUFBORU9NMWtJWUdEZysyQ1NEREx5ZDQzWnJKOG0vUFBQUE5GUFBQQk9ORFBLQXJlQlNaUjN5cFIzNkdsUXpLZzQ2MVhHdjNQUFBITlBETlBNUEpOcHNPdGxNVU96V1UrUFpCbGc2TFU3WWRrOXR2L0FDenp6enp4eHp3d2RxMEhPZkhURXJnUi9pcDJaVDdQemlIVG9TZDY5OGp6enpoenp6Uk40WW5WL0tndzBGR3dlOUVzRXFwdzNMY1NyL1lvMHl6aXh6ekR6UmJHQkErRXU3ellQUkc3d1ZaZjgzeFlYTHpxL3dDanB6bThWODg4VTg4eC9zMkpESzdZNE5PaUI0TnZMRy9kc0F5K2pxQWQvWUtzVFU4ODg4OFE0OXE3TTVEUjdaSjJibEhsSU94elhtcjhIL3Z6TlhubVowODg4NEUxU09BWjZUcGlPWVptL1ZNK0tLbGFlV1hqVGUxVS91eVJGUjg4OC9FNVJqQVlxQjVueWJaSStIa2tjNGowT21LWHFKaHAxVUpiSDV4ODhlUVJTaVNiMjFpVDRranZzMWpub1RkWHhFaVRKNWpmb2oycFgwdjhvZG9YM1ZpR1VHTFBpWVRxckJRWUNXcUFnTlNyVmp4aHVKa2xjVWVNcmZiREFSZjQzVkduZmY2RGJCSDhEeWNMUTVBY00rSUZDRExiU21aOHY3N25sSTg5U2p2UzVYQVUzS2dvMWxZVUIwelNleWw1QzdoUTgvNFFnbkJzNFd2emgzWnVEUXI2TUdQVzJKNFE2Slk5Z05DemY1R1VkVzlsa1FBNElhK0lURTdZUGJFYnk5M0FKOWxXVExMVExTRi9ZYmd5MlFtWG9Nb2YxcVJLMlVKYTN5aXlMTTkxUXpXQ25naTB0TkMxY1pSa2dhK1hCTUlTSk1sVG9Qak1aQlJoWHRlWmh5eW5QSzNmMXhyQzNKUHNYQVFYYitUR05ucEN1aVlTS29rbEhId2lSZHYvQUx0M05JTW91dmRlSlNrcDkvRjF2Sy9ycHdnQUttQ2R0TGNZdGNIMjNsTWN6LzhBbFRWN3ZNNXpCRmJ6RFhwQUpNcmEvUUJxUFczWkRsaWorZVpoRG9FbFcrdDRNR2JvNGsyeWxydldzSzlvamE3N0ZrVTF0cm5ndms4WFFQSVN2UjYySndMbDJKeVFmdDNEZmFSMGk1WlRUM3Jyd0tvaXU0c3VnL1lvTmVIODhVekN5Znp6eUtET3RCZGpzVWFMendmaU9uclQrcVNpaXVaOU9yaFl3ZWoxRDNqeGo0ditjSGV0K0hPb013L1N5ZEljNWRTZVBMSHB5ZUhqRHhyUmZpenl3MXhQbFNkN1pqbnlwWkFPb1FuWnVyR3ppd0VwTndHNHUzbnhYenpUaXpjMmk0QW9JTGdDSVE4ZEtOTWZXaTVnQlpTMlZ4SXBDV0svVHpoeXp5RnhiVnF4YnRDOE5jTGJMTHZqNzRyL0FNaUc2S3krbkFYNlkwOHM4OHM4Z1M2OWY5aFN6ZG1vdUJHeExBQlpBd3Q5Sm1nMUtweE44MDQ4ODg0ODhZazkvSExLTDZHY0psSW5FRFMvaTM3VCtpMkRJeExFODhnODhjc0Fjb0V3QXpRVWVKOWVGYjdCaUJSZWJxdjd6cG5IbFU4ODg4ODg4YzQ4ODA4VWxFOUR2OGZneEZqR1RlSyt6TTN6N1pMUFBnOGM4ODRNODA0RXM4MDhwM0hOc3VHdTNJQUZiZktRcEYvS2hkVmQ4OHNzTThFYzQ4b0U4TU04OHNNREhPY0ZxMUJwV2JiREhLVUU0OXM4MDg4ODg4ODg4ODg4MHNjODg4OE1vN0x1UnBDTFVtMytXSURzOHM0ODA4czg4ODg4ODg0ODhzODhvMDg4Y3NsSkJ4QmJpaTNoMHNjODg4ODg0OGM4ODg4Yy84UUFJaEVCQVFFQUF3RUJBQUlEQVFFQUFBQUFBUUFSRUNFeFFWRWdZVEJBY1ZDUi85b0FDQUVEQVFFL0VQOEExa2svbVV0L1Yzd3lCL2JSOTRqOVFIL2FVTEh5V3dtRkV6dGlYdkNldU5pdzhWV1dwNUg3aDMvVmVyNGtxeU1FdER5ZUZmWlI3dWp0dDVOdHUyRXFPby9kNy9wREVpc0NNWGJlRjF6aFc0OFFmV1hzZmxuR3d5RFpDbHAvb1o5RURBTzJjV3k4K1IzdVUrM1V0a0VQZi9ZdHg0eitHeWNmQi96ZkFrV0FMVDVPbnQwMnZuR1RCaExKOHV0RGxJN05pVHFYOFFzazJTL1QvSjhDMmdubHVLYWtQa2tHdlp5TzNtKzVkeTdDWG8zbStYa3ZCTWxsdFdDUytIK0xIb2pUQjVNQm1pSVczWkxMUExLYmRiME1MMU1tNngxd1RnQzJacXdad08rUzZ5WmFmNE1FZHRndWpwR0V5enVTMmIyUWkxdDQ2OGRRaEdNWXlYcmgwUEFjT0xWc0NYZkwvc3Rad091Qkx6dUhUK2V6SE8yVjcxYWpTNmo3YnMrcS9wWit6QmtDZXNFVDA4TTZ5QU1QSjlaZUpKYXRnU3NVYkFEWGdnRWF0dHNrT1A4QUxBeUdzZXVvY1dUM0k2TStyc2lVSldXV2JPSU80Nm51OWJEcmdETTRMbGt4SGFNOStYWG9TR01HY05uVXkwL2l0MUhEYmQ2dWprTTdpSDVkZG84eGRJVGM5aEhsRTlIY091THlraDFzT3VQK1RDU1JiKzNVeDVPM2hJNmQvZzhJYXowWDJQMGxpODRTdHNMa2d4Z1hIc3V4MURuc20rY0Z2VjBoMFhpOUxjTFZnejIzODRJdGJQaUVIYmQyMlJMdkk1ZkphY3Jlb2ZaVFlqcGs0R2wrVDIydStwcjdQWFpPV0oyUWo3ZXRuOG1mTHhsK2t2NVA5dy9XUDIvdkMrYm85MlIxd3VSK3NKL00reXdtR3RxM0Q5aHdQc2dJMmpzeS9EZGs0MnZYa0pHKzNvSWNidHNFTjdaNzZuOEo3NjNSRDd3RXBrYkkyM2o2Y1BrVHF4ZEZwYVNKbWJ0UEhMTCs0ZmIwNEg5dW90MGQzY1M5amZHWmx3am9qOTRUV01jQVcyMjNWa2srUjNlWVNuZzFrYi9xTUlJL1UxSXp6a3RMY2M0eU9GR2RWM0liM1prZHQyZUIyc3ZMYlpuNWQydkFGdDh2UEFrdXJKbityc2U3RVpiZHJPOTJRbjVMNGt0Nno5NE1oWnhvalN3eHY3Q25YREN4ODRTUitUejB0UEk0TmZiVjdZK1JlZUk0eUNTZVMvOEFYSTA5TFB4ZURqOHUyeis3QXRMVHhsUFdmdVNEMVpOSzh0QzdTUmJkY3RzdjJlSGVQZ3dmM2hSMlFqUysrR1lzMk93UEJiYjdmM1g5bC9aQ2RXNnU3THUwdW13bHo1TmR6cVZMTVhFOGtDOXQxV0QySHdqdXk2dXZrRE11b2xuMWtmbGYwMzlFbjdlVVdQQzl2RTl5UkladUgyNysySVRuVzAreUtWOFpIMUlmWmJ5ZUM5NUdIa0p1M3NRUGtDMnZyZFdMV1dRbkp6cGtDMHgrb0I1Qng5OFJ4SkxPZXJFelI1YXpnMlJmTEVUMWtGcWJhYXU1WUVFZ0xxT3BMQ0UrV3B0cmFmWUJabjhNNE8rUGliVjJjTnVveThuZ2tYczlGNFhhQ3pyTG9qNFNiaEpaeDZRMmJ4dHBIZGxwWTRkdkR4ZVprdDZoc0dSQlpMbmNmM0I5aUR1RXNoNjd2N3MxMXRDeGJNNmp5RHV6VzdPU0hVb20wOU93NzJjUGRoQVdCYkwxZkk0ZlorbjhDV2UwOThuVGsvYnVNN1ovSXQzeXpPMmF6WVliYlB5M2c3dnNYWHpxTWRUdnkzdkliSjY3dDRmY3Z2SXR6a0UzNHN6cUZyckNHRW5vY0liUDJRZVRCenFEdTkyM2tyYnVMWTI5c2xnSkFnN3BabXJzZHh3eE1kdS93SkRxSFFzNFdPdTQvdVpkaEhjK1JCaEh4ZTJUNjZ0REg3UCtvc1g3MjNEMlQ3RVJhUUpqZjhtTEVNOWRsL1pid3pCMUg4RzZZdkplRjFrRXZTNWgzdXdHeU5NcFFzelNYY3VrWmRtNkhVWnhzNWhhbU5obDBjRzNoRUpiYmt2QUdEM2VXelpySGIvRmg5akRac0N5R2ZaN0gveERESmliN01BV3RtdzZ5eUo0TCtxV1FsKzQrTGRvWGtIWEhjZmFiejVZdHNJc2RuL0l4SEkvSmNqcURQNUpuY2R1ckpFWkNlY044bU9teGdmT0c1THU2YVEwWDF1cTBjTm1lSVdiWVNGb1hUY244OVhzUHEwT2NldXdmelpONnNIRzlrdG5Dek80TE9jdjFMSEhndWlQZUlpZkpGaU8rUFptMW83Y3ZmVUh5UDhBQWtOODl0TEY5c3ZPVnNqWlZuMUxMZTdwVGZiZGErWGN5Q3Y2VDJOa3ZXejIzZ0VJOGwvMjZlU2ZDd2cveEpmUWdQTC9BRk8yVzNJeWIrV0F4TWQvWTNnT25YeTBtemRXUGE2clBISlRWaWRrUDdaeHVkUVFmNUV0T3oyMTZmYkl5MjI5YkRZUXdrdGlkTVlPcnVzV3diMjJoalA1UUhHM1hEOEVFSCtaSVczMGc3MmZ5eTlYaGVaOW90aDY0ZVdVUGJWOGdFSCtna2s0N2grdWNuZ2QzaGVMMGp5Mm5rY1BIOUkxN0JCL3BzUSsyejFESUJ0dElRNlhuaWZMU0hHRDIwK1dmdGtIK3ZrbGhzdkcvdVRKNUFNWkJZSllFUGU1ZmdXTDZ3WUxQOXZMT1NXTEg1d3hzYkxQOC84QS84UUFJUkVBQXdBREFBSURBUUVCQUFBQUFBQUFBQUVSRUNFeElFRXdRRkZoY1ZELzJnQUlBUUlCQVQ4US93Q3MzTUd4V2JObXpaWGt2MjJLeVpJUVlpRXdtS0ovWFlkWWhNVW9oaURFOE5seENDTDlOd050aUVoZko1UVQ4YVVZMEppZjBQUXNJTmw4VVBEN3VEMklmbTFoUDV2UUpFaFB3LzAxNG9iRzlHcU9LZWhmbytDek1vZUUvazlDRWhsRXlqUkdpakZoamV4amNOcVlVNFV1Smk1a0UvaVlTR0d4a0t4TVJCcUNLTWZhSy9ScUpNOTRhSVREZmdtWEMrQnVFckVvUFFuU0QwUXpwdENkeXhqMGgwYUk0RTlKaXpjM0NkSHBDUTBMNEc2SWJ3MkVzdEpJTkNrS0pqWTFzYVBFSW9makM1YlpvaFBWWW1Fb2RlWUorVFFTR3ZDSDBZYndKMGcwTkV3aDhGZytFanhQQ1NGR2Z3TTMwUWhrTDVOMWkwSmkweG9vMEpRZXcvVXNFNzRUQzRORUdoTE5JbTJHUVVZV1doZURFc0lRVHFIckRyVkRWRXVHSk1KVkgra0Uvd0J3K0M0UG1VVERHUGJIT0NhU0VyaERFWHpKRHdtZXg0YW9oR25XTzMzRGtOK2lwOUlONDlDRXMzRGt2QmJpOEZoREU4dm9ubGlRc3RlME9NU2owTFovTVJNclhUVFplbDlDeGNTaklwd1JCRUliTGhpdzhRaG8wVXBTbE5IQ0g5RTkrQzBQb2IyaDZMbml5eE9GRXlsekVOQ3crQ0htNXFFUWhkd29tYzFob2h3aGFERnFGc2d0c1pTNXBWamVLSjRXU0htak5wN0V6c1NHa1FOdG45QnhkRStoL2pCVFFrbndTWldVaUlRaEdOdGRFeENsS2lMd1dEY0diZUZHM1NweGlaVEd5RU5Edm9iUFlrZWNGMEI2REgxZ2t4WTBUT214SmlvSmYwUWtSS1Npd3NWRXhSUlJRblFrVEdqUkJ1RUg4aXNxMFVMSFFRVFFpR2pXSWNqQmZyTkpJa2lnc0VOWU1iUmYwcUlURktSRkRxRzAralQ5d2RVcXh3aGRFL1FWS05GTGhvWkV4TXZBSllReGZBUmxHeFZubzRKVlVOVlVnY2lVUWtJSVl4dW53V0V1RXpCWldHUXJSU28xbWxJSlllam1FaWFnbG9hSCtFejN3VEtMTlNLYndoWVo2RThUTkdMOUdpTGIwSTZiZU5za3pLYldVTytpbHBpc2V0aS9WbUVJaWo1NE1XTGhEdzloK2lGUkVtTCtFOTROK0JrRThmekQvQXZSbTZlYjhIaDRtV0pyc2FJMEtGSU53WWVnNUtpWW1RS2xKaG9OcG9TTkRkY0cxNUxlL0ZpeFI0V0hFekVvcDRIMEkxZXhwc3FKajROR0lSUktOa01kSHJGeXhlTEZydzY0TnBEZDZSNzJWSkNiYldEaEF0RGJnMjRMUUk2Smg2UjBjNFFwUFkybWorQk4wU3hPT1l1TytiTFJqZ2hEWnRpUWlpVGZSWWhQQ2FFU09oRzJLRldPVVgrQzdQUXVZMkpScG9SUnFqWmNQeXlxeFlMemFPWWMyS01OK0Nmb2tRaHJKTjROUnNFQ1RBaVllUnUyZEVNdStOaWU0UENOaWdTSVRMRytEc1hRbWhkaUVHdDR2aENwYTA4MFh4TkMzbUN3eHVDY2V4OEU5MFhlTm91eHBpRGV4OE9SNDR5cGs4SVZpWHlOQ2Q4dDlJVmoxQ3dsR2pVUmloalJ3Y0d6b2tVdVdRbnl0RnhyTTlqVkZIQ0VNVTRIcnczc1NvMFNKVEZ5MkpmUEJpdGRGbGlJTlljajZHMkl1eE5ZZmhUYkVoTDZNSWYwWHdZZzV5TnZKWWVhVDZ6UlM0Si9vbXZEeWNuUWhJVEZLSkUrekNDdlJzcG1pZytqb1RGcDByWk1KOStFUkJPRStsLy94QUFxRUFFQUFnRURCQUVFQWdNQkFRQUFBQUFCQUJFaE1VRlJZWEdCa2FHeHdkSHdFT0VnTVBGQVVQL2FBQWdCQVFBQlB4Q1ZOLzUzL3dEWlgrUksvd0JEL0xIK1QvRGIvUy8rVGY4QWdqL0IvdHovQUJuL0FCckYvd0FKTFNwWGFWWEh1VjFQZjgyTlNwVHAvQ1YvNGEvK2NRSHRBNkh1bDhTNE9Od0h5MzhUQUZOaEh3U2tzVFg1UXJNUVE1cVBvSVJtRGRQMWc0MDBvK3E0Q2VSL0JQM20rSXBoUTQvb2ppRzlQeHl3cjlXZlJVZHA5NFAxRzhibmFQZjNRZnd3WmR4KzBTVmpZM25oSUFvei9lclIrTTZpbzl5bU9QOEFWWCtEL3dEQXIvVlhFSXVUWUxmVVE2eGIralY5UWhsUzZJUGVUNm5ITENYOUI4UUtZaXFRK0JFRlV1S0d2eXpUVTZMYjhzVE40OEJFd3Q5Y3plWWVyUU85RXNvQlR4WkVXNThSTVpvNkU4RHFSdDl6L2tkZ1h6Q25TM3E1UlMxTzhadHhkdW1lZ1lINXpObU1LWjhoalp3NVp0N0ZueEFIZFo5ZEwraENnN1ZYOVFpVmltLy9BSU9uKy9QOFovbGhkUXM3Ty9pVXdaZHVyMk5YZ0pjVjA5UGVYN0lvVW1xTkwzMVB1V1p6eXR1Mk5TdEM1YU0yd0p0T0NLOERGdFYxN2ZIM2lHWjJvUHF6TkJYUlhKNENXbFIwVDlXSzA3SlRRNmZnRXRXaUtMRnlaeDhTbFNWb1VYNG1lazF0K0JBdFc3eUxwSGNmZVZTaTNVSHRaR1BwRE1TSWFaRUJYVTVCbE5QTG15TlhDdXVzQUUwYkVhVHpyRDc0eG82ODVoK1o2bGM4NHArc0ZqYTNVT2xuM0l2RkRXTnZzTVNvL3dDTy93RDZtRUl3L3dCYUlBcTZCTkNhclBSdDVxVkQ3T04rL3dCSGJCaTQ1eVhkL2FvNnVOM0t2bHhMc3UrUDcvRXBidWRBKzlZdzIrRi9PUHhMNFBjQ24xTVM4RzdqNEZJdGJMekZXcVpwc09UVDd3L0F3RUt0ZnlHL3VGV1pnRFNWbkFDUFNYM1NJR0RTODRQNzhRdWpMUlQzWnV3dmlaYURVcUx2cjFzZlkrNFROT3FBMHZ4SExMSG5TVkpjY1lJS2wzcTZmVE1UNHhUNzBsRXBWUEdZbzQ4bVk5TURJbEpFN09VTVZPLzVtWkhPcHJkbkhxcHZ3alhLNm1wL3FQOEFDLzhBMU1QNUJkQ1pra0ZoSE5iSFZxRlEzaFg2ZmoybGgrZ1laWFZZRkZoVm9iZUNPQk5hZ0Q3VEZVNnErLzhBdGNza0d3dGVYMmpGcTFZdm1GbU14SEF0OUk0WFRveFZvcjBJSXUyVU5tT3NxUW9XN05lbG51eklnZGQ0a2c1Nnc5QzliTzhHdE1BNWZlUThSR05XOG1oOTRpdVViT2NIM2ozR1hHUHYybDRhckZiTjJNeGhtcUUzV0g0bFFqZ25EUjh3Y1N0dk0rMkdHMUhjaUdCUjVaZHcyOUkrZU5VL3FKZ3ErUXQvY1lvaGVneE9UN015R0xIVXFvV1lycTEybDRyZXpoNzdQMWhTL1BRT3B0S2Y4ei9GL3dCRC93Q1IzZ3FJbTNnREs5Q0Y0bkF3L1FEMzBSVXcwcEwxRTVYVlFGTHBXbGErL3NUYzROVlcvVmxiV2xXajdhM3pVcFV6Uk5Ic01FdDh2cWFVbU9MQ2VtWldNYTUxWWNDOFgrSVpvUFdPZFFOd2hJcVI4c2QzQjVteWxhalIvQVZGZ2lSZ2E0SnFXN1ltaGI5Szh6V3c5V3lzendvN0FNSHhGWURmd09FK2t3Q0xlcitzMG1CRkhIRVFheG5BWWcrOElXcFhYa012VmVvUUZHaTdoaXhtN0tMMXQ2eWhrOHBTMEVSelE5TXh1cTRsYnhEakpOZEliWkI5eUtObnJ5WDRpZ0ZSSFNuNk1iR2pJYk0yWTVuTEhGaW03NVRzZmFXR2NCOEQvd0NGL3dESVJVN1FETEw5dnE3VjNGWi91RWd5Mmk1S3R3YmVobmxpd1FHN29Xdk1QZTFpQjNkNDBEVEZHSFhVZlBxT20rN2RIQWFCMmxGVnhRUk5Pc0xKY2F2NHpTZCtQdEM4RnNVK3hOc1ZjTFI2bFJRVkFPZ1Z4R1ZBcDJiUlZSa042V1Y3YmZCR0hWZlplbnhVdmN1MGFqYzYxVXdsbFUzZ3Avbzh4bi80VSs3TVFNZ0ZyQkp0dXpHSEYvUHhDbWhGbE8vSktvTUd6ZTlmbUJiTE53TWlzNFlEelZFWEhKOFdUUndiRzBPWnN0UGhsWHVlL3dEQlNhMGtCYnF1aU0wRDZvZDBNOFM3UXMzTnBrVmIwelJtdWRSNUlJTnhHT1JOUWkwMzNqOXFOUmY5dnJFVnFrMnZzYzl0WXF3VWpWZjdyLzhBRHY4QXlVUUZMQXVYUURkNkVRZUN4S1hxV2gwNTVUU0pRbnBEZ2hvZGlLaXdzeHlUN0ptcEtqSy9KMlBMR0MyOEgyQWQ5WnFKV1ZKWDVNdmFWcFF4bExYNGhGQUhWTmZMQ2lhSnRxOXpUQ25YOHl5NGIxZG8yZFh4djNCTkFQVlg2SXFORTJVTTlpRmh3M2hESzlRaVZ5QnNqSHFpWUdNNlhNeVRmU0V4VFZiWHJPWlJUZTU4Rmg0bGhjbEQ0UHZBb0ZKa3ZCWkJJcFpyYThNejlkZzZNUDArWVZlM2tUaHgrSmJrc09MbStDbGR6TXhhT0oxRzVpb0dDMmRmeVNwSkJnOGtHQ1VqbzNxUk43TzVVUjRsaVp3eFJxS2N3NDVwT041YmloMVRnSzM0Wmt3OG1zeWJadVZuMUJ4TWJDNDhjVEJQa3JYeEFJWXNPVzVzOXlNcVVLcHE5ZjI0dE1kT0J5TzUvcmY0ci9SY1A5SWIxaUlxWGtMUTNJNDZqNGczRkl3anBOUjFaZEphckUwQWFWMnVKZE1DeThBMVdHRXZMZWc2V2gwSnlib1JJNmlqQkI4R24wTnB2SU82dTdNRlhoNkh2KzRvRmdPd2JFc1lGWDVsUnVzNjV5MUJ3ckhGbnhwQlFIWWJZZmlKa1BhTmlDSFJvUnlyNG92MU5IaGdwQUtPeU1yMzlJTGNWcU1XQUJkOHc5WGpLQnJQMHJ6TVRDNjZXM0F1b29QUXdmZUMwNmtybVZXMEZiT055YmpRK28rYlRQSm1pVHBGdFVHa2VTRmhEaXVBNU5wbWZQWHluN1AxbDRDeXZ6dkVNa1RmSWNRV29DNWJDT1U5eGVxdHhMclV2a2xORkQ1bVJSUnc2d0xieldGL1I0Y3NCd0tZTjRiVjltRmlxM1F5ZDVaUnBUeE1tUjBiSGlIUlBCYTNmNys1bk83dyt6dy9XSlc4di96VjEveEY5WFloK2dsRzAxcXZTTzdSRUxMU1VlUjd2d0drd0FLTTUwTzM1Z0dVb0RUdTl1MnIwbDZTTVU0SWJFTWFpcldwWGtpNE5EdS9hQWdPTm4wTmpyQUNGSGFYZmQzaGhwV2hzL2UwcFZqNjBvT3o1Zlg1bkRROWRaanRlbE54RHNLNmtRTFpmZE5JRUoxQ00yQlFPQmxVN1Q5SGoyVy9jUUtSYXU3dXpQNmRVV0FDWnAzL0FGaUlnbHhXRCtsNWpuQ1VUcXdmS1RVTWp1UzBBYVNTdjJxSHRDMHFnZUI5V1RMY3k2YTFUbVZXOW0xaGRHSWJmSlVySFNyMUNiTi9lMS9NZEFMMm9HVkdzT0laRlhxY01xbEFWOGZtV2k3eGJJNVdZZWQ0dTRzNU5TSU5KU2EzTmc3aWRoT2VJaUlBM3N6TzR1TjQwYXJrY0hmL0FKTDN0bXpFcGpXWEl5YXBRNnArSVRPd2pKNy9BTlZ2ekVyVS93RFBYOGhGSUFBMWhKRTZEd0xmbG83c1FpeFVQL1JicmwzbGpoMVY2L252cE9LdE96WW5OOURibUZUY1lXeTh0NnlqbmNLNDY3UEhxWWNMMTh5RDl5RzJnY0grRGIxRncvdXRuY2JHVWhHYUdoMHZSOXhPdDBPRDJEV0tXQTV2WDN0RjBESnVaOS8zSzE3STFIVGRtZGc0TGZYNWd1ek0wdktlREJCQ3czSkVTbXVtS3gyblUzSGZUTDFpTWhuVDIyKzU5ZnhBMjJMeEhxOEl1VVJuV1A2bUR4TExEWkE0TWZKK0pRRHUzS3VGM0k2Tks1Y1YweU9rMkhmcXcvbnpLK3RJNGRORDgxRmJSK0lpYld4L01YZ3l5dFYvVWI0Zk15QU5PZnpNaDhadzh4SnBHK05JTjZaN3lvNnltcnFMaTRCYmQ1dUVITXhDSTFDTjJaNWJmZzhzdkFwb3YvQWlLSzF5NVpZdlovY3pGL3Z0K0paam1LMjdhZlE4bkRIMXhzTEp1aHh5YmJZMGRkSy93WlgrL2Y4QXdJbW8wRFZZUVhCS2E1VC9BTU5ETVJROFJSdEFmdlhNZnFwZlFOMTJQckdxamZvVmRPKzhFMVQrSWFPSFUyaVlxV3FiRHZDTFd0UmV5TlU2VVlzNjdmQ0xkVVI4WnY4QU1yR054NlVkSDRtcmVvTi9zeDRRNmx4NVB4TXkxaXpHK2JOUFVEYmZseXZtOHdMUmNtcGxSeGNFR3VvL3RTNXlzMWQ0bUJtNnh2MElhcmpvenJxZnY2RVl5MTRRd2ZFUmdEZ2pZaDdkc3RkTTdaNHJ6REN0VmRjM0dPUitJbnkyeENkcGMzUWtGZkRqV2QvaU9BVzBITzJueUZIeUtReTIzL2VrQ05tVk1GbUZLYTd4dDF0cEh0cUQ1Tlh3c05UcVRsbWF6Q08wMXpMakZYTmp0cEZncHQwNnpQRnpmQzQ5ajR0WHVDN0U5VnVjQ05jYjdHckxHNWZvR3I4UnJQcVl2aExMdFVMeEFycW9kclYzaU1WWHhEd0RZdS85eE0wdytSVlBwL2JyRVFWbEhsNm9PbTU1TVN2OTFmNkVBRnJvRXVVWFRNY3AyYTFiSFdBVE5Kb1dnZnZNSWFLdFFjcnhFK1dyR2FPcnk4ZVRHU3ROcStibzVIdEZHbEI4NjI3TUhFQ3N1Rjl1bldIMXFTcTFEcDFsOElMK0Z0SFNsc2M5aG1iY1FpRHpEVFRRdFE3RFh6TU9SQkdYcGVHV3Bya0Q2ZXA3bGlxbDdMMXFlWTFXdVIxTlQ4UzZJZEFwK1liZlJESXJyVEtBRVFMdUEvaWdkYng2WmZFWW1xRzgyNnZxL2Nac1VSZGNJbFpHOGFaekJyZ0ZXZjBnOHpQK0Q2bFlQbGpvYnNNeStwY0hDU29YVVN3QnBJRE9MNXV4OE5QaU5ndFJyMnpDMEdkSlZwaG5nN3pqeGJKbnhGVG5wRkFXMGVCeVF3MHh0TXRhN0hUbWVydkJES0YxcTJQYlFiOGVaZWpmdW5SNnVGYmVJYjhscDRsdEtNWFhQbldjWmNNRWI1WU9Bdzd4cTJ6MWxiRVV0V3RhTWF4Z0c2MHJiMjJkMnBYRm5jcHl2MklsbDNkR0E2bGE1aE1pdU93UHM4TTJ3TzJkNm14YmsyN09FVC95QmNNc0VQTWgwRG5hTmpMRURiN1o5eGRiY3EzRjlOYW9CcXJ4MWpLeFpHbml1T0RhVUZkdW5CZTQ2akFKQXEwRjd0SDl4S0FTNlpSaXVwdkIyemNyMTlPZkQxR3NvY0dwblJOWDB5d2tyZW4xL0VUSzhOVURyK0lwYUlMc3hmQTdSMGlxUnA4UmFZYjVkWXZVanJYNmRTYk1VMUR0K1VBVjEzQThtR0I1TC8zTkg0aWpjV2xYMmpBRElPcWJQcjZSQ3JwSG4xOUNqM0JOTk53Y3o1Q2lia3ZxWEFHUWFad1hBTktNSFd0OVE4UUZyVzE4R0Q1djFMbW50SzJmcTIrS1lmOEF0R3p4QlY3cEs3elljMTJNUHlmTVlGWFk1MEtwK2FqT1l2VWxNcnJkVGRhamJsWlB2RTMxVmtxRzBCbWNaM2pFSHVtUXZZMWZVeVFCb3hIZ2ZkaUxCN21uc0VJdEkyS0R0SDc2UTRDTG1JVUs4N1RSYjlvSkFLcUdhYXJvUUlXbVpmYTI5MmlGS3VZUEswN0QzTHJWbmROZThXUzF1cHBMZXJHM0VxR3JiN0RLQkwxZ0JieTNvT1E1TTk5SVpvSUhJVDZIYmpTSlZkZjlPLzhBcHpCaDZaMkRYcFBsb2x5aHRIVldyNno0d1N4eVkzYWFIbHVNVldobWgwWG9yQnZWOFJXMmJXWWY4Z3l4U1dpQnJlbzZPcEY4eXhZRnZUUWtDaG9hSWxqS2N2TkJrSGJieDZnVm9Cd2xhdjRlYVdBb3QxZ295ZGpidXlvZElaYjZPcTlkSUlMeTJINW1ZaERTSm1GWllOYS9CVE0yM3JjcjduekJEbnJJUWdGdWxPM0JycG12bURpNXVydjh1STR0cVRxdC93QUZHQ0N1L3dDMkFZamt0eFcrbGVZK0dLUndzVm11WThIeTNDTGdQOVpYMzhUb202L1J3WCs5bVd0VGNlRUMzNGsrWnZyWWhQaCt6RmFBQ0k4T3JGWE9XcXQ2aHlOY3phdjRoY2FHL0dkUG1EUlhocXExaFNKYVBrVHA0Z3prMVZrUklYV3o4VHE4aFl4Wm9GaWExRUUwQWdyS3RlQ0VsdXlCRHByTzdVZUJrVTVYenA0ZTQ2SzFkelBlNElVb0s0RVpGYWNiZW9uVTNFbUpsM3FiTVJBWVpwVFIvdWRjZXBVMHVsMk4xN0hmdzdTdnI1Q09ROG56aDMveHpIL1Uvd0FPOEU1a3VCMVlJb28xaFpwMHZrMjhUQk1zWFRKMmgzWVMwRzlIb2Erb0FacmVPalgwN1JNZGRTVmlDV2Z4ZGhOWlFCaVdyUjBkU1VvRnJUT3pRZnJDNkJaZVRrWWkxM01WemJtcDR4MGhzTFdhMWpzZm9ZZ05OUnJiNndWRWRBVy9MekZsSGY4QVFoaGlaRzg0bDM0MUQ2SnBGRkpWNlZkZndoN3UrN09WU2JXMUZvbkViVGtDR0tqUWpKS0o1TnYrS0JVbHJ1MEh5eXEydWpIZm1HMnFJUFVsMHM3d1o4NWVQN1hLb0paRURzajlpcjlrdDNSL0dmV3ZVU21GbzV2MU9nRHNzd3dabW1ERXM5U1dWbEhrMmhSckpwbGJwcHJrVmF4OFN4Qk5WY3hYQzlvM2FZaE4zRE5BWGVoRHlKa0d4NmJlN1JOWVRTNDh6VHdlWWlidFZlVjZzTFFtbGUwQ3BXYTlDQk9FbTRGZ3FjUGdIMHpBdFdUWnFzUkRsSnNXYVhWWTdXN1FNR3VHS05BYkJvZHBlSVV3L21YV3JnanN4MUVIcDRiY2xuRXVHTXEwR3ljaVpQOEF3WFlIUkgzbE9EVHF1RjBPRE12QkZvb1E2R1hrVXVrdnJzSE9kb3FvZXptamQ5N2hJS003UTE4Ym5lWlJ6MCs3eHA2bU1iSHIvQ3lpOGtYOWcybFZlVXVVYlR3czRQWVFVZ3prQyt6b3hSS1M5ajdST1E2bGFqMi9GUTB3QzFPUFo1NzFEbENoUnU4RXAyR1lycjNQMW5iM0JuMi9nV1lodEhpSWVYVGNvTFRkQzVmWllWNHp2UWp4TXJsbnJCZ3Z6OUphRDNlakNhNnVKd0IrSmdFSzJobTVRSDFtM0pWY0tmdkVpUlhPQi90TUhCRlBTS1hGYmxURDlKdmExSFoxKzBPejJqY2FzS3lyNjlwd0J0MmpDMlh0RmFCcm1GNUMrc1RBMXJSVU9zeGRBZW0zdlFsbGJzdkc3T25ZSmFxVGxYTDFiKzh2UVg5UHpQVWxzVHJiWlFNNGpTcVhjSzNVNGxoeWFjbGc2dUpRWkdnZEZ5OHJsM2hoREhXcGFDUCtwckxHd3Vwb2RsM2g3TDBkSTRMSzhOY2tUbFRRWVJNMlFBQmpyWFZ4MzFPdG04UkdrcE1mNk5abitUK0JuZnhDTkFDMHowZXExNlJHSTZhQWFVSEZWaU50b29EbHREOS9NeXdVYTBPQTZHa1lzaXRlZWt4eVl4MGZmbTNwalV0R2prUk0rRWpvcGQ0WFR1UWxRdEdYU29ySldaMUoxUDdPSGFWU0Zwemp3OGNRR3FxdUUwZzZpZ0N0aDAxRXpSSWl4WjZhR0lPWEFuWnhLMjFqeGs4Ym5qSFNNQ1RlTGYwdnZDS3NzYUI2bDRWTlZrL3FJRUJ6OGhnUjJqaThSYXdid1E5RjRBQ2puSVY1aTdhb2NYbWFpZ2RvTS9OeHdXN0t5TGNIdFRnSUZ3bWNkaW0zeXdEbm1uWmxEWnhwRy9aTHovZU9aeUdWYk9FNzQreVVvd2lMM2drV3FydU11RnMweTBidUNLekdRUzFIaUFvQXpwMWlwamtOL09lYVM5SW12ZjJkUEY1WTJWd3NzcjF6RGhPRDJYOS9FMUxmUndlb2w1eWZwRkExSnVDdk1BV0cvVzVaVkI0eXhEcHZjSnIwR1l6dHVLQUFhQVlBMkRTT0dLNFVVakkwOFY5eHZhRFpJR1hwL3dCaXRrMkhFVlZFUXlPejJobXN0SnFjUys1UEl4di9BSEhXSHhrcXNMblBHcnNqSFhQK1ova0tGM2QzOU9rSXNFcGJobnNORG9UUldLTGJkdVZpRyt4bFphUG50MGhjTzd3UllsRGhOK1dKNG9kVGhoN2JkbGlRdC9VQjI2L1pVRXBRdFBESHZTSk1wK0NPOTRLVk5vb2FJOUpUZ3BFL1ZEZmxGZ0FUb0Ezazk3SE1WZEppVmRnT0dVTkRZVzY3dHAyMU9yZWpveEx1ekZVdVRFeWJFTkRCL1hqMU5YUHdZZk8vYkRNQ08welR4dEV4QnNVK09ZS0NyVUpraTJRNUlOU29uOEFQZ0htWC9xNzFPM3lrVUlwSmF1dDd5alVTNERqa2hBZUxYc2N3QkdTS093VitqcEdOM3ZwYmt1V3VxelhHL3dBVDVBWUlXODFjcUhEaTVuZVEzMEg3VEp1dFQwbEtjTlR1NlAybFFYYTQyYVFicm1NcjlZZ0FOakVLR21hWWM2bGRhRXhrYmdhL3M2ZG92ckVWUzFxTHQ1WUpRQXhab2YzcEhzZzFCMFBFTFc4enFzRUM4SEwwMWpvS0ZRWndiNzZ3TVpDa0ZyZWdjcTRseWcyRGhjQThOMXVCQnpOcVIzV01BMUxVT1V2Mk9xUXF5VC9yUldYbFdPeGFOWUFLQ1YwaUVjWDhTNTdzMDc4UkNNcmJGdmc2cms2bldEdlZBcGphSFJKZit0dkNnQnV3NnloeW1nL284d1RHN0dOamY1bThjTXFkcytqdDNpMlBCaW40SWtnMVIraVZ4NitNQTd4SUEwb0RpSWZTV2pheGJvYVBUdEVtM0MxM080WWFkd1hTMG83UDFEbUZGTTVxUDE5SCt0WXJHNm9Ed3hUWDlKYkJ2WHNHWTM0YmVJcm9BZUFQb0l1NUwybm1DSFFUckVvQ0QzaG9nV2lMUjBkU1h0WmJ0cSt6b3pKVmltQzc4UTdaRzJvdnB1UW1DeGZXdldGbGpJZHR2eEt6Q2hkdjRtRlNJVFRWWTZZZUpYN2xqK203OFRUTmlwaUYwaTQ0Zzl6UXZoZm1Dd2lTOTJ2Z3pHZ3lvTmdNZU5KZWd2TTF5bS92QWlCeVlDNVJrTmgwR1BrcVBHTHhBdkNDTzZGK1dYeHFwVGthZnA4d0tGV1VYY2NQMm1hZ3NNWHl5cW9YZEhXQXJNTk9PaGs3MEk5WTZ5d2w4T25hUE1TMkkyUzNxVjFsZW90M1lqdElqUVNnOGZtWDFXKzhxYVpZT1ZhSUVwUUs4WiswQ3Rya3VWbmJGYXY3NmdCNnFGM2xQSTdQd2F0OGg0WW1JVE5WcFVvcUNCOStLN2RVTm9iS1c1QitzUk55cmN5TWF3NVFHSlo5WWFWckErUjB5SGQ2VGFCcFVIZ0dRYVI1SWJVZEF6eS9aM0VkZjlhMnd0bm92d2x4RUdOd0RBZDkzcXhJcXdKeXRqdmozTHVLcmc0RG9hZUlRclhXWFFub1RFb1JRbmxEQStyVmpvOURoMmpHR2dyR3gwNnpCR3lCcXlxOXYreG5PK3c0N3p4cThNWFFob2MvdFM0N0FOWVIzOC9XNVVhR0RIblg3bHJpT016OFkrYXp1SGFMemo1dUl1Yk9wQWZUR0d6K3ViNW1TWGJSeTZqUlkydUROOVBpSERUb3lOSFIxSUU5elZxdDZhR0pmZ096dXpWaXB3NmU5U1ZnSHZhRGVPdzZ4YzRkN2JTeFhBRHhyOHI2aFd6WmI3anRpcHdjTXZ2U01TQzZRR2o2eHpSZGhleEpCbE9uK01saFpSY2gwc2ZVaEo4a1hhTmJwWDk0ams3cWptd1JCazI2NHcrZ1FkMUZQb251bUFLRkp4MWhQTENlUHQ3b2dpSFVzZy9sandIZGxseXJhV1h1c01MOExiWHZlTzUwY0RqMUtYM25FWVpoUTZ4RjVqY1RqNklFZ09TYWZWV2djL2VJSTc3QjFBMWZZMTFiQ1hkM2N1dXBsYzQxSER5bUIxVUl1QVRtd2QrdXM1d2J4L0tEbVZkVmx4clJSQWdCc2k1bWgzZ3YxeUxRT1hvWmZFMEFFRDA3OTFiZTh2M2RZbE8wTUdZM05qcFRwZnBaNWdweWRQRFo0LzFIRlpBZDRqN1VWaG81ZjB3VExWemFhUFNMbW5PclREd2ZMTElMMUx4S3RhQ3VoK1JqektGeGdqUWZ6OW95QTZrK1R1YXhrZ0JKd3ExN1IwM2RadHZkNThmaU9vbWYrQityeE1nUUZPb01GOXRIcjNoRXBhVlcxM1hqaUtvTmlqMFNPRlcwSTVFeVFBWDJ5ejZWSGdkREQ5UUUvbG5ScE53ajBERytFQVQrUldseGd5ei9BQUpSQmNqQ1JaS3JscnM2a3AvVnkxWDJkSXV0WG1LVHFKWE8zekhiWkhxTUJRd2ZJbVBtTXFQRjlycmZLVjRnZzByNkdTNEtDbnZSZjlCcExGTDdXVXRSYUQ3alQ2UmlNQmQ2L3dCMEFPbHI4LzNVdUl3MzdmWlphcmJ0TFdHOWpwZWppQndkVENkWVFQSTI3d200ZmpTWTFxdThZaTNtTGNyckFFdk1GeXhsN1plazJnZVNtY1E2S0liU0dFTmF1Nk1hRExjS1IwdWlvN0VMd0ZqVjJybjZxSkRwY0R5SmIraE1HTlNWODJpaEFGVmVEV0pVQ3JkeHF6bXhlRGFHTS9xZEk0WHJkUVJTUk5aVndqcHVqazJsNVk3RHpMdjRncUs2eXJlTVNzUlhIVnMwUG5EMzFmNmtMSXJjTlg0dmt3N2FOSnNBeDRDcGtqSFYxZEQ5NngwYVNOeHpMQmtEWHY4QWlXRklGOEk2eXpaZXhhQS82OHdiY3BOdThNcFcxVjlqVis4OVFiUldFT3ZRKzdFNEJxcGQzZGlpRnRYd3R3YUhyVVI5Wkc1ZlBXWm1GVlcvL3R4Mi9oSWo2ZzUzRDMxNnhPOVB6RnNzelpTekl4bGxQL0ZjdmlWa1JwaEN4VmxEckxaNlJLMFlkTVdHSTluV3UySDVhK014V09xUlNSUnBJOElKbE5Tck1XTDc5T3BHZElVdXdaQTgvU1pHTHloTEhCdS9GWExEaFVEbzVmZytZZlZFWnU5amFpNGVCRHhEcDZmZnl3MzJzQ1JyTXRDUGdLOHdUWTJkS2hHelVUZWtuYWxJTnk2eXdOUmJyQjBwaFM2QjY5WWd1MlF4THZMci9GMHlzQWN4SS9rOXhUdzNtV2F4QWhqQmgrVG5wckMwbG82OERiem50R0xzQUZtMm5WNWROMnhORXBsR0JkQzNiYXk5QWdlRTdpc09CUmI2dEM3aFdPd2w4ZFczN2ptQVdweTg4dm1GZTlteGdEdEtzUU9PZGpwWHIwZFk2U1l5ZFdLMVg4SmZDaEtMSUdwekRHWVR1VDFlKzFjcEZkeWFiZ3l2QUh1K1l4Qm5lSmFLVll6UjFpdjl6QVZqbkpzUGhwOXpIMW5qVFdydzJlUDlCbFdnQnl5cDNMMHpaZWNQS0N4THFkNHJ3RGkzV2g0UHJGb0xyTENjcDBQdXgwZUg1bUdWVGJnNmFIc3NoR25vVjdtejlvbXdRRGxHazFyanVsdStkcHF2UUZBYkZUSnNnNzQvWGlPVXRib3Y3K284eGlBN0FiUVRjb2REVVlqWkdWTW9UWUM1RXlSc0xkSVJIRm5RNStFaUNhUzZydzdodXM5OVlyYVVCenlQY3hEcFlzQjA3Nk5sUStaZWo4RzNmU0FnV2FuVHpLSFNoV2k2Yit6Y0RUQll2SkhYdVNxRGJwS01JajFpVkcwd3RDUXlqTXArbmIzTGpsS2pxNEQwZk1KclZHT3FFRzRCQ0J4L3AyaC9SM3o1ajZ3dEJVZDJ2dExhK1pUVlVWME5UNnkrVGVQVTN1QmZPWVlMQnJDQWxOcTBEbUYwQUpWcXg5V0dMV2hPekJnaitod3JWMG1OSXYyTGE5dmFJVjdEREYwRFNXeENWMGY3TDJPb05xMGpjWUI4emVvRHJDbGZ6NVFZR2JheXlQTUZxMzUyUGFPNTJLMVMzV2tVR0VuaS9TNnJyMEdXRVVwMWJ3Y1VVSEZSeGJqNnlvZ291WkV5dENLbUxYTVdrK1VQdTdDa3RnUzl1MEtKMWxEclhYbUdISXQ2UVNvWExkWFFCZlhvWldYL0FEby9hWGxhL0x4QmNLWjhBK1czekdQQk5lMzVhSTJTazk2cGkyWmhtNWdtb3J1M2xXRjJscm9QelViSzJKdUkyUnNhbHhPZzhQMmhqaXI2QXc3WVQ5NXFha1JVSkVOTEdQek5BMGMvTDUra3FKWE1EdjhBUmZjSW54NWc4K2RmY3JyRGJLMXkrbjNZc2RKTEYra2ZNU1ZTNThnK1VqRUhCY0FIMWc4RzloZG9QZlUyU0dnUTlRSzdCdzRkR1puRUdUYmNlYTlrb2c2MFpPb2NCMmpmVGRjTHFOVkhEQnpvT1IzSmhqOFFKMFlvSjZBMFlBV2Z3dnlJcXRDT2lVeEsyY0NCRXB3T1dZekFBZnErWlF6a0dXekJEZXZSL1I5QTlSeERqenVyOVlhWHJmT0RIZXErc05qaXluZ2ZrK1l5MnJlakEwVUNuYitybmVTV0FOczN6SFVkZkVlZElLYXBxWFIxV042enhiUysrcjRqeTRkRW9QRUJXMjZNc01qbER2NUx1d2RZdFZucWFmd0hRbzd4eStwM29ibTlhSFY2TUFMSmFTOWZGTmMwY3pKdnZva282R3lLYkRoaUVvS1d1Yzd4bmFtOWJ2d280UHFDd01CdXVoQTFCRG92OFd6b2RZN3V0TG9RQWQzVmdpRVhRbHpUb2h4azRsVFlkVlI3aU1YU0RuZzZhSGlOVzNNcER1eTdLbEhXcnAzaVoxdGErc2FkYWxZelI2WVAzSjVnNlpkK0d6NUsvd0Fnd3ZFME45azljOUxQVXlhS2ZEVDYvU1VQN1ZuSDdtMkNLYXRzeFl5RjU1Mm1mYXlZd2tkZDVyV0FTTUZQVXU2cGtyZ0JoNVBwQUVTckUzL3JFcGh6dEdXZE9md2xEYkFOYjBEYUZyWjFIT3BMVWhhYlRkK1RyWkFDVmhISTJpVzVRVFJWOG14ZGVHY01tTEk1MEIxanRwY0xvUDJpWTdsdGxHbmYwaEc5bDh3c0pBaFN0YmpUanVUVFVJbVllbERSMHc4SFdGUmxsQUlhUzl3WklLT3ZEdyswMkE3WXllYjFVeXNKUldCMFl0OFZZUktiNFNYQlZ5M1owSm93WUpjSHpYSG1MY0M4aXBYTUNFVVFkSDBmT25tV0RBNzQvd0RzYnFsNndjZEFYb3ErVTlSbW02anRlSU1mSDFFRmQxOVlDVFFvZHpKOUlvY2hVK1NHMVpVZTJrdUtXRnAyaGorb1BEcDVaUUhkWUhUWFI3RVdSN2FGRHNiOTJJMVh5eEM4WktvdVV3RXJkS3VxbDZuenc2T3N0Tk1FdTYreEZ0NVRhQVdEb0J0M2d6NjE1a2RGNnVYdXN2c1FKT2VSNjlHZzQzalZxVHJwMFBYMWp4NW9Wci96ZmFCMW1KUkZHNmkzVEJWeG14cDFnbjlVQ2pzckY5TldFaW5IR2c2Qy9VUmt3MlB0SGVqc1E0Q1lOWmNNZ2ExQnN6VlpqQjZKOEl3K3g5cmlHZzBOWWFqbUN4V3hVRUFIdkxsK3pjL2VaU3NabUw4R05nMlB1RytxMTdGK0xQOEFJd2pwQzhITXlpZTlCUThENWdIUjl2MjVRaWNtMnhFcUMxbE5rMGl1NElRWWExK3N4OHQrL3dEdTQzTkF6YmtMQWU3ak9xK1lpckRjYVA4QVNBWE9FU2tUUmdscCtGUGVzUlJNajdlWnNaU212Uk90emVYTDNqaVBxUUd3RTNyZjhNUzJKa0ZqbmM2M1JtRFVTWVcxNHhpZEs5NWFCZDl0UkN6Uml3YXFuRVk1OFhlOTZkcTk0QTB5b050TStHbjNDUjJYaWdMRXFKMEhhSEs5TFk4MHJJQU05ZXNJR1EzWGh4NGxKU2pRUS9FUXVuZmdjZDNFVnFVdURGN3J5bitIdEtUSVdvVzNpblIrc2VWMHpxNi90K0loc3dhc041YytQaU02dUk3aGZPZkkvV1phb1k5cnBsQmxHWDlTR2x6bDBJY0dxTTJScVh0b1JRWTlEeWRZZU5wc0dEc0lSYzFBTFZnbUVONmI4UjZGOWtRTkVacGVlcnEyeTdvT05BZHVzSndvM0o1RDlXQ1FvZWJYOGdPdzVNcUtYdDAyZ2lNWlIvVlhMMEdEZ1F6a2Mzc0hvbkF5cExGcTM3dXhRNDNsSmhwVUhxNE8ydkJHcld2UmJmdGo0a3N2V3lHdWhsRlVOODNuTUxuaE5NOGRBSDNtVmFEbUJXdG9VbFBXRkZXM0t0d21NcnNsMDlpbGREckZXdHpxQ3NyR2NyYTVaWk8yVU5nMlp1OTVWNWh3THRueEdyZGMwdlJ6R2JERzk5MUR5Q0gvQUJhc3lBOFc1ZlF5OVVOUWRoZ2VxanVWcGptM0g1Wm9qZ3dTZ1Vadzhid1dCMEhhYkRtc1FrTFlSZDRMZ1ZVbmE1N01ZTWFta0h3ZkhxTnJlb3VBUjB6VE55V1VodHVSeGIxbGhXMWFxK1hjMWhnQWhPUnJmbUc1WGV5ZnUwWWkwRk1odjR6NHNqeUdnVGFuMGxxOVZIeHNmdmFKWVd4Zzd0Yms3YlBpMTBnbExiWkQzZWs2UFNKaWpoT3A2ejZhdUlPZHVjMjU5YXc5cFkvU1llaUwzQS80UUJHdGE1NTlSU0FWdzU2blNERXBXaHBIbU5XZEZwaWRkb1ZQT2QwNHJWUzJKNlhrN2RvZ01lVlE5bzN3QzdxWlhURHFvVEVIZ3VqWDJlb01FUDdtK2ZzdVoxNEtpZFhQbkdQb1lzTDNFWTFySEs4d0tsYTdRS3Q0cTE4YXo3WTVTS2lkS2FFdUxNSHA1TExJV1lCbWZKbm1QU0VmSWVweXhaY0VFeHJ3OVZqdGJ0QWh5dGdkQ3RqcDBJNDlBQnpEckkxYlZybCtnOHdGcXNMZmRTankzTkpRaktqOU44THZIYmpRd3ZCMEgxZDdoR0hDb1d2UTZ5d0NkQ0NiR3h4M1FpTFZYZEdlNHQ1bEFSUXFVYXBjZFY0STRVVEFCbFhRbDBNSzBHOXhvSFRxakk1dXd1VTZQT1dMK1VRQVV5bHRKcXJuRVY0VDhvYkxvOGtPalN6dnVRc2NOSjBUK2hLWktkajYzd2E4ZjRWYkxwc1VUdTArQmVZb3gwL2NlNHh4Z2k2N0gzajVUZkVvNmdvQzNNZENrTUdxeXhFTjdyUENETGltaExLajhoTGhielJQZHZ4R2JPdTRKeGZicEFvb0N0Q0tDYXdEQVJZK1VoeW5iZC9DRDhzWDlXWmxhR25iWTdSeVFpazFGL1YrbnBHSDFCbXQ3akdTOXp0ZjQzbHgwalpnSWxJbUVtZ0ZDSEo0SHlja0VFb1N0dWxtS1lRVnZnbVNtK3ZJNlJiRGhGNXlacFUyTjNJeGVrR2p6SFRRR09EK28yeFNTclc3bWowVFJoN0Nhckp6ZXFqVGVJbkU1R0ZkQXcwcEhxYlMzS3ZkOGhSOHBCRXNLOTNMOW80eFFRVXpkUFFENVNCZisxNGlDZzdoZFhTNVFxYUExQncrb25OWTZEODNMYkxEUkFxR3RRd0RsT0E2c2JLVXUyN2ZxdjFjVU1UZ0xUb0d4QnltY3JhVSsxYjVDQ0hHb1BJZGZwRUFaTFFHVmVJam9WcmI1WGNRSWNvdGlwNnFiMGZSSDdpS0kzSmFuRk84STVwa0IwT0w2dHZXSzFXMk1nWmJBMzFzNFh5aUlvTTVLMWQ3aU00T2hCaTZxR0hhYjJBeTVVcXN3MEZXRHVLZkFOSFhvaFNzWTc2VEVKY1dQa2dRdnUxUGpNbyt2Y3hCdTNxSThMUFNPa01MWkM2UDBsRnRRV1FhYWtCc2poOXlzQUZ2Tjl4NGhOLzRZaHFvUUNyRi9jYWZNVkE2ZmY4QTZ4bUpMNHg5WVJFRjVBY3l4dE0wYS9UcE1DamJDZmVYeEVtU050ZnpqNGo3UGh2cVVTL2N1NTh0UW9uVzZrc2g5RWtlV0VvRTdGSHhBNkJYZTh3WEI2bUpaakEzVENNcWV3VTB2bnN5M0xKWXIxNlE5TXVtcXVmMjdRNWd4cmYwcm5obE9WSmI5UFV4MTI4aVpxaUltZU5tRldYT3pYVDhUQ292VjJGN1FvMWUxdytUZzdsLzFQTUozREtieFV3R2pMK0ZEWGhENlF3aTB3N1FNMWVyWU96dENsV1V4WGNOa3dpWlhnRzNHMmFqWHFpQytMeDhUS0NubmphZkI4cFcrZnE0d1VGZ0NpNDl4cjhSa1hIem1ZbXNzWmVIbHdMM3oyZ3hzNzFMenJMdjRDSEZxYkRRZ2hwWnRoa3NidFpsRXlGTzA4SDZxWGJLcTc4d2paV2hOYTU3UzMzWWNVWGVkM21KZVJUQ0lXSEF5bXZrL0JGMjV1RmlheW1nRHl4UDJQZUlLR1JPaGFlV1U4c29VN2VFcEJBdzM0akZDN1lLVGgyTStrb3RwZ0cvRFlpZGV5aFpwamQyQktJZENwdk8wYmc3Rk84SHJqbVI2WlNvbk9UOFJCU0xwa1BpSXZ1RmNBRWFONWwwYm5CajFOR1VQQmM0MzhMMUgrYzVMRmJ4bVVCaStPdFg4bEJacDRRRitzQ3FDSTRpNVdyejVpRkJZUEJOSHl4eHVYdXkzcjh5MUR1NCsyYmcrMXc5RXB6OTRZVENQR0w0YWczUXVmRWNwc3k1Y1RGWk54VDl6R0tXbVIxNGkzYW1kYi9kdnJEL0FLY01NYkIrelBzRkIwcUluM1RvZ296bVlOWVNEb3hYVWxtMHpwKzlZcm9vcUJoSlZ3em1DYWVrSzVLLzcrb1JObmFCM3BQbWFYSzBjUVJzZ0JRejJsaFZaVkk4M0RSYkRTcmNQT2xYQnZTRHF6RFo1SUFQemNvTkVHN29XV3A5NEFVUVZJM2VreFhOZC8wNUl6R2czMmNQd3hYeXB2ck92RWZNaU05R0JoaW1GVVFROVJTdER0K3NSS1ZWVnRYbUVRVXhiZzVYb2F2YU0xV1NsSTFYcWxmWEVCSVcyeDFqY1M3dkErd1k4eG1XRjBMME5vZDRhUzVCYkt2V2hISWZJeDRFWTJ0QU9yRVY1TGdJbUpTR0RUTzBlWXh5QUhhZHhsOFhMYTBoUHB4QkRrZWsxTmdNTk10WkUrMFJ4ZXR0WDFoSktDemt3eWRtVkczVGRBVDdJcEtrUk92ODRtdjViTDRHR2p1bnhNalV2Mk9mZ1p2SmE2d3R0VXlPcytNQlJiSGxLaTZDdXN5NEtLdEN3eTBiWW91WnIxeHdScWMxQzdJTktDSFhYbThZaHFrUFdHckZvZ2Q3cW9PQUJXZ25ncjhUSnB1VkVlYUpaeE1JdU44QmZtQlpKb1IyWGFXTEpCYlphSldTVXdhUzBxWE1CUzUrc0dxQTlscWZSbGlHVG1YeUxSVzQyWDdNdG1DSm5tKzZEcWNRR3VUNWw2S0UxNFN4MGhwWWtIVlVmV1lpanBKLzBTbi9BS0gxZkVabXl1ZHIrMkJpRGFsRnJZeDdpaUtyb1h5em1QYVZSM3NQdEJCZEJ0VXhyTDdKaCs4ZE5DS3dtdENVQ0VLTEorbnFPa1ViVmJWbXN2c3hIZjc0UEFlWXFuUmc0SStBUGxhQXlyRzFhQ2pnYitXWXQvd0R0QllHTkNtZXc5Qlc4UUFnT3FaV05BOExwSlhxTDVaeUE5SlB2S255WE1vOUVMNmgzdldVVnlYdEVFdlUzekViSHVUVUQ0bERGT2d4TFIrb1BjaU93OW1PbzlFUk5SUEV2RVZkWm1yaHNoN2d5MDdQMUtJZk5RcVVHZEZUNi95UU0xK3FoOHNaUXQ4UHVVR3hhcndmM0tEUXVMTFF1QTZvVTVJdUJCeFF1bUdpOTJLTFdYUGlHeDNxWmVFZDBHMTZhRUthRVBNcnFRSXBnTWp0MEg2d3lpQnFCNVYrSWYweSsxM29UVTA3dCswWDVsekMwSXc5WFVVY1Y2TGo1aHpYVE5QTmdoYjZNK1dNaVhISS9TTXZnYytzc3A3cm14TVJLaVZGU2R6aHF3T1c0ZHRqMHZTQ0RkZEhuMmlzc284a1BkaXMxRStwdkxTVktOa2dZZ3BhU1hEQWFyYVdrRkxUakhCN1NVRXRXTzVmMENPcVphNnR2eWU1YVRCTHV5L1dXZDJvVXBSSmFOWlluczNYNVFWelFUa0g1R2RDVlhiYVpGdHFlbVI5NCtweS9FSGlsQm9hL1hTT2lLTnF1VmpHYUZkdHZXdXJnT3JHRkNKbXdXQjZBSDZ6V1BXWGlMSEtsMFQxOS9tSWNVY0J3RUM1ZjRBQzFYM2lJMlBTN0ZZT1hkM21uQ2NLZ0lvYmY5SUF6WkJzRlh0QW1tcWVreG5iMUtBQ056WDJVeEZ0QjNCOE56SmNEb1h5SDdSOVVjbnFrc1RUZ3A4UnNzVW1LY1RYTTlmeFZ4Ykllb0l1TUNxNHArYWhycUF4ejJuMHlTdEhOZXBmMkg4M0R2OEFJZnRMUit0NWxIU1BiL1VwV3Q0UXFMTzdVTkxRQnVmSVZLZWtNMXp3dC9FdlVzYWc5cDhrU1dxMDlKQmZNYUttc0I4elh4RnRCWUdqd0dKV0p1dy9iQUxFRFlLZ2RXVEdhMCtDV0gzWlkrYkg2cUlGUTJ0b2ZnalQ1eWZxelNHRGlMYmNXYnk0QzNLV20ydTdsV1lVNnBHanlXRlgxeWNTb2Nhb051aTRQRXpKQm9PNG0reDlNdnRORDRPM01PMFVHV215V3Bma3c3K05ZTEExbjBQc2lzSFdMZG1EZ04xTDgxQ09aR0N0Wldwa2hiaWhMTTRNSDBnSkJrdlFIMFUzSERPMTQrS2hRZ0N2Y2RBTDlKcXRpajA5ZDVjN2tEeGsrakFCS1BvdFMzZGs3cjhMNmxQdVNocFJkR3QzNmlaQTIycUsrWmtsMWxtUEM0VllTdjFtZXE4UmlxdmIzbDRkTExwb05BM1psUk9wQTRMZHZ2SzU3RkQ5WW15amUzRVlNdHJvQndOWGphSmdRMEZUeXBpKzBaY0lZZEpvM252S01lQXMxWWV3U0NaK1NTcHcrRUxseW1qV2pEb0VZcDdjbjBsQmhlS0gxWmludENmRXZlclFENk0rQ3RqNUsrWlZnYmNqOE1yelhDZlZDZE4xMSt6SEdIQk9TcGdPak4xQmZuK0NVVG4wTHdMcnlQNzh3STJhUkYxb05HK3Nyc08zbzgwZlZHek9hTEQ3M3pNdTlodDlBa0dvSG9mZUgxUWJWVTlRN05hcXNUNVk1Zjd2U1dOajc3N2JtaW53c1BSVUdha1FuMTlkMDdEaHp2bUdxVTd6Y0V5eTdlSmwyZ1RLV1R2ZExFeEIxUmFkM0hxNFhYWFkrVEkrQ01SdEdTOHNIZ2k2c3Q4L1UwQjh1bnhGY3NyVlc3OHg3TVBDNGduSDRXbndSVzBtRkU5TlNwZVdVcVREWVUxN0VyWkYyS0o0UXcrUlZEdDBiZUplRVFXMWZkL0VzZHF2S3NXRU0wZW1uNUVzVFF1VXJXOWQvYVBXeXBqNVZpTFFZSjhYbUpTcVVyMGNmaUgxV3FZdGRqMHRNTWU2bFNCVUs5WDYwK0kwVlhOVjFuZ2M5YWdpbVZFaXB6dks2UzRVa05MbzB0dW9xVzQ2d2pKWFdLQ1dqbDlwaGFLNnBsK0ppemUxNCtkSmtLU3FwS2VJWWN5cmk1dHhOV2tNMjA1UjZRUUVMM3FVTFN5ako2RzhzWnVwRXBHQXdIb3RrNXZUVUdHWjVJYnE2QkJOQTltRnE4SG5TZDlIS2ZOeTA4bmxmS0lnYTViYWRuQSs4UTE4Q0tVNm5NY0hkVnJvWWZpVm1HaHloTTN6OUlmYUZyVWF0VENGcWpYMmdJSkc3UWxxTTZxcGlWOEJRSDdyWlE3ZGdsRnJMekxsRnpnaEVPV1dQVW1Ja0FuRkpoK3BzakNMT1pSbXJGeW16dG83TFE3M3hLekRhT09DUDRUcWVVcWdQTVhrZXVOMlZqMUZWZVVNTDZ1TmVzV3JsN0gzckdISWlWaVpNSW9UUUw5RUxWdTZRbmhmd2hLTTJJbmkzN1N0clEraDBvK0lzT1gxRmdFWm9oMGFUeXgzVzEyRDAwbVVMcFdxM1lRZmVQOEFlZytZT0RseURWNHI1TU00Z2t5Tm1ESlpvczEwa3NhREJkY3ErcGZSVUVWQlRUUmJKZW1jWWdTVGNFQVBiQThRUVl4ZVl0cUVTbHVuMml4RzlSS1BUTTUxRmErY2ZNdTZEbkk5bUpmdmZTNWpRbkYyUWpDK21WemVCUFV4RXE1dlk5VFVwNms5a1NFZXo5Tk12UytvUk1aalpyc1RRcnhQUTBia3lBTjlGOXhtaXFhTW9IWE0zRzltYU9KR3I0Z1R2V3pzZlQ3ZENLeENrU2gxTXZGSFNiNjUzaTZ5ek9tbTh1SzFNOVliTXZtQUo4S05nN1FpV2c5b0kwZ3ZraEVJeHMwVlFOZ3hKWFYvZGpoWlFlU2ZNeEt0SHlJYXZIak1hbFJ6ZXJxeHorNGJFNW1ITVdZRC9kTXE4U25YOUZmYU5QeU5qOFJ4L3dCQjBtOUg5dUljNStuRS9ldnRMNGpHVWdkUVNsYUk2eGs0M2RweTU2R3VoeFRHMFBQWDd6WWZ1N3dCYllab0Y5NWozRm9uVGdhVFMvTjBmdEdBNWltYTc4Ums2d1Zuc1lnVTI3cThUWitDYkcrdDNqdXdmRXI2UVZXbThFZml1MHlQdGp5Mit5dzlHSWtOa1l0dG9udWxhSlJMZjRGWlVIbE1md1RQNVFhZ3BnRDVuTDh4U1FSUlFEM2I4UzdIbS95RE4wTFhSOVRTZ2FxTlpqWXpLWk1LQWQydDlJTUZMa0tVNmhCQktZcldISTZ6ME5YWjh3eE92TFh4R0NyNXlQWkVMYk9nSDdSeHE5MHFqMC9tYVkzbCtjZk1iTURhT09GdWFUUE1QcnFUaUJrcWNKU09vWmIyWHhFU3I3WUo5cG1DT2xIMHhMSm5KRmVWaERsSzlIcTRvMHU1SlRJK2FHdXNBYVBjUEFEdkgxcXhtSjJaOGpLME8wQTNnTmg4U2p5UytqM21XeTh3OGhCK0owNXlNb1l5UXhZTFVzSEZ5NXVMU2RaWnJXc2QvbEVmcnRIV2ZBUjEwejhyTUZOdytrdXd1alB1SnNTZ3hHRjBVcnpGajd3elo2OUw5R2dkNWRmOXVKTXIxVmp0OTYvTlAwejd6cm5mOGs1aC9UbUNidjZjeXo5ejVsbjduekhyUllIWTh6RnZEZXIrWVFZZndRRTBBUFFlZ2ZoTHVQN29UeVorSVl3Sjl3MEhmY0FIb2dDZVZIdGovdGxuR0hhRDduaGxzWEo3VS83U0NJVmtnYVhtRmNhb3BxbkpYcUNPZ0I1YlpLN2tDWVlOdFUxbXN4VmNKUlhXdFk1YjZrdlJsN1Mxbko2QzZ1b2dQQkJqTjZRQWdMTHlHS2Q1VktTcldoN2JRa2h3dEd5K084VlpCRUdWdlNLQVVMV1l0bytqS2hCa3BkR3RhbGRTNjl4V3R5emNnVk5GdFBveWlWZXBnemczZWtWMXVickZEUjlSWEQ2anp2VWVEMVowUEltbXpzTlRjL2FKS01VK05vMzJ1K0MzeEFudEk1K1lVV0lPakRpd3QzSXJOUVhablNaVHFWR0tleDZsemt2eEczR0lhc3dMVVFocEI1aWxrZG5FUFZLTlV5UnhDYllQQ3FUOFJITUJwWk9IYVZOM3pNREpaZHZ0RXVSZFFOVnRlOGNMbmtING1uaThHZUtFdWhRNEtqb1ZSRnQyWVVQNEF4am5VNFZTdUZ2MDRsSDdIeFAzcjdRM3YzZWtKVWxHeUllYXJQYUlPTE5BUnRlQ0x5enQ5NEJRenJWNVBjUG1ld2lQbGZhSmFCMWo1SS9FWmp6b1R4bU92ZzZYK1lIcDZXQS9EL2NzSDBtVnV2MC9tV2YxZ0RpMEtaeGdwSzhpbFJlOXd4aEZHcFJidXFYa3NTTEFHNjdwVUFSQmxOcTMyWFVIZ3RPM1FsYTFNWXNOdEdyeHAxbE1zd0JLelBIVkdBWEtNRmlDY2hwVkFycVo3d05KR0R0Vmdxb3BXQ0NzbGM0aWZwb0NvYVRaang1aVFGQzAycmRkT2hFclZoMkxwZWwzRkhvYjFzSEZWMWdJNE5LS3g0bEZsODlYOHhkekM1KzFGZFY2aStKUDloSFZlNkcvNy83bHI2SmZtQTJmdEdMWjcxRUdkV0FQbTdsK1pQQVhFbVBNc0hhVUlxVmVkSUEwQUZmOXo5SSs4RCt6NnorcVB6THZ4NDE2Y2lHTFFHZEVPdmpBVW9kWkl4Unc1NEsyd2RMN3pDb1VhbXR3UkxqY0xyQmpwdXI5SloyVStvaEt0QlVKZ3dLTVJUU2pWOFdINmpMZHlNMHQ4aWZNZE9Hb2dIMmZwRWd4cVVzOWtVcDF3QjlwZC9VL0VQOEFoUHhBOTNwK0ljMzErRTZ3L1RpTmVGWForSi93SDRqdStoK0k2VU5TaUhCb3FOc1R3ZVkwWjhFRUw0RjBWQWxWTlNGMkdGTXY5MDNlTWZFQ3ZqZ1Q5VDRtbGhNNGZnMHhyS21CcmVXVkFzYlNrV01yTWcxS3M5dzFSVzdGKzU1YmxEeU5rejlUdnZxRDZSN3NSRDBOekIzYkNQcG1sSzBpcTdpeUJDb3pZNmN4MWRGeTJlRXZyTXlQVWlsdTR6MGU1cExIS2xPSGtaaFd0d1Q5aStpT3cvVzB2MEo0UldFOHhPR3JRM050Wm91NVYwZWlyWHZTV2tvSDhEdE5mMHBYelcvQkhLYk4vcWJTdDExQlVPd1kvalNldEhXR1VBYWp0VWZyQUpFNnAzcUg4bDRIQTVUUlBLTy9MOEdSMGRlU1B4N1l6Z3VlaytGaTFFY1l5eXptNGo5S3ZkeEFnazdIdWJydEtTL1FuWS9YUmZkdnhETGQyTFlkViswZEorbjBoanJqYVQ5dnpGSGtoMWprVnhXazFlL3BxRDMyOFlJVjRsakt5NEFHOFdnVkhkVS9BdjRUUno5NDBqOFNqQ080K1lCOVloNFBtanVZK1o4bEtnRXdqTHpVVU5ZeC9ocHhYV3pXR1UzcWYwN3c3dFhmTll5OGZNQjVKcXpLNlNzMXYyaWx0NkxNS3k2S1R5UmhVZ3lZYnd4eW1DNzFQQjlrdlJkaEgzK0V3QUdhRCtqNFNtM1l0RDh4emhwb2xJVmU0K3pNb0NYNmQ1VjdWVklRWlFiS0t2dzJmU0JxYjR6cm5aN3l2ZUxIV1cxVXUydjlSKzAwd01YMlNwVG00VXdTMUFzNVZVNEhXV1hKL1F0VHRHZTRpS253VWZFMDU5eStDS0lvT3hwOFJXMHZWYmxEb2RiME83b1M0STdMOXhmckVnK2JSOVdBT0JKOTlxOFZGYW9lRDFHc0E0TXkzY0l4R2JId0xsTHo3RW51QjFVNjNUMnhOS09aayt4Q25UK0hEVlBjNnA3aHUyai9BTndGQldwOG15Um5OeXVMZmdmVGNkWXJwTHRBN29jdWtFN0hDdm91VXNpOUUrWDhTclNmS2ZpVVJ3Z1hZL21aaXJkN3JYNnhVeWg4UTJ2aVJqS2htdlptM2lkbDErUDRxbTZKWVhBUG1HaXVqTGpzbjRXS2taNlJwbHJ0QmJRTkMvMFpUMEUzL0lpc1BjM2YxbXkyOGFqRmo5eWRlSUt2aW9WVVIxTDVjL00xV2JuTDAyVEY4SitReStJNndIWWVxajhTL3JqY0QyUkNrUnJaVVI3OVNVR1NvVENOcjZ6R2NBakIzS2NyNUtab3luR0o5R0JyMHlyMlV6Q1dPTE1zUlEwdzRKYWxUaWtRc0RyUjlrVkJSUkZhMEJpSThhVjFmWnNZT3hiRUgyUFVZVVBzN2ZENFR0MWhQekNZOXlqTXFPb1daK2x5eXN4RVhGM0FncDlYMGhMcDlBcGpnd1JBTW1QRnRYNEk2ZFg0Umdyd1RQdGM1WFVCMzVvV0h2U1dhZXpnL2UxUE5RTmZZVDVOdGVva0xCcytheDhSZllyV1gyTkphQUdxdFQ1Wm1henZZbFZhT1hTWG9EZU9lYzF5dmlQbmpWSG9pUjQwTDVheG41V1ExNWlBWlZ2VVNjZ09XMlBPQ3ZVbHJWOEJmckNGQnlBUjJvNk1JOWhtWkx5SDVhaUVCeFFUdFdudUF1blhHL2JjeTE3c3FIaUtxNVZNR0I0aE1VaHhGbWwxZ2pkWlF0WHZLMHF0aGM3cEFlbWFFc0xBRitjc2ZNY05SVTNVaU5MMEgzanJYSVZORWIvTmYzZ3ZkNmdIUWNWRTBXWEd3NDBnWUliNUxtenIyaXpLR2l6Q0VtMlV4NlE0cEhxYTZaakFkcXFWUUpoUFJ1UEdGMFFIcVZ1Z0tOcDNLWmFwdmZBL1RyR2NiYUpwNFdUOU9Gd016cXl4cjVtZTB6bDhVVTh5dXdGOHZ6QXlnTm40RE0yenplbkVzRllMUTRmYU5vdHhGZUhNcVJ1QnVzcGRGZE5UNnpwMHFJWkxWc2hSTTR1ejFCd2szb2E4UjRnRXVvaHlYcE9VbVBjRnJsWHAvd0FZTmZWcWRDWU1YUU1OOTFLMWxra0hJQWpyVy9hSWMxK0xwOVNNQWRUM3dmU1hGaUVXRkRUaG9zZFFqQ1JaRko2REUxMWJpajVsemFkYlhOZm8yMmVrRTV0TjdaZ0NlVk5HSyt4R1FLZG44d1BIdXdlV0Y3SmFYdkViNWZrcjFCekhRYWdDaWp4bU9Hc2NWcEw4OTVtWnZoRCt1V2hsT1Z0ODZRMUN6TkkraTM2UWFnekEzUGRwMkhSVTlFTDNDNnFCMGc1bWw5Z1RiVytXY09kaW9tem9IY3VCclNJM1dJS3l1a292Mko4Q2hOYW1IeE42WGE0OHJrL0hIOHh5c1BtWVJyWW5rL3FMSGNsb3BWOU9CL1VBeW5CS01XZEZUODlBaEZWNFJvdHZGeGZSaWEvZG9NT0c4UHd2aVU4RDJNSC9BQ240aHJVNldNT3J0WkNGYjlSUHhNMzhnbVFTdVZuNGkza0ZoSjRxMHJCa0tHKyt2aUFRcFZWVHBUTnNBclI0cCt3OHBLNG1qV1JYTFB5SnJ5UTA2TGEzU0JBRm5PQVhKQ0wwT01TbFlUYjIvc3ZNYk00SGdsSlRPNXBCVVBxVmdadWdiZllKZDh3VFYyK2t2OW9lV2pHcEhVUG9Nd3ZRaGZ6SGpzb3ExdHZrTDB5TXBrUEFyNmVFQkN4NjZEOVNGNk4wSHhLNFoxM1VxK3F4bWd0S3ZyTGE5eGRJMnlXS2pXd0xZdXpEWVZpWTBkejk1akkyU1lCTldwekVwcGNUWkV0KzVRTmFkSGhKZlZCckx2TmlLa0tYYUk0UzM0andIWEh5WmlMdUVyUFVDTllwWnRXKzRsWjVOc1N2MUlMV2VxeEpWU0lzUTczZndHZ0JXZHBSdXlrQk1JZE84d1BZTUZjcjZGeEZDcjNpNkQxQzVWb21TWXRFVW85MzhSelhjSmQrRzN1V2Z0L0pLNlB3L3dCekJDRU9MU0JZZzAvV1BpcWFBZnAxaG1hYnBlMi9sTWhlMmZaWktBT3pXcHloUG9xWU0xZVJCTWpzMUdhVHhaTUNBOE1Wb3NHeVJWWmk5b1h0Yzk1cXhIcGlKYVhLQjZyMi9xWG9odjVvMzZuVjd3ZHlUSTI2U3hQNEJ2dnBHT0Z2ckxRdzZuZ2ZtVkhpM0J3UjlEYndmSytvUW1GQkd3VWZENnhqTGE2dzhBTmF4NnBsMTNUOU1SY0NYVWw1blR6aXM5bmJvNVBwTE1kUitUODFNVzZXL3IrWlJpQU9HRzE2RDh4RUJzb3FueXpVcVdwN29TbnhTTytYYkJXMlM5TXI5Y1F5dUVtcCtzOW9EaitNdEhuYW9EaUdsZlM5b2gwb3BPR0ZRYlE3YXltWVlVL2hoaUk3OUpXbDVPSlFKdDNkSVgyR3F1dlgxbENweDVFMlIzR0YwemNhc0FkcFZsMmw2Ymd0Z1NIRkY2enNnMHpOR3ZWRzJFMlU3Q2FmTXdsUnJVM3hLdEZPY0NDY3gzSUF2ZmxqMUhpNmJoeGcvTEx2c3pOdEVQdlg4dStWZmt4SGJFL0lSVFgwSVlVT3BVZXduZ1poWlAxVWZKQXlyNG9INzFocmxkYlFmTEhzMEM5NVBtTHV1ZEMrYlN3aGRrdEt4TVpsRlZBdzZIdldMRldkOVVGYnJITUt1OURtVUNqVnFPbDdhdldqYUZaVjRpN3NkSmRybE4yN040RTBmeHBTREEvV2JFSEIwR2tYTVpZQXNNbjNHcnhHaFpYMURRNUhFS0tGNlovU2lhcmFBS2ptWloyaXVJS0thdTZLZ2JDUWhhcWg3L3VjWWtiRkxjUndQb0VWQmNiNTFnbDFRbmFDdnRPR1FIb2J2cTRLa0dGMDF3UXkvaFlGVEM1TlRVZG8rNUJKVE5NTDJPZG1hRjNseGUrUE12RHpLcldWR0twaTBnNTJPWUFpYnF6ck1GWTJ1cU9Ydk1wNUpsMSswcXh2Rm1rSzAyMmpsV0hUU2FwdU0xWHhHTVhQK1JBWVJicW90U0d4WXdWenkxOEVlSjJ6SDJ4bGt1cTVod3BNeWZxREFRNkcvTDlLZ0Rud0lBamhNY3IrQWpyL0FBMXhzbnBBRUdrdTdRVDFMTndmTVNrQkU4eTRzQnRxbW9IS3lNUUFENys0ald1bVNWd2g2d0pWSDYwUDV1Zm1ZOTYzVitubVdaRE42bmR1cGQ3QlZsOXgzSVBMTVNYb2RDVVVNS2lFSXF3ZFgzUGZtWENicXNxNnJHWEdhSGcvdVdjd3loaENtMExMcGFPamRYUU9yaU5CUXNOYjd5ODRhc2F4NTdlYjhEQ1NtMjZidkhpS2Q3VVFZNE90Zy9RK3NiNEZoeXNWSlFTTXJRZVV3SFZpU3JGNWJ1ZzVmZWpveXZMZ0Npck5LRFlseGFvU3d0TzJWbVBSVU1tTnF1RXVxU2NyZVVjZ3FXdGRWMGluUFQwSHdzb3lLQ0YvZ1pqMExscFg5VHpGK3VJS1R4QmpsbEo4d3N6RHVjUVdjV2ZTVXhCbFc1ekdldFdIaHN5cXJsNUdOd2RoZHIwdHhHaGlXRFZuSTZKMU1SWTZSeUpFSWJRUk5OK2tMcUNRMUUzamtPNVJhYnVPSFU4bTBvMndabExyNWZhRmtTYmpWUTlURzlmSWZpTDJGVzhlenBVdEFhYVAyaWI2R3dmTFdHN0Rjby9XWTVPcU9YUU12a1dNOHFoQjJ4S1RxYjhMbHcyS1hZd2ZTVXNXTjNZeS9TVWsyRVhzRCtlOHNTNDhobVdPaWRwcERIbEtwK1NLeTdRQUJ4NmcxRk5yMTl6VUp3UkxmT0JtVFJhSURjQTIxTzJZNVRReWN4cWJXRXg1aTQ2c3FBYUdrZDdNS01EcTkzUTZzUXJPdVlIUSs3MVppbklHN3NTM0JMSmZ0SEFUYU93Q1hlVXlMc1p1eWRnbE5abElKMUJjOTQ5cFVOdHE0UDdnR0tpZ040L0E1MmFMcjROUGZNMitYYXU4NktaMytqVGVXMjNCYS92RU9zWlFMVndCS2x4UlNYK0w1OUJyT2pod0x5dFYxYmUwYXQwOUNKWVVCZ2FiQlBLQ3dNUnhCYWY3RTJGTHZZWnR2RmRDV1JSWXV4K1Y5Ukxsa1p2cm1OTzNFTUdJeGJYWmVPbWtBVHFTTTl4OXpFQWw3YzdSaHR6S1VQSnhFQnhXcHlURXdWbGI3L1VTVmNWNXJsNG14a0JVTDNGK1ZYUmwwcHNvTzM4QTEwTVRodE9JNmptZE5sSXdLYUxpQ3ljYjdQV2Q3ZGxPVHFha0FVTkYxSW5lWEttN2Y5NWlNS3dkRHpGbW9ocEtHSXVXbFhFMXFkNFZBWmdLb014R3NKbWRJZDN0Tlh0ZHZpQzYrZW5oWiswc2xmbm1FWXUydWcvOEdLK3RiOHQveXJYeENJdksrSW1mcjFtcFM5OUJ5Zkl5M09kMFNKamZHblNmTzNCekYzS0RCODI1Z2srN2xyRHBCUTMzNGhFWkRTUGlUcVN0aUVSNUcwV3g0MGRXQUF3MTM4dzBqTnJYbDVnbExDQVZyUVZjWVlMUTl0VmluWjh4T2pQWGZFcmI2SFJBU0ZHeUQwZFBaMUlYQTJmRjRHUE9ySFVkWm5zcE0yblB3UGxJTUJGMEh5eW1DZERIZDZSQ1M3UmxoYTRWQytPcysyT3NxNXRTbzloTUhwNUxBMmhzVWF2bUhsQnF3eENXK0dqUWY3cVl2cVpnN2V3K1pwSXpQMkhwQlJhMHZyQW5PUXpCc2lIdXo5VEs1eXloNXVPdTVGaGRnY00wOERiaG1XRDAzWDZhU2xxdGo0VXdRS3ArczNORGVMU3FodnM0bHB0UmR3Y2VOSXd1Mi9hVjg0MmpLemV2MlpPU0c1bXdxRDVUdUhhSHVTMG9mZWRtenBIckNKMVByZkU1djJJbVFhaFdrcFdiSzBoYmx2YVM4TE1HMHdMYW5RYXYzSFcrWmFTdFhlQWpsd1lsRDFERmpNMlpXaTIwNGQ0K0oybytZT2p0QU95Q3FIU0RFQ24xQmUzNnhHTjZTbitqNWpROVc1bml1SHRhUTYvemUwRzdPVXJ5ZjFEQVhXS2NXOXNHVDd5cEc1bnhGZ20wTWowbCtta1Z6Z3NkMi9xTU42d2lxMjZ1YmQ1UzRDM2lZRk1qTXFzRXFjSUpQN0swT3NGbFZGcXhMMEZZT3o4dzNBWVl4TjZueE8wOG5iSEtTbFo0U1BoRDFMNm84c0ZXUDNwcSt1aHV3THAwOWgrQThIZUs0eThCTGVmZU1HelRIQWJyTk9ONERmdXNJVm4wRGxBN1pwZ2VVd084ZnNxclAzT1gxdzZNYUJYR3UxdFhUcHAwbDNTbnU0RlRydTZZYjhZZkp0QkFNbmdGMWw3WGlJSFlybzZrVnhnR24yNEh5ZnJBWE1DUGJWK0lBTzh6cHRLZzVsOWhDamMyeEVXUTQzUEVwZ1lsa1FlRGVJakFhQkdkZDJVOHZzelpwU0NkeUdkbUViSUtEbWZEdWVhbWJJa2R3MWRYMGpyYnRWSjBaWEMwNnA2R3Ird21ra3NHR3czSjFJYjBvRWRrMGU5ZFUxZXhYTDBMazc0NnhkTUxEK1kxeXJZeG9NQ0ZzQ0pzbThFMWhhaHB5OXZxbEw3b0dJWVRoWUhyK0kyTkpTWWpwaU9JTjNJQ3ZWMlAyOVIrSmN1bDFhOFEwalRXWU84RGF1TWQ4RVZnUWVUK2dpMHJ6TmdhUWMxWDFXYXYrR1FOYkdCbHM1aUhrZG4ybExhdmF5ZkVlbzZrVnhkWWwzQnNXMFBUbVpBNHZ5alZLc1VBOW9ZT3NkS0gwZkE2cmlvVUFRQzBMUVF0WUhzOFM5YVUvd0FwVGZnTFhpQTZJT3lUbGM5M3FtQ0Yyd09BMERvWWpnSWkzbUxUZkdpSUd1TE5EZzRPQ0k2YTZGYlRHODRYVmRBNWp0ZHF0N3czQmFCOXI1Zmc2eFFiaVVlRXpzYWFwNDJEMHk5RFdEcUNiUFR3dkwxYlpiTE9teERqWmNvWUlMdCtTTFR3R3MwNTVWMHQ1MjhlNHRRVnJyZXN0Vk43ajVtWllYR05KK3NiVEMzVnZNS3V3MWRWeDk0MUhSOFJMSTBKZGJ6ZzlLZ2t5UE1wUlZOajZrdU1OdGpIU2JzYXEyNm9VN05aYTgzRThQS3BPNXQzaU42cTNGY3dnQ0MyaDVUN3dpeExCVG1Hc1JBbEt4eVRWaGpmVjBKZFZyMUNQWEZJeWdGOVFhbUpNbU5qaDVPamlYdThtWjhocDM5V0JqSzRFZGtHanlOUFNLNlhwQlU5MjVxZmMxSXBsNEsycG8vazVsazVXTFJnemFuY2tlbk1ybEt6STZOdDRRT1U3bThDczVyV20wVjFNb0JtVnE1ZGdNSHpueEd1bXZzajRxWVlIQ2RETXFKS2VBL3Uvd0NYK0tUak9qVDJsMnB0cER5cjBldjNFb25JdUVhRlR3UmR0MlZHRkY5Qi9mOEFDMXVqV0FHTkkydDlCdXk1R0kzd2REUTh3c1p0QngxamhTM3p6QzNJMk5adFE1ZWRZUEoxbVRPWXhlRmhGNGdLMWRDYThhQmZYcGEvOUdJckpLc28yVlhYcHV3clM1T0VQdTZUWFd1d0EwQTFYcEFOTkw2QWNPaDdsNEdYWnJBdW9MaXFoRTF2VjBRalFwWVNIckJ0NWlWQXR2THpQTDJtaUZWK0VxOG1uMHl1ZXlvT3JXdERWNVg0M2x1VEtPbWVEWit1MFlVampYRXhQTkkrSmwxVllQQlVOdFN0dTJZMEZTV3pPZEJmeExDMVlHSzFSalliTE11TVBNWFAwcWtHa2loZS9YeE1FRGM0WDNKMDF0dkxUWFdPRm5zMWkwQmMyc3ZHME1WbW9DVTA3TDE3eXNZbWxDMHptbzI4VVlsdmwwM0QxSXZKamJpK3dkZlFscVRURW8vdGYvRUtSUUZiTms4NkY0ZFNXcVdhUG1IYlNpNlRMWHQyZGU4ZFpJeFR0Q2RMcGhXM2FBNFAwUDRyRG8rWm4rOU41L3BNbzNpbXI4QjNhZmVaWHJKdnRYK0MwMjBiK3Q2akpWdFcxL3hOWllKMUxPaVIwTHRDNjZkako4L1dJVU9wQlZOWDBnNUhaRHBMaFc2b2dEVmdBUzAxZVdPQzl0SUxOQk5uYmU5MFBNVXRWRnNWT280T2h4RmJEK0R6R3VUTWFZZ0RWYTRQaVVRTlZVdS9iR2g4bTZ6UXlGKzFwdjB0OGpTTUs0WWdMUUdBYkJpQ2JGSlhianczNnNBdE1jdHUwYmNxdThTY3kzZHE0bGdHNmcyOUgxWW5FUnRuWWFFczErc0V5NUNsampGQnYyR05ncDdhSUUrK0ljRGFhTXpocWJpYkh3emlZUnl2ci9Ydkt5emVWM0VzS2pWaHNPTVJMWHVHdkVZdmlDT0hHMTBldW4wSGVLdFdUa1dTdFZydVdqQnNBZGlPb0VUVWlWRlhtRVVoM1lldlNGUXVXM2g0WWFSN3J3TENmcFVHdFIya3BycWllRHJGS0JrQStEL1h1Z0RUaXdRV1Jaam1hSW5NbUp1TlNKVHNtYjRoYS9VQ1k2TzEzNjk1VXV5OTZndkRHdm1JamJUZm5yR0VaV0RSMWxicjRaWE54eSsweC9JUGZSNlB2TmxHbktENXF2Y2RRWlRhTUgrcityOFJ6VkgrUzNuY2dYRGgrOEVyUVNnQ3ZxZEI1K3NCa2FSY0Y0Lyt6S1ZHYjFZWmxRbStuU0ZydExPdFlNSzJQVmg4aFpqUUF3Qk5lWmJhM2VKbWhwdEdDZ2hGYU53WTVleDE5U3FhNlRTeWJkR3IxaUpkQTNZSFUySHM2YVJteEtPVzlQN2pZTWRlRDgrSXY2aXBvWUtCN1hnT1hCRWhnM016OExmNmNYckFXVDNoZURucnJDMS9NQ0JmOEhHNmlWMWVTeFhUcWpCeGE0bHRYeXl0UWF2b2Fma2duS1VDTTBybkhVY2RYdVVLVEQ1T28zSDl5bXF5NHo5MXh6SFlhMHVVa1ExRW9MYXdoYXpyTUdGelY2VFZQMFN5WDk2dlZUWGNMWGJyS2pTTkdXanFuYUFVOVRjOHh4aXFPM2tOVTdTbFJRQ3F6bENyczdWY3dwdUkxQ3hHa2RrWjAyUXQ5aitEN0VJN1VleEpoMFdxNFlpOXc2ckk1VjlHdmZXTE5vSWt3UjNtSERpcGs5NHN1dHFRcWhZd2RyeVp2dEZvemRjYnNVRG9kZWt0VmIvU1ZKR3Q5c2hLblVIQkQvM0x6UHhpTHNEdjFmMzRnaGM1eDZhZk16eGR2QWZ6di9nZ0pOWjNXVHN6TGY4QXFGVFgzcE56MW54RXN0MnoyZ3NNM2hqdWN2TXhoZys0YXU0TnlFQnl5MjQ2cDNkZnNPa3hPT0E4Y3NyVWI2dk15dWN3akZvK0p6aUVGZVZaKzc1blNneUp3V01kL3FRUVNxamR5ZGhRQmI3dGg5M1BHUEhUckRDR2lhaDhpRDVZaHFDMWhScnFQaU4wbUZreHNvMyt3dzY2eEsyNnlyL2dXM0R2QU1KcmdpSXN0MHhyQW5BcWpRSlMrMTNIS0cwN3l2N3RDRjdLMVZHZEN3VllpcWJwWU9oenNZZ3ppSWRYb0hONXZhbzBBRllpR05vbzlyaVdIRVpxMlgxTXlhZHkxU3ZJa2JLaXJFR3YzYlJYVm5ZcVhXMFNsaG9JR2tnekc3L0F2eWxkbDBTY0lpYUowbXJwSzVONG41c2R6QVVUQVJjbUlqVmtIczE5b0lab1l4ZWtMMEh6SG91RUh0YUlVclRzUmtibVh3V0lFS0RWVnhTYWoxdXQ2ek9LU3k3Vm9vd0hraWlGeFVicFIwU1dRa2JHbks2ZlZVQ0tWVWlVblZGZUV3TjFCS2RtOGlwbGIwZ3pxMEFOWE9EM1VlRDFVYnE3OTM0RXlDMjFoWDhMMUEvNWYraXBXM3A5REtsenhYYVgwaGJON1ExWUNOd25KNHlTNzBCanNqMC9jSUFZbE9oQ2lzZDhYZnU2ZG9yUTNFdGFJcFFjRVdNMC9nWmtMSmdnUmRBbmhQQWV1aWNzOG9IMkowVjBSeUVIUkRMMk4vcEhUcGRHN3ZlNDVYVnNVZ1lCYXJzRVBOSnN6V3FhWWRsdXRhaTVHSUFOZ0JnZENMZUpjd0xZSDQ0dnB5dXhGS24xWUI0K2tXaVdRcVdpQldVVzhCeEE4RE5LVlhzRmRIRURKVk81YlgzR2V4aURjMlNMU2RFU2FjTEhxL2xldTAwLytYSzdBM1g5eDFuVmIrMHU3QW1NM0ZBYXFPb0tHODRtTU9YVE1GTldVT1ZRc04zTEV6Z2paVlMyZ29EbGQ3MXVaZFY2aTdPM21ObWRhWmtkNFpkbm9TaUpNWGlIRHVWRkkrVjZhTzVBZGN0cXlySTZDckN6dExyaERRWFpsTTBNeS92U25tRXpRc3VxbG1iTENOOVhWZmJEdVRKQVNRL2Y3aTE3N294eWd6MTdEcm83TzBUQVJBNGxPakc4eHRUSitrSG8rMThPOFlJRnJ4ZWEvdjZ5dEhVZWtFWTJkWmJkWjhCMW5vejZpNHQySjJQQVZHcGNMTmJFQzBzOFdsN3Y4UDhBa3hEZ2lzcUd2TU9oTTVsMUdoTGRENmg5SlZOTytrRTJNdWJtZ3EyY25ZRGZzTy8wbmJOVGJwMmhxbVcxNnhaQmxoekJEc3J5amsrZ1l3NjlIaDUrNDI5WTNMclYxQ3YxbTZlYnUvZDhkNHJWSzR6RGIxaE42QWdZSGVZaFlENjdSa3pzbWVRT2VwcTlKY0ZxaTlhTWZNTXM4eGFBRlhRQzdpTFJwWHJCNGlGQXRrcTdqMWdkWWtwS2pGZW9aOGpLQkNxR3RKV08xcVREUmxXd3ZQMW1XclBsUVdIVmcxUk1qbVhRRGwwdmFZNFkxZGRnMVZHR1V3VytvNVc3NmphVzFLaXBtS1JNWjd3TkxXTFAyL2lOOS9wOW93Qlh4K01lcWluVWlxNHN5bDkwSUFVR1JIVzVRT1JpbXp1T0lpMzAxVmZucVBGOW83dittVURyeDVpcWpZMnFNQXV1MHhlTk9TZzl4VVU0eERUdlJMelB2KzBWUHZGcEh0eE1yTEE1VjFMQVdST1QrZ3pEV0g3Qk1pYWtLbWVod01NSjJXaTl5TWE5bEdYdWxYMGI0YkpoKzQ5SzdSRjZ0Um1XaHZ4V2tZRUdoMUFPRWVqREYvNUtPbzZ4ck5TdHZlWmQzTzhhdVp5QzRJbndjZmRjM1hsK0J6TUZMYnJjQlV3ZWJtS3FxMnV2K29UVHBsN1N3azBUMlFWMERiVzhQa0dSV200SDFPa3FpYmxrRm0xUlVzaGFhKzc4T2t3b2c5T2h6QkNtRFU5SzRPWW1CMVVtTEI1ck5uQVlYM3FHU29NUzREWTdIQUIwZ0hnVjBYMkRZNnNkRHFaVFBlMWZwMGdXWG5PczZQajJoQkUwVUN4Vlk3WmVIVnhMUUlFcUx6NjlkNEF4RzFzUTRNVmtpSGZ3bWVvQlUvZE1IbWVpT2w1RitVOW9iZGFoUjhCZ094S3QxcnJMQ051ZUpaQzFFWkJ0bUJBbUhQYVlKbDNwc042MkptVkRzVTBOeGlobVVoNnpuVmVmRVJOdm1YZFk0N3pQcmsxWTNZaU9Ldk9BOVE5bkRkSytVSXdYYjVSUVU2SUMxdGl0bmFSYzZIUHdtTEJEUkxFNjh3d09qS3ZmVjRLZENiUVdIdjhBSnAyYVp3TDlLamJldFFGM2RDOXFtc0NDbGp1YW5xSjhDMjVvWUV3MXJFRzdOaGc2MnZoY1ZHWHNXTEtnSE5Ebzc4elZXeXc3bCtmQVJNb2JTOGF6Q2FKUkhwSThBSUVCNk5ETWJHaFZUWU5YMFpYQUZVYlBFT09zenlvZkNEMmRIM3RCQURYQVlhQTdMbnBLNnkveHIzTEE2dlNCS3dsb2NCMENpRUhkeXpiRDA2dlArdGlHcEJKYkd2NHlvTWFaL3FNV1ViNG5iMTlMbWtrVnU3aUlUUXNmcnEvU1ZvQWZTTlk3YmRKZTZ3QTJkV1BLTjRIV0RMYWcwbmxjOWEzU3BhREhBTzR6SWRQc2R4OVhQYUpYWm1RckZER1dDdFRvQWFzSFhRaHN1VTBlTFJ1M2laaXR4ZXBvNEN0aU8yaWdhQ0FMTDFMb2hyeUhhRFFIWUR3MmVnWHJIYVphcWVXVUN3SFZYMW04SG12ekxndWRpR0ZVZDRMR3lxOGtLbDd3VmFyREZLKzVNcGxDcmlvSitoeGpqTE1kemE3Sk5TRVhtUE5DTTBaT1plQnkvV2J5elpwWTI2ejNMRGJScnZBVEVSTkpUVGhIVVRST2pLbEMyd1c3dkhwSjNGcDZkelVpRGxBS3BQTXN3MnNVcjMwZk1valVXblhwdjRZcVZScWo2bXBNSkEzTUtMQTRQMXpIRFF0aHVVeUFDdkFXb1dUaUpTalpqRllSOUdzdWcyaEQzVmdQREZ6TG82QTB1eW5OVHNta0JHbFVjSk1GdWs1RWRjdHZ1TkhwVUJ4VnR0QTNYUUpjTURNMDZ2YTIrcXhGMGFobU16dFVkRVhQK3hqTDZuZUFDdXVYb3hEUlFJbk16QldpelUwK2Rla1EybGE3OGZ3SjkwUkxXYmFyTzdoZVRydTdIdVVJem9Mc24zL2dTWUpVdTBMa2xnUGwydWFiY05MZ2YydDAwbHJxaFdsMWh6dGVXRjAyMVJ2eG9QRVhERXJTRHFaZUtKa0UxemQydjl3Mjc5WjlROGluditqYVhMUjFkSUpNTTFBZHljRkF2REFHMEhIYUZ1Z3NYN1NubWpVL3h4OW5McitDanFUL0FIVVVXWnprUithSys1OTVjRGRNcEF1aHJaRlpHd1FlSlFQbnBGZU5YYVdwWnd1Q0EyS3lWck1Fdzl2Y0pzVnZvZlc4Y1l0S2Nja29GQjBYSWZLYWJsT29CZE9qZEhHa0dJTnFEQ2Z2TUpzektocVFkSjJCM0NwV2xRdExIUVdCMWlSZFJ5bDltV044eTl1cFlESDF4ZWxYWnc5SlNMR2VNUEd2ZWphTjA1Vlc3VzFZRjRUSW42Um1WOEIwam4vWmRNeU5kNmt3YTN2NGpPa3ZpcXg4YndnQzVWcmZsMTQ2UmJydTREdEdGd1preWJEenJEQm1xL2k2SXY3VVM4MUE2SEx3ZFhFc1E0bHArOEhRckV3QkpsYTN1TDhEek1uaHM5b0RLNnF3NU9kZ1d5c29QKy9zUW9rOGxlWFR4TEhIeXdKdE1KZzFRN3dNQmZXT1NkWldVVkEzYmU1bDlJM1lnK0g3VGF5bUwyVEhxTC9CK1lxNW9kNEZYRS9LQ3JaQlZMSFovUmkvYnJOcDFoV1k5MExYZ1g3UjN0Y3ViajNZTDRKYm9BVEtNekRGK3Y4QVVhTGE4YnpUUUIzWlo5b3hMZW9PTDFlR05GdllIOE1DcUkwYWtJRE0wYU8yNTRsdFZYVmJxV2ZjOHpKa1R4SjNYZU1PNHk4M01WbS92R3JaMm1LbXRSYy95T0tsazFjVGhVcE5IUURlblRsZWpGRURDWEE2RHQ4cXhMeVc4RzdLUXhXdE9lUDk2R20wSU56dCtJaHNWMEl0YlJCTmRoT3ZIbm1HeTJIbzJpZnVzcWxnN25CNWFqMTJ0cnJGVVNwaTcwT1lrZ1JkMHVmcGNETUdrNlpyU25VTmhvTmdnaGRyT3V4Y0VzNy9BS0pmbkF2ajNCa3o2aFM5M1ZsVGNEQWlCYWhEcWpjUzBXTGd5bHB1UTNYT1ZRM1RBTlUrelErOEZodEpScmRXZlNKYXhlWWI3a3JMcXlJNk9Rd1h0NGc0SWJzZzYwdE1XZzNQT2NUcGNkWVV2dkVxN1A2TXFnWUJ1MUFkR3FyemlVSUFBOC8yTWZHZkZ5bFpCcXRZdWp2UW1haXpTUjdsR3paamxyUXpOTU1IZ210UUtiN2ZsTmFHL2RoQ2lXbjRRZXJjVG41Z0ZKNHpHRzBOcnozQ0liSFNyR3E5VnhtV2I5ZE4wWmVmZW1rY0xhdG1HWlVvV0hXQUZRbWFjTjh0TmVYYUJhUFdLRVl4OTE3MVdOc083TXdaNEJ0MWlWYnIvd0NCN2JhK2t6em8wU3dpT1RSaXFsVnhPb2VqOXJpMXdCRE5tUHo3aXNxb0JWN1JhTXd4L29aOXdRQU5wWitwZHhhQ00zSHhzZUlETm9Pc0lvdWhXeUYxU3M2QkJOaWE3L2dEYXBMV3I5NWRXMWhKb3QxamdaRjAzYkhsUWdXZHVBaXNZRjJLek9sUUxxZXV0T3ZuWHpNWnRTMkI1VjlTQ0FORUtibEx0cldOWTV5MTJueTRjRTJpQ3c3V1ZYa2h0L0JXN0ZLOHFQWlhQQWFxZ1FlY05QTHBRNTdCakFqOGt0bU43ekhrc0g2QW90ZzJWSmxVYW1yMG85NVlaVFVSNXBsR0tJYzBvMUtMQ2NwRnVlNHhFU2xWZkFyN1RBdlFCS04wNzB2ekYzdFNJbzFjczY0SEdWMWRrUnF4bmFlcWNqbUttS3FLOE5NUW8zVk9XVVlNY2Z0RUpqWFQ5K2tkZ3ZwQmRoZlNXUG9kSm5xcDUyaWlBcHZlZGZEcXI3eWdkQ05MMzNlSUVFOHJuM0RVaEluWkxseHlkTjdvRXBjVXhjTElkZGZHeGozbEZ3aGxyZm9SVThYdHgvNHIrZmJmcE1SYnZFUnRFc1J6SFFWZEFJWUM4WCs4UjFBOGZsbjlGUnprZmJIZGY0blEvdXhHeXJ4dEtTQ29UVlU5eG5XSXpTbnVGWmRSZE9YcEs5cE5uMzFkRDNEYUtVT1F2SmJCYlJ4RXVOQXF0bCs3Nmh0amFNaW9wOG9mRW9aL1k1VlQ1Z0Y4L1dpMUs2RDhSbWE5WnN2QVBlTkMzZlFSVTlDeFdYUzZHVm9NeHlVQ3Z2ekhoZUdneHJhc1Z1NjNHR3liZTBjanBOUUhYd1paM2E5cFh5VzhBcmw0YWhGQlZEb1VvOS9XWEt1WmYzRmZFdjdOZXVjdm1MWDFuOEQ2TWIwWmxVRHI5NUhRZXNVLzQ4REx4eFlJOVFqaWhCakFGMGRyU0h0QW5Kb3k4RkZSV1FMTWVmckVLWXVYTDQ0alJnNEhTSlc5dGlXTFFRSTRPcmFMb053YlpyQmUxU0JQVXlod0ZLOHV5YnE2RUxVNURYaTRQQnRxelZLMXFJdWxybVdLWU9oejEvd1A1ZjhBWmNRUzlkSHJDcXlzMFlEWHdONFFVTmZqcWRmcjNnMWtEV2NWRmMyUUFnVFNWQkxjOUpwc0hhQ2kxdk1wMzRKeUJZcXZzYXZpSWpyQmp1eHEvRTlPb2ZnMTh4RGM3R3MxK05RT0MxcXNGSGlZWWF0RVF3TlZ1T3QyTHFXcFVLY3RIVTd6VjZxRTZNeWxlSDJ1dnd3MWMzUG1VSGtaZWpNM1lMeS9DS0N1enM2Q2NXbWdkMVlHK0Fvcm9QNkRubUt4cVFaUTBqQW50YVp6NnJVZURJNjBETjA2MnErWW9KazN6eGJ5RnlaWVFURnBtWnlQV0k2MCtrTlc2QTM0Wmcrbm1oZUc5a3J2SkhUVmUwd2pVRDdxVldBS3ozVVBNRTR2ZnhaK3MwTm01ZGo0alRJL2ZTTENuY05UeEU2c1JFeVhpVlg1eExOeTYyMWd0b2FCckF5am9rQjB6RVUzWUc4SDV3KzFkSTNHSWEyOGZ1V2RBdFlwRjdVNnE4eE0xeGpkNWpjUDl6L2lLckdvNlU3Ni9tQ2FsOG9tQTNDY1J5RjIwUWNuWHI3NWdvNjBRVlR3OFFGRjQxaEdXM2dpR3hLT0pqMTloeEd3TUdrTTd1aDdqeE90TmQ1Y0hnbW9WNVhzWmlaUE1Wclc0b1FPNG1MUGtjOWxBS0FNVTc1OHlqTzN3elZ5ekZtRGluNnlrdzRBSmZpdDdKWmwrNGltdXNyY0RtQVdUa3dYanZMQ09uVllLd1pqVmFMQUZhYzZQYkxJVzF5T3VyTHFrMHUwY1Flb25xZURxb3A1TTdNVTNrMEFvV3J1UmFPM3lFYUFXYkFEQmlWZm5UVGpyYnNtMmVZWjJuNG5ieGttZjZRa1dRWm9QS0dBM1luUXdmQkRGYXhkUEFjMEFpcWRZZEZjdlJoWDRoa3VFYWJJRFVldlYxcU9FMzFGWE1MTldCM2NRRUpSdWF6N2dwN21wQndISGhpVjFobU4yZHBSQ0V4YnFROFZrYjZuajd4allnZmRpU3pydmUzQnl4ZWRGZHMyL3JYVTBZVndZZnRHcXlndkJlaEcyZGNQK2hoL3F2OEF3U3JOWVR5NUgyaFdFYkhTTUkwQ012QkVCb3A1L2I3eGV3MXUrOXlhK2h5emtoT2krMjc0aWtCYWF2ME5YNGhYYkw4WnI1dUFhVWNTM3hTRHRxb0c3QTdJaHlpbDdwV3ZINWVaWnFMa1R2TURyTTZpTkVpN0E2ZTlEYmVib3Z0RlRkckJZU2tsMGFYbnJGUTlGVWV2dU9FWmhBTTAzTUMwQUYxS25IZUxXckZQVmlpdXBvVnUyOWQ1UjF3RjlHaVh0RUlreUxiYlhkanFsWEE1cFRTUThqWnNVYTQxMGcwTVhVYmErREFGcTI1VTZ5eTRxTFlsVWNVbWJDTkVGeXExZm1PbzFYSUhzM0UyL2FLT3F4R2RBbVNncHBlSUlXRytsd3V3OTRsalI4WmxBRFpBZEVkVm8rSlF6SjN5SmlzamtqckJZWXlGYmdQZlkrcnJMMG91RDBSeWJlVm5BbXZqNVJxcTZzWUNyT1JtYi84QW5ZaUV4MWh1SFBUOFFTamx1Z2x5TEUxSWRHQyttZW42U3BRbXRUeU9NOVVUMzhvbXBYMmdoa2dHaFBPQ0pYOExyYmtOM2h4ZXM0eFU2R3Y0V2RxQWVjZmFCV2J1WXlMdUV6RGljTGQzak1HWVprZUlwdFFTOVNyT1JKOE10SU5WUG1PdjJJNUdHNGVjUVVqREVhc2JSQ3pxUmFCdktIcUxnWEoraDRqN2djc2JBWFhSMjd4UHU3QmxqdW15QVlPaE5RQzhoclVNYWoxMEphS3NLRm8xVmNnYzAyOXBDMnV3ZXJ2YjQyQm9ieHBhTHZMK1lZV3ZZallYai93Yi93Q3NveWpKbnJvd1d4cnB1UXE0eDJsQ2VBTDJYcjk1bDU4bVI3dW5YNlNtTDJOanR6TDdhOFNxaDVacngyM2xTNnhLczZRYS9lQWdseXFXNFl6bk1MckxLcWN4Q21tMEhVNFlPUUFVU2tnekJFZUtVVFNnditLMDB2OEFFenBKYjVpT2NJcjVDSnpVNElRQWI1WnBMaENxR0JjUm9pdTBJQnpHMVd4WEZUV25NUXd3ODd3TkJBNjl2TXVVOUNPeHZMS3J0NWJXQlRPZGd6S2NLZUdQNmR0WUN1UVYyQU5ROU05dFlhVnRCQTB4K251NWQxMDBtbGRZNnd2NWwzL2cvd0NpNXY4QTVQOEFpZjRieHNmQm11TmQrdmFXSlNMRVlMNnBZOFZITzQ4UnZvOFk3UThleGt5Zm1GUzJIZVlNY3c5ZFl4TVNvdHJZYmp6S3djeXEwbUEzWXYybjRJc0ZvSDRncitDMWxRUDRhRk4xSnV4U2tWL3laM0Nmd0FjazN1TVJNQjZNczdFcUt4VUNyUmlHRUhYVWxCcWJrMnd1dGZFOG1KUUFtdzBlTjVnVjVKY1UwVGc5dCt4RFFpL0lDdUQ4eHE2YVBOdWlmb2lCZ3daUWNHeDg4eGQ5SlFhMUxISDMvaXYvQUR2K2JQT1IyNGxCczJIVWcyWlk1SU1PbTdWSi9jNFZzYUR6RmhkNGJUdWZpVkx1M0VLNEk5WWlFL2NUU0pjR0ZCZzhrZEp3MndXb2tPOVlqYWJFZ01ibUZhWk95VVJzZ2ovSEpSNlc5NDYvdy9RY001b1drdXZVelo0RDd3OVFaZ2FDcVVGUTJqVXdpUEl2eENLQ0R6Y050MFdEM0Jxa1ZzRkJBbkFIQnZFem10VGp1eGcrWTVGOFo4TVFuejBTazRHbllGN1JESmFMTmRWZnlYckZMMTU1aXBuRXJ4Y2RmNUgrR2Y1MWxRL3dmOTlpeGJscmEyTnRvU3BVMWJjMXd6VzB3cURxakQzSTRsaml6SjFtb2V6bEFjMXRLalg2RFdPNEowZDVadkZQREs1eDNqWUhMdExpOFlsNnQxR3FVNUxsV0pNQTRLK1pWUnZmOTl3bEdvT21WZ29wTC9BeTZMbjJUVkRjUDZHek1mbDErWlRZRVF0c3FWWXFPeGVYZWFOYXMyN3dJNndmYmc3UjROWXlsOWEwMDd1aEhSWVFOeDR2VjhUWG8yZ2gwMitjOUlRaDhtN0RWK0RveFJxOGEwNkhCMEk1emVodkFEOVk3Z2JpcnEzL0FMZy8wNnpUL0RYL0FFczBsK2lFTXJEVWRZQnZJOU1hcFpwMWdJdjd4ZmlGTWRQUGxwejN5K1B4S3ByTmNXZXRZa05VbnBGUUpLYVBGeWhpTTIwQmg0Nm9sZXoyVHVwcjNEVTJWU0xDUzVZZnhGOTJuOGlZNW1HSTZmOEFiTUJaWU5IVzdpeHZTQ3k5M01ERUZjUTJQTGNmWUxtZTFsZ0JRRjVmaUk2SndGdDdQdXdNQUYzQzdEQSsyTnJnWVM5UU9mbzZTdkw2RjZSZ2psbHY3UkJsdUNHRW00VWYrblNhL3dDNFViTVROamJuZUhTblBZMUlONUJCMnFVL3U0c1BjZ3JqNTBJZDlmMCs0VmI4Zlg0aHNidHFucExFMkk3UnJUNmdWa2x4SElyeEt6Z2pLSVlJVk5DVGk0U21HMzhHUzkwRnh3WEFKdmpERFEwTlhZanZkS2o2WnhXOGJnVGVVNk1Xd3dnTFU2QnJDcjR6aUs3YS9FTXJYYzhYd28vVkpwWkRRcjE0dnZjZHNXcjE0dlR4RUV5WExuMlZ2SHdNRWMvL0FDMFZqVHpFTkE4Nk1Kc3lic1E2NzluRVd3dlBlQ21qVUxEcUpUMHdyS2twT245N3h1bU93czcvQU54UUkxd1BweEM4ZHNtSHVIa1dObVhSVDhreis5SllRdENyZ0RjdlJnekppcGY0Qm5LSElDT2hOSzd4VWJjVysyV0liT2czZ0srUHlLaERMN3EyRHBzZk1zT3FWcDhuNWpiYXJDK2NiK1dlSXhvK0ZFNE5BMmxjd09CWDRtc2hlRE0waDRmN2QvOEFBLzhBZU5OaWpLd1hTWnphNDFKWm85cUtxbkR3d2haMW82eWxEUjlINXVaOUQ0L01VZFhYZDdYRTE0TUY0ZkRLbG9DaG1EeVFWMnd3WDVZYis4ZjhUSUtkVCtrVjhIbkZRSWxYdmlOdnFBdnhFTE4zcTc4c00zc3krNWc2K09WUG9UVFBEUlgzTFlEb2tLdk45Q0dLUjJCVHBabjVpL2Z0YjlyTXRKYWFtSUZZVzZTaGZjMldkaTVYU0RVc09EL08vd0NYL3dCYi9rLzZsTEE3TUlwbzlTYVJmbFFNQ2IyWE1vV091bVl0Mk84cDRqTllCbkpEbzlKb1lRNmhEUkwyaXVGcHhiSGtQTXJZZW8xZXY4VThRYXl0VE9pL2xGYnc1WmRzM1RKakdSNVdJSFFoNEZSV3BWNi8vWVA0dXVKcEM4eHlsQjFJTjlZcWFnZGh1Q2FHNFVxc1BVR3lNZElzMEVjeDBudVBHOXk3V2tLTkQ3Uk5ZNXE5bmVqK0FjU1p5ZEE4Q2EyUG1YLzcvd0QvMlE9PSIgYWx0PSJBTEtBSUQiPgogICAgPHAgY2xhc3M9ImFzaCIgc3R5bGU9Im1hcmdpbi10b3A6MTRweCI+UHJpdmF0ZSBsYXVuY2ggc25pcGVyLjwvcD4KICAgIDxwIGNsYXNzPSJub3RlIiBpZD0icHJpdk5vdGUiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlcjttYXJnaW4tdG9wOjE4cHgiPlRoaXMgZGFzaGJvYXJkIGlzIHByaXZhdGUuIElmIHlvdSB3ZXJlIHNlbnQgYSB2aWV3LW9ubHkgbGluaywgb3BlbiB0aGF0IGxpbmsgdG8gd2F0Y2guPC9wPgogICAgPGRpdiBpZD0ib3duZXJHYXRlIiBoaWRkZW4+CgogICAgPGJ1dHRvbiBjbGFzcz0iYnRuIG1pbnQiIGlkPSJ3YWxsZXQiIHR5cGU9ImJ1dHRvbiIgc3R5bGU9IndpZHRoOjEwMCU7bWFyZ2luLXRvcDoyMnB4Ij5TaWduIGluIHdpdGggbXkgd2FsbGV0PC9idXR0b24+CiAgICA8YSBjbGFzcz0iYnRuIiBpZD0ib3BlblBoYW50b20iIGhpZGRlbiBzdHlsZT0id2lkdGg6MTAwJTttYXJnaW4tdG9wOjEwcHgiPk9wZW4gdGhpcyBwYWdlIGluIFBoYW50b208L2E+CiAgICA8cCBjbGFzcz0ibm90ZSIgaWQ9Indub3RlIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPk93bmVyIG9yIGFwcHJvdmVkIHZpZXdlcjogc2lnbiBpbiB3aXRoIHlvdXIgd2FsbGV0LiBGcmVlLCBzZW5kcyBub3RoaW5nLCBubyB0b2tlbnMgbmVlZGVkLjwvcD4KCiAgICA8bGFiZWwgY2xhc3M9InJlbSIgc3R5bGU9Im1hcmdpbi10b3A6MTRweCI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0icmVtZW1iZXIiIGNoZWNrZWQ+IFJlbWVtYmVyIHRoaXMgZGV2aWNlIGZvciAzMCBkYXlzPC9sYWJlbD4KICAgIDxkaXYgaWQ9ImNvZGVTbG90Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgPHRlbXBsYXRlIGlkPSJjb2RlVHBsIj4KICAgICAgPGRpdiBjbGFzcz0ib3IiPjxzcGFuPm93bmVyIGJhY2t1cDogeW91ciBjb2RlPC9zcGFuPjwvZGl2PgogICAgICA8Zm9ybSBpZD0iY29kZUZvcm0iIGF1dG9jb21wbGV0ZT0ib24iIG9uc3VibWl0PSJyZXR1cm4gZmFsc2UiPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJ1c2VybmFtZSIgYXV0b2NvbXBsZXRlPSJ1c2VybmFtZSIgdmFsdWU9ImFsa2FpZC1vd25lciIgY2xhc3M9InZoIiB0YWJpbmRleD0iLTEiIGFyaWEtaGlkZGVuPSJ0cnVlIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwdyI+CiAgICAgICAgICA8aW5wdXQgaWQ9ImNvZGUiIG5hbWU9InBhc3N3b3JkIiB0eXBlPSJwYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJjdXJyZW50LXBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iT3duZXIgY29kZSIgYXV0b2NhcGl0YWxpemU9Im9mZiIgYXV0b2NvcnJlY3Q9Im9mZiIgc3BlbGxjaGVjaz0iZmFsc2UiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJleWUiIGFyaWEtbGFiZWw9IlNob3cgY29kZSI+U2hvdzwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBwcmkiIGlkPSJnbyIgdHlwZT0ic3VibWl0IiBzdHlsZT0id2lkdGg6MTAwJSI+VW5sb2NrPC9idXR0b24+CiAgICAgIDwvZm9ybT4KICAgIDwvdGVtcGxhdGU+CiAgICA8cCBjbGFzcz0ibXNnIiBpZD0iZ21zZyIgcm9sZT0ic3RhdHVzIj48L3A+CiAgPC9zZWN0aW9uPgoKICA8bWFpbiBpZD0iYXBwIiBoaWRkZW4+CiAgICA8aGVhZGVyPgogICAgICA8ZGl2IGNsYXNzPSJicmFuZHJvdyI+PGltZyBzcmM9ImRhdGE6aW1hZ2UvanBlZztiYXNlNjQsLzlqLzRBQVFTa1pKUmdBQkFRQUFBUUFCQUFELzJ3QkRBQVFEQXdRREF3UUVCQVFGQlFRRkJ3c0hCd1lHQnc0S0NnZ0xFQTRSRVJBT0VBOFNGQm9XRWhNWUV3OFFGaDhYR0JzYkhSMGRFUllnSWg4Y0lob2NIUnovMndCREFRVUZCUWNHQncwSEJ3MGNFaEFTSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCei93QUFSQ0FDd0FMQURBU0lBQWhFQkF4RUIvOFFBSEFBQUFnTUJBUUVCQUFBQUFBQUFBQUFBQkFVQUF3WUNCd0VJLzhRQVRCQUFBUU1EQVFRR0JnVUtBUW9IQUFBQUFRSURCQUFGRVNFR0VqRkJFMUZoY1lHUkJ4UWlNa0toSTFKeXNjRVZKRE5EWW9LU3d0SHdVd2dXSlRSRVk1T2lzdUZGVkdTRG83UHgvOFFBR2dFQUF3RUJBUUVBQUFBQUFBQUFBQUFBQVFJREFBUUZCdi9FQUNzUkFBSUNBUVFCQXdJR0F3QUFBQUFBQUFBQkFoRURFaUV4UVZFRUUwSWlZUlF5UTVHaDBjSGg4UC9hQUF3REFRQUNFUU1SQUQ4QS9BTlNwVXJHSlVxVkt4aVZLbFhSWWtpZElianhXWEg1RGgzVU50SktsS1BVQU9OWXhUVXIyWFpiL0ovdWt4S1pPME1qOG5NWTNqR2J3dDhqdCtGSGprOWxhUjI1K2pqMGQvUndrUjVFOXZRcWFUNnk5bnRXZlpUNFlwZFhnbThpNFc1NHhhZGc5cEwyZ09Rck5MV3lmMXEwZEczL0FCS3dQbldsWTlERjZLUVpkd3RFUHJTdVFYRkR3YlNxdERjZlM3YzdxNFJhckdyWFFPU2xsWjhoZ2ZPazl4Mm0ycWF0S3BjMlVtTzYrK0k4WmxscEkzaUJsYWprRTRHUU84OWxhMkRWTmtUNklZNk5IZHFJZ0kvdzRiNnZ2QXF0MzBVUTBqMk5xb2dWL3ZJVDZSOGttbSt6OEc1Q0ZjN3Z0RFBsT1E0cldVdHR1bEJLdUpPbllNWTYxVXMycmhYV0RjMjEyMjRTQkJrTXBkYVN0d3E3OVQ0SHhvV3hkVXJxeFUvNkxaNlFUR3ZOa2xIa2xNb3NrLzhBRlNuNzZUWExZVGFTMU5GK1RaNVhxNEdTK3lucFdoKytqS2ZuVGQyNjNxTzNGV2g1THdkM20xaDFBMGNUeEdSamlDQ1BHcm9lMTA2M3VCeFVaNk80UDFzUndvUHlvMnhsS1JnS2xlblAzMjI3VEt4Y1dZMHg1V20rNmpvbi93RGlKd1Q0NzFaKzViSE5rbGRzZlVyL0FOUElJQy9CWEErT0tOaktma3lOU3JINDdzWjFUVHphMjNFNkZLeGdpcTZJNUtsU3BXTVNwVXFWakVxVktsWXhLbFN2WGZSTDZIbDdXYmw2dllYSHNLRGxDTTdxcFJISEI1SUhOWGwxZ04wTEtTaXJablBSOTZMTHh0Ni8wclE5VXRLRmJyczExUHM1K3FnZkVyc0dnNWtWN05NdmV4UG9SakdCYVkzcjEvVW5kV0VLQ24xSC9lT2ZBUDJScjJjNkEyMjlKOHRUcld5ZXcwTG8yV2toQmxOSUxhZWorcTExSlAxK2ZMck9BdEpzTnV2Q2xTV1hiUGRpckttYnNrdngxSHJTNm5DMDU2MUJRN2FYbmtpN2x2TGdhelhkdHZTV3NtNHlUYnJVclVSR0FVSkk3UnhWNDVwM2FmUmZiTGFrS1V6MHpnK0pldGFxTmZqQ2p0dXo3WTR6SFdQWWx3MWlSSFYyaFNlRk1HcnhBdUNmeldZMDZmcXBPRDVIV3RZTlhnU3QyRkNTR21Xa0JSMFNBSzg2MmtkYnVXM2NhMXNuTUcwSjZQc1VzYXJWNHFQeXIyQzZ6bTluTm5iaGRuUGZhYlBScFAxdUErWkhuWGpIbzN0eXJyYzVFcDBsUmVjM1ZLUE1EMmxtZ1pQczFHMk1VQ3kybXhod3RHNXlHMHZLU01sS1ZLQk9uaWdVcTZNU2RtbUFwZlNPMnRaWUt5TlZJQndEL0R1bndydThUMVhUMGxXdUlEbERNeGx2SExQU0FuNW5IaFZWaGVRYmplTGM1N3EzSEJqdVVmd0o4cWpyZXJTYzN1djNOSWdjWTlaZmtRa25kVklTSDJEOVYxUDlSa1Y4WTNKY2RLeWtCWEJTVHlJNGlxN24wc0Y1bHdIRDBWM2RQOStIem9xV2xMVWdTbWNlcnlRRkVjZ1R6cTUxb1Z5N1F5OW4yQURReURPdDJpRkY1a2ZBczhPNDFvMm9VbVNCMGJLMUpQUEdublZjdUNtRWtxbHlHbVFPSUp5ZktzR3hhSkVLOHRkREthMzkwWTNGSERpUHNxLy9BRWRsWnk3N092VzVDcExDaklnNUFMZ0dGTms4QXNjdS9nZmxSY3k0UTFQWWlOTGtPamdzK3lCNWEwZmFMeEpRcjZVWWNTbkNsRk84aFNUeFNzY0NEd3dkRFI0R1ZveGRTdGJmOW0yVnhYTHBha2JyRGVESmlaSlZHenB2QW5VdGs4K0tTY0hrVGtxWWRPeVZLbFNzRWxTcFRmWmZaNlR0VGZZZHFpRDZTUXZCV2VDRThWS1BZQnJXTTNSdHZSRDZORHRwY2pPdUNGQ3h3MURwTWFHUXZrMlB4UFYzMXZ2VEx0ZGM0K3o3REZpYVN6czkweGlPUzJTTjF4U1AxU1FPRFl3Um40aWtqZ05iL1NKZjIvUi9zckQyWDJjQmJrdm9ES1ZwMExhRlp5c25rdFp6anhQSVZSc1paV0lPekIyZHZDMVBXbTdqY1Z2ZjdQSVB1cVQxQWtBZGlnUHJHcDg3bk8yMzlURWV6ZnB4Y2xKWmk3VjI5RWxwQUNFVFlxQWgxQTdVOEQ0WTdqWHBLb095KzNkcHhIWEd1a2RJeU1hT3NrK1JTZkt2Q3Joc1ZQczc4aVBKWVZ1c09GdnBVNnBQVWV6STFHYTR0VnVreFpRZWdQdXhweklLMHVNcUtWRURVaWcya3JST1VvcjZvbXRuN0ZiUzdEeUhKZXk5eGtMakhKWEdQdkVkUlFmWlg1Wm9TRDZRYlJPWDBWL3RKaFRBY0dYQkdBRDFxYlBEd3BqWi9UQytRaU5mbzNyRGZEMWhwSVE2TzlQQStHS2MzVFp6WjNicU1aY0Y1cDkwREhTTkhkZFIyS0g0R3Rma1pTVC9BRENYMHJiYXhieFo3WEJ0OHRxUTJ0UFN2T05LMFZ1NkRJNUVuSndlb1Zic0l3YkRzekl1VG93R21pclhyVjdSK1FBL2VyRFhQWVM0MjZhMnlsQmZqT09CSmRRTUVEUHhEbFczMjZuZmtIWXlKYmNicnNwVzhvZG1pai9JS3oyUVpiS2tJTmtWQ1J0M1laVHF5cGNtWXc0c25rb3ZZSTh4UkxiSWEyaHUwc0x3R0gxRUQ2eExwR1BMTkpkbmdsVXl6NUpDbVd5NnZsb0ZxVURYMTJVWTZMcXdTb3VsOUJDdU9nSk9mSElxUHR1OVNPUjRKYW5OUDdmeUc3Vk1qMWh4U1I3TDZOOGZhSDlpaGJSZG9UTnZIcnBTVzJsWkNTY2J3NGdlZWFZemwrdjJWcC9IMHJCOW9IajIvSTFoVldpWmNKWllqdEtVaHZPb0dtT3ZQSWQ5WGk3UjJZOTRqeThla0tYSldwdUVubzBIUVlHUCsvOEFmQ2tMRUNiZUh0NTlUaTFjU004Ty9rS2NNMmlCWjBCVXgxSzNQcUpPaDhlSjhQT3VWM1J5YzRpTENDR2dvN3FFQVl5Znc3em1pMmtNNUtKODlTaFdsc0Y5YVNlTzRnNkh4NG53ODZBazNoNldsYlVOam8ya3BLaVFPQUhFNDRlZFV4NHJzdFRqemgzWTdlQzYrdlVEUEFkcFBJQ3I0a1JONGxwaU1iN01Cc2RJK3M2cUtSOFI3VG5BSERKSGFhQ2RnVXJEN0ZNblFHWXMxYWdsU2xLUzBwWXp2cDRFS1NkQ2s2cHdlT0NLQzJxc1RFWkxkMXRxQ20yU1Y3aW1jNU1WM0dTMlR6QkdxU2VJMDRwTmNYcVd1Yy8wVGZzTU1FSlFoUEJPQmdBZGdHbm1hYzdQM0JybzFzM0Z0YTRFcEpZbElTTlZJem90UDdTVGhRN1JqZ1RURDdyY3dWU21OOHREdGl1a2lDOHBMaGJJS0hVZTY2Z2pLVnA3RkpJSTc2WFV4UWxlOGVpRzBSdG1ObUoyMU53SVF0NXRSU284VXNKNDQ3VktHUEFWNHJaN2E1ZUxyRGdOZS9KZFMyT3pKMVBsWHNucFNuSWpXdTA3TFc0N3FIeW5lU09UU05FanhPdmhTeThFOG05Uk0zYXA4emE2NlhKTjNJYmo3VEszV0ZxT2pEN2Y2RWc4Z003bmNvMTZGc1BkR3J4YXBGb3VpUDhBU01QTEVscFdoVU00Q3UvSXhuckdlZFphNldrTjdJNGFHNDVEVWgxQkdoR05EOGpud3JpNlRYWXpscjIxdDRCZGQraG50alFGd0RCejJLQXozNE5ZUjdtMXY3VTZmQlZKWmRJdk5vVHVQa0QvQUZ1T2RRb2pnZVpJUE1LSFZTSFo0MjJaZG9McDZPRytYQWxRVm5vVmhYc250VG9UMWp1clIvbGR1V3hFdkZ2SmR3Z3EzQnhjYlB2dG50MHlPMGRwckwzSzFKanpXNU52V2d4WkpEckdWWUJ6cmdFL2RVWnhUUnpaY2FhZlJtN3JzdklGd2NnaGhYcktTVWhzOFZZNnV2T05NY2VWWmhxUFB0OHNPd1hIbXBMWjBMWktWanN4eDhLOVh1cVZ0ekpEaTIxUFJBc3V0bEp3NHdvbmUwNXBPZVIwT1BHa20wTndpWHB4TXFReVpEVW4yUklaU0VQTXVKR294d1dEb29Bbk9wd3JTbWhMVWhzTTlTVmdkbzlLTHFRSTkvaWlRa2Flc05Kd3NkNmVCOE1VQnRmZGh0NXRiQmlRVjlJd3NKWmJXbEpBeXJWU3Nkbjh0VXlvdTZ5WDVyS2J2YXdkMzEyUDdMN1BZdk91ZjJWalBVYVpiUHhMTlk0Tjd2OEFDdUhyTHpFTlNJelpUdXJhV3M3cDNoeEJ3ZE9XcDFwcUxhVXQwQU52c3BWYzNXTjNvRXpHYmRIVU9KVHZKL2xiSi9lTkRkT2lSRWhwS2gwa3plUXJUZ3BBM1JyM2dVTTBESHQyeThVNkxsU2xUVjlvM3cyai9wVWZHZ0dsckZyVzRqMzRVemZIWWxlbjNwSG5Sb09rMEVhOXhtMTNCVWhXN0VjTzhBUWM0NEFZSFpTYTRiWHV2Z1JiY3owYldjSkFUcWU1STU5cHlhTmVoMlJEYjB1N1RYbWtPS0NtWWtVQXVPNlp5U2RFcHljWnBhVnVQaEtZY1VXdUc4ZDFDV3dYSkVqc0I5NVdlekFySkJoRkpDZHhFcDJSdXVoYTMxZkRuZVY0MXB0a0xBOUx1OFZ4ektHV25BU3NFWUpIRUFuVFRtVG9QSUVkSFEyaGxhUzMwZVZkRnVvSVV0U3ZpeXJnU0J5R21UalhCclJNeUphNUxHR3VoUTBnOUJEWkc4NDRkMGdFZ2NnVDd4d09PS25sZEtrUTlUSnFOUjdGazlxQTMwYlQ4cFRzWnI5RkVnalRKNGtyVU5WSHJBTmZiMnBpelJoQmlNcFlrdVlMNFNzcUlXT1JKNDdvT09yZUo2cXZoV3o4aU1tNnluV1N0a2xMQ0VLMzhPREdWRWpRN29PZENmYUlyTU92S2t1dVNYTTYrNk9KQTVEdnJRajJOaGozWjFGaXFmZGJZUm9wZkVuNFJ6TmNTSm1ibnZSOGlMR0FhU090UE05L09tVGcvSlZyVTR2SHJVc2NQcW8vNy9nYVV3V2lHc25pc2s2ODZzZENOQmVvcWJ6c3lIa2F6Yk5qSjVyaXJWL0l0WGs1MlZoSzMyejB4cUZMYU1uS29pdDZQSVQ5WmhZM1ZmOEFLU2U5SXJIWGUydTJlNlRMZS84QXBZcnFtbEVjRGc0eU93OGZHc2d4OEd5OUVrSHB0bzNaaWs1VERaSkgybGV5UHhyUlNiYy9mOXRadDFjZGp4N1pHUFFOdnlYQWxKM2REdWppZGMwSDZMaW1EWnJsTFZvVnVBWjdFSnorTklyRHNoSzJpUXVVOGlXcEMxayt5a2dhblBFaWgyVGZMWjY5QzIyMkwyZVQrZHpCUGZTTWJxRTVUNUFHc250RDZSOWxKYkU2UGI3R3VPek1IMGpiSDBiYWxjbDRKT0QzQWNLb2kramUyb3gwcVd4amlIcE9UNUp6UjUyWTJZdFl5KzdEVGpqaHNFK2F5UHVvV2hQcE16c0Z0UzNDbUczT3UvbXNwV1VEUHVPZjBQMzRyZXlXVzNFTzJ0WkFqeXN1UjFmNFR2RXA3anFvZnZEcXBXTm9ka0xYcWxDblZENmdQOHFSOTlMYmg2VmJZeUNtSFpnNmM1Q25NREhVY25lTkM3TTJwYkkrTTNTU3dwVU9Ya3FZSlJna2hTTzVRMXh6eHc3S0J5d3hLTERpZ2kzWE5PaStURG9PaC9kVWY0VlV2algrWnRydEJIalI3Y2xNdDhiaUVNa2tyUEVaejVaMHJWM3pZZWZaTEhJVGVaRnRqRndkTTB5cVdndk51QWNDbnFVTkRnOFFLeVZDcUtpNjRNNjJxUTFNY1QwcTRkMWFKYVV0UHg0MEtGamdvZGgwTkJUTGJEdVRoYUtHN1ZkWFBaU29aOVZrSGtPdHNrOTZlNnJsUGZsVzNJbjd3OWFpQkRFblhWU09EYnY4aFBZazFvTm5yZklueUk4aVhDZjlRakxEN3NsVFJEZTRqMmpsUkdNNlk4YXpkSWR5cmNTWEdBRTN4MVRnS1diSzlCdHlOZE40SDI4K0lVZkdrOEtBc29MVGFncE55anVFYngwQzByT1ArbjUxb0ZKZi9JTmtkY0JVL2VybzVjWE9zcENnbFB6S3FBYmI2RzJScEtjZ3dKNUIrd3ZYN3dmT2s5eGNDZTZ1QmZaYkU3ZlovcTFwWjllblpHL0xjR0dHQjJBOGU4K0FwbmRGeDluNUs3UGFKUHJsNmV5aWJkVmE5RU1lMGh2Nm9Bems4ZVZNNzF0UzdzNXN2SHNsb2lPTVBMQ3ZXWnpiWkFJS2pnSlYxa1l5ZVhLc0l5d3FORWJaU3RDSlZ4MDMxcXdHbWM4U2VXZVBjTzJxTGN0RjN1R051c0ZLcmlVRVE0ZUk4TnM2RmErSlY0REtqMmxOZHdwVXE3dm9nUTl5S3c3a3JDTTRDUU1xVXRYRldBQ2RUM0N2bDFoR2NobHEyS2FjZ1FrOUcyQXNiNno4U3lPdFIxN3NVSkN1cmxoVktZRERhM0hRRUxYdmE3bzEzUVJ5empQWGdVR2t4WlJVaGpmN2lKYnpVR01DaUZGUUcwSTZnTlFEMmtrcVBhZXlsYk0yR3crbFVqZVUyMmNocEhGUjcrQW90RjJodnF5N0RTbFI0cXgrSXhWeGFndkRlQ1ZnZGh5UG1EUlRTQ21sc0NyMmhpeXBMajBtSUZoUjlsQ3lTRURrQmc4aDJWYUpsc2YvQUVhbHh5ZVIxVFZhN1pFYzFRdEIrMGpIM0dobFdWS2o3QVNyN0xuNEdqc05zTUdsTm5lQVdsd0VIVko0L3dCNjF4dHVreVYyaTZFZTFOaHBRNnJyZGFKYVBpVXBRZjNxRWpXdGNXUzA0VXVwQ1ZEaW5RamhUQzgvbk95RFJWbmVnM0JTQjJKZGJCKzlvK2RaR1QzSG16S2l4c1BJS2RWTERxc2ZLa3lkczc1UDNXMjNRRll3RW9Uay9QTk50bDVQUmJMZzZubzk4NmRoelRXMjdUMjlMQ2tRN3pMaEJ6aWtodFNUNExRTStkSkxWMGlPUnkzMHF6SlNEY1pLY3pidzBuUDZ2cHlwUTd3blFVTzFDRFRnY2JteGd0SnlDcFJKei9EWG93dVY4V25NTyt3M2tEaDBrZERaOHdrajUxUTVldHJXY25SMUkrSmh0cHdmOG9OUmZ1UG81bTh6Nlg3L0FPakhTTGRGdWhTc3pvVWVSK3NTU3NJV2ZySndrNDdSNWRRK0oyU2NhVWh4RGtTVWcvNzFiYVIza3BHbmNhZnlOdHI2QXB0eVNVRWpCQlpTay9kV1RjbnpXM1NvU3pqa0hpVko4em1ueHhuMlV3ckw4dGhvbTR6NGpTNHliekZ0VWMreXBtMU5LS2xqdFVrWlBpcWw2VjJWaDNmWEJ1dDJjNjVEblFvSjdrZ3ErZGZmVzV6emUrNURmVTBPTGtHUXI3Z1NQa0txYm1OTFZ1dDN5ZkZYOVdVVjRIN3lUK0ZWT28wZG0yaGNRRmlDdTA3Tkl4dWxUVUp4NTVRKzBvS1B6SENqSGJuYTU3aVRkcHUwTzBMZzRCMXdzTmVBMVBsaWtzUDF3SVVsUmxYTkIrT0ZjVkVnZlo0K1lvaUs5Q2FjQ1JkcmhCZEg2cWNoV243eVQrRlJ5Y2JITmxYai92OEFKNkJzL2FYdHJydmJSRWdlclI0aUVNeDQ2Q3BRU2dLenhPcE90QmJRV0JWZ1ZOaXlZUmVRNm9iN1pKVHFEa0hUblRiWXZhMmZzdmRvVHJNM2ZXU2hUYmpUaFVrZ25RZzBQdEp0SEsycGx6SlQxeFRHU2s3N3J6N2lna1pPQnd6azE1TjVOZmZKOHduNno4Ylg2WjVwSkVScFN1Z2R1TUE4eG5wRS9oU2FZNG9ySFNkQlBIRGVVeXBLc2QrbGFHYklncWRVaEZ3dU56WHpURVFVcDh6ay9LbEVsbVlzNzVlWEFiNDRsVFR2SHc0L0t2WXhYVzU5Vmh1dHhRcHVPclhvSk1kWFdnN3crZXRkRU91SkNRK2w4ZlZkU1FSNS93QmF1VSt5bFc0YmpNa3VmVmo3MlBOUno4cTdVdVd5bklpcVpTZUM1YnB6NUVqN3FxWEtHSXF5VHZLVTFydzNDc2ZLbmJNZjFRWlJBY2xPNDBXdENrSUhnTlQ0a2QxSVV6SE9tQ25uQzZuT29iSlNENDRyZncvU1hmWEdRdzNKdkc2bFBGaTR2RlNVam1Ca2pUdXFHVlMrS09UMUh1YmFGWmtYWUVsMXhiaW1IMExVY25kUnA1WXJqMU9jZ1lTaGF1eFNGSk5iQ1Z0UnRnMlVxYTJodWkyRmplU3R5WXRzanNVRkt5RC9BR00wUC9uaHRPalY3YXVla2N3M0pkV2ZQSUh6cEU4aE9Ncy9TWDgvMFpYRTFsU1FXbm0xRTRHaEFOTlphQWJCdEd5UitqZWp1Z2RSQzFwL25vaWZ0eGNIVUpEdDl1MGxTRGtkSkxPTTl3ejk5RHpWRlZ1Mm5VZmlEUG4wdy9vYXZqMWZJNmNYdWZORm14NittdERyR2ZqVWsrSW9TRGJwaUlpVU5zTVMwamswOE40ZGhTYUgyTmtsQzVMT2RTQW9WOWV0NlB5ak5UdkthV0hOOUswSEJ3clVmZlQ5bHUyZE9wUkdXZWtoeW9xeHpDQ1BtS3NhdWpxQ09odVNzamdIY0g3OWFqZDJ2VnRLVUpjRXBrbkFDaGsrVlczdTdJYWpvUTdCaUdZc1pQczUzUExRMFRCcWRwYmlFQkx5V3BUWTB3VGtlUnlLNzNvTnhqT3lKRnREQ0VhRmFGYmdKeHJqQndmTG5TV3hXMVVod3VMd2dyR1NjWUNFOHpqKytRcTNhQzQ3eVVRMkJ1c285a0QrL24yMHIyRmRKN0N1RzdCUkplZFVaYUFEOUVHVkpDajNxNWVBcGl6ZHBRaHZTWmhaa3gwSGNiUkliQzFLUGZ4MHFXN1poeFNBN01jRVJvamVBVU11S0hXRTZZSGFvZ2Q5Q3pFc3VUZlYwaFJ0OExWUUp5Vm5QREk0a25TaEZwc1dNbEtUU0NyVkJrelhHWWNOS1VYQzVrS1dVSjNlaFpCeU1ZNFo0OXdGYW0rekxkYUxsR3N6YzZWUFVwUWFsR1FzT050WkdNSkpHZDRFZzZIU2tiTnprV3hwOWlDa3IyZ21qTDdxT0VWSDFBZVJ4eFBMdjRKbTJHSVBTcktUY1piU2VrVWx2SlpaMTRxVjhXcDdCbnJyTldNNDZ1VFJ3NTYyMmJTU29wWEdrK3JLd2VIdEFqOGE1WEtWTnQwYUdyL3hDZmhSejhDVHI4eWFVQjFSazd3MUQ3N01nRHFKT3Y0MXcxTUtDSFFOSUREaENUdzMxS0kvR3ArMnJzaXNTdXdxUmVabHlja3NzVG5HSXdXb05NTTRiUnU1MEhzNHljVXVjTzgyeklXMjI1SWlhTFM0amVEaU9SSTU0NGQyS2lHbVhsQU5KOVVmT0ZkQTRyMlZaK3FvL2NmT3JBNnB0MzZWQkRxZEZKVU1idzVnMVJLaXlWRmt5OXpVOUYwYmlHWWEvd0JYR1FscnZHVWpOQ1NWV3gyUXd0c1RBbFIrbFM2dEpVTzVXUHZGV3gyV1JJVEhmM2xSVkhmUVVxQ1Rqdk9RQ08zcW8yZHN3dEtWTGd1ZXRJU25lVWdKdzZnZFpScmtmdEpKSGJRbEpKN2lTbW95VmxMd2hXNEpjYmdKY0JPQXB3bHpYeE9QbFhDN3ZNV2toQVN3MzFKd2tlU2NWMUVXSG9xbTNCbElHRkRzNUVkdEN5NFpDZDdDVk90YW5JeUZwNjhVVlRIalQ1S1haS3prcmxKeit4eHF0dHN5Q2QxdDk4OWlTYVpRN2lGSVMyekRodFBjTi9jenZIeHlCUVQ5d3VVeGFrTGNVZ0pPQ2thWThCVERIYlZ2ZFc2MHlwcERYU0xDY0xXQXJVNDRVMHVqd1RaYjA0T0Q4eHBwUGNPa1YrQW9XeVFRbWMxSldTcjFiZWZVVCt3a2tmUEZVWGh3czJXM3h5ZmFlZGNrS0hXQmhDZitsVmJzM0xBTEhLOVV1VEs4NFNvN2g4YTFkeGIzWDJaQTRLSFJLN3hxUGtUNVZnd1NDQ09JcmNRSGhkYmVFbFFDM0VnWjZuQncvcDQwV0dma3NTKzNHYlhKV2NKYkduZldjWVF1NVRGeUhSN0FQRDdoVnR4ZVhLY2FoTlpBUnF2N1hQeXBwQ2JSQ1lEaDBDUGQ3K3YrK2RBRDJDSnNzV3FIMElPSDNOVjloNUR3Ky91cm1GY29uNVFaYXR6QkMxckNmVzN3QzRrZnNKMVNudjFQYUtSU1M5Y1pZUWhDbHJVZDFLVWdrazlRSE90UFliT3hhN2cwdVk4RlMyZ3Raak5LQkxlRUUrMnZnazZjQms5MVJuWExPYks0MWJBM29zNlN3OUtXb0lRMzlKdUxWeFZ4QlVUeFVlV2NrOGhpbGFTbTNOb0R6aFNvSHBDRTRLMUwvREhJbm5yVGlHbVRlbmlWcURVS0kydHdxOTF0bjJTUWVlcE9PdFI3YVNTbm1tSFFJZStwZWY4QVdIQjdhajJENGZ2N2VWTkI5RFlwZkVNYVlRcHYvU0Rxb0VFKzBJakdyNzNhYzhQdEs4QWFaR1cvTXRoZ3dvcUlWbmNWdWh0dlV1ckF5Q3RaMVdSeDZoeUFwVzFzdmMxTkY5OXJvMUxJS1czMTdycm1UeENUN1dPMDRGYUtHa0plVXkwZDVpMk5ieWNjRkszazd5dkVrK0FGTGtuV3lGejVkT3lDYjk2UHI3c2V1Mk9YbUVwaG1TeTNJWWNCQ2t1Tm5DZ1FvYUVqT280aXNjOG5NZHlNZ0hwWDNnQ2NmQ000K1orVmZxN1lYRXowVFhaRzNLczdIc0JYNU1kWC9yQ0pPdUV4ODhSeHlPSEh0eCtjWkVBaVgwcmFCMGFGRlF6enh3cmt3K3BiZFNQTTlGNitXUnloazZmUFFDL0dNNDNBL1J1TXd0MGJtZmJDUGQzazlnT005OUsrbFVoc0lYK2N4MDhBVDdiZmNmN0ZObG9Ycy9kdW5aZFM4blJXOG9leTRsU1JsS2gxRUVnaWdycmFoMC9UMjdmWEZjSFNOcHo5SWhKNUVjOGFqSTQ0elhYQ2VwL1k5UEhrMVA3TUhDQkpaSlpYdmx2MjBaMFVPc0VVNnRjT1kwSWF2MGtWMVlLZHhYdE5ra1pLQ05RUm5sNGlrTUJMWmNQU3VLWmRCOWw1STkwL3REcTdScjJHdEV4NjdZTGkyMkFGeG4xSWRUdmUwMjhuUWhRSTZzOFJnanNvNUgwYk85cVIwNWQ0cXByamR6amxTMHFVMnFYSFNBNG9aSTl0T2lWOStoN1RTY0w2WkkzVGxRT1VIcjdQeEhiMzFwTDlaNE1xN3ptNHovUlNTOG9wYmVPaXdUa1lWejQ5aDc2elM0VWlCSVhHa3RLYVh4d29Zd2VScGNiaXQwSmhsR3JRdmt0QmwwUE5qNk5meU5GdXVCNWJidzk1d0JLL3REbjRpckhVaDNJS2RGSGRXbnFVZWZqOTlDTU5QSWtDS2xCY2NXb0J0SStNazZBZDUwcTUxMlBOMzFPeXVyU1BwWmJnWVFPdEl3cFh6M0I0bXN6Zm5nNWNDeWs1UkZRbGhKSFBkNG54VnZHdEhlWmJjV1Z1dHJDMmJXam8wS0hCYnVkU093cko4RWlzU1NWRWtuSk9wTkZEUVhaS2EyU2FJN3haV2NOdS9JMHFxQTRPUm9hSXpWbTJrUld5OFp5ZEM1by9nZTZyNjM3MzM1b1l5WTAyUXREc2dNTk1wemdKS2xLT2NCS1FPSjRuVWdkdFYyYTZKY1J1dkozL0FHZHh4R2NiNmZ3UE1IcnFoeXdURXlDaUcyNUlRNzdUYnlSZ0ZITXFKMFNjNkhQREZJMTBTa3VneE4yRnViV3pCYjlYUXJSYXdyTHpnNmxMK0Vmc3B4MjB4c0Z2THp4ZWVTN2xiRG5ReFk2Y3V1NVNSbEkrRk92dkh3elFkdVp0MW1VWFo2a1RIeDdyVFN2b2tIclVzakN1NUlJN2Erek5wWG53NGlNa050T0hLMHRaU2xmMmxlOHZ4Tkk0RW5qdlpmdU5sc3FaU3RxNVNHNDdJUVVwZ3dpSEZvR1FUazUzVWs0MUpKUFpTNWQvaTIvS2JURlJIWHc2VkozM3ZGMDhQM0Fta1Q4dGJ1RU9yeU9UU0JnZVg5YWJXL1krNzNSZ3ZKYlJFamtZUzQ4Y2J4T2dIaVNCNDB5aW9qcUNnanEyeVhwWmY2WTd5MW5HUjJnOFR6cG5za29MVGNFckhHTVFmNDBVTnNyYVpOd3UwZTJ0Z0lseVhFTnBEbW1GNzJOZm5USFoyT0JjTHkyak80R1NVOXhjYng5OVJ6VlZITjZwcW1nL2E3MGozbmE0d0kxd2ZRSTF1WVRIak1Nb0RiVGFVakdRa2FaT05UenJldjhBcHN1MnhUTVd4eExkWTNvc05ocEtGeWJlaHh4UUtFcTlwUjRuSk90ZVNQMko5cTRYQnQxMXBERUhWNlNyTzRuSTBBMHlTZUFBMVBkclRLK1F2ODQ5cGd3eTRoc0xhYktuWFRoTGFVc3BLbEs3QUJYTkxERzBqaG42UERKeGkxOU83UG5wRTI3bmJlUHdaODZQQVlXaHBUYUVRb3lXRTRDanhBNG5QT2tOeGtHRVl5QWhLeWhLVWJxdXhPdkRocWE2bldsK1BLdDhKeE9IZWxXeXBQYjBoQm81ZGdjdVY0bXNQVElzWk1CTHp6enIrOXVCS1hBamtDZVBaWFZqaW9xbHdlaGdoREZGUmp3aGE3Y0k4Z0RwMmlvblRMbnZEdVdPUGpUTzNTUzMwU0V1SmZqREc5RmtIRzlnNkZLaG9GWTB5TUhUbndxaTdiS3k3UGJJMXphbFE3cGJIMUZ2MW1HNFZCRGdHU2hRVUFwSnhxTWpVY0RTSnRZZEo2QlpRbzhXei9UK2xPMHBJcTR4eUxZMTIwc0JxUzVLbXdWcmRRMDRvT3RyR0hHMGxSS1NSelRxUnZEVFFaeFNsaStyVXltSmNXeE1oSjBTbGFzT05kcUY4VTkybzdLRmlYbVRiMXBPcDNEa2N3bnU1andyNVBkajNSM3BtRXR4bkZEMm0rRGFqMWcvRG5xNFVxeDlNbEhCUzB5M1hrdnVhNEtIV25JRDZubTNVZTJoeE82dEp6d1Z5endJSU9PN2hSMEZhTFRiRlhWeE9aYXlwbUNvalhleGhUbyt5RGdmdEVmVk5BV2l3S2xMZWZtcVZHdHNRQmNsOGFrRE9pVWNpdFIwU1BIZ0NhQjJndmhuU09rUzJsaHRDUTFIam9PVXNOamdrSG54Sko1a2s4NnBGVnNYeHhwYVJUY0pBTzdIUjdxRGxYYXIvc05QT2dLbFNxSFFsUktsU3BXTWR0T3FaY0MwSENoV25nWE5FbU11TzZWZXJPRUZTVW5WQ3VTd09HZnZIbldWcnRwMWJLd3RCd1I4NnpRcmpZOGxXMTZNK2hDa3FrcWQxYWNhQlVIUjFqcTdRZFJWL3dDVFVzSjNyak5iaUovd0cvcEhqNERoNGtWM2FyNWh0eGtqZVpkR0hHU29wejJnalVIdEhqa2FWRjJWdFNGUFFsbDVwT3Fra2ZTTi9hSE1mdERUdXBlT1JMcms2YnYwYTNwM2JSYlVvYy84eklBY2M3eG4yUjVHbXNEYUNPM0MzcnQ2eGNaTXB3S2RTaVVXbE1vUWNwRzl1bmljcXdCeUZaN285M2lNVnlwc1lKNnhyV2F2WUVvcVNvOVpZMmwyZlBwSTJmMmtpS1F4RWtxYmt6R0ZLSjlVZTFTNENjYWdrQllJSEJWWnUzaEVLWktjYW54SCtsWVNncFpLeVQ5SWdFaktScHBXSWdyTzR0T2RVbXRGWndsMTVLdUFTQWsrSzBIK3RRbmpwSEpsd3FNQWk1WHBpNjNDWkNmZGJSQlVvclpkU05FdTQ5OVhXRDdwNmhqSENpYnJjSWR2OWNMclBUeUppRzJWTkpkS0Noc0lRVDdRSHhISGdEV1FXajZaWjdUVG5hMWtJdXlrNC9WdEgvNDAwS1dwSU5KU2l2dC9RVTdlVVhDNTJ1ZHVsdm9ra0xiVW9xS2R3Kzl2WTF5TWE5WU5GdFNZYys4N1VKWGNZMFZxYkhkYVlmZkpEWktua3JHb0JPb3p5cE1wdm9MV3k5OVp0U0I0dUg4QlNOekpRM3Ira2Nxa1lwOEZZUVRXeHU3dk50dXp1eXY1SHQxemJ1ZDBuU0duMzNJeVZCaGhEYVZicVFwUUJVb2xaenBnQUFhNXJEdXlrdjZ5STVTb2ZyRURCK1dsZldVaHlRb2daQ2RCUnlHbE9IQ1FWSHNIQ25qR2lrSUtLQVczRkkxUXNQb0hJNktGTmJSWmZ5MTZ3LzBvaFJJMkRJbE9BN2pJUEFZK0pSNEJJMVBka2hpNXN4RXRiQ0pWOWRWSERpUXB1SzBCNnk4T1dBZEVKUDExYWRRVlNhKzdUT1RVTXgyMjI0MEtQbjFlR3lUdU5aNHFKT3Fsbm1zNm5zR0FDTXQrQzIvWDl0VVptM3drTFp0a1lrc3NxSTMzRm5RdXVFYUZaeHkwU05CcHFjbXRhbkZsU2prbW90YW5GRlNqa211YUtSUktpVktsU2lFbFNwVXJHSlVxVkt4ajZDVW5JT0NLWlE3czR5dENsS1VsYVRsTGlUZ2lsbFNzQnF6WU4zS0xNUitkdFpKL1hNWUN2RlBBK0dEVnFiV0pBL01ubTVPZmdTY09md0hYeXpXTVE0dHM1UW9nOWxGdDNFalJ4QVYyalNoWGdUUlhBd1JHZGl6bm1YV2xvWGpPNm9GSjhqVFMxcktaYmJmRDZWcytHOEtFaWJVU21FQkNKcStqeGpvM2dGcDhsQWlqV0wra3VoMVZ1dHpybytOQVUyZU9maFVCOHFXU2JWRTV4bEpOVUxPTHkrckpyUTdhZ0M5cXgvaE0vd0QxSW9RVHJhU1ZLc1p5ZU81TFdCOHdhTHVkL2dYT1NaTHRoSFNrSlRyTFh1NFNrSkdnQTVBVkxROVNaRndsclRyZ0R1THFCWkxjaEpCVUM0VkFjc0hUNzZUUjR6ODJRd3hGWmRmZUNWSG8ya0Zhczl3eWFidlg5bENVaEZwdFRRVHdMcVZPa2Z4cUkrVkRUTnNMaElaTEM3aTZtUGpIUVJVaGx2OEFoUUVqenFzWTBpOEl0S2crSHM4bTNJQ3IzTGF0L01zS1YwajZ2L2FSa2o5NHBvbDNhOWkwSUtMSEVFWlEvd0J0bGJxMys5STkxdnY5cFg3VllsYzRqUnBBU09zMEt0eFRpc3FVU2UybW9wcHZrTm1YUjZVODQ0cHhhM1hEdkxkY1VWS1dlc2s2azBBVGs1UEdwVW9qSlVTcFVxVmdrcVZLbFl4Ly85az0iIGFsdD0iIj48ZGl2IGNsYXNzPSJsb2dvIiBzdHlsZT0ibGV0dGVyLXNwYWNpbmc6LjE2ZW0iPkFMSzxzcGFuPkFJRDwvc3Bhbj48L2Rpdj48L2Rpdj4KICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIHBhcGVyIj5QQVBFUiBNT0RFIMK3IE5PIFJFQUwgTU9ORVk8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJmZWVkIiBpZD0iZmVlZCI+PGk+PC9pPjxzcGFuPmNvbm5lY3RpbmfigKY8L3NwYW4+PC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0ic3AiPjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9InZiYWRnZSI+VklFVyBPTkxZPC9zcGFuPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gb3duIiBpZD0idG9nZ2xlIiB0eXBlPSJidXR0b24iPlBhdXNlPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9Im91dCIgdHlwZT0iYnV0dG9uIj5Mb2NrPC9idXR0b24+CiAgICA8L2hlYWRlcj4KCiAgICA8c2VjdGlvbiBjbGFzcz0iYmFuayIgaWQ9ImJhbmsiPgogICAgICA8ZGl2IGNsYXNzPSJiayBtYWluIj48c21hbGw+VG90YWwgKHRyYWRpbmcgKyB2YXVsdCArIG9wZW4pPC9zbWFsbD48YiBpZD0iYlRvdGFsIj7igJQ8L2I+PGVtIGlkPSJiR3Jvd3RoIj48L2VtPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJiayI+PHNtYWxsPlRyYWRpbmcgYmFsYW5jZTwvc21hbGw+PGIgaWQ9ImJDYXNoIj7igJQ8L2I+PGVtIGlkPSJiTmV4dCI+PC9lbT48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iYmsgdmF1bHQiPjxzbWFsbD7wn5SSIFZhdWx0IChsb2NrZWQgcHJvZml0KTwvc21hbGw+PGIgaWQ9ImJWYXVsdCI+4oCUPC9iPjxlbT5uZXZlciB0cmFkZWQgYWdhaW48L2VtPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJiayB2YXVsdCI+PHNtYWxsPvCfkrAgU2VudCB0byBzYXZpbmdzPC9zbWFsbD48YiBpZD0iYlNlbnQiPuKAlDwvYj48ZW0gaWQ9ImJTZW50VG8iPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImJrIj48c21hbGw+VG9kYXk8L3NtYWxsPjxiIGlkPSJiVG9kYXkiPuKAlDwvYj48ZW0gaWQ9ImJTdGF0dXMiPjwvZW0+PC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPGRpdiBjbGFzcz0iY2FyZHMiPgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48c21hbGw+TGF1bmNoZXMgc2Vlbjwvc21hbGw+PGIgaWQ9ImNTZWVuIj7igJQ8L2I+PGVtIGlkPSJjUXVldWUiPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxzbWFsbD5QYXBlciB0cmFkZXM8L3NtYWxsPjxiIGlkPSJjVHJhZGVzIj7igJQ8L2I+PGVtIGlkPSJjT3BlbiI+PC9lbT48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PHNtYWxsPldpbiByYXRlPC9zbWFsbD48YiBpZD0iY1dpbiI+4oCUPC9iPjxlbSBpZD0iY0Jlc3QiPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxzbWFsbD5QYXBlciBQJmFtcDtMPC9zbWFsbD48YiBpZD0iY1BubCI+4oCUPC9iPjxlbSBpZD0iY1BubFVzZCI+PC9lbT48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PHNtYWxsPlJ1bm5pbmc8L3NtYWxsPjxiIGlkPSJjVXAiPuKAlDwvYj48ZW0gaWQ9ImNTb2wiPjwvZW0+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxzbWFsbD7imqEgTGF1bmNoIFNob3Q8L3NtYWxsPjxiIGlkPSJjRmFzdCI+4oCUPC9iPjxlbSBpZD0iY0Zhc3QyIj48L2VtPjwvZGl2PgogICAgPC9kaXY+CgogICAgPGRpdiBjbGFzcz0iZ3JpZCI+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPuKaoSBMSVZFOiBldmVyeSBsYXVuY2gsIGFzIGl0IGhhcHBlbnM8L3NwYW4+PHNwYW4gaWQ9InB1bHNlIj53YWl0aW5n4oCmPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0idGFwZSI+PHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBsYXVuY2hlc+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn6SWIEF1dG9waWxvdDwvc3Bhbj48c3BhbiBpZD0iYXBTdGF0Ij7igJQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJhcCI+PHAgY2xhc3M9ImVtcHR5Ij5Mb2FkaW5n4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfk4kgV2h5IHlvdSdyZSBsb3Npbmc8L3NwYW4+PHNwYW4gaWQ9ImR4U3RhdCI+Y2hlY2tpbmfigKY8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJkeCI+PHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBjbG9zZWQgdHJhZGVz4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfp60gVGhlIHN0cmF0ZWd5LCBpbiBwbGFpbiB3b3Jkczwvc3Bhbj48c3Bhbj5leGFjdGx5IHdoYXQgaXQgZG9lcyBub3c8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJzdHJhdCI+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPjxzcGFuIHN0eWxlPSJmb250OmluaGVyaXQ7Y29sb3I6aW5oZXJpdCI+8J+agCBNb21lbnR1bSB3YXRjaDwvc3Bhbj48c3BhbiBpZD0id1N0YXQiPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9IndhdGNoIj48cCBjbGFzcz0iZW1wdHkiPlNhZmUgbGF1bmNoZXMgd2FpdCBoZXJlIHVudGlsIHJlYWwgYnV5aW5nIHNob3dzIHVwLjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7wn46TIEdyYWR1YXRlIHN0cmF0ZWd5PC9zcGFuPjxzcGFuIGlkPSJnU3RhdCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZ3JhZCI+PHAgY2xhc3M9ImVtcHR5Ij5Mb2FkaW5n4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfkaUgQ29weSB0cmFkaW5nPC9zcGFuPjxzcGFuIGlkPSJjcFN0YXQiPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImNvcHkiPjxwIGNsYXNzPSJlbXB0eSI+TG9hZGluZ+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgoKICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPjxzcGFuIHN0eWxlPSJmb250OmluaGVyaXQ7Y29sb3I6aW5oZXJpdCI+8J+OkyBBbGwgbGF1bmNoZXMgJmFtcDsgZ3JhZHVhdGlvbnM8L3NwYW4+PHNwYW4+bGFzdCAyNCBob3Vyczwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImdyIj48cCBjbGFzcz0iZW1wdHkiPkNvdW50aW5n4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfj4YgVG9wIDEwMCB0cmVuZGluZzogaG93IHRoZXkgZ290IHRoZXJlPC9zcGFuPjxzcGFuIGlkPSJ0U3RhdCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0idG9wIj48cCBjbGFzcz0iZW1wdHkiPkxvYWRpbmfigKY8L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KCiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfp6ogV2lubmVyIExhYjwvc3Bhbj48c3BhbiBpZD0ibGFiU3RhdCI+Y29sbGVjdGluZ+KApjwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImxhYiI+PHAgY2xhc3M9ImVtcHR5Ij5Db2xsZWN0aW5nIGxhdW5jaGVz4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfjq8gU3dlZXQgU3BvdDwvc3Bhbj48c3BhbiBpZD0ic3dTdGF0Ij5yZWNvcmRpbmfigKY8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiPjxkaXYgaWQ9InN3ZWV0Ij48cCBjbGFzcz0iZW1wdHkiPlJlY29yZGluZyBsYXVuY2hlc+KApjwvcD48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9Im93biIgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbi10b3A6MTJweCI+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBpZD0ic3dBcHBseSIgdHlwZT0iYnV0dG9uIj5Vc2UgdGhlIHN3ZWV0IHNwb3Qgbm93PC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImRhdGFEbCIgdHlwZT0iYnV0dG9uIj5Eb3dubG9hZCBhbGwgdGhlIGRhdGEgKHNwcmVhZHNoZWV0KTwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSIgaWQ9InN3Tm90ZSI+PC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj48c3BhbiBzdHlsZT0iZm9udDppbmhlcml0O2NvbG9yOmluaGVyaXQiPvCfp6ogRXhwZXJpbWVudHM6IHNhbWUgdHJhZGVzLCBkaWZmZXJlbnQgZXhpdHM8L3NwYW4+PHNwYW4gaWQ9InhTdGF0Ij7igJQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJleHAiPjxwIGNsYXNzPSJlbXB0eSI+TG9hZGluZ+KApjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+PHNwYW4gc3R5bGU9ImZvbnQ6aW5oZXJpdDtjb2xvcjppbmhlcml0Ij7ilqYgR3JpZCB0cmFkaW5nIChpdHMgb3duIHBhcGVyIHBvb2wpPC9zcGFuPjxzcGFuIGlkPSJnclN0YXQyIj7igJQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJncmlkIj48cCBjbGFzcz0iZW1wdHkiPkxvYWRpbmfigKY8L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KCiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPk9wZW4gcGFwZXIgcG9zaXRpb25zIDxzcGFuIGlkPSJvcGVuTiI+PC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0ib3BlbiI+PHAgY2xhc3M9ImVtcHR5Ij5Ob3RoaW5nIG9wZW4uIEFMS0FJRCBvbmx5IGZpcmVzIGF0IHdoYXQgcGFzc2VzIGV2ZXJ5IGZpbHRlci48L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+V2h5IGxhdW5jaGVzIHdlcmUgc2tpcHBlZCA8c3Bhbj50aGUgZmlsdGVycyBhdCB3b3JrPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZnVubmVsIj48cCBjbGFzcz0iZW1wdHkiPldhaXRpbmcgZm9yIGxhdW5jaGVz4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPkxpdmUgZGVjaXNpb25zIDxzcGFuPmV2ZXJ5IGxhdW5jaCBpdCBqdWRnZWQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJkZWNpc2lvbnMiPjxwIGNsYXNzPSJlbXB0eSI+V2FpdGluZyBmb3IgbGF1bmNoZXPigKY8L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+Q2xvc2VkIHBhcGVyIHRyYWRlcyA8c3Bhbj5hZnRlciBmZWVzLCB0aXBzIGFuZCBzbGlwcGFnZTwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9ImNsb3NlZCI+PHAgY2xhc3M9ImVtcHR5Ij5ObyBjbG9zZWQgdHJhZGVzIHlldC48L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPlJlYWR5IGZvciByZWFsIG1vbmV5PyA8c3Bhbj5pdCBoYXMgdG8gcHJvdmUgYW4gZWRnZSBmaXJzdDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiIgaWQ9InNjb3JlIj48cCBjbGFzcz0iZW1wdHkiPkJ1aWxkaW5nIGEgdHJhY2sgcmVjb3Jk4oCmPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPldoYXQgaXQgbGVhcm5lZCA8c3Bhbj5mcm9tIGl0cyBvd24gdHJhZGVzPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0ibGVhcm5lZCI+PHAgY2xhc3M9ImVtcHR5Ij5MZWFybmluZzogZWFjaCBzZXR1cCBuZWVkcyBhIGRvemVuIHRyYWRlcyBiZWZvcmUgaXQncyBqdWRnZWQuPC9wPjwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPkRpZCB0aGUgZmlsdGVycyBwYXkgb2ZmPyA8c3Bhbj5za2lwcGVkIGxhdW5jaGVzLCAzMCBtaW4gbGF0ZXI8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiIGlkPSJmcmVwb3J0Ij48cCBjbGFzcz0iZW1wdHkiPkNoZWNraW5nIHdoYXQgaGFwcGVuZWQgdG8gdGhlIGxhdW5jaGVzIGl0IHNraXBwZWTigKY8L3A+PC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIG93biIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5TaGFyZSB3aXRoIHNvbWVvbmUgPHNwYW4+dGhleSBjYW4gd2F0Y2gsIG5vdCB0b3VjaDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYiI+CiAgICAgICAgICA8cCBpZD0ic2hhcmVTdGF0dXMiIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luLXRvcDowIj5TaGFyaW5nIGlzIG9mZi48L3A+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tdG9wOjhweCI+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBpZD0ic2hhcmVNYWtlIiB0eXBlPSJidXR0b24iPkNyZWF0ZSBzaGFyZSBsaW5rPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biB3YXJuIiBpZD0ic2hhcmVPZmYiIHR5cGU9ImJ1dHRvbiIgaGlkZGVuPlR1cm4gb2ZmIHRoZSBsaW5rPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InNoYXJlYm94IiBpZD0ic2hhcmVCb3giIGhpZGRlbj48Y29kZSBpZD0ic2hhcmVMaW5rIj48L2NvZGU+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InNoYXJlQ29weSIgdHlwZT0iYnV0dG9uIj5Db3B5IGxpbms8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJidG4gcHJpIiBpZD0ic2hhcmVTZW5kIiB0eXBlPSJidXR0b24iPlNlbmQgaXTigKY8L2J1dHRvbj48L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJub3RlIj5XaG9ldmVyIG9wZW5zIHRoZSBsaW5rIHNlZXMgZXZlcnl0aGluZyBsaXZlICh0cmFkZXMsIGJhbGFuY2UsIHZhdWx0LCBkZWNpc2lvbnMsIHJ1bGVzKSBidXQgY2FuJ3QgY2hhbmdlLCBwYXVzZSwgcmVzZXQgb3Igc2VuZCBhbnl0aGluZy4gTWFraW5nIGEgbmV3IGxpbmssIG9yIHR1cm5pbmcgaXQgb2ZmLCBsb2NrcyB0aGUgb2xkIG9uZSBvdXQgcmlnaHQgYXdheS48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIG93biIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5Zb3VyIG93bmVyIGNvZGUgPHNwYW4+cGljayBvbmUgeW91J2xsIHJlbWVtYmVyPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj4KICAgICAgICAgIDxkaXYgaWQ9Im5ld0NvZGVTbG90Ij48L2Rpdj4KICAgICAgICAgIDx0ZW1wbGF0ZSBpZD0ibmV3Q29kZVRwbCI+CiAgICAgICAgICA8Zm9ybSBpZD0ibmV3Q29kZUZvcm0iIGF1dG9jb21wbGV0ZT0ib24iIG9uc3VibWl0PSJyZXR1cm4gZmFsc2UiPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0idXNlcm5hbWUiIGF1dG9jb21wbGV0ZT0idXNlcm5hbWUiIHZhbHVlPSJhbGthaWQtb3duZXIiIGNsYXNzPSJ2aCIgdGFiaW5kZXg9Ii0xIiBhcmlhLWhpZGRlbj0idHJ1ZSI+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InB3Ij48aW5wdXQgaWQ9Im5ld0NvZGUiIG5hbWU9InBhc3N3b3JkIiB0eXBlPSJwYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJuZXctcGFzc3dvcmQiIHBsYWNlaG9sZGVyPSJOZXcgY29kZSAoMTIgb3IgbW9yZSBjaGFyYWN0ZXJzKSIgYXV0b2NhcGl0YWxpemU9Im9mZiIgYXV0b2NvcnJlY3Q9Im9mZiIgc3BlbGxjaGVjaz0iZmFsc2UiCiAgICAgICAgICAgICAgc3R5bGU9IndpZHRoOjEwMCU7YmFja2dyb3VuZDojMDcxMDFFO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjExcHggNzRweCAxMXB4IDEycHg7Zm9udDo2MDAgMTRweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1pbmspIj4KICAgICAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9Im5ld0V5ZSIgYXJpYS1sYWJlbD0iU2hvdyBjb2RlIj5TaG93PC9idXR0b24+PC9kaXY+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBpZD0ibmV3U2F2ZSIgdHlwZT0ic3VibWl0Ij5TYXZlIG15IGNvZGU8L2J1dHRvbj4KICAgICAgICAgICAgPHAgY2xhc3M9Im1zZyIgaWQ9Im5ld01zZyIgcm9sZT0ic3RhdHVzIiBzdHlsZT0iY29sb3I6dmFyKC0tbWludCkiPjwvcD4KICAgICAgICAgIDwvZm9ybT4KICAgICAgICAgIDwvdGVtcGxhdGU+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSI+WW91J3JlIHNpZ25lZCBpbiB3aXRoIHlvdXIgd2FsbGV0LCBzbyB5b3UgY2FuIHNldCB0aGlzIHNhZmVseS4gQWZ0ZXIgeW91IHNhdmUsIHlvdXIgaVBob25lIHdpbGwgb2ZmZXIgdG8gc3RvcmUgaXQgaW4gUGFzc3dvcmRzLiBUaGUgb2xkIGNvZGUgc3RvcHMgd29ya2luZy4gTm9ib2R5IGVsc2UgY2FuIGNoYW5nZSBpdC48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIG93biIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj7wn5SMIENvbm5lY3Rpb25zIDxzcGFuPmZhc3RlciBjaGFpbiBkYXRhIMK3IFRlbGVncmFtPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj4KICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTttYXJnaW4tYm90dG9tOjZweCI+Q0hBSU4gQ09OTkVDVElPTiAoUlBDKTwvZGl2PgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJjb25uUnBjIiBzdHlsZT0ibWFyZ2luOjAgMCA4cHgiPkxvYWRpbmfigKY8L3A+CiAgICAgICAgICA8aW5wdXQgaWQ9InJwY1VybCIgdHlwZT0icGFzc3dvcmQiIGF1dG9jb21wbGV0ZT0ib2ZmIiBhdXRvY2FwaXRhbGl6ZT0ib2ZmIiBzcGVsbGNoZWNrPSJmYWxzZSIgcGxhY2Vob2xkZXI9IlBhc3RlIHlvdXIgSGVsaXVzIGFkZHJlc3MgKGh0dHBzOi8vbWFpbm5ldC5oZWxpdXMtcnBjLmNvbS8/YXBpLWtleT3igKYpIiBzdHlsZT0id2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiMwNzEwMUU7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMik7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweDtmb250OjYwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWluaykiPgogICAgICAgICAgPGlucHV0IGlkPSJycGNDYXAiIHR5cGU9Im51bWJlciIgaW5wdXRtb2RlPSJudW1lcmljIiBwbGFjZWhvbGRlcj0iRGFpbHkgY2FsbCBjYXAgKDAgPSBub25lKS4gSGVsaXVzIGZyZWUg4omIIDMzLDAwMCBhIGRheSIgc3R5bGU9IndpZHRoOjEwMCU7bWFyZ2luLXRvcDo4cHg7YmFja2dyb3VuZDojMDcxMDFFO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZTIpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHg7Zm9udDo2MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1pbmspIj4KICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbi10b3A6OHB4Ij48YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9InJwY1NhdmUiIHR5cGU9ImJ1dHRvbiI+U2F2ZSBjaGFpbiBjb25uZWN0aW9uPC9idXR0b24+PGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0icnBjUmVzZXQiIHR5cGU9ImJ1dHRvbiI+R28gYmFjayB0byB0aGUgZnJlZSBvbmU8L2J1dHRvbj48L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJub3RlIiBpZD0icnBjTXNnIj48L3A+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjE2cHggMCA2cHgiPlRFTEVHUkFNIEJPVDwvZGl2PgogICAgICAgICAgPGEgY2xhc3M9ImJ0biBtaW50IiBpZD0idGdQYWdlIiBocmVmPSIjIiBzdHlsZT0id2lkdGg6MTAwJTttYXJnaW4tYm90dG9tOjhweCI+RWFzaWVyOiBvcGVuIHRoZSBzaW1wbGUgVGVsZWdyYW0gc2V0dXAgcGFnZSDihpI8L2E+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSIgaWQ9ImNvbm5UZyIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5Mb2FkaW5n4oCmPC9wPgogICAgICAgICAgPGlucHV0IGlkPSJ0Z1Rva2VuIiB0eXBlPSJwYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJvZmYiIGF1dG9jYXBpdGFsaXplPSJvZmYiIHNwZWxsY2hlY2s9ImZhbHNlIiBwbGFjZWhvbGRlcj0iUGFzdGUgeW91ciBib3QgdG9rZW4gZnJvbSBAQm90RmF0aGVyIiBzdHlsZT0id2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiMwNzEwMUU7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMik7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweDtmb250OjYwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWluaykiPgogICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7ZmxleC13cmFwOndyYXA7bWFyZ2luLXRvcDo4cHgiPjxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBpZD0idGdTYXZlIiB0eXBlPSJidXR0b24iPlNhdmUgYm90IHRva2VuPC9idXR0b24+PGJ1dHRvbiBjbGFzcz0iYnRuIHByaSIgaWQ9InRnQ29kZUJ0biIgdHlwZT0iYnV0dG9uIj5NYWtlIGEgcGFpcmluZyBjb2RlPC9idXR0b24+PGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0idGdUZXN0IiB0eXBlPSJidXR0b24iPlNlbmQgYSB0ZXN0IG1lc3NhZ2U8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJ0Z1VucGFpciIgdHlwZT0iYnV0dG9uIj5VbnBhaXIgcGhvbmVzPC9idXR0b24+PGJ1dHRvbiBjbGFzcz0iYnRuIHdhcm4iIGlkPSJ0Z1JlbW92ZSIgdHlwZT0iYnV0dG9uIj5SZW1vdmUgYm90PC9idXR0b24+PC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSIgaWQ9InRnQ29kZSIgaGlkZGVuPjwvcD48cCBjbGFzcz0ibm90ZSIgaWQ9InRnTXNnIj48L3A+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSI+U2VjcmV0cyBhcmUga2VwdCBvbmx5IG9uIHlvdXIgc2VydmVyJ3MgZGlzayBhbmQgYXJlIG5ldmVyIHNob3duIGFnYWluIGFmdGVyIHlvdSBzYXZlIHRoZW0uIFRoZSBib3QgdGFsa3Mgb25seSB0byBwaG9uZXMgeW91IHBhaXIgd2l0aCBhIG9uZS10aW1lIGNvZGUuPC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCBvd24iIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwaCI+8J+StSBNb3ZlIG1vbmV5IDxzcGFuPnZhdWx0IOKGkiB0cmFkaW5nIGNhc2g8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiPgogICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7ZmxleC13cmFwOndyYXA7YWxpZ24taXRlbXM6Y2VudGVyIj48aW5wdXQgaWQ9InYyY0FtdCIgdHlwZT0ibnVtYmVyIiBzdGVwPSJhbnkiIGlucHV0bW9kZT0iZGVjaW1hbCIgcGxhY2Vob2xkZXI9IkFtb3VudCAoJCkiIHN0eWxlPSJmbGV4OjEgMSAxMjBweDtiYWNrZ3JvdW5kOiMwNzEwMUU7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMik7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweDtmb250OjcwMCAxNHB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWluaykiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9InYyYyIgdHlwZT0iYnV0dG9uIj5Nb3ZlIHRvIHRyYWRpbmcgY2FzaDwvYnV0dG9uPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9InYyY0FsbCIgdHlwZT0iYnV0dG9uIj5Nb3ZlIGFsbDwvYnV0dG9uPjwvZGl2PgogICAgICAgICAgPHAgY2xhc3M9Im5vdGUiIGlkPSJ2MmNNc2ciPkxvY2tlZCBwcm9maXQgY29tZXMgYmFjayBpbnRvIHRoZSB0cmFkaW5nIHBvdCwgc28gaXQgY2FuIHdvcmsgYWdhaW4uIChQYXBlciBtb25leTogbm90aGluZyByZWFsIG1vdmVzLik8L3A+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIG93biIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5TYXZpbmdzIHdhbGxldCA8c3Bhbj53aGVyZSB5b3VyIHByb2ZpdCBnb2VzPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj4KICAgICAgICAgIDxsYWJlbCBjbGFzcz0ic2V0IiBzdHlsZT0iZGlzcGxheTpibG9jayI+PHNwYW4gc3R5bGU9ImZvbnQ6NzAwIDExcHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKSI+WW91ciBzYXZpbmdzIHdhbGxldCBhZGRyZXNzPC9zcGFuPgogICAgICAgICAgICA8aW5wdXQgaWQ9InNhdnciIHR5cGU9InRleHQiIGF1dG9jb21wbGV0ZT0ib2ZmIiBhdXRvY2FwaXRhbGl6ZT0ib2ZmIiBzcGVsbGNoZWNrPSJmYWxzZSIgc3R5bGU9ImRpc3BsYXk6YmxvY2s7d2lkdGg6MTAwJTttYXJnaW4tdG9wOjRweDtiYWNrZ3JvdW5kOiMwNzEwMUU7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lMik7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweDtmb250OjYwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWluaykiPjwvbGFiZWw+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tdG9wOjEwcHgiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gbWludCIgaWQ9InNhdlNhdmUiIHR5cGU9ImJ1dHRvbiI+U2F2ZSB3YWxsZXQ8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHByaSIgaWQ9InNlbmROb3ciIHR5cGU9ImJ1dHRvbiI+U2VuZCB2YXVsdCB0byBteSB3YWxsZXQgbm93PC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJub3RlIj5XaXRoICJhdXRvLXNlbmQiIG9uIChpbiBSdWxlcyksIGV2ZXJ5IHRpbWUgcHJvZml0IGdldHMgbG9ja2VkIGl0IGdvZXMgc3RyYWlnaHQgdG8gdGhpcyB3YWxsZXQuIEluIHBhcGVyIG1vZGUgaXQncyByZWNvcmRlZCwgbm90IHNlbnQ7IGluIGxpdmUgbW9kZSBpdCdzIGEgcmVhbCB0cmFuc2Zlci48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvc2VjdGlvbj4KICAgICAgPHNlY3Rpb24gY2xhc3M9InBhbmVsIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPk1vbmV5IG1vdmVzIDxzcGFuPnZhdWx0IGxvY2tzLCBzYXZpbmdzLCBwYXVzZXMsIHN0b3BzPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIiBpZD0iZXZlbnRzIj48cCBjbGFzcz0iZW1wdHkiPk5vdGhpbmcgeWV0LjwvcD48L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgICA8c2VjdGlvbiBjbGFzcz0icGFuZWwgb3duIiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGgiPkF1dG9waWxvdCA8c3Bhbj5vbmUgdGFwIHNldHMgdGhlIHdob2xlIHN0cmF0ZWd5PC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBiIj4KICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2ZsZXgtd3JhcDp3cmFwIj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBkYXRhLXByZXNldD0iZGVmZW5zZSIgdHlwZT0iYnV0dG9uIj7wn5uhIERlZmVuc2U8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIG1pbnQiIGRhdGEtcHJlc2V0PSJiYWxhbmNlZCIgdHlwZT0iYnV0dG9uIj7impYgQmFsYW5jZWQ8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBkYXRhLXByZXNldD0ib2ZmZW5zZSIgdHlwZT0iYnV0dG9uIj7impQgT2ZmZW5zZTwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSIgaWQ9InByZXNldE5vdGUiPjxiPkRlZmVuc2U6PC9iPiBzbWFsbGVyIHJpc2suIFRha2VzIHByb2ZpdCBlYXJsaWVyLCBzdG9wcyBzb29uZXIsIHBhdXNlcyBmYXN0ZXIsIHNraXBzIHRoZSByaXNraWVzdCBlYXJseSBidXlzLiA8Yj5CYWxhbmNlZDo8L2I+IHRoZSBkZWZhdWx0LiA8Yj5PZmZlbnNlOjwvYj4gYmlnZ2VyIHN3aW5ncywgbGV0cyB3aW5uZXJzIHJ1biBsb25nZXIuIE5vbmUgb2YgdGhlc2UgY2FuIHJlbW92ZSBsb3NzZXM7IERlZmVuc2UganVzdCBrZWVwcyB0aGVtIHNtYWxsZXIuPC9wPgogICAgICAgIDwvZGl2PgogICAgICA8L3NlY3Rpb24+CiAgICAgIDxzZWN0aW9uIGNsYXNzPSJwYW5lbCIgc3R5bGU9ImdyaWQtY29sdW1uOjEvLTEiPgogICAgICAgIDxkaXYgY2xhc3M9InBoIj5SdWxlcyA8c3Bhbj5jaGFuZ2UgYW55dGltZSwgYXBwbGllcyB0byB0aGUgbmV4dCBsYXVuY2g8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGIiPgogICAgICAgICAgPGRpdiBjbGFzcz0ic2V0IiBpZD0ic2V0Ij48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9Im93biIgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbi10b3A6MTJweCI+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBtaW50IiBpZD0ic2F2ZSIgdHlwZT0iYnV0dG9uIj5TYXZlIHJ1bGVzPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biB3YXJuIiBpZD0icmVzZXQiIHR5cGU9ImJ1dHRvbiI+UmVzZXQgcGFwZXIgcmVzdWx0czwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0ibm90ZSI+UGFwZXIgbW9kZTogQUxLQUlEIHdhdGNoZXMgZXZlcnkgbmV3IHB1bXAuZnVuIGxhdW5jaCwgd2FpdHMsIHJ1bnMgdGhlIGZpbHRlcnMsIGFuZCBwcmV0ZW5kcyB0byBidXkgdGhlIG9uZXMgdGhhdCBwYXNzLiBFYWNoIGJldCBpcyBhIHNsaWNlIG9mIHRoZSB0cmFkaW5nIGJhbGFuY2UsIHNvIGJldHMgZ3JvdyBhcyBpdCB3aW5zIGFuZCBzaHJpbmsgYXMgaXQgbG9zZXMuIFdoZW4gdGhlIGJhbGFuY2UgaGl0cyB5b3VyIGxvY2sgdGFyZ2V0LCB0aGUgcHJvZml0IG1vdmVzIHRvIHRoZSB2YXVsdCBhbmQgaXMgbmV2ZXIgdHJhZGVkIGFnYWluLiBBIGJhZCBkYXkgb3IgYSBsb3Npbmcgc3RyZWFrIHBhdXNlcyBpdC4gUmVzdWx0cyBpbmNsdWRlIHRoZSBwdW1wLmZ1biBmZWUsIHByaW9yaXR5IGZlZSwgSml0byB0aXAgYW5kIHNsaXBwYWdlLCBzbyB0aGV5J3JlIGhvbmVzdC4gTm8ga2V5IGlzIHN0b3JlZCBhbmQgbm90aGluZyBpcyBldmVyIHNlbnQuIExpdmUgbW9kZSBjb21lcyBvbmx5IGFmdGVyIHBhcGVyIHJlc3VsdHMgcHJvdmUgdGhlIHJ1bGVzLjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgPC9zZWN0aW9uPgogICAgPC9kaXY+CiAgPC9tYWluPgoKICA8Zm9vdGVyPkFMS0FJRCDCtyBwcml2YXRlIMK3IGJ1aWx0IG9uIFNMQVBCT1QncyBzY2FtIGNoZWNrczwvZm9vdGVyPgo8L2Rpdj4KCjxzY3JpcHQ+CihmdW5jdGlvbigpewogIHZhciBBUEk9KC9naXRodWJcLmlvJC8udGVzdChsb2NhdGlvbi5ob3N0bmFtZSl8fGxvY2F0aW9uLnByb3RvY29sPT09J2ZpbGU6Jyk/J2h0dHBzOi8vc2xhcGJvdC1iYWNrZW5kLXByb2R1Y3Rpb24udXAucmFpbHdheS5hcHAnOmxvY2F0aW9uLm9yaWdpbjsKICB2YXIgJD1mdW5jdGlvbihpZCl7cmV0dXJuIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKX07CiAgdmFyIHBhc3M9bnVsbCx0aW1lcj1udWxsLHN0YXRlPW51bGw7CiAgdmFyIEZJRUxEUz1bWydzdGFydFVzZCcsJ1N0YXJ0aW5nIGJhbmtyb2xsICgkKSddLFsnc2xvdHMnLCdTbmlwZXMgYXQgb25jZSAobW9uZXkgc3BsaXQgZXZlbmx5LCAwID0gb2ZmKSddLFsncmlza1BjdCcsJ0JldCBzaXplICUgKG9ubHkgd2hlbiBzbmlwZXMtYXQtb25jZSBpcyAwKSddLFsnbWluVHJhZGVVc2QnLCdTbWFsbGVzdCBiZXQgKCQpJ10sWydtYXhMb3NzUGN0JywnTWF4IGxvc3MgcGVyIHNuaXBlICglIG9mIEFMTCB5b3VyIG1vbmV5LCAwID0gb2ZmKSddLAogICAgWyd2YXVsdEF0WCcsJ0xvY2sgcHJvZml0cyB3aGVuIGJhbGFuY2UgaGl0cyAow5cgc3RhcnQpJ10sWydrZWVwWCcsJ0tlZXAgdHJhZGluZyAow5cgc3RhcnQpIGFmdGVyIGxvY2tpbmcnXSxbJ2RhaWx5U3RvcFBjdCcsJ1N0b3AgZm9yIHRoZSBkYXkgaWYgZG93biAoJSknXSwKICAgIFsnbWF4TG9zc1N0cmVhaycsJ1BhdXNlIGFmdGVyIHRoaXMgbWFueSBsb3NzZXMgaW4gYSByb3cnXSxbJ3BhdXNlTWluJywnUGF1c2UgbGVuZ3RoIChtaW51dGVzKSddLFsnbGVhcm4nLCdMZWFybiBmcm9tIHJlc3VsdHMgKDEgPSBvbiwgMCA9IG9mZiknXSxbJ2xlYXJuTWluJywnVHJhZGVzIG5lZWRlZCBiZWZvcmUganVkZ2luZyBhIHNldHVwJ10sCiAgICBbJ3RwMVNlbGxQY3QnLCdBdCB0YWtlIHByb2ZpdCwgc2VsbCB0aGlzICUgKHJlc3QgcmlkZXMpJ10sWyd0cmFpbFBjdCcsJ0FmdGVyICsxMDAlOiByaWRpbmcgcGFydCBzZWxscyBpZiBpdCBkcm9wcyB0aGlzICUgZnJvbSBpdHMgaGlnaCddLFsnbW9vbkhvbGRNaW4nLCdSaWRpbmcgcGFydCBtYXggaG9sZCAobWludXRlcyknXSwKICAgIFsnc21hcnRCb29zdCcsJ0JldCBtdWx0aXBsaWVyIHdoZW4gc21hcnQgbW9uZXkgaXMgaW4nXSxbJ2Zhdm9yQm9vc3QnLCdCZXQgbXVsdGlwbGllciBvbiB3aW5uaW5nIHNldHVwcyddLFsnbWF4QmV0UGN0JywnTWF4IGJldCAoJSBvZiB0cmFkaW5nIGJhbGFuY2UpJ10sCiAgICBbJ2RldkV4aXQnLCdFeGl0IGluc3RhbnRseSBpZiBjcmVhdG9yIGR1bXBzICgxID0gb24pJ10sWydjYXNoT3V0TWNhcCcsJ1J1ZyB6b25lOiBzZWxsIGV2ZXJ5dGhpbmcgYXQgdGhpcyBtYXJrZXQgY2FwICgkLCAwID0gb2ZmKSddLFsnZ3JhZE9uJywnR3JhZHVhdGVzOiBidXkgYWZ0ZXIgZ3JhZHVhdGlvbiAoMSA9IG9uKSddLFsnZ3JhZE1pbkxpcScsJ0dyYWR1YXRlczogbWluIGxpcXVpZGl0eSAoJCknXSxbJ2dyYWRNaW5NY2FwJywnR3JhZHVhdGVzOiBtaW4gbWFya2V0IGNhcCAoJCknXSxbJ2dyYWRNYXhNY2FwJywnR3JhZHVhdGVzOiBtYXggbWFya2V0IGNhcCAoJCknXSxbJ2dyYWRCdXlzNScsJ0dyYWR1YXRlczogbWluIGJ1eXMgaW4gNSBtaW4nXSxbJ2dyYWRCdXlTaGFyZScsJ0dyYWR1YXRlczogbWluIGJ1eSAlJ10sWydncmFkTWluQ2g1JywnR3JhZHVhdGVzOiBtaW4gNS1taW4gY2hhbmdlICUnXSxbJ2dyYWRNYXhDaDUnLCdHcmFkdWF0ZXM6IG1heCA1LW1pbiBjaGFuZ2UgJSAobm90IGNoYXNpbmcpJ10sWydncmFkTWF4T3BlbicsJ0dyYWR1YXRlczogbWF4IG9wZW4gYXQgb25jZSddLFsnZ3JhZFRwJywnR3JhZHVhdGVzOiB0YWtlIHByb2ZpdCAlJ10sWydncmFkVHAxU2VsbCcsJ0dyYWR1YXRlczogc2VsbCB0aGlzICUgdGhlcmUnXSxbJ2dyYWRTbCcsJ0dyYWR1YXRlczogc3RvcCBsb3NzICUnXSxbJ2dyYWRUcmFpbCcsJ0dyYWR1YXRlczogdHJhaWxpbmcgc3RvcCAlJ10sWydncmFkSG9sZCcsJ0dyYWR1YXRlczogbWF4IGhvbGQgKG1pbiknXSwKICAgIFsnY29weU9uJywnQ29weSB0cmFkaW5nICgxID0gb24pJ10sWydjb3B5VG9wTicsJ0NvcHk6IGZvbGxvdyB0aGUgdG9wIE4gd2FsbGV0cyddLFsnY29weU1pblVzZCcsJ0NvcHk6IHRoZWlyIGJ1eSBtdXN0IGJlIGF0IGxlYXN0ICgkKSddLFsnY29weU1pbldhbGxldHMnLCdDb3B5OiBzbWFydCB3YWxsZXRzIG5lZWRlZCddLFsnY29weU1heE9wZW4nLCdDb3B5OiBtYXggb3BlbiBhdCBvbmNlJ10sWydjb3B5VHAnLCdDb3B5OiB0YWtlIHByb2ZpdCAlJ10sWydjb3B5U2wnLCdDb3B5OiBzdG9wIGxvc3MgJSddLFsnY29weVRyYWlsJywnQ29weTogdHJhaWxpbmcgc3RvcCAlJ10sWydjb3B5SG9sZCcsJ0NvcHk6IG1heCBob2xkIChtaW4pJ10sCiAgICBbJ2dyaWRPbicsJ0dyaWQgdHJhZGluZyAoMSA9IG9uKSddLFsnZ3JpZFN0YXJ0VXNkJywnR3JpZDogcGFwZXIgcG9vbCAoJCknXSxbJ2dyaWRNYXgnLCdHcmlkOiB0b2tlbnMgYXQgb25jZSddLFsnZ3JpZExldmVscycsJ0dyaWQ6IGRpcCBsZXZlbHMnXSxbJ2dyaWRTdGVwUGN0JywnR3JpZDogc3RlcCAlJ10sWydncmlkTWluTGlxJywnR3JpZDogbWluIGxpcXVpZGl0eSAoJCknXSwKICAgIFsnYXV0b3BpbG90JywnQXV0b3BpbG90OiBwcm90ZWN0cyB0aGUgYWNjb3VudCBieSBpdHNlbGYgKDEgPSBvbiknXSxbJ2F1dG9TbG90cycsJ0F1dG9waWxvdDogZmV3ZXIsIGJpZ2dlciBiZXRzIGFzIHRoZSBiYWxhbmNlIHNocmlua3MgKDEgPSBvbiknXSxbJ2RkQnJha2UxUGN0JywnQXV0b3BpbG90OiBkb3duIHRoaXMgJSBmcm9tIHRoZSBwZWFrLCBzd2l0Y2ggdG8gc2FmZXN0IHNldHRpbmdzJ10sWydkZEJyYWtlMlBjdCcsJ0F1dG9waWxvdDogZG93biB0aGlzICUsIGFsc28gcGF1c2UgbmV3IHRyYWRlcyA4IGhvdXJzJ10sWydraWxsQXZnUGN0JywnQXV0b3BpbG90OiBzd2l0Y2ggb2ZmIGFuIGVudHJ5IHR5cGUgYXZlcmFnaW5nIHdvcnNlIHRoYW4gdGhpcyAlIHBlciB0cmFkZSddLFsna2lsbE1pblRyYWRlcycsJ0F1dG9waWxvdDogLi4ub3ZlciBhdCBsZWFzdCB0aGlzIG1hbnkgdHJhZGVzJ10sWydtb21lbnR1bScsJ01vbWVudHVtIGVudHJ5OiBidXkgb25seSB3aGVuIHJlYWwgYnV5aW5nIHNob3dzIHVwICgxID0gb24pJ10sWydtb21XaW5kb3dNaW4nLCdNb21lbnR1bTogd2F0Y2ggZWFjaCBsYXVuY2ggdGhpcyBtYW55IG1pbnV0ZXMnXSxbJ21vbUJ1eWVyczYwJywnTW9tZW50dW06IGRpZmZlcmVudCBidXllcnMgaW4gdGhlIGxhc3QgbWludXRlJ10sWydtb21CdXlTaGFyZScsJ01vbWVudHVtOiBidXlzIGF0IGxlYXN0IHRoaXMgJSBvZiB0cmFkZXMnXSxbJ21vbU5ldFNvbCcsJ01vbWVudHVtOiBTT0wgZmxvd2luZyBpbiwgbGFzdCBtaW51dGUnXSxbJ21vbVJpc2UybScsJ01vbWVudHVtOiBwcmljZSB1cCBhdCBsZWFzdCB0aGlzICUgaW4gMiBtaW4nXSxbJ21vbU1heE1jYXAnLCdNb21lbnR1bTogdG9vIGxhdGUgYWJvdmUgdGhpcyBtYXJrZXQgY2FwICgkKSddLFsnYXV0b1R1bmUnLCdBdXRvLXR1bmU6IGFkb3B0IHRoZSBTd2VldCBTcG90IGV2ZXJ5IDYgaCB3aGVuIGl0IHByb3ZlcyBiZXR0ZXIgKDEgPSBvbiknXSxbJ2xhYkZpbHRlcicsJ1dpbm5lciBMYWI6IHNraXAgbGF1bmNoZXMgYmVsb3cgdGhlIGxpbmUgKDEgPSBvbiknXSxbJ2xhYk1pbkxpZnQnLCdXaW5uZXIgTGFiOiB0aGUgbGluZSAoMSA9IGFuIGF2ZXJhZ2UgbGF1bmNoKSddLFsnbGFiQm9vc3QnLCdXaW5uZXIgTGFiOiBiZXQgbXVsdGlwbGllciB3aGVuIGl0IHNjb3JlcyAyLjXDlysnXSxbJ3RyYWlsQXQ1eCcsJ1RpZ2h0ZXIgd2luZG93IG9uY2UgdXAgNcOXICglKSddLFsndHJhaWxBdDEweCcsJ1RpZ2h0ZXN0IHdpbmRvdyBvbmNlIHVwIDEww5cgKCUpJ10sWydhdXRvU2VuZCcsJ0F1dG8tc2VuZCBsb2NrZWQgcHJvZml0IHRvIHNhdmluZ3MgKDEgPSBvbiknXSwKICAgIFsnZmFzdExhbmUnLCdMYXVuY2ggU2hvdDogZmlyZSBhdCBsYXVuY2ggKDEgPSBvbiknXSxbJ2Zhc3RNYXhNY2FwJywnTGF1bmNoIFNob3Q6IG9ubHkgdW5kZXIgdGhpcyBtYXJrZXQgY2FwICgkKSddLFsnZmFzdEJldFBjdCcsJ0xhdW5jaCBTaG90IGJldCAoJSBvZiBiYWxhbmNlKSddLAogICAgWydmYXN0TWF4UGVyTWluJywnTGF1bmNoIFNob3Q6IG1heCBidXlzIHBlciBtaW51dGUnXSxbJ2Zhc3RNYXhPcGVuJywnTGF1bmNoIFNob3Q6IG1heCBvcGVuIGF0IG9uY2UnXSxbJ2Zhc3RNYXhEZXZQY3QnLCdMYXVuY2ggU2hvdDogc2tpcCBpZiBjcmVhdG9yIGJvdWdodCBvdmVyICglKSddLAogICAgWydmYXN0VGltZW91dFNlYycsJ0xhdW5jaCBTaG90OiBtdXN0IGxpZnQgb2ZmIHdpdGhpbiAoc2VjKSddLFsnZmFzdE1pbkdhaW5QY3QnLCdMYXVuY2ggU2hvdDogbGlmdC1vZmYgbWVhbnMgdXAgYXQgbGVhc3QgKCUpJ10sWyd3YWl0U2VjJywnV2FpdCBiZWZvcmUganVkZ2luZyAoc2VjKSddLFsnbWluUHJvZ3Jlc3MnLCdNaW4gJSBib25kZWQgYnkgdGhlbiddLFsnbWF4RGV2UGN0JywnTWF4IGNyZWF0b3IgaG9sZGluZyAlJ10sCiAgICBbJ21heFRvcDEwUGN0JywnTWF4IHRvcC0xMCB3YWxsZXRzICUnXSxbJ21heFRvcDFQY3QnLCdNYXggc2luZ2xlIHdhbGxldCAlJ10sWyd0cFBjdCcsJ1Rha2UgcHJvZml0ICUnXSxbJ3NsUGN0JywnU3RvcCBsb3NzICUnXSwKICAgIFsnbWF4SG9sZE1pbicsJ01heCBob2xkIChtaW51dGVzKSddLFsnbWF4T3BlbicsJ01heCBvcGVuIHBvc2l0aW9ucyddLFsnbWF4RXZhbFBlck1pbicsJ0xhdW5jaGVzIGp1ZGdlZCBwZXIgbWludXRlJ11dOwogIGZ1bmN0aW9uIGVzYyhzKXtyZXR1cm4gU3RyaW5nKHM9PW51bGw/Jyc6cykucmVwbGFjZSgvWyY8PiInXS9nLGZ1bmN0aW9uKGMpe3JldHVybnsnJic6JyZhbXA7JywnPCc6JyZsdDsnLCc+JzonJmd0OycsJyInOicmcXVvdDsnLCInIjonJiMzOTsnfVtjXX0pfQogIGZ1bmN0aW9uIGFwaShwLG9wdCl7b3B0PW9wdHx8e307b3B0LmhlYWRlcnM9eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJyxBdXRob3JpemF0aW9uOidCZWFyZXIgJytwYXNzfTsKICAgIHJldHVybiBmZXRjaChBUEkrcCxvcHQpLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpLmNhdGNoKGZ1bmN0aW9uKCl7cmV0dXJue319KS50aGVuKGZ1bmN0aW9uKGope2ouX3M9ci5zdGF0dXM7cmV0dXJuIGp9KX0pfQogIGZ1bmN0aW9uIGFnbyh0KXt2YXIgcz1NYXRoLm1heCgwLE1hdGgucm91bmQoKERhdGUubm93KCktdCkvMTAwMCkpO3JldHVybiBzPDYwP3MrJ3MnOnM8MzYwMD9NYXRoLnJvdW5kKHMvNjApKydtJzpNYXRoLnJvdW5kKHMvMzYwMCkrJ2gnfQogIGZ1bmN0aW9uIHNjYW4obSxzeW0pe3JldHVybiAnPGEgaHJlZj0iaHR0cHM6Ly9jcnlwdG9iaXptbzIuZ2l0aHViLmlvL1NMQVBCT1QvP3NjYW49JytlbmNvZGVVUklDb21wb25lbnQobSkrJyI+Jytlc2Moc3ltfHwnPycpKyc8L2E+J30KICBmdW5jdGlvbiB0b2sobSxzeW0sbmFtZSl7cmV0dXJuIHNjYW4obSxzeW0pKyhuYW1lJiZuYW1lIT09c3ltPyc8c3BhbiBjbGFzcz0idG9rbiI+Jytlc2MobmFtZSkrJzwvc3Bhbj4nOicnKX0KICBmdW5jdGlvbiBjYUxpbmUobSl7cmV0dXJuIG0/JzxkaXYgY2xhc3M9ImNhIj48Y29kZT4nK2VzYyhtKSsnPC9jb2RlPjxidXR0b24gdHlwZT0iYnV0dG9uIiBkYXRhLWNvcHk9IicrZXNjKG0pKyciPkNvcHk8L2J1dHRvbj48YSB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciIgaHJlZj0iaHR0cHM6Ly9kZXhzY3JlZW5lci5jb20vc29sYW5hLycrZW5jb2RlVVJJQ29tcG9uZW50KG0pKyciPkNoYXJ0PC9hPjwvZGl2Pic6Jyd9CiAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGZ1bmN0aW9uKGUpe3ZhciBiPWUudGFyZ2V0LmNsb3Nlc3QoJ1tkYXRhLWNvcHldJyk7aWYoIWIpcmV0dXJuOwogICAgKG5hdmlnYXRvci5jbGlwYm9hcmQ/bmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoYi5kYXRhc2V0LmNvcHkpOlByb21pc2UucmVqZWN0KCkpLnRoZW4oZnVuY3Rpb24oKXtiLnRleHRDb250ZW50PSdDb3BpZWQnO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtiLnRleHRDb250ZW50PSdDb3B5J30sMTIwMCl9LGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nSG9sZCB0byBjb3B5J30pfSk7CiAgZnVuY3Rpb24gc29sKG4pe3JldHVybiAobj49MD8nKyc6JycpKygrbikudG9GaXhlZCg0KSsnIFNPTCd9CgogIHZhciByb2xlPSdvd25lcic7CiAgZnVuY3Rpb24gYXNWaWV3ZXIocCl7cGFzcz1wO3JvbGU9J3ZpZXdlcic7ZG9jdW1lbnQuYm9keS5jbGFzc0xpc3QuYWRkKCd2aWV3ZXInKTtzdGFydCgpfQogIHZhciB2dD0obG9jYXRpb24uaGFzaC5tYXRjaCgvdmlldz0oW0EtWmEtejAtOV8tXXsyMCwxMDB9KS8pfHxbXSlbMV07CiAgaWYodnQpewogICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwnJyxsb2NhdGlvbi5wYXRobmFtZSk7CiAgICBmZXRjaChBUEkrJy9hcGkvbXAvdmlldycse21ldGhvZDonUE9TVCcsaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nfSxib2R5OkpTT04uc3RyaW5naWZ5KHt0b2tlbjp2dH0pfSkudGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29uKCl9KS50aGVuKGZ1bmN0aW9uKHIpewogICAgICBpZighci5wYXNzKXskKCdnbXNnJykudGV4dENvbnRlbnQ9ci5lcnJvcnx8J1RoaXMgbGluayBpc25cJ3QgdmFsaWQgYW55bW9yZS4nO3JldHVybn0KICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ2Nhbm5vblZpZXcnLEpTT04uc3RyaW5naWZ5KHtwYXNzOnIucGFzcyxleHA6RGF0ZS5ub3coKSs2LjkqMjQqMzYwMGUzfSkpO2FzVmlld2VyKHIucGFzcykKICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCl7JCgnZ21zZycpLnRleHRDb250ZW50PSdUaGUgc2VydmVyIGRpZG5cJ3QgYW5zd2VyLiBUcnkgdGhlIGxpbmsgYWdhaW4gaW4gYSBtaW51dGUuJ30pOwogIH0gZWxzZSB7CiAgICB2YXIgc2F2ZWQ9bnVsbCxzdj1udWxsO3RyeXtzYXZlZD1KU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdtcFNlc3Npb24nKXx8J251bGwnKTtzdj1KU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdjYW5ub25WaWV3Jyl8fCdudWxsJyl9Y2F0Y2goZSl7fQogICAgaWYoc2F2ZWQmJnNhdmVkLmV4cD5EYXRlLm5vdygpKXtwYXNzPXNhdmVkLnBhc3M7c3RhcnQoKX0KICAgIGVsc2UgaWYoc3YmJnN2LmV4cD5EYXRlLm5vdygpKWFzVmlld2VyKHN2LnBhc3MpOwogIH0KICBmdW5jdGlvbiBrZWVwKHIpewogICAgdmFyIGxpZmU9ci5yZW1lbWJlcmVkPzI5LjUqMjQqMzYwMGUzOjExLjUqMzYwMGUzOwogICAgcGFzcz1yLnBhc3M7bG9jYWxTdG9yYWdlLnNldEl0ZW0oJ21wU2Vzc2lvbicsSlNPTi5zdHJpbmdpZnkoe3Bhc3M6cGFzcyxleHA6RGF0ZS5ub3coKStsaWZlfSkpO3N0YXJ0KCk7CiAgfQogIC8vIHNob3cgLyBoaWRlIHdoYXQgeW91J3JlIHR5cGluZwogIGZ1bmN0aW9uIHNob3dDb2RlRm9ybSgpewogICAgaWYoJCgnY29kZUZvcm0nKSlyZXR1cm47CiAgICAkKCdjb2RlU2xvdCcpLmFwcGVuZENoaWxkKGRvY3VtZW50LmltcG9ydE5vZGUoJCgnY29kZVRwbCcpLmNvbnRlbnQsdHJ1ZSkpOwogICQoJ2V5ZScpLm9uY2xpY2s9ZnVuY3Rpb24oKXt2YXIgYz0kKCdjb2RlJyksc2hvdz1jLnR5cGU9PT0ncGFzc3dvcmQnO2MudHlwZT1zaG93Pyd0ZXh0JzoncGFzc3dvcmQnO3RoaXMudGV4dENvbnRlbnQ9c2hvdz8nSGlkZSc6J1Nob3cnO3RoaXMuc2V0QXR0cmlidXRlKCdhcmlhLWxhYmVsJyxzaG93PydIaWRlIGNvZGUnOidTaG93IGNvZGUnKTtjLmZvY3VzKCl9OwogICAgLy8gb3duZXIgY29kZSAoYSByZWFsIGZvcm0sIHNvIGlQaG9uZSBvZmZlcnMgdG8gc2F2ZSBpdCBpbiBQYXNzd29yZHMpCiAgICAkKCdjb2RlRm9ybScpLm9uc3VibWl0PWFzeW5jIGZ1bmN0aW9uKGUpewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7dmFyIGM9JCgnY29kZScpLnZhbHVlO2lmKCFjKXJldHVybiBmYWxzZTt2YXIgYj0kKCdnbycpO2IuZGlzYWJsZWQ9dHJ1ZTskKCdnbXNnJykudGV4dENvbnRlbnQ9Jyc7CiAgICAgIHZhciByPWF3YWl0IGZldGNoKEFQSSsnL2FwaS9hdXRoL293bmVyJyx7bWV0aG9kOidQT1NUJyxoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LGJvZHk6SlNPTi5zdHJpbmdpZnkoe2NvZGU6YyxyZW1lbWJlcjokKCdyZW1lbWJlcicpLmNoZWNrZWR9KX0pLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSkuY2F0Y2goZnVuY3Rpb24oKXtyZXR1cm57fX0pOwogICAgICBiLmRpc2FibGVkPWZhbHNlOwogICAgICBpZighci5wYXNzKXskKCdnbXNnJykudGV4dENvbnRlbnQ9ci5lcnJvcnx8J1dyb25nIGNvZGUuJztyZXR1cm4gZmFsc2V9CiAgICAgIGtlZXAocik7cmV0dXJuIGZhbHNlOwogICAgfTsKICB9CiAgaWYoL293bmVyLy50ZXN0KGxvY2F0aW9uLmhhc2gpKXskKCdvd25lckdhdGUnKS5oaWRkZW49ZmFsc2U7JCgncHJpdk5vdGUnKS5oaWRkZW49dHJ1ZTtzaG93Q29kZUZvcm0oKX0gICAvLyBvd25lciBzaWduLWluIGxpdmVzIG9ubHkgYXQgY2Fubm9uLmh0bWwjb3duZXIKCiAgLy8gd2FsbGV0IHNpZ24taW46IHByb3ZlcyB5b3Ugb3duIHRoZSBvd25lciB3YWxsZXQsIG5vIGNvZGUgbmVlZGVkCiAgZnVuY3Rpb24gcHJvdmlkZXIoKXtyZXR1cm4gKHdpbmRvdy5waGFudG9tJiZ3aW5kb3cucGhhbnRvbS5zb2xhbmEpfHwod2luZG93LnNvbGFuYSYmd2luZG93LnNvbGFuYS5pc1BoYW50b20/d2luZG93LnNvbGFuYTpudWxsKXx8d2luZG93LnNvbGZsYXJlfHxudWxsfQogIGlmKCFwcm92aWRlcigpKXt2YXIgdT1sb2NhdGlvbi5ocmVmOyQoJ29wZW5QaGFudG9tJykuaHJlZj0naHR0cHM6Ly9waGFudG9tLmFwcC91bC9icm93c2UvJytlbmNvZGVVUklDb21wb25lbnQodSkrJz9yZWY9JytlbmNvZGVVUklDb21wb25lbnQobG9jYXRpb24ub3JpZ2luKTskKCdvcGVuUGhhbnRvbScpLmhpZGRlbj1mYWxzZTskKCd3bm90ZScpLnRleHRDb250ZW50PSdPbiBpUGhvbmUsIHdhbGxldCBzaWduLWluIHdvcmtzIGluc2lkZSB0aGUgUGhhbnRvbSBhcHA6IHRhcCAiT3BlbiB0aGlzIHBhZ2UgaW4gUGhhbnRvbSIuJ30KICAkKCd3YWxsZXQnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7CiAgICB2YXIgcD1wcm92aWRlcigpO2lmKCFwKXskKCdnbXNnJykudGV4dENvbnRlbnQ9J05vIHdhbGxldCBmb3VuZCBoZXJlLiBUYXAgIk9wZW4gdGhpcyBwYWdlIGluIFBoYW50b20iLic7cmV0dXJufQogICAgdmFyIGI9dGhpcztiLmRpc2FibGVkPXRydWU7JCgnZ21zZycpLnRleHRDb250ZW50PScnOwogICAgdHJ5ewogICAgICB2YXIgdz0oYXdhaXQgcC5jb25uZWN0KCkpLnB1YmxpY0tleS50b1N0cmluZygpOwogICAgICB2YXIgY2g9YXdhaXQgZmV0Y2goQVBJKycvYXBpL2F1dGgvY2hhbGxlbmdlP3dhbGxldD0nK2VuY29kZVVSSUNvbXBvbmVudCh3KSkudGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29uKCl9KS5jYXRjaChmdW5jdGlvbigpe3JldHVybiB7fX0pOwogICAgICBpZighY2gubWVzc2FnZSl0aHJvdyBuZXcgRXJyb3IoY2guZXJyb3J8fCdZb3VyIHNlcnZlciBkaWRuXCd0IGFuc3dlciwgc28gc2lnbi1pbiBjYW5cJ3Qgc3RhcnQuIFRoZSB3YWxsZXQgaXMgZmluZS4gVHJ5IGFnYWluIGluIGEgbWludXRlLicpOwogICAgICB2YXIgc2lnPWF3YWl0IHAuc2lnbk1lc3NhZ2UobmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKGNoLm1lc3NhZ2UpLCd1dGY4Jyk7CiAgICAgIHZhciBieXRlcz1zaWcuc2lnbmF0dXJlfHxzaWcsYmluPScnO2Zvcih2YXIgaT0wO2k8Ynl0ZXMubGVuZ3RoO2krKyliaW4rPVN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZXNbaV0pOwogICAgICB2YXIgcj1hd2FpdCBmZXRjaChBUEkrJy9hcGkvYXV0aC92ZXJpZnknLHttZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sYm9keTpKU09OLnN0cmluZ2lmeSh7d2FsbGV0Oncsc2lnbmF0dXJlOmJ0b2EoYmluKSxyZW1lbWJlcjokKCdyZW1lbWJlcicpLmNoZWNrZWR9KX0pLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSk7CiAgICAgIHZhciBzaD13LnNsaWNlKDAsNCkrJ+KApicrdy5zbGljZSgtNCk7CiAgICAgIGlmKHIuaXNPd25lcj09PWZhbHNlfHwoci5wYXNzJiYhci5pc093bmVyKSl7CiAgICAgICAgLy8gbm90IHRoZSBvd25lcjogaWYgdGhpcyB3YWxsZXQgaXMgb24gdGhlIHZpZXdlciBsaXN0LCBvcGVuIHRoZSBkYXNoYm9hcmQgaW4gVklFVyBPTkxZIG1vZGUKICAgICAgICB2YXIgdnA9ci5wYXNzfHxyLmJhc2ljUGFzczsKICAgICAgICBpZih2cCl7dmFyIHN0PWF3YWl0IGZldGNoKEFQSSsnL2FwaS9tcC9zdGF0ZScse2hlYWRlcnM6e0F1dGhvcml6YXRpb246J0JlYXJlciAnK3ZwfX0pLnRoZW4oZnVuY3Rpb24oeCl7cmV0dXJuIHguanNvbigpLnRoZW4oZnVuY3Rpb24oail7ai5fcz14LnN0YXR1cztyZXR1cm4gan0pfSkuY2F0Y2goZnVuY3Rpb24oKXtyZXR1cm57fX0pOwogICAgICAgICAgaWYoc3QuX3M9PT0yMDAmJnN0LnJvbGU9PT0ndmlld2VyJyl7bG9jYWxTdG9yYWdlLnNldEl0ZW0oJ2Nhbm5vblZpZXcnLEpTT04uc3RyaW5naWZ5KHtwYXNzOnZwLGV4cDpEYXRlLm5vdygpKzExLjUqMzYwMGUzfSkpO2FzVmlld2VyKHZwKTtyZXR1cm59fQogICAgICAgICQoJ2dtc2cnKS50ZXh0Q29udGVudD0nVGhpcyB3YWxsZXQgY2FuXCd0IG9wZW4gdGhpcyBkYXNoYm9hcmQuJztiLmRpc2FibGVkPWZhbHNlO3JldHVybn0KICAgICAgaWYoIXIucGFzcyl7JCgnZ21zZycpLnRleHRDb250ZW50PSdUaGUgc2VydmVyIGRpZG5cJ3QgY29uZmlybSBpdC4gVHJ5IGFnYWluIGluIGEgbWludXRlLic7Yi5kaXNhYmxlZD1mYWxzZTtyZXR1cm59CiAgICAgIGtlZXAocik7CiAgICB9Y2F0Y2goZSl7JCgnZ21zZycpLnRleHRDb250ZW50PShlJiZlLm1lc3NhZ2UpfHwnV2FsbGV0IHNpZ24taW4gd2FzIGNhbmNlbGxlZC4nO2IuZGlzYWJsZWQ9ZmFsc2V9CiAgfTsKICAkKCdvdXQnKS5vbmNsaWNrPWZ1bmN0aW9uKCl7bG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0ocm9sZT09PSd2aWV3ZXInPydjYW5ub25WaWV3JzonbXBTZXNzaW9uJyk7bG9jYXRpb24ucmVsb2FkKCl9OwoKICBmdW5jdGlvbiBzdGFydCgpeyQoJ2dhdGUnKS5oaWRkZW49dHJ1ZTskKCdhcHAnKS5oaWRkZW49ZmFsc2U7bG9hZCgpO2NsZWFySW50ZXJ2YWwodGltZXIpO3RpbWVyPXNldEludGVydmFsKGxvYWQsNDAwMCl9CiAgYXN5bmMgZnVuY3Rpb24gbG9hZCgpewogICAgdmFyIGQ9YXdhaXQgYXBpKCcvYXBpL21wL3N0YXRlJyk7CiAgICBpZihkLl9zPT09NDAzfHxkLl9zPT09NDAxKXsKICAgICAgaWYocm9sZT09PSd2aWV3ZXInKXtsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnY2Fubm9uVmlldycpO2NsZWFySW50ZXJ2YWwodGltZXIpOyQoJ2FwcCcpLmhpZGRlbj10cnVlOyQoJ2dhdGUnKS5oaWRkZW49ZmFsc2U7JCgnZ21zZycpLnRleHRDb250ZW50PWQuZXJyb3J8fCdUaGlzIGxpbmsgd2FzIHR1cm5lZCBvZmYuIEFzayB0aGUgb3duZXIgZm9yIGEgbmV3IG9uZS4nO3JldHVybn0KICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ21wU2Vzc2lvbicpO2xvY2F0aW9uLnJlbG9hZCgpO3JldHVybn0KICAgIGlmKCFkLnNldHRpbmdzKXJldHVybjtzdGF0ZT1kOwogICAgaWYoZG9jdW1lbnQuaGlkZGVuKXJldHVybjsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIG5vYm9keSBpcyBsb29raW5nOiBkb24ndCB0b3VjaCB0aGUgcGFnZQogICAgaWYoZWRpdGluZ3x8KGRvY3VtZW50LmFjdGl2ZUVsZW1lbnQmJi9eKElOUFVUfFRFWFRBUkVBfFNFTEVDVCkkLy50ZXN0KGRvY3VtZW50LmFjdGl2ZUVsZW1lbnQudGFnTmFtZSkpKXJldHVybjsgICAvLyBuZXZlciBtb3ZlIHRoaW5ncyB3aGlsZSB5b3UgdHlwZSBvciBlZGl0IHNldHRpbmdzCiAgICBrZWVwUGxhY2UoZnVuY3Rpb24oKXtyZW5kZXIoZCl9KTsKICB9CiAgLy8gd2hpbGUgYW55IG9mIFlPVVIgc2V0dGluZ3MgcGFuZWxzIGlzIG9uIHNjcmVlbiwgdGhlIGxpdmUgbnVtYmVycyBob2xkIHN0aWxsIHNvIG5vdGhpbmcganVtcHMgdW5kZXIgeW91ciB0aHVtYgogIHZhciBlZGl0aW5nPWZhbHNlLHZpc1BhbmVscz17fTsKICBpZignSW50ZXJzZWN0aW9uT2JzZXJ2ZXInIGluIHdpbmRvdyl7dmFyIGlvPW5ldyBJbnRlcnNlY3Rpb25PYnNlcnZlcihmdW5jdGlvbihlcyl7ZXMuZm9yRWFjaChmdW5jdGlvbihlKXt2aXNQYW5lbHNbZS50YXJnZXQuZGF0YXNldC5waWRdPWUuaXNJbnRlcnNlY3Rpbmd9KTtlZGl0aW5nPU9iamVjdC5rZXlzKHZpc1BhbmVscykuc29tZShmdW5jdGlvbihrKXtyZXR1cm4gdmlzUGFuZWxzW2tdfSl9LHt0aHJlc2hvbGQ6MC4wMn0pOwogICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnc2VjdGlvbi5wYW5lbC5vd24nKS5mb3JFYWNoKGZ1bmN0aW9uKGVsLGkpe2VsLmRhdGFzZXQucGlkPSdwJytpO2lvLm9ic2VydmUoZWwpfSl9CiAgLy8gd2hlbiBudW1iZXJzIGRvIHJlZnJlc2gsIGtlZXAgd2hhdGV2ZXIgeW91IHdlcmUgbG9va2luZyBhdCBleGFjdGx5IHdoZXJlIGl0IHdhcwogIGZ1bmN0aW9uIGtlZXBQbGFjZShmbil7CiAgICB2YXIgYW5jaG9yPW51bGwsdG9wPTAsZWxzPWRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5wYW5lbCwuY2FyZCwuYmsnKTsKICAgIGZvcih2YXIgaT0wO2k8ZWxzLmxlbmd0aDtpKyspe3ZhciByPWVsc1tpXS5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTtpZihyLmJvdHRvbT44MCl7YW5jaG9yPWVsc1tpXTt0b3A9ci50b3A7YnJlYWt9fQogICAgZm4oKTsKICAgIGlmKGFuY2hvciYmZG9jdW1lbnQuYm9keS5jb250YWlucyhhbmNob3IpKXt2YXIgbnQ9YW5jaG9yLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpLnRvcDtpZihNYXRoLmFicyhudC10b3ApPjEpd2luZG93LnNjcm9sbEJ5KDAsbnQtdG9wKX0KICB9CiAgZnVuY3Rpb24gcmVuZGVyKGQpewogICAgdmFyIGY9JCgnZmVlZCcpO2YuY2xhc3NOYW1lPSdmZWVkJysoZC5vbiYmZC5mZWVkLmNvbm5lY3RlZD8nIG9uJzonJyk7Zi5xdWVyeVNlbGVjdG9yKCdzcGFuJykudGV4dENvbnRlbnQ9IWQub24/J3BhdXNlZCc6ZC5mZWVkLmNvbm5lY3RlZD8oJ2xpdmUgwrcgcHVtcC5mdW4nKyhkLmZlZWQubGFzdEV2ZW50QXQ/JyDCtyBsYXN0IGxhdW5jaCAnK2FnbyhkLmZlZWQubGFzdEV2ZW50QXQpKycgYWdvIMK3ICcrKGQuZmVlZC5wZXJNaW58fDApKycvbWluJzonJykpOidjb25uZWN0aW5n4oCmJzsKICAgICQoJ3B1bHNlJykudGV4dENvbnRlbnQ9ZC5mZWVkLmxhc3RFdmVudEF0PydsYXN0IGxhdW5jaCAnK2FnbyhkLmZlZWQubGFzdEV2ZW50QXQpKycgYWdvIMK3ICcrKGQuZmVlZC5wZXJNaW58fDApKycgYSBtaW51dGUgwrcgUEFQRVIgbW9uZXknOid3YWl0aW5nIGZvciB0aGUgZmlyc3QgbGF1bmNo4oCmJzsKICAgIHZhciBMQj1kLmxhYjsKICAgIGlmKExCKXsKICAgICAgJCgnbGFiU3RhdCcpLnRleHRDb250ZW50PUxCLnJlYWR5PyfinIUgc3RlZXJpbmcgdHJhZGluZyc6J2xlYXJuaW5nOiAnK0xCLmZpbmlzaGVkKycgLyAnK0xCLnJlYWR5QXQrJyBmaW5pc2hlZCc7CiAgICAgIHZhciByb3dzVz0oTEIud2lubmVyc3x8W10pLm1hcChmdW5jdGlvbihyKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj4nK2VzYyhyLmxhYmVsKSsnPHNtYWxsPicrci53aW5zKycgb2YgJytyLm4rJyBiZWNhbWUgd2lubmVyczwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciB1cCI+JytyLmxpZnQrJ8OXPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOwogICAgICB2YXIgcm93c0E9KExCLmF2b2lkfHxbXSkubWFwKGZ1bmN0aW9uKHIpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKHIubGFiZWwpKyc8c21hbGw+JytyLndpbnMrJyBvZiAnK3IubisnIGJlY2FtZSB3aW5uZXJzPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyIGRvd24iPicrci5saWZ0KyfDlzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTsKICAgICAgdmFyIGhvdD0oTEIuaG90fHxbXSkubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKHgubWludCx4LnN5bWJvbCx4Lm5hbWUpKyc8L2Rpdj4nK2NhTGluZSh4Lm1pbnQpKyc8c21hbGw+Jyt4LnByb2dyZXNzKyclIGJvbmRlZCDCtyAkJysoeC5tY2FwPj0xMDAwPyh4Lm1jYXAvMTAwMCkudG9GaXhlZCgxKSsnSyc6eC5tY2FwKSsnIMK3ICcrKHguc29jaWFsPT1udWxsPydzb2NpYWxzIHVua25vd24nOnguc29jaWFsKycgc29jaWFsIGxpbmsnKyh4LnNvY2lhbD09PTE/Jyc6J3MnKSkrJyDCtyAnK2Fnbyh4LmF0KSsnIG9sZDwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyh4LmxpZnQ+PTEuNT8ndXAnOngubGlmdDwwLjc/J2Rvd24nOidhc2gnKSsnIj4nK3gubGlmdCsnw5c8c21hbGw+ficreC5vZGRzUGN0KyclIG9kZHM8L3NtYWxsPjwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTsKICAgICAgJCgnbGFiJykuaW5uZXJIVE1MPQogICAgICAgICc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5TdHVkaWVkIDxiPicrTEIuY29sbGVjdGVkKyc8L2I+IGxhdW5jaGVzIMK3IDxiPicrTEIuZmluaXNoZWQrJzwvYj4gZmluaXNoZWQgwrcgPGI+JytMQi53aW5zKyc8L2I+IHdpbm5lcnMgKCcrTEIuZ3JhZHVhdGVkKycgZ3JhZHVhdGVkLCAnK0xCLnRyZW5kZWQrJyBtYWRlIHRoZSB0cmVuZGluZyBsaXN0KSDCtyBhIHJhbmRvbSBsYXVuY2ggd2lucyA8Yj4nK0xCLmJhc2VsaW5lUGN0KyclPC9iPiBvZiB0aGUgdGltZS4gQSB3aW5uZXIgPSBncmFkdWF0ZWQsIHRyZW5kZWQsIG9yIHJlYWNoZWQgYSAkMTAwSyBtYXJrZXQgY2FwLjwvcD4nKwogICAgICAgIChMQi5zdGFydGVyPyc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgMTBweDtjb2xvcjp2YXIoLS1nb2xkKSI+U3RhcnRpbmcgZ3Vlc3NlcyBmcm9tIHB1Ymxpc2hlZCByZXNlYXJjaCBhcmUgc2hvd24gdW50aWwgaXQgaGFzICcrTEIucmVhZHlBdCsnIGZpbmlzaGVkIGxhdW5jaGVzIG9mIGl0cyBvd24uIEl0IGRvZXMgbm90IGNoYW5nZSB5b3VyIHRyYWRpbmcgdW50aWwgdGhlbi48L3A+JzonJykrCiAgICAgICAgJzxkaXYgc3R5bGU9ImZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTttYXJnaW46MTBweCAwIDJweCI+8J+UpSBIT1QgUklHSFQgTk9XIMK3IHNjb3JlZCBhdCA5MCBzZWNvbmRzLCBiZWZvcmUgdHJlbmRpbmc8L2Rpdj4nKyhob3R8fCc8cCBjbGFzcz0iZW1wdHkiPldhaXRpbmcgZm9yIHNjb3JlZCBsYXVuY2hlc+KApjwvcD4nKSsKICAgICAgICAnPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxNHB4IDAgMnB4Ij7inIUgV0lOTkVSUyBURU5EIFRPIEhBVkUgwrcgdGltZXMgbW9yZSBsaWtlbHkgdGhhbiBhdmVyYWdlPC9kaXY+Jysocm93c1d8fCc8cCBjbGFzcz0iZW1wdHkiPk5vdCBlbm91Z2ggZmluaXNoZWQgbGF1bmNoZXMgeWV0LiBDaGVjayBiYWNrIGluIGEgZmV3IGhvdXJzLjwvcD4nKSsKICAgICAgICAnPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxNHB4IDAgMnB4Ij7im5QgTE9TRVJTIFRFTkQgVE8gSEFWRTwvZGl2PicrKHJvd3NBfHwnPHAgY2xhc3M9ImVtcHR5Ij5Ob3QgZW5vdWdoIGZpbmlzaGVkIGxhdW5jaGVzIHlldC48L3A+Jyk7CiAgICB9CiAgICB2YXIgQVB2PWQuYXV0b3BpbG90OwogICAgaWYoQVB2KXskKCdhcFN0YXQnKS50ZXh0Q29udGVudD1BUHYucGF1c2VkPyfij7ggJytBUHYucGF1c2VkOkFQdi5vbj8nb24gwrcgJytBUHYuZGRQY3QrJyUgYmVsb3cgaXRzIGJlc3QnOidvZmYnOwogICAgICAkKCdhcCcpLmlubmVySFRNTD0nPHAgY2xhc3M9Im5vdGUiIHN0eWxlPSJtYXJnaW46MCAwIDhweCI+QWNjb3VudCA8Yj4kJytBUHYuZXF1aXR5LnRvRml4ZWQoMikrJzwvYj4gwrcgYmVzdCBzbyBmYXIgPGI+JCcrQVB2LnBlYWsudG9GaXhlZCgyKSsnPC9iPiDCtyA8YiBjbGFzcz0iJysoQVB2LmRkUGN0Pj1BUHYuYnJha2UxPydkb3duJzonYXNoJykrJyI+JytBUHYuZGRQY3QrJyUgYmVsb3cgaXQ8L2I+LiBBdCA8Yj4nK0FQdi5icmFrZTErJyU8L2I+IGl0IHN3aXRjaGVzIHRvIHRoZSBzYWZlc3Qgc2V0dGluZ3M7IGF0IDxiPicrQVB2LmJyYWtlMisnJTwvYj4gaXQgYWxzbyBwYXVzZXMgbmV3IHRyYWRlcyBmb3IgOCBob3Vycy4gSXQgc3dpdGNoZXMgb2ZmIGFueSB3YXkgb2YgZW50ZXJpbmcgdGhhdCBpcyBsb3NpbmcsIGFuZCB1c2VzICcrKEFQdi5hdXRvU2xvdHM/J2Zld2VyLCBiaWdnZXIgYmV0cyBhcyB0aGUgYmFsYW5jZSBzaHJpbmtzICgnK2VzYyhBUHYuc2xvdHNOb3RlfHxBUHYuc2xvdHMrJyBhdCBhIHRpbWUnKSsnKSc6J3RoZSBiZXQgY291bnQgeW91IHNldCcpKycuPC9wPicrCiAgICAgICAgKEFQdi5sb2cubGVuZ3RoP0FQdi5sb2cubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKHgudGV4dCkrJzxzbWFsbD4nK2Fnbyh4LmF0KSsnIGFnbzwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPk5vdGhpbmcgbmVlZGVkIGNoYW5naW5nIHlldC4gV2hlbiBpdCBkb2VzIHNvbWV0aGluZywgaXQgc2hvd3MgdXAgaGVyZSBhbmQgb24geW91ciBwaG9uZS48L3A+Jyl9CiAgICB2YXIgRFg9ZC5kaWFnbm9zaXM7CiAgICBpZihEWCl7CiAgICAgICQoJ2R4U3RhdCcpLnRleHRDb250ZW50PURYLnRyYWRlcysnIGNsb3NlZCB0cmFkZXMnKyhEWC53aW5SYXRlIT1udWxsPycgwrcgJytEWC53aW5SYXRlKyclIHdpbnMnOicnKTsKICAgICAgdmFyIGY9KERYLmZpbmRpbmdzfHxbXSkubWFwKGZ1bmN0aW9uKHgpe3ZhciBjb2w9eC5sZXZlbD09PSdiYWQnPydkb3duJzp4LmxldmVsPT09J2dvb2QnPyd1cCc6J2FzaCc7CiAgICAgICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0iJytjb2wrJyIgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMCI+JysoeC5sZXZlbD09PSdiYWQnPyfinYwgJzp4LmxldmVsPT09J2dvb2QnPyfinIUgJzon4oS577iPICcpK2VzYyh4LnRleHQpKyc8L2Rpdj4nKyh4LmZpeCYmcm9sZT09PSdvd25lcic/JzxidXR0b24gY2xhc3M9ImJ0biBtaW50IG93biIgdHlwZT0iYnV0dG9uIiBzdHlsZT0ibWFyZ2luLXRvcDo4cHg7cGFkZGluZzo3cHggMTJweDtmb250LXNpemU6MTJweCIgZGF0YS1maXg9XCcnK2VzYyhKU09OLnN0cmluZ2lmeSh4LmZpeCkpKydcJz5GaXggaXQ6ICcrZXNjKHguZml4VGV4dCkrJzwvYnV0dG9uPic6JycpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk7CiAgICAgIHZhciBycz0oRFgucmVhc29uc3x8W10pLm1hcChmdW5jdGlvbihyKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj4nK2VzYyhyLnJlYXNvbikrJzxzbWFsbD4nK3IudHJhZGVzKycgdHJhZGVzIMK3ICcrci53aW5zKycgd29uPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyICcrKHIucG5sVXNkPj0wPyd1cCc6J2Rvd24nKSsnIj4nKyhyLnBubFVzZD49MD8nKyQnOifiiJIkJykrTWF0aC5hYnMoci5wbmxVc2QpLnRvRml4ZWQoMikrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTsKICAgICAgJCgnZHgnKS5pbm5lckhUTUw9ZisoRFguYXZnV2luUGN0IT1udWxsPyc8cCBjbGFzcz0ibm90ZSI+QXZlcmFnZSB3aW4gPGIgY2xhc3M9InVwIj4rJytEWC5hdmdXaW5QY3QrJyU8L2I+IMK3IGF2ZXJhZ2UgbG9zcyA8YiBjbGFzcz0iZG93biI+JytEWC5hdmdMb3NzUGN0KyclPC9iPiDCtyB3aW5uZXJzIHZzIGxvc2VycyA8Yj4nK0RYLnByb2ZpdEZhY3Rvcisnw5c8L2I+IMK3IGZlZXMsIHRpcHMgYW5kIHNsaXBwYWdlIOKJiCA8Yj4kJytEWC5mZWVzVXNkKyc8L2I+IG9uIGJldHMgb2YgYWJvdXQgJCcrRFguYXZnQmV0VXNkKyc8L3A+JzonJykrCiAgICAgICAgKHJzPyc8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjEycHggMCAycHgiPldIRVJFIFRIRSBNT05FWSBXRU5ULCBCWSBIT1cgRUFDSCBUUkFERSBFTkRFRDwvZGl2PicrcnM6JycpKwogICAgICAgICgoRFgudHlwZXN8fFtdKS5sZW5ndGg/JzxkaXYgc3R5bGU9ImZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTttYXJnaW46MTJweCAwIDJweCI+QlkgV0FZIE9GIEVOVEVSSU5HPC9kaXY+JytEWC50eXBlcy5tYXAoZnVuY3Rpb24odCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+Jytlc2ModC50eXBlKSsnPHNtYWxsPicrdC50cmFkZXMrJyB0cmFkZXMgwrcgJyt0LndpbnMrJyB3b24gwrcgYXZnICcrKHQuYXZnUGN0Pj0wPycrJzonJykrdC5hdmdQY3QrJyU8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysodC5wbmxVc2Q+PTA/J3VwJzonZG93bicpKyciPicrKHQucG5sVXNkPj0wPycrJCc6J+KIkiQnKStNYXRoLmFicyh0LnBubFVzZCkudG9GaXhlZCgyKSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOicnKTsKICAgIH0KICAgIGlmKGQuc3RyYXRlZ3kpJCgnc3RyYXQnKS5pbm5lckhUTUw9ZC5zdHJhdGVneS5tYXAoZnVuY3Rpb24odCl7dmFyIGk9dC5pbmRleE9mKCc6Jyk7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGI+Jytlc2ModC5zbGljZSgwLGkpKSsnPC9iPjxzbWFsbCBzdHlsZT0iZm9udC1zaXplOjEyLjVweDtsaW5lLWhlaWdodDoxLjUiPicrZXNjKHQuc2xpY2UoaSsxKSkrJzwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOwogICAgdmFyIFdUPWQud2F0Y2h8fFtdOyQoJ3dTdGF0JykudGV4dENvbnRlbnQ9ZC5zZXR0aW5ncy5tb21lbnR1bT9XVC5sZW5ndGgrJyB3YXRjaGluZyc6J29mZiAoYnV5cyBhdCA5MHMpJzsKICAgIHZhciBvaz1mdW5jdGlvbih2LG4pe3JldHVybiB2Pj1uPyc8YiBjbGFzcz0idXAiPicrdisnPC9iPic6JzxiIGNsYXNzPSJhc2giPicrdisnPC9iPid9OwogICAgJCgnd2F0Y2gnKS5pbm5lckhUTUw9V1QubGVuZ3RoP1dULm1hcChmdW5jdGlvbih3KXt2YXIgRj13LmZsb3d8fHt9LFM9ZC5zZXR0aW5nczsKICAgICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+Jyt0b2sody5taW50LHcuc3ltYm9sLHcubmFtZSkrJzwvZGl2PicrY2FMaW5lKHcubWludCkrJzxzbWFsbD5idXllcnMvbWluICcrb2soRi5idXllcnM2MHx8MCxTLm1vbUJ1eWVyczYwKSsnLycrUy5tb21CdXllcnM2MCsnIMK3IGJ1eXMgJytvayhGLmJ1eVNoYXJlNjB8fDAsUy5tb21CdXlTaGFyZSkrJyUvJytTLm1vbUJ1eVNoYXJlKyclIMK3IFNPTCBpbiAnK29rKEYubmV0NjB8fDAsUy5tb21OZXRTb2wpKycvJytTLm1vbU5ldFNvbCsnIMK3IDItbWluICcrb2soRi5yaXNlMm18fDAsUy5tb21SaXNlMm0pKyclLycrUy5tb21SaXNlMm0rJyU8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgYXNoIj4nK3cubGVmdFNlYysnczxzbWFsbD5sZWZ0PC9zbWFsbD48L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+JysoZC5zZXR0aW5ncy5tb21lbnR1bT8nU2FmZSBsYXVuY2hlcyB3YWl0IGhlcmUgdW50aWwgcmVhbCBidXlpbmcgc2hvd3MgdXAuJzonTW9tZW50dW0gZW50cnkgaXMgb2ZmOiBpdCBidXlzIHJpZ2h0IGF0IDkwIHNlY29uZHMuJykrJzwvcD4nOwogICAgdmFyIEc9ZC5ncmFkczsKICAgIGlmKEcpeyQoJ2dyJykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij48Yj4nK0cubGF1bmNoZXMyNGgudG9Mb2NhbGVTdHJpbmcoKSsnPC9iPiBsYXVuY2hlcyDCtyA8Yj4nK0cuZ3JhZHMyNGgrJzwvYj4gZ3JhZHVhdGVkIMK3IHJhdGUgPGI+JysoRy5ncmFkUmF0ZVBjdD09bnVsbD8n4oCUJzpHLmdyYWRSYXRlUGN0KyclJykrJzwvYj4gwrcgbWVkaWFuIHRpbWUgdG8gZ3JhZHVhdGUgPGI+JysoRy5tZWRpYW5NaW5zVG9HcmFkPT1udWxsPyfigJQnOkcubWVkaWFuTWluc1RvR3JhZCsnIG1pbicpKyc8L2I+JysoRy5mYXN0ZXN0TWlucyE9bnVsbD8nIMK3IGZhc3Rlc3QgJytHLmZhc3Rlc3RNaW5zKycgbWluJzonJykrKEcuYmVzdEhvdXJVdGMhPW51bGw/JyDCtyBiZXN0IGhvdXIgPGI+JytHLmJlc3RIb3VyVXRjKyc6MDAgVVRDPC9iPiAoJytHLmJlc3RIb3VyUmF0ZVBjdCsnJSknOicnKSsnPC9wPicrCiAgICAgICc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIDAgOHB4Ij5PZiB0aG9zZSBncmFkdWF0ZXMsIEFMS0FJRCBoYWQgYWxyZWFkeSBqdWRnZWQgPGI+JytHLmdyYWRzSnVkZ2VkKyc8L2I+LCBzY29yZWQgPGI+JytHLmdyYWRzU2NvcmVkSGlnaCsnPC9iPiBhcyBob3QgKDEuNcOXKyksIGFuZCBoZWxkIDxiPicrRy5ncmFkc0hlbGQrJzwvYj4uPC9wPicrCiAgICAgICgoRy5yZWNlbnR8fFtdKS5sZW5ndGg/Ry5yZWNlbnQubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKHgubWludCx4LnN5bWJvbHx8Jz8nLHgubmFtZSkrKHguaGVsZD8nIDxzcGFuIGNsYXNzPSJ0YWcgYnV5Ij5XRSBIRUxEIElUPC9zcGFuPic6eC5qdWRnZWQ/JyA8c3BhbiBjbGFzcz0idGFnIHdhdGNoIj5XRSBTQVcgSVQ8L3NwYW4+JzonIDxzcGFuIGNsYXNzPSJ0YWcgc2tpcCI+TUlTU0VEPC9zcGFuPicpKyc8L2Rpdj4nK2NhTGluZSh4Lm1pbnQpKyc8c21hbGw+JysoeC5taW5zIT1udWxsPydncmFkdWF0ZWQgJyt4Lm1pbnMrJyBtaW4gYWZ0ZXIgbGF1bmNoJzonbGF1bmNoZWQgYmVmb3JlIHRoZSBib3Qgd2FzIHdhdGNoaW5nJykrKHgubGlmdCE9bnVsbD8nIMK3IGxhYiBzY29yZSAnK3gubGlmdCsnw5cnOicnKSsnPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyIGFzaCI+JythZ28oeC5hdCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5ObyBncmFkdWF0aW9ucyBpbiB0aGUgbGFzdCAyNCBob3VycyB5ZXQuPC9wPicpO30KCiAgICB2YXIgc2c9ZnVuY3Rpb24obil7cmV0dXJuIChuPDA/J+KIkiQnOicrJCcpK01hdGguYWJzKCtufHwwKS50b0ZpeGVkKDIpfSxrZj1mdW5jdGlvbihuKXtyZXR1cm4gbj49MWU2PyhuLzFlNikudG9GaXhlZCgxKSsnTSc6bj49MWUzPyhuLzFlMykudG9GaXhlZCgxKSsnSyc6U3RyaW5nKE1hdGgucm91bmQobnx8MCkpfTsKICAgIHZhciBHUHY9ZC5ncmFkdWF0ZTsKICAgIGlmKEdQdil7JCgnZ1N0YXQnKS50ZXh0Q29udGVudD1HUHYub24/R1B2LnRyYWRlcysnIHRyYWRlcyDCtyAnK3NnKEdQdi5wbmxVc2QpKyhHUHYub3Blbj8nIMK3ICcrR1B2Lm9wZW4rJyBvcGVuJzonJyk6J29mZic7CiAgICAgICQoJ2dyYWQnKS5pbm5lckhUTUw9KEdQdi53YXRjaGluZy5sZW5ndGg/R1B2LndhdGNoaW5nLm1hcChmdW5jdGlvbih3KXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3Rvayh3Lm1pbnQsdy5zeW0sJycpKyc8L2Rpdj4nK2NhTGluZSh3Lm1pbnQpKyc8c21hbGw+Jysody5saXEhPW51bGw/J2xpcSAkJytrZih3LmxpcSkrJyDCtyBjYXAgJCcra2Yody5tY2FwKSsnIMK3ICcrdy5idXlzNSsnIGJ1eXMvNW0gwrcgNW0gJyt3LmNoNSsnJSDCtyAnOicnKStlc2MoKHcud2h5fHxbXSkuam9pbignIMK3ICcpfHwnY2hlY2tpbmfigKYnKSsnPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyIGFzaCI+Jyt3LmxlZnRNaW4rJ208c21hbGw+bGVmdDwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPicrKEdQdi5vbj8nVG9rZW5zIHRoYXQgZ3JhZHVhdGUgd2FpdCBoZXJlIHVudGlsIHJlYWwgYnV5aW5nIHNob3dzIHVwIG9uIHRoZSB0cmFkaW5nIHBvb2wuJzonR3JhZHVhdGUgc3RyYXRlZ3kgaXMgb2ZmICh0dXJuIGl0IG9uIGluIFJ1bGVzKS4nKSsnPC9wPicpKwogICAgICAgICc8cCBjbGFzcz0ibm90ZSI+QnV5cyBhIGdyYWR1YXRlZCB0b2tlbiBvbmx5IHdoZW46IGVub3VnaCBsaXF1aWRpdHksIGEgaGVhbHRoeSBtYXJrZXQgY2FwLCAyNSsgYnV5cyBpbiA1IG1pbnV0ZXMgd2l0aCA1OCUrIGJ1eXMsIGEgcmlzaW5nIChidXQgbm90IHNwaWtpbmcpIHByaWNlLCB0aGUgY3JlYXRvciBjYW5cJ3QgcHJpbnQgb3IgZnJlZXplLCBhbmQgSnVwaXRlciBjb25maXJtcyBhICQxMDAgc2FsZSBnb2VzIHRocm91Z2guIFVzZXMgaXRzIG93biB0aWdodGVyIGV4aXRzLjwvcD4nfQogICAgdmFyIENQdj1kLmNvcHk7CiAgICBpZihDUHYpeyQoJ2NwU3RhdCcpLnRleHRDb250ZW50PUNQdi5vbj9DUHYudHJhZGVzKycgdHJhZGVzIMK3ICcrc2coQ1B2LnBubFVzZCkrKENQdi5vcGVuPycgwrcgJytDUHYub3BlbisnIG9wZW4nOicnKTonb2ZmJzsKICAgICAgJCgnY29weScpLmlubmVySFRNTD0nPHAgY2xhc3M9Im5vdGUiIHN0eWxlPSJtYXJnaW46MCI+JysoQ1B2Lm9uPydPTjogd2hlbiBhIHRvcCBTbWFydCBXYWxsZXQgYnV5cyAkMTUwKyBvZiBhIHRva2VuIHRoYXQgcGFzc2VzIG91ciBvd24gc2FmZXR5IGNoZWNrcywgd2UgcGFwZXItYnV5IGl0LCBhbmQgc2VsbCB3aGVuIHRoYXQgd2FsbGV0IHNlbGxzLic6J09GRi4gVHVybiBpdCBvbiBpbiBSdWxlcyAob3IgdGFwIOKalCBPZmZlbnNlKS4gU21hcnQgV2FsbGV0cyBtdXN0IGhhdmUgcHJvdmVuIHRoZW1zZWx2ZXMgZmlyc3QuJykrJzwvcD4nKwogICAgICAgIChDUHYudHJhZGVzPyc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+Q29waWVkIHRyYWRlczxzbWFsbD4nK0NQdi53aW5zKycgd29uIG9mICcrQ1B2LnRyYWRlcysnIMK3IGF2ZXJhZ2UgJysoQ1B2LmF2Z1BjdD49MD8nKyc6JycpK0NQdi5hdmdQY3QrJyU8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoQ1B2LnBubFVzZD49MD8ndXAnOidkb3duJykrJyI+JytzZyhDUHYucG5sVXNkKSsnPC9kaXY+PC9kaXY+JzonJykrCiAgICAgICAgKChDUHYuc2tpcHN8fFtdKS5sZW5ndGg/JzxkaXYgc3R5bGU9ImZvbnQ6NzAwIDEycHggdmFyKC0tbW9ubyk7Y29sb3I6dmFyKC0tYXNoKTttYXJnaW46MTBweCAwIDJweCI+V0hZIElUIFBBU1NFRCBPTiBTT01FPC9kaXY+JytDUHYuc2tpcHMubWFwKGZ1bmN0aW9uKHMpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKHMucmVhc29uKSsnPC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrcy5uKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JycpfQogICAgdmFyIFRQdj1kLnRvcDEwMDsKICAgIGlmKFRQdil7dmFyIHN0PVRQdi5zdGF0c3x8e307JCgndFN0YXQnKS50ZXh0Q29udGVudD1UUHYuY291bnQ/VFB2LmNvdW50KycgdHJhY2tlZCBub3cgwrcgJytUUHYudHJhY2tlZCsnIGV2ZXInOidjb2xsZWN0aW5n4oCmJzsKICAgICAgJCgndG9wJykuaW5uZXJIVE1MPVRQdi5jb3VudD8KICAgICAgICAnPHAgY2xhc3M9Im5vdGUiIHN0eWxlPSJtYXJnaW46MCAwIDhweCI+TmV3IG9uIHRoZSBsaXN0IGluIHRoZSBsYXN0IDI0aDogPGI+JytzdC5uZXdFbnRyaWVzMjRoKyc8L2I+LiBBIHR5cGljYWwgbmV3Y29tZXIgd2FzIDxiPiQnK2tmKHN0Lm1lZGlhbk1jYXBBdEVudHJ5fHwwKSsnPC9iPiBtYXJrZXQgY2FwLCA8Yj4nKyhzdC5tZWRpYW5BZ2VNaW5BdEVudHJ5PT1udWxsPyc/JzpzdC5tZWRpYW5BZ2VNaW5BdEVudHJ5KycgbWluJykrJzwvYj4gb2xkLCB3aXRoIDxiPicrKHN0Lm1lZGlhbkJ1eVNoYXJlPT1udWxsPyc/JzpzdC5tZWRpYW5CdXlTaGFyZSsnJScpKyc8L2I+IGJ1eXMgYW5kIDxiPiQnK2tmKHN0Lm1lZGlhbkxpcUF0RW50cnl8fDApKyc8L2I+IGxpcXVpZGl0eS4gPGI+Jysoc3QucHVtcFBjdD09bnVsbD8nPyc6c3QucHVtcFBjdCsnJScpKyc8L2I+IGNhbWUgZnJvbSBwdW1wLmZ1bi4gQUxLQUlEIGhhZCBhbHJlYWR5IHNlZW4gPGI+Jysoc3Quc2F3QmVmb3JlUGN0PT1udWxsPyc/JzpzdC5zYXdCZWZvcmVQY3QrJyUnKSsnPC9iPiBvZiB0aGVtJysoc3QubWVkaWFuTGVhZE1pbiE9bnVsbD8nIChtZWRpYW4gPGI+JytzdC5tZWRpYW5MZWFkTWluKycgbWluPC9iPiBiZWZvcmUgdGhleSBsaXN0ZWQpJzonJykrJy48L3A+JysKICAgICAgICAnPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxMHB4IDAgMnB4Ij7wn4aVIEpVU1QgRU5URVJFRCBUSEUgTElTVDwvZGl2PicrKChUUHYuZW50cmllc3x8W10pLm1hcChmdW5jdGlvbihlKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3RvayhlLmFkZHIsZS5zeW0sZS5uYW1lKSsnPC9kaXY+JytjYUxpbmUoZS5hZGRyKSsnPHNtYWxsPmVudGVyZWQgYXQgIycrZS5yYW5rKycgwrcgY2FwICQnK2tmKGUubWNhcCkrJyDCtyAnKyhlLmFnZU1pbj09bnVsbD8nYWdlID8nOmUuYWdlTWluKycgbWluIG9sZCcpKyhlLmJ1eVNoYXJlIT1udWxsPycgwrcgJytlLmJ1eVNoYXJlKyclIGJ1eXMnOicnKSsoZS5zYXdCZWZvcmU/JyDCtyA8YiBjbGFzcz0idXAiPndlIHNhdyBpdCAnK2UubGVhZE1pbisnIG1pbiBlYXJsaWVyPC9iPicrKGUubGlmdCE9bnVsbD8nIChzY29yZSAnK2UubGlmdCsnw5cpJzonJyk6JyDCtyB3ZSBoYWRuXCd0IHNlZW4gaXQnKSsnPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyIGFzaCI+JythZ28oZS5hdCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKXx8JzxwIGNsYXNzPSJlbXB0eSI+V2FpdGluZyBmb3IgbmV3Y29tZXJz4oCmPC9wPicpKwogICAgICAgICc8ZGl2IHN0eWxlPSJmb250OjcwMCAxMnB4IHZhcigtLW1vbm8pO2NvbG9yOnZhcigtLWFzaCk7bWFyZ2luOjE0cHggMCAycHgiPlRIRSBMSVNUIFJJR0hUIE5PVyAodG9wIDI1KTwvZGl2PicrVFB2Lmxpc3Quc2xpY2UoMCwyNSkubWFwKGZ1bmN0aW9uKHApe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPiMnK3AucmFuaysnICcrdG9rKHAuYWRkcixwLnN5bSxwLm5hbWUpKyc8L2Rpdj4nK2NhTGluZShwLmFkZHIpKyc8c21hbGw+Y2FwICQnK2tmKHAubWNhcCkrJyDCtyBsaXEgJCcra2YocC5saXEpKycgwrcgJysocC5hZ2VNaW49PW51bGw/Jyc6KHAuYWdlTWluPDEyMD9wLmFnZU1pbisnIG1pbic6TWF0aC5yb3VuZChwLmFnZU1pbi82MCkrJ2gnKSsnIG9sZCcpKyhwLnB1bXA/JyDCtyBwdW1wLmZ1bic6JycpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysocC5jaDE+PTA/J3VwJzonZG93bicpKyciPicrKHAuY2gxPj0wPycrJzonJykrcC5jaDErJyU8c21hbGw+MWg8L3NtYWxsPjwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKQogICAgICAgIDonPHAgY2xhc3M9ImVtcHR5Ij5SZWNvcmRpbmcgdGhlIHRvcCAxMDAgZXZlcnkgNSBtaW51dGVzLiBUaGUgZmlyc3Qgc25hcHNob3QgbGFuZHMgYSBtaW51dGUgYWZ0ZXIgdGhlIHNlcnZlciBzdGFydHMuPC9wPid9CiAgICB2YXIgRVh2PWQuZXhwZXJpbWVudHM7CiAgICBpZihFWHYpeyQoJ3hTdGF0JykudGV4dENvbnRlbnQ9RVh2LmJlc3Q/J2Jlc3Qgc28gZmFyOiAnKyhFWHYucm93cy5maWx0ZXIoZnVuY3Rpb24ocil7cmV0dXJuIHIuaWQ9PT1FWHYuYmVzdH0pWzBdfHx7fSkubmFtZTonY29sbGVjdGluZ+KApic7CiAgICAgICQoJ2V4cCcpLmlubmVySFRNTD0nPHAgY2xhc3M9Im5vdGUiIHN0eWxlPSJtYXJnaW46MCAwIDZweCI+RXZlcnkgcmVhbCBlbnRyeSBpcyBhbHNvIG9wZW5lZCBhcyBhIDxiPiQxMDAgcGFwZXIgYmV0PC9iPiB1bmRlciBmaXZlIHdheXMgb2Ygc2VsbGluZy4gU2FtZSBlbnRyaWVzLCBkaWZmZXJlbnQgZXhpdHMsIHNvIHRoZSBjb21wYXJpc29uIGlzIGZhaXIuIEEgIisyMCUiIG1lYW5zICskMjAgb24gYSAkMTAwIGJldC48L3A+JysKICAgICAgICBFWHYucm93cy5tYXAoZnVuY3Rpb24ocil7dmFyIGJlc3Q9ci5pZD09PUVYdi5iZXN0O3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrKGJlc3Q/J/Cfj4YgJzonJykrZXNjKHIubmFtZSkrJzwvZGl2PjxzbWFsbD4nK3IudHJhZGVzKycgdHJhZGVzIMK3ICcrKHIud2luUmF0ZT09bnVsbD8n4oCUJzpyLndpblJhdGUrJyUgd2lucycpKycgwrcgd2lubmVycyB2cyBsb3NlcnMgJytyLnBmKyfDlyDCtyAnK3Iub3BlbisnIG9wZW48L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoKHIuYXZnUGN0fHwwKT49MD8ndXAnOidkb3duJykrJyI+Jysoci5hdmdQY3Q9PW51bGw/J+KAlCc6KHIuYXZnUGN0Pj0wPycrJzonJykrci5hdmdQY3QrJyUnKSsnPHNtYWxsPmF2ZyBwZXIgdHJhZGU8L3NtYWxsPjwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKSsKICAgICAgICAnPHAgY2xhc3M9Im5vdGUiPk5lZWRzIDEwKyB0cmFkZXMgcGVyIHJvdyBiZWZvcmUgYSB3aW5uZXIgaXMgbmFtZWQuIFRoZSBTd2VldCBTcG90IGFib3ZlIGNhbiBhcHBseSB0aGUgYmVzdCBvbmUgZm9yIHlvdS48L3A+J30KICAgIHZhciBHRHY9ZC5ncmlkOwogICAgaWYoR0R2KXskKCdnclN0YXQyJykudGV4dENvbnRlbnQ9R0R2Lm9uPydwb29sICQnK0dEdi5jYXNoLnRvRml4ZWQoMikrJyArICQnK0dEdi5pbkxvdHMudG9GaXhlZCgyKSsnIGluIGxvdHMgwrcgJytzZyhHRHYucG5sVXNkKTonb2ZmJzsKICAgICAgJCgnZ3JpZCcpLmlubmVySFRNTD0nPHAgY2xhc3M9Im5vdGUiIHN0eWxlPSJtYXJnaW46MCAwIDZweCI+UGlja3MgY2FsbSwgbGlxdWlkIHRva2VucyAobGlxdWlkaXR5ICQ2MEsrLCBwcmljZSBiYXJlbHkgbW92aW5nKSwgYnV5cyBzbWFsbCBkaXBzIGFuZCBzZWxscyBzbWFsbCBib3VuY2VzLiBTZWxscyBldmVyeXRoaW5nIGlmIHRoZSByYW5nZSBicmVha3MsIGxpcXVpZGl0eSBkcmllcyB1cCwgb3IgMyBob3VycyBwYXNzLiBJdHMgb3duIHBhcGVyIHBvb2wsIHNlcGFyYXRlIGZyb20geW91ciBtYWluIG1vbmV5LjwvcD4nKwogICAgICAgIChHRHYudHJhZGVzPyc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+QWxsIGdyaWQgdHJhZGVzPHNtYWxsPicrR0R2LnRyYWRlcysnIMK3ICcrR0R2LndpblJhdGUrJyUgd2luczwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnKyhHRHYucG5sVXNkPj0wPyd1cCc6J2Rvd24nKSsnIj4nK3NnKEdEdi5wbmxVc2QpKyc8L2Rpdj48L2Rpdj4nOicnKSsKICAgICAgICAoR0R2LmFjdGl2ZS5sZW5ndGg/R0R2LmFjdGl2ZS5tYXAoZnVuY3Rpb24oZyl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+Jyt0b2soZy5taW50LGcuc3ltLCcnKSsnPC9kaXY+JytjYUxpbmUoZy5taW50KSsnPHNtYWxsPicrZy5vcGVuKycvJytnLmxldmVscysnIGxvdHMgb3BlbiDCtyAnK2cucm91bmRzKycgcm91bmRzIMK3IGNlbnRlcmVkICQnKygrZy5jZW50ZXIpLnRvUHJlY2lzaW9uKDQpKycgwrcgbm93ICQnKygrZy5sYXN0KS50b1ByZWNpc2lvbig0KSsnIMK3ICcrZy5sZWZ0TWluKycgbWluIGxlZnQ8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoZy5wbmw+PTA/J3VwJzonZG93bicpKyciPicrc2coZy5wbmwpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+JysoR0R2Lm9uPydMb29raW5nIGZvciBhIGNhbG0sIGxpcXVpZCB0b2tlbuKApic6J0dyaWQgdHJhZGluZyBpcyBvZmYgKHR1cm4gaXQgb24gaW4gUnVsZXMpLicpKyc8L3A+JykrCiAgICAgICAgKChHRHYuZG9uZXx8W10pLmxlbmd0aD8nPGRpdiBzdHlsZT0iZm9udDo3MDAgMTJweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1hc2gpO21hcmdpbjoxMHB4IDAgMnB4Ij5GSU5JU0hFRDwvZGl2PicrR0R2LmRvbmUubWFwKGZ1bmN0aW9uKGcpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKGcuc3ltKSsnPHNtYWxsPicrZy5yb3VuZHMrJyByb3VuZHMgwrcgJytlc2MoZy5zdGF0dXMpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoZy5wbmw+PTA/J3VwJzonZG93bicpKyciPicrc2coZy5wbmwpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JycpfQogICAgaWYocm9sZT09PSdvd25lcicmJiFjb25uQ2hlY2tlZCl7Y29ubkNoZWNrZWQ9dHJ1ZTthcGkoJy9hcGkvbXAvY29ubmVjdGlvbnMnKS50aGVuKHNob3dDb25uKX0KICAgIHZhciBTVz1kLnN3ZWV0OwogICAgaWYoU1cpewogICAgICBpZighU1cucmVhZHkpeyQoJ3N3U3RhdCcpLnRleHRDb250ZW50PVNXLmNvbXB1dGluZz8nd29ya2luZ+KApic6J3JlY29yZGluZyAnKyhTVy51c2FibGV8fDApKycgLyAnKyhTVy5uZWVkfHwxMjApOwogICAgICAgICQoJ3N3ZWV0JykuaW5uZXJIVE1MPSc8cCBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIj5SZWNvcmRpbmcgdGhlIHJlYWwgcHJpY2Ugb2YgZXZlcnkgbGF1bmNoIGl0IGp1ZGdlcywgZXZlcnkgMTUgc2Vjb25kcyBmb3IgNDUgbWludXRlcycrKFNXLnJlY29yZGluZz8nICgnK1NXLnJlY29yZGluZysnIGJlaW5nIHJlY29yZGVkIHJpZ2h0IG5vdyknOicnKSsnLiBPbmNlIGl0IGhhcyAnKyhTVy5uZWVkfHwxMjApKycsIGl0IHJlcGxheXMgdGhlbSB1bmRlciA0MDArIHJ1bGUgY29tYmluYXRpb25zIHdpdGggZXZlcnkgZmVlIGNvdW50ZWQsIGFuZCBzaG93cyB5b3UgdGhlIHNldHRpbmdzIHRoYXQgbWFkZSBtb25leS48L3A+Jzt9CiAgICAgIGVsc2V7CiAgICAgICAgdmFyIEI9U1cuYmVzdCxDPVNXLmN1cnJlbnQsc3Q9U1cuc2V0dGluZ3MsY2VsbD1mdW5jdGlvbih2LHMpe3JldHVybiAnPGIgY2xhc3M9IicrKHY+MD8ndXAnOidkb3duJykrJyI+Jysodj4wPycrJzonJykrdisoc3x8JyUnKSsnPC9iPid9OwogICAgICAgICQoJ3N3U3RhdCcpLnRleHRDb250ZW50PVNXLnRydXN0d29ydGh5PyfinIUgcHJvdmVuIG9uIGJvdGggaGFsdmVzJzon4pqg77iPIG5vdCBwcm92ZW4geWV0JzsKICAgICAgICAkKCdzd2VldCcpLmlubmVySFRNTD0nPHAgY2xhc3M9Im5vdGUiIHN0eWxlPSJtYXJnaW46MCAwIDhweCI+UmVwbGF5ZWQgPGI+JytTVy51c2FibGUrJzwvYj4gcmVhbCBsYXVuY2hlcy4gVG8gYXZvaWQgbHVjaywgaXQgc3BsaXQgdGhlbSBpbnRvIG9sZGVyIGFuZCBuZXdlciBoYWx2ZXMsIGRyb3BwZWQgZWFjaCBoYWxmXCdzIHNpbmdsZSBiZXN0IHRyYWRlLCBhbmQgb25seSB0cnVzdHMgc2V0dGluZ3MgdGhhdCBtYWRlIG1vbmV5IGluIDxiPmJvdGg8L2I+LjwvcD4nKwogICAgICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj5Zb3VyIGN1cnJlbnQgcnVsZXM8L2Rpdj48c21hbGw+JytDLnRyYWRlcysnIHRyYWRlcyDCtyAnK0Mud2luUmF0ZSsnJSB3aW5zIMK3IG9sZGVyIGhhbGYgJysoQy5vbGRlckF2Zz09bnVsbD8n4oCUJzpDLm9sZGVyQXZnKyclJykrJyDCtyBuZXdlciBoYWxmICcrKEMubmV3ZXJBdmc9PW51bGw/J+KAlCc6Qy5uZXdlckF2ZysnJScpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIiPicrY2VsbChDLmF2Z1BjdCkrJzxzbWFsbD5hdmcgcGVyIHRyYWRlPC9zbWFsbD48L2Rpdj48L2Rpdj4nKwogICAgICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj7wn46vIFN3ZWV0IHNwb3Q8L2Rpdj48c21hbGw+JytCLnRyYWRlcysnIHRyYWRlcyDCtyAnK0Iud2luUmF0ZSsnJSB3aW5zIMK3IG9sZGVyIGhhbGYgJysoQi5vbGRlckF2Zz09bnVsbD8n4oCUJzpCLm9sZGVyQXZnKyclJykrJyDCtyBuZXdlciBoYWxmICcrKEIubmV3ZXJBdmc9PW51bGw/J+KAlCc6Qi5uZXdlckF2ZysnJScpKyc8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIiPicrY2VsbChCLmF2Z1BjdCkrJzxzbWFsbD5hdmcgcGVyIHRyYWRlPC9zbWFsbD48L2Rpdj48L2Rpdj4nKwogICAgICAgICAgJzxwIGNsYXNzPSJub3RlIj5Td2VldC1zcG90IHJ1bGVzOiB0YWtlIHByb2ZpdCBhdCA8Yj4rJytzdC50cFBjdCsnJTwvYj4sIHNlbGwgPGI+JytzdC50cDFTZWxsUGN0KyclPC9iPiB0aGVyZSwgc3RvcCBsb3NzIDxiPuKIkicrc3Quc2xQY3QrJyU8L2I+LCB0cmFpbGluZyB3aW5kb3cgPGI+JytzdC50cmFpbFBjdCsnJTwvYj4sIG1heCBob2xkIDxiPicrc3QubWF4SG9sZE1pbisnIG1pbjwvYj4sIG9ubHkgYnV5IGxhdW5jaGVzIGF0IGxlYXN0IDxiPicrc3QubWluUHJvZ3Jlc3MrJyUgYm9uZGVkPC9iPiwgdG9wIDEwIHVuZGVyIDxiPicrc3QubWF4VG9wMTBQY3QrJyU8L2I+LCBjcmVhdG9yIHVuZGVyIDxiPicrc3QubWF4RGV2UGN0KyclPC9iPicrKHN0LmxhYkZpbHRlcj8nLCBXaW5uZXIgTGFiIGxpbmUgPGI+JytzdC5sYWJNaW5MaWZ0KyfDlzwvYj4nOicnKSsnLjwvcD4nKwogICAgICAgICAgJzxwIGNsYXNzPSJub3RlIj5QYXN0IHJlc3VsdHMgb24gcmVjb3JkZWQgcGF0aHMsIG5vdCBhIHByb21pc2UuIFJlYWwgZmlsbHMgY2FuIGJlIHNsb3dlciB0aGFuIHRoZSByZXBsYXkuPC9wPic7CiAgICAgIH0KICAgICAgJCgnc3dOb3RlJykudGV4dENvbnRlbnQ9J0F1dG8tdHVuZSBpcyAnKyhkLnNldHRpbmdzLmF1dG9UdW5lPydPTjogaXQgYWRvcHRzIHRoZSBzd2VldCBzcG90IGJ5IGl0c2VsZiBldmVyeSA2IGhvdXJzLCBvbmx5IHdoZW4gaXQgcHJvdmVkIGJldHRlciBvbiBib3RoIGhhbHZlcy4nOidPRkYgKHR1cm4gaXQgb24gaW4gUnVsZXMpLicpOwogICAgfQogICAgdmFyIFQ9ZC50YXBlfHxbXTsKICAgICQoJ3RhcGUnKS5pbm5lckhUTUw9VC5sZW5ndGg/VC5zbGljZSgwLDI1KS5tYXAoZnVuY3Rpb24odCl7dmFyIHN0PXQuc3RhdHVzfHwnd2F0Y2hpbmcnLGI9c3QuaW5kZXhPZignQk9VR0hUJyk9PT0wLHNrPXN0LmluZGV4T2YoJ3NraXBwZWQnKT09PTA7CiAgICAgIHZhciB0YWc9Yj8nPHNwYW4gY2xhc3M9InRhZyBidXkiPicrZXNjKHN0KSsnPC9zcGFuPic6c2s/JzxzcGFuIGNsYXNzPSJ0YWcgc2tpcCI+U0tJUFBFRDwvc3Bhbj4nOic8c3BhbiBjbGFzcz0idGFnIHdhdGNoIj5XQVRDSElORzwvc3Bhbj4nOwogICAgICByZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3Rvayh0Lm1pbnQsdC5zeW1ib2wsdC5uYW1lKSsnICcrdGFnKyc8L2Rpdj4nK2NhTGluZSh0Lm1pbnQpKyhzaz8nPHNtYWxsPicrZXNjKHN0LnJlcGxhY2UoJ3NraXBwZWQ6ICcsJycpKSsnPC9zbWFsbD4nOicnKSsnPC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrYWdvKHQuYXQpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+V2FpdGluZyBmb3IgbGF1bmNoZXPigKY8L3A+JzsKICAgICQoJ3RvZ2dsZScpLnRleHRDb250ZW50PWQub24/J1BhdXNlJzonUmVzdW1lJzsKICAgICQoJ2NTZWVuJykudGV4dENvbnRlbnQ9ZC5zZWVuLnRvTG9jYWxlU3RyaW5nKCk7JCgnY1F1ZXVlJykudGV4dENvbnRlbnQ9ZC5xdWV1ZWQrJyB3YWl0aW5nIHRvIGJlIGp1ZGdlZCc7CiAgICAkKCdjVHJhZGVzJykudGV4dENvbnRlbnQ9ZC5zdGF0cy50cmFkZXM7JCgnY09wZW4nKS50ZXh0Q29udGVudD1kLm9wZW4ubGVuZ3RoKycgb3Blbic7CiAgICAkKCdjV2luJykudGV4dENvbnRlbnQ9ZC5zdGF0cy53aW5SYXRlPT1udWxsPyfigJQnOmQuc3RhdHMud2luUmF0ZSsnJSc7JCgnY0Jlc3QnKS50ZXh0Q29udGVudD1kLnN0YXRzLmJlc3Q9PW51bGw/Jyc6J2Jlc3QgJytkLnN0YXRzLmJlc3QrJyUgwrcgd29yc3QgJytkLnN0YXRzLndvcnN0KyclJzsKICAgICQoJ2NQbmwnKS50ZXh0Q29udGVudD1zb2woZC5zdGF0cy5wbmxTb2wpOyQoJ2NQbmwnKS5jbGFzc05hbWU9ZC5zdGF0cy5wbmxTb2w+PTA/J3VwJzonZG93bic7JCgnY1BubFVzZCcpLnRleHRDb250ZW50PWQuc3RhdHMucG5sVXNkPT1udWxsPycnOifiiYggJCcrZC5zdGF0cy5wbmxVc2Q7CiAgICAkKCdjVXAnKS50ZXh0Q29udGVudD1hZ28oZC5zdGFydGVkQXQpOwogICAgdmFyIEZMPWQuZmFzdHx8e307JCgnY0Zhc3QnKS50ZXh0Q29udGVudD1GTC5vbj8oRkwudHJhZGVzPygoRkwucG5sVXNkPj0wPycrJzon4oiSJykrJyQnK01hdGguYWJzKEZMLnBubFVzZCkudG9GaXhlZCgyKSk6J2FybWVkJyk6J29mZic7CiAgICAkKCdjRmFzdCcpLmNsYXNzTmFtZT1GTC5vbiYmRkwudHJhZGVzPyhGTC5wbmxVc2Q+PTA/J3VwJzonZG93bicpOicnOwogICAgJCgnY0Zhc3QyJykudGV4dENvbnRlbnQ9Rkwub24/KEZMLnRyYWRlcysnIHRyYWRlcyDCtyAnK0ZMLndpbnMrJyB3aW5zJysoRkwuYXZnRW50cnlNY2FwPycgwrcgYXZnIGVudHJ5ICQnKyhGTC5hdmdFbnRyeU1jYXAvMTAwMCkudG9GaXhlZCgxKSsnSyc6JycpKyhGTC5vcGVuPycgwrcgJytGTC5vcGVuKycgb3Blbic6JycpKTondHVybiBvbiBpbiBSdWxlcyc7JCgnY1NvbCcpLnRleHRDb250ZW50PWQuc29sVXNkPydTT0wgJCcrTWF0aC5yb3VuZChkLnNvbFVzZCk6Jyc7CiAgICB2YXIgQj1kLmJhbmt8fHt9LHVzZD1mdW5jdGlvbihuKXtyZXR1cm4gKG48MD8n4oiSJCc6JyQnKStNYXRoLmFicygrbnx8MCkudG9GaXhlZCgyKX07CiAgICBpZihkLmJhbmspeyQoJ2JUb3RhbCcpLnRleHRDb250ZW50PXVzZChCLnRvdGFsKTskKCdiR3Jvd3RoJykudGV4dENvbnRlbnQ9J3N0YXJ0ZWQgd2l0aCAnK3VzZChCLnN0YXJ0KSsnIMK3ICcrKEIuZ3Jvd3RoUGN0Pj0wPycrJzonJykrQi5ncm93dGhQY3QrJyUnOwogICAgICAkKCdiQ2FzaCcpLnRleHRDb250ZW50PXVzZChCLnRyYWRpbmcpOwogICAgICAkKCdiTmV4dCcpLmlubmVySFRNTD0nbmV4dCBiZXQgJyt1c2QoQi5uZXh0QmV0VXNkKSsnIMK3IHNsb3RzICcrQi5zbG90c1VzZWQrJy8nK0Iuc2xvdHMrKEIuaW5UcmFkZXM/JyDCtyAnK3VzZChCLmluVHJhZGVzKSsnIGluIHRyYWRlcyc6JycpKwogICAgICAgIChCLmNvc3RQY3QhPW51bGw/Jzxicj48c3BhbiBjbGFzcz0iJysoQi5jb3N0UGN0PjE1Pydkb3duJzonYXNoJykrJyI+ZmVlcyArIHNsaXBwYWdlIOKJiCAnK0IuY29zdFBjdCsnJSBwZXIgc25pcGUnKyhCLmNvc3RQY3Q+MTU/Jzogc21hbGwgYmV0cyBsb3NlIGEgbG90IHRvIGZlZXMnOicnKSsnPC9zcGFuPic6JycpKwogICAgICAgIChCLm1pblNhZmVCYWxhbmNlPyc8YnI+PHNwYW4gY2xhc3M9IicrKEIudG90YWw8Qi5taW5TYWZlQmFsYW5jZT8nZG93bic6J2FzaCcpKyciPm1heC1sb3NzIGNhcCBuZWVkcyBhdCBsZWFzdCAnK3VzZChCLm1pblNhZmVCYWxhbmNlKSsoQi50b3RhbDxCLm1pblNhZmVCYWxhbmNlPyc6IG5vdCB0cmFkaW5nIHVudGlsIHRoZW4nOicnKSsnPC9zcGFuPic6JycpOwogICAgICAkKCdiVmF1bHQnKS50ZXh0Q29udGVudD11c2QoQi52YXVsdCk7JCgnYlNlbnQnKS50ZXh0Q29udGVudD11c2QoQi5zZW50fHwwKTsKICAgICAgJCgnYlNlbnRUbycpLnRleHRDb250ZW50PXJvbGU9PT0ndmlld2VyJz8ndG8gdGhlIG93bmVyXCdzIHNhdmluZ3MnOkIuc2F2aW5nc1dhbGxldD8ndG8gJytCLnNhdmluZ3NXYWxsZXQuc2xpY2UoMCw0KSsn4oCmJytCLnNhdmluZ3NXYWxsZXQuc2xpY2UoLTQpOidzZXQgYSB3YWxsZXQgYmVsb3cnOwogICAgICBpZighJCgnc2F2dycpLnZhbHVlJiZCLnNhdmluZ3NXYWxsZXQmJmRvY3VtZW50LmFjdGl2ZUVsZW1lbnQhPT0kKCdzYXZ3JykpJCgnc2F2dycpLnZhbHVlPUIuc2F2aW5nc1dhbGxldDskKCdiVG9kYXknKS50ZXh0Q29udGVudD0oQi50b2RheT49MD8nKyc6JycpK3VzZChCLnRvZGF5KTskKCdiVG9kYXknKS5jbGFzc05hbWU9Qi50b2RheT49MD8ndXAnOidkb3duJzsKICAgICAgJCgnYlN0YXR1cycpLmlubmVySFRNTD1CLnBhdXNlZD8nPHNwYW4gY2xhc3M9InBpbGwgb2ZmIj5QQVVTRUQgwrcgJytlc2MoQi5wYXVzZWQud2h5KSsnPC9zcGFuPiA8YnV0dG9uIGNsYXNzPSJidG4gb3duIiBkYXRhLXJlc3VtZT0iMSIgdHlwZT0iYnV0dG9uIiBzdHlsZT0icGFkZGluZzo2cHggMTBweDtmb250LXNpemU6MTJweDttYXJnaW4tdG9wOjZweCI+UmVzdW1lIG5vdzwvYnV0dG9uPic6JzxzcGFuIGNsYXNzPSJwaWxsIG9uIj5UUkFESU5HPC9zcGFuPic7fQogICAgdmFyIFNDPWQuc2NvcmVjYXJkOwogICAgaWYoU0MpeyQoJ3Njb3JlJykuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJyb3ciPjxkaXYgY2xhc3M9InMiPicrKFNDLnJlYWR5Rm9yTGl2ZT8nPHNwYW4gY2xhc3M9InVwIj7inIUgUHJvdmVuOiByZWFkeSB0byBnbyBsaXZlIHdpdGggc21hbGwgbW9uZXk8L3NwYW4+JzonPHNwYW4gY2xhc3M9ImFzaCI+4o+zIE5vdCB5ZXQ6IGtlZXAgcGFwZXIgdHJhZGluZzwvc3Bhbj4nKSsKICAgICAgJzwvZGl2PjxkaXYgY2xhc3M9InIgYXNoIj4nK1NDLnRyYWRlcysnIHRyYWRlcyDCtyAnKyhTQy53aW5SYXRlPT1udWxsPyfigJQnOlNDLndpblJhdGUrJyUgd2lucycpKyc8L2Rpdj48L2Rpdj4nKwogICAgICBTQy5nYXRlcy5tYXAoZnVuY3Rpb24oZyl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+JysoZy5vaz8n4pyFICc6J+KsnCAnKStlc2MoZy50ZXN0KSsnPC9kaXY+PGRpdiBjbGFzcz0iciAnKyhnLm9rPyd1cCc6J2FzaCcpKyciPicrZXNjKGcubm93KSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpO30KICAgIHZhciBMPWQubGVhcm5lZHx8W107CiAgICAkKCdsZWFybmVkJykuaW5uZXJIVE1MPUwubGVuZ3RoP0wubWFwKGZ1bmN0aW9uKHgpe3ZhciBjPXgudmVyZGljdD09PSdza2lwJz8nZG93bic6eC52ZXJkaWN0PT09J2Zhdm9yJz8ndXAnOidhc2gnOwogICAgICB2YXIgdz14LnZlcmRpY3Q9PT0nc2tpcCc/J3NraXBwaW5nIGl0IG5vdyc6eC52ZXJkaWN0PT09J2Zhdm9yJz8nd29ya2luZyc6eC52ZXJkaWN0PT09J2xlYXJuaW5nJz8nbGVhcm5pbmcgKCcreC50cmFkZXMrJy8nK2Quc2V0dGluZ3MubGVhcm5NaW4rJyknOiduZXV0cmFsJzsKICAgICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdj4nK2VzYyh4LnNldHVwKSsnPC9kaXY+PHNtYWxsPicreC50cmFkZXMrJyB0cmFkZXMgwrcgJyt4LndpblJhdGUrJyUgd2luczwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciAnK2MrJyI+JysoeC5hdmdQY3Q+PTA/JysnOicnKSt4LmF2Z1BjdCsnJTxzbWFsbD4nK3crJzwvc21hbGw+PC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPkxlYXJuaW5nOiBlYWNoIHNldHVwIG5lZWRzIGEgZG96ZW4gdHJhZGVzIGJlZm9yZSBpdFwncyBqdWRnZWQuPC9wPic7CiAgICB2YXIgRj1kLmZpbHRlclJlcG9ydHx8W107CiAgICAkKCdmcmVwb3J0JykuaW5uZXJIVE1MPUYubGVuZ3RoP0Yuc2xpY2UoMCwxMCkubWFwKGZ1bmN0aW9uKHgpe3ZhciBnb29kPXgudmVyZGljdD09PSdzYXZpbmcgeW91IG1vbmV5JzsKICAgICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdj4nK2VzYyh4LnJlYXNvbikrJzwvZGl2PjxzbWFsbD4nK3guY2hlY2tlZCsnIGNoZWNrZWQgwrcgJyt4LndvdWxkTG9zZSsnIHdvdWxkIGhhdmUgbG9zdCDCtyAnK3gud291bGRXaW4rJyB3b3VsZCBoYXZlIGRvdWJsZWQ8L3NtYWxsPjwvZGl2PjxkaXYgY2xhc3M9InIgJysoeC52ZXJkaWN0PT09J3N0aWxsIGNoZWNraW5nJz8nYXNoJzpnb29kPyd1cCc6J2Rvd24nKSsnIj4nK2VzYyh4LnZlcmRpY3QpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+Q2hlY2tpbmcgd2hhdCBoYXBwZW5lZCB0byB0aGUgbGF1bmNoZXMgaXQgc2tpcHBlZOKApjwvcD4nOwogICAgdmFyIEU9ZC5ldmVudHN8fFtdOwogICAgJCgnZXZlbnRzJykuaW5uZXJIVE1MPUUubGVuZ3RoP0UubWFwKGZ1bmN0aW9uKGUpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PicrZXNjKGUudGV4dCkrJzwvZGl2PjxkaXYgY2xhc3M9InIgYXNoIj4nK2FnbyhlLmF0KSsnPC9kaXY+PC9kaXY+J30pLmpvaW4oJycpOic8cCBjbGFzcz0iZW1wdHkiPk5vdGhpbmcgeWV0LjwvcD4nOwogICAgJCgnb3Blbk4nKS50ZXh0Q29udGVudD1kLm9wZW4ubGVuZ3RoKycgLyAnKyhkLnNldHRpbmdzLnNsb3RzPjA/ZC5zZXR0aW5ncy5zbG90czpkLnNldHRpbmdzLm1heE9wZW4pOwogICAgJCgnb3BlbicpLmlubmVySFRNTD1kLm9wZW4ubGVuZ3RoP2Qub3Blbi5tYXAoZnVuY3Rpb24ocCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJyb3ciPjxkaXY+PGRpdiBjbGFzcz0icyI+Jyt0b2socC5taW50LHAuc3ltYm9sLHAubmFtZSkrJzwvZGl2PicrY2FMaW5lKHAubWludCkrJzxzbWFsbD5ib3VnaHQgYXQgJysoK3AucHJvZ3Jlc3NBdEJ1eSkudG9GaXhlZCgxKSsnJSBib25kZWQgwrcgJytwLmFnZU1pbisnbSBhZ28gwrcgZGV2ICcrKHAuZGV2UGN0PT1udWxsPyc/JzooK3AuZGV2UGN0KS50b0ZpeGVkKDEpKyclJykrKHAuc2l6ZVVzZD8nIMK3IGJldCAkJysoK3Auc2l6ZVVzZCkudG9GaXhlZCgyKTonJykrKHAubWNhcE5vdz8nIMK3IGNhcCAkJysocC5tY2FwTm93Pj0xMDAwPyhwLm1jYXBOb3cvMTAwMCkudG9GaXhlZCgxKSsnSyc6TWF0aC5yb3VuZChwLm1jYXBOb3cpKTonJykrKHAucG9zdEdyYWQ/JyDCtyBvbiB0aGUgcG9vbCc6JycpKyc8L3NtYWxsPicrKHAucGhhc2U9PT0nbW9vbic/JzxzcGFuIGNsYXNzPSJ0YWcgYnV5Ij7wn4yZIE1PTkVZIEJBQ0sgwrcgUklESU5HIFRIRSBSRVNUPC9zcGFuPic6JycpKygocC5ib29zdHN8fFtdKS5tYXAoZnVuY3Rpb24oeCl7cmV0dXJuICc8c3BhbiBjbGFzcz0idGFnIHNraXAiPuKaoSAnK2VzYyh4KSsnPC9zcGFuPid9KS5qb2luKCcnKSkrJzwvZGl2PjxkaXYgY2xhc3M9InIgJysocC5jaFBjdD49MD8ndXAnOidkb3duJykrJyI+JysocC5jaFBjdD49MD8nKyc6JycpK3AuY2hQY3QrJyU8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+Tm90aGluZyBvcGVuLiBBTEtBSUQgb25seSBmaXJlcyBhdCB3aGF0IHBhc3NlcyBldmVyeSBmaWx0ZXIuPC9wPic7CiAgICB2YXIgc2s9T2JqZWN0LmtleXMoZC5za2lwcykubWFwKGZ1bmN0aW9uKGspe3JldHVybiBbayxkLnNraXBzW2tdXX0pLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gYlsxXS1hWzFdfSksbXg9c2subGVuZ3RoP3NrWzBdWzFdOjE7CiAgICAkKCdmdW5uZWwnKS5pbm5lckhUTUw9c2subGVuZ3RoP3NrLnNsaWNlKDAsMTIpLm1hcChmdW5jdGlvbihzKXtyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2PicrZXNjKHNbMF0pKyc8L2Rpdj48ZGl2IGNsYXNzPSJiYXIiPjxpIHN0eWxlPSJ3aWR0aDonK01hdGgubWF4KDMsc1sxXS9teCoxMDApKyclIj48L2k+PC9kaXY+PC9kaXY+PGRpdiBjbGFzcz0iciI+JytzWzFdLnRvTG9jYWxlU3RyaW5nKCkrJzwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5XYWl0aW5nIGZvciBsYXVuY2hlc+KApjwvcD4nOwogICAgJCgnZGVjaXNpb25zJykuaW5uZXJIVE1MPWQuZXZhbHVhdGVkLmxlbmd0aD9kLmV2YWx1YXRlZC5zbGljZSgwLDI1KS5tYXAoZnVuY3Rpb24oZSl7dmFyIGJ1eT1lLnZlcmRpY3Q9PT0ncGFwZXIgYnV5JztyZXR1cm4gJzxkaXYgY2xhc3M9InJvdyI+PGRpdj48ZGl2IGNsYXNzPSJzIj4nK3RvayhlLm1pbnQsZS5zeW1ib2wsZS5uYW1lKSsnPHNwYW4gY2xhc3M9InRhZyAnKyhidXk/J2J1eSc6J3NraXAnKSsnIj4nKyhidXk/J1BBUEVSIEJVWSc6J1NLSVAnKSsnPC9zcGFuPjwvZGl2PicrY2FMaW5lKGUubWludCkrJzxzbWFsbD4nK2VzYyhlLnJlYXNvbikrJzwvc21hbGw+PC9kaXY+PGRpdiBjbGFzcz0iciBhc2giPicrYWdvKGUuYXQpKyc8L2Rpdj48L2Rpdj4nfSkuam9pbignJyk6JzxwIGNsYXNzPSJlbXB0eSI+V2FpdGluZyBmb3IgbGF1bmNoZXPigKY8L3A+JzsKICAgICQoJ2Nsb3NlZCcpLmlubmVySFRNTD1kLmNsb3NlZC5sZW5ndGg/ZC5jbG9zZWQuc2xpY2UoMCwyNSkubWFwKGZ1bmN0aW9uKGMpe3JldHVybiAnPGRpdiBjbGFzcz0icm93Ij48ZGl2PjxkaXYgY2xhc3M9InMiPicrdG9rKGMubWludCxjLnN5bWJvbCxjLm5hbWUpKyc8L2Rpdj4nK2NhTGluZShjLm1pbnQpKyc8c21hbGw+Jytlc2MoYy53aHkpKycgwrcgaGVsZCAnK01hdGgubWF4KDEsTWF0aC5yb3VuZCgoYy5jbG9zZWRBdC1jLm9wZW5lZEF0KS82MDAwMCkpKydtIMK3ICcrYWdvKGMuY2xvc2VkQXQpKycgYWdvPC9zbWFsbD48L2Rpdj48ZGl2IGNsYXNzPSJyICcrKChjLnBubFVzZCE9bnVsbD9jLnBubFVzZDpjLnBubFNvbCk+PTA/J3VwJzonZG93bicpKyciPicrKGMucG5sVXNkIT1udWxsPyhjLnBubFVzZD49MD8nKyc6J+KIkicpKyckJytNYXRoLmFicyhjLnBubFVzZCkudG9GaXhlZCgyKTpzb2woYy5wbmxTb2wpKSsnPHNtYWxsPicrKGMucG5sUGN0Pj0wPycrJzonJykrYy5wbmxQY3QrJyU8L3NtYWxsPjwvZGl2PjwvZGl2Pid9KS5qb2luKCcnKTonPHAgY2xhc3M9ImVtcHR5Ij5ObyBjbG9zZWQgdHJhZGVzIHlldC48L3A+JzsKICAgIGlmKCEkKCdzZXQnKS5jaGlsZHJlbi5sZW5ndGgpJCgnc2V0JykuaW5uZXJIVE1MPUZJRUxEUy5tYXAoZnVuY3Rpb24oZil7cmV0dXJuICc8bGFiZWw+JytmWzFdKyc8aW5wdXQgdHlwZT0ibnVtYmVyIiBzdGVwPSJhbnkiIGlucHV0bW9kZT0iZGVjaW1hbCIgZGF0YS1rPSInK2ZbMF0rJyIgdmFsdWU9IicrZXNjKGQuc2V0dGluZ3NbZlswXV0pKyciJysocm9sZT09PSd2aWV3ZXInPycgZGlzYWJsZWQnOicnKSsnPjwvbGFiZWw+J30pLmpvaW4oJycpOwogICAgaWYocm9sZT09PSdvd25lcicmJiFzaGFyZUNoZWNrZWQpe3NoYXJlQ2hlY2tlZD10cnVlO2FwaSgnL2FwaS9tcC9zaGFyZScpLnRoZW4oc2hvd1NoYXJlKTtzaG93TmV3Q29kZUZvcm0oKX0KICB9CiAgJCgnc2F2ZScpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXsKICAgIHZhciBib2R5PXt9O2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyNzZXQgaW5wdXQnKS5mb3JFYWNoKGZ1bmN0aW9uKGkpe2JvZHlbaS5kYXRhc2V0LmtdPU51bWJlcihpLnZhbHVlKX0pOwogICAgdmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KGJvZHkpfSk7CiAgICBpZihyLm9rKXskKCdzZXQnKS5pbm5lckhUTUw9Jyc7bG9hZCgpO3RoaXMudGV4dENvbnRlbnQ9J1NhdmVkIOKckyc7dmFyIGI9dGhpcztzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nU2F2ZSBydWxlcyd9LDE1MDApfQogIH07CiAgZnVuY3Rpb24gc2hvd05ld0NvZGVGb3JtKCl7CiAgICBpZigkKCduZXdDb2RlRm9ybScpKXJldHVybjsKICAgICQoJ25ld0NvZGVTbG90JykuYXBwZW5kQ2hpbGQoZG9jdW1lbnQuaW1wb3J0Tm9kZSgkKCduZXdDb2RlVHBsJykuY29udGVudCx0cnVlKSk7CiAgJCgnbmV3RXllJykub25jbGljaz1mdW5jdGlvbigpe3ZhciBjPSQoJ25ld0NvZGUnKSxzaG93PWMudHlwZT09PSdwYXNzd29yZCc7Yy50eXBlPXNob3c/J3RleHQnOidwYXNzd29yZCc7dGhpcy50ZXh0Q29udGVudD1zaG93PydIaWRlJzonU2hvdyc7Yy5mb2N1cygpfTsKICAgICQoJ25ld0NvZGVGb3JtJykub25zdWJtaXQ9YXN5bmMgZnVuY3Rpb24oZSl7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTt2YXIgYz0kKCduZXdDb2RlJykudmFsdWUsbT0kKCduZXdNc2cnKTttLnN0eWxlLmNvbG9yPSd2YXIoLS1hc2gpJzsKICAgICAgaWYoYy5sZW5ndGg8MTIpe20uc3R5bGUuY29sb3I9J3ZhcigtLWRvd24pJzttLnRleHRDb250ZW50PSdVc2UgYXQgbGVhc3QgMTIgY2hhcmFjdGVycy4nO3JldHVybiBmYWxzZX0KICAgICAgbS50ZXh0Q29udGVudD0nU2F2aW5n4oCmJzt2YXIgcj1hd2FpdCBhcGkoJy9hcGkvbXAvb3duZXItY29kZScse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7Y29kZTpjfSl9KTsKICAgICAgaWYoci5vayl7bS5zdHlsZS5jb2xvcj0ndmFyKC0tbWludCknO20udGV4dENvbnRlbnQ9ci5zYXZlZD8nU2F2ZWQg4pyTIFVzZSB0aGlzIGNvZGUgbmV4dCB0aW1lLic6J1NhdmVkIHVudGlsIHRoZSBuZXh0IHJlc3RhcnQgKHRoZSBzZXJ2ZXIgaGFzIG5vIHNhdmVkIHN0b3JhZ2UpLid9CiAgICAgIGVsc2V7bS5zdHlsZS5jb2xvcj0ndmFyKC0tZG93biknO20udGV4dENvbnRlbnQ9ci5lcnJvcnx8J05vdCBzYXZlZC4gVHJ5IGFnYWluLid9CiAgICAgIHJldHVybiBmYWxzZTsKICAgIH07CiAgfQoKICB2YXIgUFJFU0VUUz17CiAgICBkZWZlbnNlOntzbG90czoxMCx0cFBjdDo2MCx0cDFTZWxsUGN0OjcwLHNsUGN0OjIwLHRyYWlsUGN0OjIwLHRyYWlsQXQ1eDoxMix0cmFpbEF0MTB4OjgsZGFpbHlTdG9wUGN0OjE1LG1heExvc3NTdHJlYWs6MyxwYXVzZU1pbjoxODAsY2FzaE91dE1jYXA6ODAwMDAsbWluUHJvZ3Jlc3M6OCxtYXhUb3AxMFBjdDozMCxtYXhUb3AxUGN0OjEwLG1heERldlBjdDo1LGZhc3RMYW5lOjAsbWF4SG9sZE1pbjoyMCxsZWFybjoxLGxhYkZpbHRlcjoxLGxhYk1pbkxpZnQ6MS4yLGxhYkJvb3N0OjEuNSxtb21lbnR1bToxLG1vbUJ1eWVyczYwOjEwLG1vbUJ1eVNoYXJlOjY1LG1vbU5ldFNvbDozLG1vbVJpc2UybToyMCxtb21NYXhNY2FwOjMwMDAwLGdyYWRPbjoxLGdyYWRTbDoxMixncmFkTWF4T3BlbjoyLGNvcHlPbjowfSwKICAgIGJhbGFuY2VkOntzbG90czoxMCx0cFBjdDoxMDAsdHAxU2VsbFBjdDo1MCxzbFBjdDozMCx0cmFpbFBjdDoyNSx0cmFpbEF0NXg6MTUsdHJhaWxBdDEweDoxMCxkYWlseVN0b3BQY3Q6MzAsbWF4TG9zc1N0cmVhazo1LHBhdXNlTWluOjEyMCxjYXNoT3V0TWNhcDoxMDAwMDAsbWluUHJvZ3Jlc3M6NSxtYXhUb3AxMFBjdDozNSxtYXhUb3AxUGN0OjEyLG1heERldlBjdDo4LGZhc3RMYW5lOjAsbWF4SG9sZE1pbjozMCxsZWFybjoxLGxhYkZpbHRlcjowLGxhYk1pbkxpZnQ6MSxsYWJCb29zdDoxLjUsbW9tZW50dW06MSxtb21CdXllcnM2MDo4LG1vbUJ1eVNoYXJlOjYwLG1vbU5ldFNvbDoyLG1vbVJpc2UybToxNSxtb21NYXhNY2FwOjQwMDAwLGdyYWRPbjoxLGdyYWRTbDoxNSxncmFkTWF4T3BlbjozLGNvcHlPbjowfSwKICAgIG9mZmVuc2U6e3Nsb3RzOjYsdHBQY3Q6MTUwLHRwMVNlbGxQY3Q6NDAsc2xQY3Q6MzUsdHJhaWxQY3Q6MzAsdHJhaWxBdDV4OjE4LHRyYWlsQXQxMHg6MTIsZGFpbHlTdG9wUGN0OjQwLG1heExvc3NTdHJlYWs6NyxwYXVzZU1pbjo2MCxjYXNoT3V0TWNhcDoxMDAwMDAsbWluUHJvZ3Jlc3M6NCxtYXhUb3AxMFBjdDo0MCxtYXhUb3AxUGN0OjE1LG1heERldlBjdDoxMCxmYXN0TGFuZToxLG1heEhvbGRNaW46NDUsbGVhcm46MSxsYWJGaWx0ZXI6MCxsYWJNaW5MaWZ0OjEsbGFiQm9vc3Q6Mixtb21lbnR1bToxLG1vbUJ1eWVyczYwOjYsbW9tQnV5U2hhcmU6NTUsbW9tTmV0U29sOjEuNSxtb21SaXNlMm06MTAsbW9tTWF4TWNhcDo2MDAwMCxncmFkT246MSxncmFkU2w6MTgsZ3JhZE1heE9wZW46NCxjb3B5T246MX19OwogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ1tkYXRhLXByZXNldF0nKS5mb3JFYWNoKGZ1bmN0aW9uKGIpe2Iub25jbGljaz1hc3luYyBmdW5jdGlvbigpewogICAgdmFyIGs9dGhpcy5kYXRhc2V0LnByZXNldCxyPWF3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShQUkVTRVRTW2tdKX0pOwogICAgJCgncHJlc2V0Tm90ZScpLmlubmVySFRNTD1yLm9rPyfinIUgPGI+JytrLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpK2suc2xpY2UoMSkrJzwvYj4gaXMgb24uIEl0IGFwcGxpZXMgdG8gdGhlIG5leHQgbGF1bmNoLiBZb3UgY2FuIHN0aWxsIGZpbmUtdHVuZSBhbnkgbnVtYmVyIGluIFJ1bGVzIGJlbG93Lic6J05vdCBzYXZlZDogJytlc2Moci5lcnJvcnx8J3RyeSBhZ2FpbicpOwogICAgaWYoci5vayl7JCgnc2V0JykuaW5uZXJIVE1MPScnO2xvYWQoKX19fSk7CiAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGFzeW5jIGZ1bmN0aW9uKGUpe2lmKCFlLnRhcmdldC5jbG9zZXN0KCdbZGF0YS1yZXN1bWVdJykpcmV0dXJuOwogICAgYXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtyZXN1bWU6dHJ1ZX0pfSk7bG9hZCgpfSk7CiAgJCgnc3dBcHBseScpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXt2YXIgYj10aGlzO2IuZGlzYWJsZWQ9dHJ1ZTt2YXIgcj1hd2FpdCBhcGkoJy9hcGkvbXAvc3dlZXRzcG90L2FwcGx5Jyx7bWV0aG9kOidQT1NUJyxib2R5Oid7fSd9KTtiLmRpc2FibGVkPWZhbHNlOwogICAgJCgnc3dOb3RlJykudGV4dENvbnRlbnQ9ci5vaz8n4pyFIFN3ZWV0IHNwb3QgaXMgb24uIEl0IGFwcGxpZXMgdG8gdGhlIG5leHQgbGF1bmNoLic6KHIuZXJyb3J8fCdOb3QgYXBwbGllZC4gVHJ5IGFnYWluLicpO2lmKHIub2speyQoJ3NldCcpLmlubmVySFRNTD0nJztsb2FkKCl9fTsKICAkKCdkYXRhRGwnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7dmFyIGI9dGhpcztiLnRleHRDb250ZW50PSdQcmVwYXJpbmfigKYnOwogICAgdHJ5e3ZhciByPWF3YWl0IGZldGNoKEFQSSsnL2FwaS9tcC9kYXRhLmNzdicse2hlYWRlcnM6e0F1dGhvcml6YXRpb246J0JlYXJlciAnK3Bhc3N9fSk7aWYoIXIub2spdGhyb3cgMDt2YXIgYmw9YXdhaXQgci5ibG9iKCksdT1VUkwuY3JlYXRlT2JqZWN0VVJMKGJsKSxhPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2EnKTsKICAgICAgYS5ocmVmPXU7YS5kb3dubG9hZD0nYWxrYWlkLWRhdGEtJytuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCkrJy5jc3YnO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7YS5jbGljaygpO2EucmVtb3ZlKCk7c2V0VGltZW91dChmdW5jdGlvbigpe1VSTC5yZXZva2VPYmplY3RVUkwodSl9LDQwMDApO2IudGV4dENvbnRlbnQ9J0Rvd25sb2FkZWQg4pyTJ30KICAgIGNhdGNoKGUpe2IudGV4dENvbnRlbnQ9J0NvdWxkblwndCBkb3dubG9hZC4gVHJ5IGFnYWluJ31zZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nRG93bmxvYWQgYWxsIHRoZSBkYXRhIChzcHJlYWRzaGVldCknfSwyNTAwKX07CiAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGFzeW5jIGZ1bmN0aW9uKGUpe3ZhciBiPWUudGFyZ2V0LmNsb3Nlc3QoJ1tkYXRhLWZpeF0nKTtpZighYilyZXR1cm47dmFyIGZ4O3RyeXtmeD1KU09OLnBhcnNlKGIuZ2V0QXR0cmlidXRlKCdkYXRhLWZpeCcpKX1jYXRjaChfKXtyZXR1cm59CiAgICBiLmRpc2FibGVkPXRydWU7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL3NldHRpbmdzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KGZ4KX0pO2IudGV4dENvbnRlbnQ9ci5vaz8n4pyFIEZpeGVkLiBBcHBsaWVzIHRvIHRoZSBuZXh0IGxhdW5jaC4nOidOb3Qgc2F2ZWQ6ICcrKHIuZXJyb3J8fCd0cnkgYWdhaW4nKTtpZihyLm9rKXskKCdzZXQnKS5pbm5lckhUTUw9Jyc7bG9hZCgpfX0pOwoKICB2YXIgY29ubkNoZWNrZWQ9ZmFsc2U7JCgndGdQYWdlJykuaHJlZj1BUEkrJy9hbGthaWQvdGVsZWdyYW0nOwogIGZ1bmN0aW9uIHNob3dDb25uKHIpe2lmKCFyfHxyLl9zPj00MDB8fCFyLnJwYylyZXR1cm47dmFyIFJwPXIucnBjLFRnPXIudGVsZWdyYW07CiAgICAkKCdjb25uUnBjJykuaW5uZXJIVE1MPShScC5vd24/J+KchSBVc2luZyA8Yj55b3VyIG93bjwvYj4gY29ubmVjdGlvbiAoPGI+Jytlc2MoUnAudXNpbmcpKyc8L2I+KSc6J1VzaW5nIHRoZSBmcmVlIHB1YmxpYyBjb25uZWN0aW9uICg8Yj4nK2VzYyhScC51c2luZykrJzwvYj4pLiBBIEhlbGl1cyBrZXkgbWFrZXMgZXZlcnl0aGluZyBmYXN0ZXIuJykrJzxicj5DYWxscyB0b2RheSA8Yj4nK1JwLnRvZGF5LnRvTG9jYWxlU3RyaW5nKCkrJzwvYj4nKyhScC5jYXA/JyBvZiB5b3VyIGNhcCAnK1JwLmNhcC50b0xvY2FsZVN0cmluZygpOicnKSsnIMK3IHRoaXMgbW9udGggPGI+JytScC5tb250aC50b0xvY2FsZVN0cmluZygpKyc8L2I+JysoUnAuY2FwSGl0PycgPGIgY2xhc3M9ImRvd24iPsK3IGNhcCByZWFjaGVkOiBiYWNrZ3JvdW5kIHJlc2VhcmNoIHBhdXNlZCwgdHJhZGluZyBjb250aW51ZXM8L2I+JzonJykrKFJwLnRvcC5sZW5ndGg/Jzxicj48c21hbGw+YnVzaWVzdDogJytScC50b3AubWFwKGZ1bmN0aW9uKHgpe3JldHVybiBlc2MoeC5tKSsnICcreC5ufSkuam9pbignIMK3ICcpKyc8L3NtYWxsPic6JycpOwogICAgJCgnY29ublRnJykuaW5uZXJIVE1MPVRnLnNldD8oKFRnLm9uPyfinIUgQ29ubmVjdGVkIHRvIDxiPkAnK2VzYyhUZy5ib3R8fCd5b3VyIGJvdCcpKyc8L2I+Jzon4pqg77iPIFRoZSBib3QgaXNuXCd0IGFuc3dlcmluZyB5ZXQnKSsnIMK3IHBob25lcyBwYWlyZWQ6IDxiPicrVGcucGFpcmVkKyc8L2I+IMK3IGFsZXJ0cyAnKyhUZy5hbGVydHM/J29uJzonb2ZmJykrKFRnLmVycm9yPyc8YnI+PGIgY2xhc3M9ImRvd24iPicrZXNjKFRnLmVycm9yKSsnPC9iPic6JycpKTonTm90IHNldCB1cCB5ZXQuIEluIFRlbGVncmFtLCBtZXNzYWdlIDxiPkBCb3RGYXRoZXI8L2I+LCBzZW5kIC9uZXdib3QsIGFuZCBwYXN0ZSB0aGUgdG9rZW4gaXQgZ2l2ZXMgeW91IGhlcmUuJzsKICAgIGlmKFRnLmNvZGUpeyQoJ3RnQ29kZScpLmhpZGRlbj1mYWxzZTskKCd0Z0NvZGUnKS5pbm5lckhUTUw9KFRnLmxpbms/JzxhIGNsYXNzPSJidG4gbWludCIgdGFyZ2V0PSJfYmxhbmsiIHJlbD0ibm9vcGVuZXIiIGhyZWY9IicrZXNjKFRnLmxpbmspKyciIHN0eWxlPSJkaXNwbGF5OmlubGluZS1mbGV4O21hcmdpbi1ib3R0b206MTBweCI+T3BlbiBUZWxlZ3JhbSBhbmQgY29ubmVjdDwvYT48YnI+JzonJykrJ1RhcCB0aGUgZ3JlZW4gYnV0dG9uLCB0aGVuIHRhcCA8Yj5TVEFSVDwvYj4gaW4gVGVsZWdyYW0uIChPciBzZW5kIHlvdXIgYm90IHRoaXMgYnkgaGFuZDogPGIgc3R5bGU9ImZvbnQ6ODAwIDE1cHggdmFyKC0tbW9ubykiPi9zdGFydCAnK2VzYyhUZy5jb2RlKSsnPC9iPik8YnI+PHNtYWxsPm9uZS10aW1lIGNvZGUsIGdvb2QgZm9yIDE1IG1pbnV0ZXM8L3NtYWxsPid9ZWxzZSAkKCd0Z0NvZGUnKS5oaWRkZW49dHJ1ZX0KICB2YXIgcG9zdENvbm49YXN5bmMgZnVuY3Rpb24oYm9keSxtc2dJZCl7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL21wL2Nvbm5lY3Rpb25zJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KGJvZHkpfSk7CiAgICAkKG1zZ0lkKS50ZXh0Q29udGVudD1yLm9rPyhtc2dJZD09PSd0Z01zZycmJnIudGVsZWdyYW0mJnIudGVsZWdyYW0uZXJyb3I/J+KaoO+4jyBTYXZlZCwgYnV0OiAnK3IudGVsZWdyYW0uZXJyb3I6bXNnSWQ9PT0ndGdNc2cnJiZyLnRlbGVncmFtJiZyLnRlbGVncmFtLm9uJiZyLnRlbGVncmFtLnBhaXJlZD09PTA/J+KchSBTYXZlZCBhbmQgY29ubmVjdGVkIHRvIEAnK3IudGVsZWdyYW0uYm90KycuIE5vdyB0YXAgTWFrZSBhIHBhaXJpbmcgY29kZS4nOihyLnJlc3RhcnQ/J+KchSBTYXZlZC4gVGhlIHNlcnZlciBpcyByZXN0YXJ0aW5nIHRvIHVzZSBpdCAoYWJvdXQgMTUgc2Vjb25kcyksIHRoZW4gdGhpcyBwYWdlIHJlY29ubmVjdHMuJzon4pyFIFNhdmVkLicpKTooci5lcnJvcnx8J05vdCBzYXZlZC4gVHJ5IGFnYWluLicpOwogICAgaWYoci5vayl7c2hvd0Nvbm4ocik7aWYoci5yZXN0YXJ0KXNldFRpbWVvdXQoZnVuY3Rpb24oKXtjb25uQ2hlY2tlZD1mYWxzZTtsb2FkKCl9LDE2MDAwKX1yZXR1cm4gcn07CiAgJCgncnBjU2F2ZScpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXt2YXIgdj0kKCdycGNVcmwnKS52YWx1ZS50cmltKCksYz0kKCdycGNDYXAnKS52YWx1ZTtpZighdiYmYz09PScnKXJldHVybjt2YXIgYj17fTtpZih2KWIucnBjVXJsPXY7aWYoYyE9PScnKWIucnBjRGFpbHlDYXA9TnVtYmVyKGMpO3ZhciByPWF3YWl0IHBvc3RDb25uKGIsJ3JwY01zZycpO2lmKHIub2speyQoJ3JwY1VybCcpLnZhbHVlPScnfX07CiAgJCgncnBjUmVzZXQnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7aWYoIWNvbmZpcm0oJ0dvIGJhY2sgdG8gdGhlIGZyZWUgcHVibGljIGNvbm5lY3Rpb24/IFRoZSBzZXJ2ZXIgcmVzdGFydHMuJykpcmV0dXJuO2F3YWl0IHBvc3RDb25uKHtycGNVcmw6Jyd9LCdycGNNc2cnKX07CiAgJCgndGdTYXZlJykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3ZhciB2PSQoJ3RnVG9rZW4nKS52YWx1ZS50cmltKCk7aWYoIXYpcmV0dXJuO3ZhciByPWF3YWl0IHBvc3RDb25uKHt0Z1Rva2VuOnZ9LCd0Z01zZycpO2lmKHIub2spJCgndGdUb2tlbicpLnZhbHVlPScnfTsKICAkKCd0Z0NvZGVCdG4nKS5vbmNsaWNrPWZ1bmN0aW9uKCl7cG9zdENvbm4oe3RnTmV3Q29kZTp0cnVlfSwndGdNc2cnKX07CiAgJCgndGdUZXN0Jykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3ZhciByPWF3YWl0IGFwaSgnL2FwaS9tcC9jb25uZWN0aW9ucycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7dGdUZXN0OnRydWV9KX0pOwogICAgJCgndGdNc2cnKS50ZXh0Q29udGVudD1yLm9rPyfinIUgVGVzdCBzZW50LiBDaGVjayBUZWxlZ3JhbSAoJytyLnNlbnQrJyBwaG9uZScrKHIuc2VudD09PTE/Jyc6J3MnKSsnKS4nOign4pqg77iPICcrKHIuZXJyb3J8fCdDb3VsZG5cJ3Qgc2VuZC4nKSk7aWYoci5ycGMpc2hvd0Nvbm4ocil9OwogICQoJ3RnVW5wYWlyJykub25jbGljaz1mdW5jdGlvbigpe2lmKGNvbmZpcm0oJ1VucGFpciBhbGwgcGhvbmVzPycpKXBvc3RDb25uKHt0Z1VucGFpcjp0cnVlfSwndGdNc2cnKX07CiAgJCgndGdSZW1vdmUnKS5vbmNsaWNrPWZ1bmN0aW9uKCl7aWYoY29uZmlybSgnUmVtb3ZlIHRoZSBUZWxlZ3JhbSBib3QgYW5kIGl0cyB0b2tlbj8nKSlwb3N0Q29ubih7dGdSZW1vdmU6dHJ1ZX0sJ3RnTXNnJyl9OwogIHZhciBtb3ZlQ2FzaD1hc3luYyBmdW5jdGlvbihhbGwpe3ZhciB2PWFsbD8xZTk6cGFyc2VGbG9hdCgkKCd2MmNBbXQnKS52YWx1ZSk7aWYoISh2PjApKXskKCd2MmNNc2cnKS50ZXh0Q29udGVudD0nVHlwZSBhbiBhbW91bnQgZmlyc3QuJztyZXR1cm59CiAgICB2YXIgcj1hd2FpdCBhcGkoJy9hcGkvbXAvc2V0dGluZ3MnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe3ZhdWx0VG9DYXNoOnZ9KX0pOyQoJ3YyY01zZycpLnRleHRDb250ZW50PXIub2s/J+KchSBNb3ZlZC4gSXQgc2hvd3MgaW4gVHJhZGluZyBiYWxhbmNlIG5vdy4nOihyLmVycm9yfHwnTm90IG1vdmVkLicpO2lmKHIub2speyQoJ3YyY0FtdCcpLnZhbHVlPScnO2xvYWQoKX19OwogICQoJ3YyYycpLm9uY2xpY2s9ZnVuY3Rpb24oKXttb3ZlQ2FzaChmYWxzZSl9OyQoJ3YyY0FsbCcpLm9uY2xpY2s9ZnVuY3Rpb24oKXttb3ZlQ2FzaCh0cnVlKX07CiAgdmFyIHNoYXJlQ2hlY2tlZD1mYWxzZTsKICBmdW5jdGlvbiBzaG93U2hhcmUocil7aWYoIXJ8fHIuX3M+PTQwMClyZXR1cm47JCgnc2hhcmVTdGF0dXMnKS50ZXh0Q29udGVudD1yLm9uPydTaGFyaW5nIGlzIE9OIChzaW5jZSAnK25ldyBEYXRlKHIuc2luY2UpLnRvTG9jYWxlU3RyaW5nKCkrJykuIEFueW9uZSB3aXRoIHRoZSBsaW5rIGNhbiB3YXRjaC4nOidTaGFyaW5nIGlzIG9mZi4nOwogICAgJCgnc2hhcmVPZmYnKS5oaWRkZW49IXIub247JCgnc2hhcmVNYWtlJykudGV4dENvbnRlbnQ9ci5vbj8nTWFrZSBhIG5ldyBsaW5rIChvbGQgb25lIHN0b3BzIHdvcmtpbmcpJzonQ3JlYXRlIHNoYXJlIGxpbmsnOwogICAgaWYoci50b2tlbil7dmFyIGxpbms9bG9jYXRpb24ub3JpZ2luK2xvY2F0aW9uLnBhdGhuYW1lKycjdmlldz0nK3IudG9rZW47JCgnc2hhcmVMaW5rJykudGV4dENvbnRlbnQ9bGluazskKCdzaGFyZUJveCcpLmhpZGRlbj1mYWxzZX0KICAgIGlmKCFyLm9uKSQoJ3NoYXJlQm94JykuaGlkZGVuPXRydWV9CiAgJCgnc2hhcmVNYWtlJykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3Nob3dTaGFyZShhd2FpdCBhcGkoJy9hcGkvbXAvc2hhcmUnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2FjdGlvbjonY3JlYXRlJ30pfSkpfTsKICAkKCdzaGFyZU9mZicpLm9uY2xpY2s9YXN5bmMgZnVuY3Rpb24oKXtpZighY29uZmlybSgnVHVybiBvZmYgdGhlIHNoYXJlIGxpbms/IEFueW9uZSB1c2luZyBpdCBpcyBsb2NrZWQgb3V0IHJpZ2h0IGF3YXkuJykpcmV0dXJuO3Nob3dTaGFyZShhd2FpdCBhcGkoJy9hcGkvbXAvc2hhcmUnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2FjdGlvbjonb2ZmJ30pfSkpfTsKICAkKCdzaGFyZUNvcHknKS5vbmNsaWNrPWZ1bmN0aW9uKCl7dmFyIHQ9JCgnc2hhcmVMaW5rJykudGV4dENvbnRlbnQsYj10aGlzOyhuYXZpZ2F0b3IuY2xpcGJvYXJkP25hdmlnYXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KHQpOlByb21pc2UucmVqZWN0KCkpLnRoZW4oZnVuY3Rpb24oKXtiLnRleHRDb250ZW50PSdDb3BpZWQg4pyTJztzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nQ29weSBsaW5rJ30sMTUwMCl9LGZ1bmN0aW9uKCl7Yi50ZXh0Q29udGVudD0nSG9sZCB0aGUgbGluayB0byBjb3B5J30pfTsKICAkKCdzaGFyZVNlbmQnKS5vbmNsaWNrPWZ1bmN0aW9uKCl7dmFyIHQ9JCgnc2hhcmVMaW5rJykudGV4dENvbnRlbnQ7aWYobmF2aWdhdG9yLnNoYXJlKW5hdmlnYXRvci5zaGFyZSh7dGl0bGU6J0FMS0FJRCAodmlldyBvbmx5KScsdGV4dDonV2F0Y2ggQUxLQUlEIGxpdmU6Jyx1cmw6dH0pLmNhdGNoKGZ1bmN0aW9uKCl7fSk7ZWxzZSAkKCdzaGFyZUNvcHknKS5jbGljaygpfTsKICAkKCdzYXZTYXZlJykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe3ZhciByPWF3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7c2F2aW5nc1dhbGxldDokKCdzYXZ3JykudmFsdWUudHJpbSgpfSl9KTsKICAgIHRoaXMudGV4dENvbnRlbnQ9ci5vaz8nU2F2ZWQg4pyTJzooci5lcnJvcnx8J05vdCBzYXZlZCcpO3ZhciBiPXRoaXM7c2V0VGltZW91dChmdW5jdGlvbigpe2IudGV4dENvbnRlbnQ9J1NhdmUgd2FsbGV0J30sMTgwMCk7bG9hZCgpfTsKICAkKCdzZW5kTm93Jykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe2F3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7c2VuZFZhdWx0OnRydWV9KX0pO3RoaXMudGV4dENvbnRlbnQ9J1NlbnQg4pyTJzt2YXIgYj10aGlzO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtiLnRleHRDb250ZW50PSdTZW5kIHZhdWx0IHRvIG15IHdhbGxldCBub3cnfSwxODAwKTtsb2FkKCl9OwogICQoJ3Jlc2V0Jykub25jbGljaz1hc3luYyBmdW5jdGlvbigpe2lmKCFjb25maXJtKCdDbGVhciBhbGwgcGFwZXIgcmVzdWx0cyBhbmQgc3RhcnQgZnJlc2g/JykpcmV0dXJuO2F3YWl0IGFwaSgnL2FwaS9tcC9zZXR0aW5ncycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7cmVzZXQ6dHJ1ZX0pfSk7bG9hZCgpfTsKICAkKCd0b2dnbGUnKS5vbmNsaWNrPWFzeW5jIGZ1bmN0aW9uKCl7aWYoIXN0YXRlKXJldHVybjthd2FpdCBhcGkoJy9hcGkvbXAvc2V0dGluZ3MnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe29uOiFzdGF0ZS5vbn0pfSk7bG9hZCgpfTsKfSkoKTsKPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=";
/*ALKAID_EMBED_END*/
