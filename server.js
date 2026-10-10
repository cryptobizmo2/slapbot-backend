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
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
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

const connection = new Connection(SOLANA_RPC_URL, "confirmed");

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
      alerts.push({ kind: "sell", w, t: buy.mint, sym, usd: buy.usd, at: buy.at, seen: now, tx: sig, stack: 0,
                    soldPct: p.bt > 0 ? Math.min(100, Math.round((p.st / p.bt) * 100)) : null });
      alertBuySigs.add(sig);
      log("alert", `${w.slice(0, 4)}… SOLD ${sym} $${buy.usd}`);
      return;
    }
    const stack = new Set(alerts.filter((a) => a.kind !== "sell" && a.t === buy.mint && now - a.seen < 30 * 60e3).map((a) => a.w).concat(w)).size;
    alerts.push({ kind: "buy", w, t: buy.mint, sym, usd: buy.usd, at: buy.at, seen: now, tx: sig, stack });
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
 *   2. THE CANNON's launch watcher: a creator whose token got dumped while they sold out
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
    fastLane: 1,          // 1 = on
    fastMaxMcap: 8000,    // only if it's still under this market cap when we see it
    fastBetPct: 5,        // smaller bets: the earliest entries are the riskiest
    fastMaxPerMin: 3,     // at most this many fast buys a minute
    fastMaxOpen: 4,       // and at most this many fast positions at once
    fastMaxDevPct: 15,    // skip if the creator bought more than this % at launch
    cashOutMcap: 100000,  // RUG ZONE: a fast mover that reaches this market cap gets sold completely (0 = off)
    fastTimeoutSec: 180,  // if it hasn't lifted off by then...
    fastMinGainPct: 30,   // ...(up at least this %), get out
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
  bank: null, outcomes: [], report: {}, events: [],
};
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
function mpEvent(text) { MP.events.unshift({ at: Date.now(), text }); MP.events = MP.events.slice(0, 50); log("cannon", text); }

// ── saved to the server's disk, so paper results survive restarts and updates ──
const MP_FILE = VOLUME_DIR ? nodePath.join(VOLUME_DIR, "masterpeace.json") : "";
try {
  if (MP_FILE && nodeFs.existsSync(MP_FILE)) {
    const d = JSON.parse(nodeFs.readFileSync(MP_FILE, "utf8"));
    if (d.settings) Object.assign(MP.settings, d.settings);
    for (const k of ["bank", "closed", "report", "skips", "events", "startedAt", "seen", "outcomes"]) if (d[k] != null) MP[k] = d[k];
    if (!MP.bank || !Number.isFinite(MP.bank.cash)) MP.bank = mpNewBank(MP.settings.startUsd);
  }
} catch (e) { log("error", `loading THE CANNON: ${e.message}`); }
setInterval(() => {
  if (!MP_FILE) return;
  try { const tmp = MP_FILE + ".tmp";
    nodeFs.writeFileSync(tmp, JSON.stringify({ settings: MP.settings, bank: MP.bank, closed: MP.closed, report: MP.report, skips: MP.skips,
      events: MP.events, startedAt: MP.startedAt, seen: MP.seen, outcomes: MP.outcomes.slice(-600) }));
    nodeFs.renameSync(tmp, MP_FILE); } catch (e) { log("error", `saving THE CANNON: ${e.message}`); }
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
function mpBankGate(bank, S, now = Date.now()) {
  const d = new Date(now).toISOString().slice(0, 10);
  if (bank.day !== d) { bank.day = d; bank.dayStart = bank.cash; if (bank.pauseWhy === "daily stop") { bank.pausedUntil = 0; bank.pauseWhy = null; } }
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
  if (bank.cash < bank.dayStart * (1 - S.dailyStopPct / 100)) {
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

function mpSkip(reason, ev) {
  MP.skips[reason] = (MP.skips[reason] || 0) + 1;
  if (ev) { MP.evaluated.unshift({ ...ev, verdict: "skip", reason, at: Date.now() }); MP.evaluated = MP.evaluated.slice(0, 120); }
}

/** A new launch arrives: note the creator, queue it to be judged after the wait. */
function mpOnLaunch(ev) {
  MP.seen++; MP.feed.lastEventAt = Date.now();
  const c = MP.creators.get(ev.creator) || [];
  c.push(Date.now()); MP.creators.set(ev.creator, c.filter((t) => Date.now() - t < 24 * 3600e3));
  if (MP.creators.size > 50000) MP.creators.delete(MP.creators.keys().next().value);
  // instant rejects that need no chain reads
  if (!/pump$/.test(ev.mint)) return mpSkip("not a pump.fun mint");
  if (!ev.uri) return mpSkip("no metadata");
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
  MP.evaluated.unshift({ ...ev, verdict: "paper buy", reason: `Launch Shot · $${(m.mcap / 1000).toFixed(1)}K market cap · ${m.progress.toFixed(1)}% bonded · creator ${devPct != null ? devPct.toFixed(1) + "%" : "?"} · ${ms} ms`, at: Date.now() });
  MP.evaluated = MP.evaluated.slice(0, 120);
  log("cannon", `LAUNCH SHOT BUY ${ev.symbol} $${sizeUsd.toFixed(2)} at $${Math.round(m.mcap)} mcap in ${ms} ms`);
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
  if (m.progress >= 3) { rugWatch.push({ mint: ev.mint, sym: ev.symbol, creator: ev.creator, peakSol: Number(c.rSol) / 1e9, devAt, due: Date.now() + 30 * 60e3, round: 0 }); if (rugWatch.length > 2000) rugWatch.shift(); }
  if (m.progress < S.minProgress) return skipT(`weak demand (<${S.minProgress}% bonded)`, { progress: m.progress });
  // creator's bag and holder concentration, curve excluded
  const chk = await getMintCheck(ev.mint).catch(() => null);
  if (!chk || !chk.found) return mpSkip("couldn't check holders", ev);
  if (!chk.mintAuthorityRenounced || !chk.freezeAuthorityRenounced) return skipT("can print or freeze");
  const top10 = chk.top10WalletPct, top1 = chk.top1WalletPct;
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
  // bankroll: protection first, then size from the balance
  if (MP.positions.some((p) => p.mint === ev.mint)) return mpSkip("already holding (Launch Shot)", ev);
  const gate = mpBankGate(MP.bank, S);
  if (gate) return mpSkip(gate, ev);
  if (MP.positions.length >= mpMaxOpen(S)) return mpSkip("all snipe slots are full", ev);
  // offense: bet bigger with evidence, never past the cap
  const boosts = [];
  let mult = 1;
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
                tokensLeft: tokens, realizedUsd: 0, phase: "full", boosts, devCheckedAt: 0 };
  MP.positions.push(pos);
  MP.evaluated.unshift({ ...ev, verdict: "paper buy", reason: `${m.progress.toFixed(1)}% bonded · top10 ${top10 != null ? Math.round(top10) + "%" : "?"} · dev ${devPct != null ? devPct.toFixed(1) + "%" : "?"}`, at: Date.now() });
  MP.evaluated = MP.evaluated.slice(0, 120);
  log("cannon", `PAPER BUY ${ev.symbol} $${sizeUsd.toFixed(2)} at ${m.progress.toFixed(1)}% bonded${boosts.length ? " (" + boosts.join(", ") + ")" : ""}`);
}

/** Price + market cap from the live trading pool (used once a token graduates off the pump.fun curve). Cached 8 s. */
const mpDexCache = new Map();
async function mpDexPrice(mint) {
  const h = mpDexCache.get(mint);
  if (h && Date.now() - h.ts < 8000) return h.v;
  let v = null;
  try {
    const d = await (await withTimeout(fetch(`https://api.dexscreener.com/latest/dex/tokens/${mint}`), 6000, "dex price")).json();
    const p = trustedDexPair(d.pairs, mint);
    if (p && +p.priceUsd > 0) v = { price: +p.priceUsd, mcap: +p.marketCap || +p.fdv || 0 };
  } catch {}
  mpDexCache.set(mint, { v, ts: Date.now() });
  if (mpDexCache.size > 500) mpDexCache.delete(mpDexCache.keys().next().value);
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
    log("cannon", `PAPER CLOSED ${p.symbol} ${why} ${pnlUsd >= 0 ? "+" : ""}$${pnlUsd.toFixed(2)}`);
    for (const msg of mpAfterClose(MP.bank, S, pnlUsd)) mpEvent(msg);
    if (S.autoSend && MP.bank.vault > 0) mpSendVault("auto: profit locked");
  };
  for (const p of MP.positions.slice()) {
    if (p.tokensLeft == null) { p.tokensLeft = p.tokens; p.realizedUsd = 0; p.phase = "full"; }
    let price = null, graduated = false;
    try {
      const c = await readBondingCurve(p.mint);
      if (c && !c.complete) { const m = curveMarket(c, sol, 6); price = m.price; p.mcapNow = m.mcap; }
      else if (c && c.complete) {
        const dx = await mpDexPrice(p.mint);                              // graduated: keep following it on the trading pool
        if (dx) { price = dx.price; p.mcapNow = dx.mcap; p.postGrad = true; }
        else { price = p.last; graduated = true; }                         // no pool price yet: cash out at the last curve price
      }
    } catch {}
    if (price == null) continue;
    p.last = price; p.high = Math.max(p.high, price);
    const ch = (price / p.entry - 1) * 100, age = Date.now() - p.openedAt;

    // defense: creator dumped → out now (checked every 30 s per position)
    if (S.devExit && p.devPct != null && p.devPct >= 0.5 && Date.now() - (p.devCheckedAt || 0) > 30000) {
      p.devCheckedAt = Date.now();
      try { const now = ((await balanceOf(p.creator, p.mint)) / 1e9) * 100;
        if (now < 0.1) { sell(p, 1, price); close(p, "creator dumped: got out"); continue; } } catch {}
    }
    // RUG ZONE: fast movers that reach this market cap are usually being pumped to dump on late buyers. Take everything and go.
    if (S.cashOutMcap > 0 && p.mcapNow >= S.cashOutMcap) {
      const k = Math.round(p.mcapNow / 1000);
      sell(p, 1, price);
      MP.outcomes.push({ mint: p.mint, sym: p.symbol, reason: "cashed out in the rug zone", p0: price, due: Date.now() + 30 * 60e3, dex: true });
      mpEvent(`${p.symbol} reached $${k}K market cap: sold everything (rug zone)`);
      close(p, `rug zone: cashed out at $${k}K market cap (+${Math.round(ch)}%)`); continue;
    }
    if (graduated) { sell(p, 1, price); close(p, p.phase === "moon" ? "moon bag: graduated, cashed out" : "graduated, cashed out"); continue; }

    if (p.phase === "full") {
      if (ch >= S.tpPct) {                           // offense: lock the win, keep a free ride
        if (S.tp1SellPct >= 100) { sell(p, 1, price); close(p, `take profit +${S.tpPct}%`); continue; }
        sell(p, S.tp1SellPct / 100, price);
        p.phase = "moon"; p.moonHigh = price;
        mpEvent(`${p.symbol} hit +${Math.round(ch)}%: sold ${S.tp1SellPct}%, letting the rest ride`);
        continue;
      }
      if (ch <= -S.slPct) { sell(p, 1, price); close(p, `stop loss −${S.slPct}%`); continue; }
      if (p.fast && age > S.fastTimeoutSec * 1000 && ch < S.fastMinGainPct) { sell(p, 1, price); close(p, `Launch Shot: no lift-off in ${Math.round(S.fastTimeoutSec / 60)}m`); continue; }
      if (age > S.maxHoldMin * 60e3) { sell(p, 1, price); close(p, `time limit ${S.maxHoldMin}m`); continue; }
    } else {                                         // moon bag: ride it, trail the high
      p.moonHigh = Math.max(p.moonHigh || price, price);
      const run = p.moonHigh / p.entry;
      const trail = run >= 10 ? Math.min(S.trailPct, S.trailAt10x) : run >= 5 ? Math.min(S.trailPct, S.trailAt5x) : S.trailPct;
      p.trailNow = trail;
      if (price <= p.moonHigh * (1 - trail / 100)) { sell(p, 1, price); close(p, `moon bag: trailing stop (peaked +${Math.round((p.moonHigh / p.entry - 1) * 100)}%)`); continue; }
      if (age > S.moonHoldMin * 60e3) { sell(p, 1, price); close(p, `moon bag: time limit ${S.moonHoldMin}m`); continue; }
    }
  }
}

/** Live feed of pump.fun launches, straight from the chain. */
function mpConnect() {
  if (!MP.on || MP.feed.subId != null) return;
  try {
    MP.feed.subId = connection.onLogs(PUMP_PROGRAM, (l) => {
      MP.feed.connected = true;
      if (l.err || !Array.isArray(l.logs) || !l.logs.some((x) => x.includes("Instruction: Create"))) return;
      for (const line of l.logs) {
        if (!line.startsWith("Program data: ")) continue;
        const ev = decodeCreateEvent(line.slice(14));
        if (ev) { mpOnLaunch(ev); return; }
      }
      MP.feed.decodeFails++;
    }, "confirmed");
    MP.feed.connected = true;
    log("cannon", "watching pump.fun launches (paper mode)");
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
 * Wallets that may WATCH THE CANNON by signing in with their own wallet (no tokens needed).
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
    growthPct: +(((total / B.start) - 1) * 100).toFixed(1), today: +(B.cash + openValue - B.dayStart).toFixed(2), peak: +(B.peak || 0).toFixed(2),
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
    feed: { ...MP.feed, subId: undefined }, seen: MP.seen, queued: MP.queue.length,
    stats: { trades: done.length, wins, winRate: done.length ? Math.round((wins / done.length) * 100) : null, pnlSol: +pnl.toFixed(4), pnlUsd: sol ? +(pnl * sol).toFixed(2) : null,
             best: done.length ? Math.max(...done.map((x) => x.pnlPct)) : null, worst: done.length ? Math.min(...done.map((x) => x.pnlPct)) : null },
    skips: MP.skips, open, closed: done.slice(0, 60), evaluated: MP.evaluated.slice(0, 60),
    bank, events: MP.events.slice(0, 20), learned: mpLearned(done, MP.settings.learnMin), filterReport,
    scorecard: mpScorecard(done.filter((x) => x.pnlUsd != null), MP.bank.start) });
});

/** Owner-only: change the rules (numbers are clamped to sane ranges) */
app.post("/api/mp/settings", (req, res) => {
  if (!requireOwner(req, res)) return;
  const b = req.body || {}, S = MP.settings;
  const clamp = (k, lo, hi) => { if (b[k] == null) return; const v = Number(b[k]); if (Number.isFinite(v)) S[k] = Math.min(hi, Math.max(lo, v)); };
  clamp("startUsd", 1, 100000); clamp("slots", 0, 30); clamp("maxLossPct", 0, 100); clamp("riskPct", 1, 50); clamp("minTradeUsd", 0.1, 1000); clamp("vaultAtX", 1.2, 100); clamp("keepX", 0.2, 50);
  clamp("tp1SellPct", 10, 100); clamp("trailPct", 5, 90); clamp("moonHoldMin", 5, 2880); clamp("smartBoost", 1, 3); clamp("favorBoost", 1, 3);
  clamp("maxBetPct", 2, 50); clamp("devExit", 0, 1); clamp("cashOutMcap", 0, 100000000); if (S.cashOutMcap > 0 && S.cashOutMcap < 10000) S.cashOutMcap = 10000; clamp("autoSend", 0, 1); clamp("trailAt5x", 3, 90); clamp("trailAt10x", 2, 90);
  if (typeof b.savingsWallet === "string") {
    const w = b.savingsWallet.trim();
    if (w === "") S.savingsWallet = "";
    else if (SOL_ADDR.test(w)) S.savingsWallet = w;
    else return res.status(400).json({ error: "That isn't a valid Solana wallet address." });
  }
  if (b.sendVault === true) mpSendVault("you tapped Send");
  clamp("fastLane", 0, 1); clamp("fastMaxMcap", 3000, 100000); clamp("fastBetPct", 1, 25); clamp("fastMaxPerMin", 1, 20); clamp("fastMaxOpen", 1, 20);
  clamp("fastMaxDevPct", 0, 100); clamp("fastTimeoutSec", 30, 3600); clamp("fastMinGainPct", 0, 500);
  clamp("dailyStopPct", 5, 100); clamp("maxLossStreak", 2, 50); clamp("pauseMin", 5, 1440); clamp("learn", 0, 1); clamp("learnMin", 5, 200);
  if (S.keepX >= S.vaultAtX) S.keepX = Math.max(0.2, S.vaultAtX - 0.2);
  clamp("waitSec", 10, 900); clamp("minProgress", 0, 90); clamp("maxDevPct", 0, 100);
  clamp("maxTop10Pct", 5, 100); clamp("maxTop1Pct", 1, 100); clamp("tpPct", 5, 2000); clamp("slPct", 5, 95);
  clamp("maxHoldMin", 1, 1440); clamp("maxOpen", 1, 30); clamp("maxEvalPerMin", 1, 30);
  if (typeof b.on === "boolean") { MP.on = b.on; if (MP.on) mpConnect(); }
  if (b.reset === true) { MP.closed = []; MP.positions = []; MP.evaluated = []; MP.skips = {}; MP.seen = 0; MP.startedAt = Date.now();
    MP.bank = mpNewBank(S.startUsd); MP.report = {}; MP.outcomes = []; MP.events = []; mpEvent(`Started fresh with $${S.startUsd}`); }
  res.json({ ok: true, settings: S, on: MP.on });
});

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
    cannon: { running: MP.on && MP.feed.connected },   // details are owner-only (/api/mp/state)
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
