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

// ── config from environment (set these in Railway/Render dashboard) ───────
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const SLAPGOLD_MINT = process.env.SLAPGOLD_MINT; // e.g. 4R7Hbdhh3YeVqZaESRA3qPJ8Z3xh3Qedsw88RDjxL1Q9
const MY_WALLET = process.env.MY_WALLET;         // YOUR wallet address — the only one allowed in
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
const GATE_MIN_HOLD = parseFloat(process.env.GATE_MIN_HOLD || "100000");

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
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  if (req.path.startsWith("/api/auth") || req.path.startsWith("/api/exclusive")) res.setHeader("Cache-Control", "no-store");
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
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/api/health",
  message: { error: "Rate limit exceeded. Slow down." },
});
app.use(limiter);
app.use("/api/auth", rateLimit({ windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Wait a minute." } }));
app.use(["/api/token", "/api/mint-check"], rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true,
  legacyHeaders: false, message: { error: "Too many lookups. Slow down." } }));

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
    let top10Pct = null, top10WalletPct = null;
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
          if (PublicKey.isOnCurve(new PublicKey(owner).toBytes())) { walletSum += a.uiAmount || 0; counted++; }
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

function issuePass(wallet) {
  const body = Buffer.from(JSON.stringify({ w: wallet, exp: Date.now() + SESSION_MS })).toString("base64url");
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
async function getHolderStatus(wallet) {
  const hit = holderCache.get(wallet);
  if (hit && Date.now() - hit.ts < HOLDER_TTL) return hit.data;
  const accts = await withTimeout(
    connection.getParsedTokenAccountsByOwner(new PublicKey(wallet), { mint: new PublicKey(GATE_MINT) }),
    8000, "holder balance");
  const balance = accts.value.reduce((s, a) => s + (a.account.data.parsed.info.tokenAmount.uiAmount || 0), 0);
  const isOwner = !!MY_WALLET && wallet === MY_WALLET;   // base58 is case-sensitive: exact match only
  const data = { balance, isOwner, minRequired: GATE_MIN_HOLD, authorized: isOwner || balance >= GATE_MIN_HOLD };
  holderCache.set(wallet, { data, ts: Date.now() });
  if (holderCache.size > 5000) holderCache.delete(holderCache.keys().next().value);
  return data;
}


/**
 * GET /api/gate — public: which token opens Exclusive, how much, and roughly
 * what that's worth right now. Price is read live so the requirement always
 * shows its real dollar value.
 */
let gateInfoCache = { data: null, ts: 0 };
app.get("/api/gate", async (req, res) => {
  if (gateInfoCache.data && Date.now() - gateInfoCache.ts < 60000) return res.json(gateInfoCache.data);
  const base = { mint: GATE_MINT, minRequired: GATE_MIN_HOLD, symbol: null, name: null, logo: null, price: null, minUsd: null };
  try {
    const r = await withTimeout(fetch(`https://api.dexscreener.com/latest/dex/tokens/${GATE_MINT}`), 8000, "gate price");
    const d = await r.json();
    const pairs = (d.pairs || []).filter((p) => p.chainId === "solana");
    if (pairs.length) {
      const top = pairs.reduce((b, p) => ((p.liquidity?.usd || 0) > (b.liquidity?.usd || 0) ? p : b), pairs[0]);
      const price = parseFloat(top.priceUsd || 0) || null;
      Object.assign(base, { symbol: top.baseToken?.symbol || null, name: top.baseToken?.name || null,
        logo: top.info?.imageUrl || null, price, minUsd: price ? +(price * GATE_MIN_HOLD).toFixed(2) : null });
    }
  } catch (err) { log("error", `gate info lookup failed: ${err.message}`); }
  gateInfoCache = { data: base, ts: Date.now() };
  res.json(base);
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
  const { wallet, signature } = req.body || {};
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
  if (!status.authorized) return res.status(403).json({ error: "Not enough tokens", ...status });
  res.json({ pass: issuePass(wallet), ...status });
});

/** Guard for every exclusive endpoint — re-checks the balance on each visit */
async function requireHolder(req, res, next) {
  const h = req.headers.authorization || "";
  const data = readPass(h.startsWith("Bearer ") ? h.slice(7) : "");
  if (!data) return res.status(401).json({ error: "Please sign in." });
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
async function geckoFeed(kind) {
  const r = await withTimeout(fetch(
    `https://api.geckoterminal.com/api/v2/networks/solana/${kind}?include=base_token`,
    { headers: { accept: "application/json" } }), 10000, kind);
  if (!r.ok) throw new Error(`GeckoTerminal ${r.status}`);
  return mapGecko(await r.json());
}

/**
 * GET /api/exclusive/picks — the holder-only feed
 *   verified: fresh launches that PASSED on-chain safety
 *             (mint revoked, freeze revoked, top-10 wallets under 60%)
 *   momentum: trending tokens with rising price and strong buy pressure
 * Computed once a minute and shared, so holders never trigger RPC storms.
 */
let picksCache = { data: null, ts: 0 };
const PICKS_TTL = 60 * 1000;
app.get("/api/exclusive/picks", requireHolder, async (req, res) => {
  if (picksCache.data && Date.now() - picksCache.ts < PICKS_TTL) return res.json(picksCache.data);
  try {
    const [fresh, trending] = await Promise.all([
      geckoFeed("new_pools").catch(() => []),
      geckoFeed("trending_pools").catch(() => []),
    ]);

    // Cheap gates first, then the expensive on-chain check on the best few
    const seen = new Set();
    const candidates = [...fresh, ...trending]
      .filter((p) => p.liq >= 3000 && p.txns >= 20 && !seen.has(p.addr) && seen.add(p.addr))
      .sort((a, b) => b.vol - a.vol)
      .slice(0, 14);

    const checks = await Promise.allSettled(candidates.map((p) => getMintCheck(p.addr)));
    let checked = 0;
    const verified = [];
    candidates.forEach((p, i) => {
      const c = checks[i].status === "fulfilled" ? checks[i].value : null;
      if (!c || !c.found) return;
      checked++;
      const safe = c.mintAuthorityRenounced && c.freezeAuthorityRenounced &&
                   ((c.top10WalletPct ?? c.top10HolderPct) == null || (c.top10WalletPct ?? c.top10HolderPct) < 60);
      if (safe) verified.push({ ...p, top10: c.top10WalletPct ?? c.top10HolderPct,
        buyPct: p.txns ? Math.round((p.buys / p.txns) * 100) : 50 });
    });

    const momentum = trending
      .filter((p) => p.liq >= 10000 && p.txns >= 100 && p.ch1 > 0 && p.txns && p.buys / p.txns >= 0.55)
      .map((p) => ({ ...p, buyPct: Math.round((p.buys / p.txns) * 100) }))
      .sort((a, b) => b.ch1 - a.ch1)
      .slice(0, 12);

    const payload = { updated: Date.now(), verified: verified.slice(0, 12), momentum,
                      checked, candidates: candidates.length };
    picksCache = { data: payload, ts: Date.now() };
    log("exclusive", `picks: ${verified.length} verified of ${checked} checked, ${momentum.length} momentum`);
    res.json(payload);
  } catch (err) {
    log("error", `picks failed: ${err.message}`);
    if (picksCache.data) return res.json(picksCache.data);
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

async function gecko(path, ms = 9000) {
  const r = await withTimeout(fetch("https://api.geckoterminal.com/api/v2/networks/solana" + path,
    { headers: { accept: "application/json" } }), ms, "gecko " + path.split("?")[0]);
  if (!r.ok) throw new Error("GeckoTerminal " + r.status);
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
    gecko(`/tokens/${mint}/pools?include=base_token&page=1`),
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
  };

  // Graduated / indexed: the most liquid pool wins
  if (poolsR.status === "fulfilled") {
    const raw = poolsR.value, inc = raw.included || [];
    const pools = (raw.data || []).slice().sort((a, b) => n(b.attributes?.reserve_in_usd) - n(a.attributes?.reserve_in_usd));
    const top = pools[0];
    if (top) {
      const a = top.attributes || {}, tx = a.transactions?.h24 || {};
      const bt = inc.find((x) => x.id === top.relationships?.base_token?.data?.id);
      Object.assign(p, {
        source: "pool", poolAddress: a.address || null, dex: top.relationships?.dex?.data?.id || null,
        price: n(a.base_token_price_usd), ch1: n(a.price_change_percentage?.h1), ch24: n(a.price_change_percentage?.h24),
        vol24: n(a.volume_usd?.h24), liq: n(a.reserve_in_usd),
        mcap: n(a.market_cap_usd) || n(a.fdv_usd) || null,
        buys24: n(tx.buys), sells24: n(tx.sells), txns24: n(tx.buys) + n(tx.sells),
        createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
      });
      if (bt?.attributes) {
        p.symbol = p.symbol || bt.attributes.symbol || null;
        p.name = p.name || bt.attributes.name || null;
        p.logo = bt.attributes.image_url || null;
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
  const key = chain + pool + tf, hit = chartCache.get(key);
  if (hit && Date.now() - hit.ts < 20000) return res.json(hit.data);
  try {
    const [unit, agg] = TF[tf];
    const gid = await resolveGecko(chain);
    if (!gid) return res.status(404).json({ error: "Charts aren't available for this chain yet." });
    const d = await geckoAny(`/networks/${gid}/pools/${pool}/ohlcv/${unit}?aggregate=${agg}&limit=120&currency=usd`);
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
      return { kind: a.kind === "sell" ? "sell" : "buy", usd: +a.volume_in_usd || 0,
        wallet: a.tx_from_address || null, tx: a.tx_hash || null,
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
      const r = await withTimeout(fetch(`https://api.geckoterminal.com/api/v2/networks?page=${page}`,
        { headers: { accept: "application/json" } }), 9000, "networks");
      if (!r.ok) break;
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
async function geckoAny(fullPath, ms = 9000) {
  const r = await withTimeout(fetch("https://api.geckoterminal.com/api/v2" + fullPath,
    { headers: { accept: "application/json" } }), ms, "gecko " + fullPath.split("?")[0]);
  if (!r.ok) throw new Error("GeckoTerminal " + r.status);
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

app.get("/api/pools/:type", async (req, res) => {
  const type = req.params.type === "new" ? "new" : "trending";
  const now = Date.now();
  const hit = poolCache[type];
  if (hit.data && now - hit.ts < POOL_TTL) return res.json(hit.data);

  const endpoint = type === "new" ? "new_pools" : "trending_pools";

  try {
    const r = await fetch(
      `https://api.geckoterminal.com/api/v2/networks/solana/${endpoint}?include=base_token`,
      { headers: { accept: "application/json" } }
    );
    if (!r.ok) throw new Error(`GeckoTerminal ${r.status}`);
    const raw = await r.json();

    const included = raw.included || [];
    const pools = (raw.data || []).map((p) => {
      const a = p.attributes || {};
      const btId = p.relationships?.base_token?.data?.id || "";
      const bt = included.find((x) => x.id === btId);
      const n = (v) => (Number.isFinite(+v) ? +v : 0);
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
        buys, sells,
        txns: buys + sells,
        createdAt: a.pool_created_at ? new Date(a.pool_created_at).getTime() : null,
        dex: p.relationships?.dex?.data?.id || "",
      };
    }).filter((x) => x.addr && x.price > 0);

    const payload = { source: "geckoterminal", type, count: pools.length, pools };
    poolCache[type] = { data: payload, ts: now };
    log("discovery", `${type}: ${pools.length} pools`);
    res.json(payload);
  } catch (err) {
    log("error", `pool discovery (${type}) failed: ${err.message}`);
    if (hit.data) return res.json(hit.data); // serve stale over failing
    res.status(502).json({ error: "Market data unavailable right now.", pools: [] });
  }
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
    const r = await fetch(
      `https://api.geckoterminal.com/api/v2/networks/solana/dexes/${dexId}/pools?include=base_token&page=1`,
      { headers: { accept: "application/json" } }
    );
    if (!r.ok) throw new Error(`GeckoTerminal ${r.status}`);
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
    exclusiveGate: { token: GATE_MINT, mustHold: GATE_MIN_HOLD },
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
  log("init", `Exclusive gate: hold ${GATE_MIN_HOLD} of ${GATE_MINT}`);
});
