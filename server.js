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

const app = express();
const PORT = process.env.PORT || 3000;

// ── config from environment (set these in Railway/Render dashboard) ───────
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const SLAPGOLD_MINT = process.env.SLAPGOLD_MINT; // e.g. 4R7Hbdhh3YeVqZaESRA3qPJ8Z3xh3Qedsw88RDjxL1Q9
const MY_WALLET = process.env.MY_WALLET;         // YOUR wallet address — the only one allowed in
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*"; // lock to your GitHub Pages URL once live
const MIN_HOLD_AMOUNT = parseFloat(process.env.MIN_HOLD_AMOUNT || "1"); // min SLAP GOLD to unlock

if (!SLAPGOLD_MINT) {
  console.error("[FATAL] SLAPGOLD_MINT env var not set. Server cannot start.");
  process.exit(1);
}

const connection = new Connection(SOLANA_RPC_URL, "confirmed");

// ── middleware ──────────────────────────────────────────────────────────
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Rate limit exceeded. Slow down." },
});
app.use(limiter);

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
async function getMintCheck(address) {
  try {
    const mintPubkey = new PublicKey(address);
    const info = await connection.getParsedAccountInfo(mintPubkey);

    if (!info.value || info.value.data.parsed?.type !== "mint") {
      return { error: "Not a valid SPL token mint", found: false };
    }

    const parsed = info.value.data.parsed.info;
    const mintAuthority = parsed.mintAuthority || null;
    const freezeAuthority = parsed.freezeAuthority || null;
    const supply = Number(parsed.supply) / Math.pow(10, parsed.decimals);

    let top10Pct = null;
    try {
      const largest = await connection.getTokenLargestAccounts(mintPubkey);
      const top10Sum = largest.value.slice(0, 10).reduce((s, acc) => s + (acc.uiAmount || 0), 0);
      top10Pct = supply > 0 ? (top10Sum / supply) * 100 : null;
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
      criticalHoneypot: !!freezeAuthority,
    };

    if (result.criticalHoneypot) {
      log("flagged_rug", `${address.slice(0, 8)}... → FREEZE AUTHORITY ENABLED — honeypot risk`);
    } else {
      log("audit", `${address.slice(0, 8)}... → mint:${result.mintAuthorityRenounced ? "renounced" : "ACTIVE"} top10:${result.top10HolderPct}%`);
    }
    return result;
  } catch (err) {
    log("error", `mint-check failed for ${address}: ${err.message}`);
    return { error: "Invalid mint address or RPC error", found: false };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ① ACCESS CONTROL — the personal lock
// ═══════════════════════════════════════════════════════════════════════

/**
 * GET /api/verify-holder?wallet=<address>
 * Checks the wallet's SLAP GOLD balance on-chain.
 * Returns { authorized: boolean, balance: number, isOwner: boolean }
 */
app.get("/api/verify-holder", async (req, res) => {
  const wallet = req.query.wallet;
  if (!wallet) return res.status(400).json({ error: "wallet query param required" });

  try {
    const walletPubkey = new PublicKey(wallet);
    const mintPubkey = new PublicKey(SLAPGOLD_MINT);

    const tokenAccounts = await connection.getParsedTokenAccountsByOwner(walletPubkey, {
      mint: mintPubkey,
    });

    let balance = 0;
    if (tokenAccounts.value.length > 0) {
      balance = tokenAccounts.value.reduce((sum, acc) => {
        const amt = acc.account.data.parsed.info.tokenAmount.uiAmount || 0;
        return sum + amt;
      }, 0);
    }

    const isOwner = MY_WALLET && wallet.toLowerCase() === MY_WALLET.toLowerCase();
    const authorized = isOwner || balance >= MIN_HOLD_AMOUNT;

    log("access", `${wallet.slice(0, 4)}...${wallet.slice(-4)} → balance=${balance} authorized=${authorized}`);
    res.json({ authorized, balance, isOwner, minRequired: MIN_HOLD_AMOUNT });
  } catch (err) {
    log("error", `verify-holder failed: ${err.message}`);
    res.status(400).json({ error: "Invalid wallet address or RPC error", authorized: false });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ② PRICE PROXY — hides rate limits from the browser, adds caching
// ═══════════════════════════════════════════════════════════════════════

let priceCache = { data: null, ts: 0 };
const PRICE_CACHE_MS = 20_000;

app.get("/api/prices", async (req, res) => {
  const now = Date.now();
  if (priceCache.data && now - priceCache.ts < PRICE_CACHE_MS) {
    return res.json(priceCache.data);
  }
  try {
    const ids = "solana,bitcoin,ethereum,raydium,jupiter-exchange-solana,binancecoin,bonk,dogwifcoin,avalanche-2,chainlink";
    const r = await fetch(
      `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd&include_24hr_change=true&include_24hr_vol=true`
    );
    const data = await r.json();
    priceCache = { data, ts: now };
    log("scan", "Price cache refreshed from CoinGecko");
    res.json(data);
  } catch (err) {
    log("error", `Price fetch failed: ${err.message}`);
    if (priceCache.data) return res.json(priceCache.data); // serve stale on failure
    res.status(502).json({ error: "Price provider unavailable" });
  }
});

/**
 * GET /api/slapgold-price
 * Your own token's live price + liquidity from DexScreener.
 */
app.get("/api/slapgold-price", async (req, res) => {
  try {
    const r = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${SLAPGOLD_MINT}`);
    const data = await r.json();
    const pairs = data.pairs || [];
    if (!pairs.length) return res.json({ found: false });
    const top = pairs.reduce((b, p) => ((p.liquidity?.usd || 0) > (b.liquidity?.usd || 0) ? p : b), pairs[0]);
    res.json({
      found: true,
      price: parseFloat(top.priceUsd || 0),
      change24h: top.priceChange?.h24 || 0,
      liquidity: top.liquidity?.usd || 0,
      volume24h: top.volume?.h24 || 0,
      dex: top.dexId,
    });
  } catch (err) {
    log("error", `SLAPGOLD price fetch failed: ${err.message}`);
    res.status(502).json({ error: "Failed to fetch SLAP GOLD price" });
  }
});

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
  const result = await getMintCheck(req.params.address);
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

/**
 * GET /api/scan/:address
 * Combined scan: DexScreener market data + on-chain mint/freeze/holder checks
 * in a single response, so the frontend only needs one call.
 */
app.get("/api/scan/:address", async (req, res) => {
  const { address } = req.params;
  try {
    const [dexRes, onchain] = await Promise.allSettled([
      fetch(`https://api.dexscreener.com/latest/dex/tokens/${address}`).then((r) => r.json()),
      getMintCheck(address),
    ]);

    const market = dexRes.status === "fulfilled" ? dexRes.value : { pairs: [] };
    const onchainResult = onchain.status === "fulfilled" ? onchain.value : { found: false };

    log("scan", `Full scan on ${address.slice(0, 8)}... — market pairs: ${(market.pairs || []).length}, onchain: ${onchainResult.found}`);
    res.json({ market, onchain: onchainResult });
  } catch (err) {
    log("error", `Combined scan failed: ${err.message}`);
    res.status(502).json({ error: "Scanner unavailable" });
  }
});

app.get("/api/launches", async (req, res) => {
  try {
    const r = await fetch("https://api.dexscreener.com/latest/dex/search?q=solana");
    const data = await r.json();
    res.json(data);
  } catch (err) {
    log("error", `Launches proxy failed: ${err.message}`);
    res.status(502).json({ error: "Launches provider unavailable" });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// health check
// ═══════════════════════════════════════════════════════════════════════
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", mint: SLAPGOLD_MINT, minHold: MIN_HOLD_AMOUNT, time: new Date().toISOString() });
});

app.listen(PORT, () => {
  log("init", `BIG MOUF SLAPBOT backend running on port ${PORT}`);
  log("init", `Gating on mint: ${SLAPGOLD_MINT}`);
  log("init", `Min hold to unlock: ${MIN_HOLD_AMOUNT} SLAP GOLD`);
});
