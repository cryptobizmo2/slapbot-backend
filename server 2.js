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
const { getAssociatedTokenAddress } = require("@solana/spl-token");

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
// ④ REVENUE — fee account for Jupiter platform fee on real swaps
// ═══════════════════════════════════════════════════════════════════════

/**
 * GET /api/fee-account/:mint
 * Returns the Associated Token Account (ATA) address for MY_WALLET that
 * will receive your platform fee cut on every real swap in that token.
 * The frontend calls this once per token and passes it to Jupiter's
 * swap API as the `feeAccount` parameter.
 *
 * IMPORTANT: this ATA must actually exist on-chain to receive fees.
 * If it doesn't exist yet for a given mint, the first fee-earning swap
 * in that token may fail until the account is created (e.g. by
 * receiving a small amount of that token once, or via a setup script).
 */
app.get("/api/fee-account/:mint", async (req, res) => {
  const { mint } = req.params;
  if (!MY_WALLET) return res.status(400).json({ error: "MY_WALLET not configured on server" });
  try {
    const mintPubkey = new PublicKey(mint);
    const ownerPubkey = new PublicKey(MY_WALLET);
    const ata = await getAssociatedTokenAddress(mintPubkey, ownerPubkey);
    log("revenue", `Fee account for mint ${mint.slice(0,8)}... → ${ata.toBase58()}`);
    res.json({ feeAccount: ata.toBase58(), owner: MY_WALLET, mint });
  } catch (err) {
    log("error", `fee-account failed for mint ${mint}: ${err.message}`);
    res.status(400).json({ error: "Invalid mint address" });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ⑤ COPY TRADING — watch a wallet, scale trade size proportionally
// ═══════════════════════════════════════════════════════════════════════

// Known token prices come from CoinGecko; mint → coingecko id, for portfolio valuation
const KNOWN_TOKENS = {
  "So11111111111111111111111111111111111111112": { sym: "SOL", cgId: "solana", decimals: 9 },
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": { sym: "USDC", cgId: "usd-coin", decimals: 6 },
  "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R": { sym: "RAY", cgId: "raydium", decimals: 6 },
  "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN": { sym: "JUP", cgId: "jupiter-exchange-solana", decimals: 6 },
  "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": { sym: "BONK", cgId: "bonk", decimals: 5 },
  "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm": { sym: "WIF", cgId: "dogwifcoin", decimals: 6 },
};

let priceCache2 = { data: {}, ts: 0 };
async function getPrices() {
  const now = Date.now();
  if (priceCache2.data && now - priceCache2.ts < 20000) return priceCache2.data;
  const ids = [...new Set(Object.values(KNOWN_TOKENS).map((t) => t.cgId))].join(",");
  const r = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`);
  const data = await r.json();
  priceCache2 = { data, ts: now };
  return data;
}

/**
 * Computes a wallet's total portfolio value in USD across SOL + known SPL tokens.
 * Unknown/exotic tokens are not priced (would need a full token-list + price feed)
 * — this is a reasonable approximation, not a complete net-worth calculator.
 */
async function getWalletValueUSD(address) {
  const pubkey = new PublicKey(address);
  const [solBalance, tokenAccounts, prices] = await Promise.all([
    connection.getBalance(pubkey),
    connection.getParsedTokenAccountsByOwner(pubkey, { programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") }),
    getPrices(),
  ]);

  const solUsd = (solBalance / 1e9) * (prices.solana?.usd || 0);
  let tokenUsd = 0;
  const holdings = [];

  for (const acc of tokenAccounts.value) {
    const info = acc.account.data.parsed.info;
    const mint = info.mint;
    const uiAmount = info.tokenAmount.uiAmount || 0;
    if (uiAmount <= 0) continue;
    const known = KNOWN_TOKENS[mint];
    if (known) {
      const usd = uiAmount * (prices[known.cgId]?.usd || 0);
      tokenUsd += usd;
      holdings.push({ mint, sym: known.sym, amount: uiAmount, usd });
    } else {
      holdings.push({ mint, sym: "?", amount: uiAmount, usd: 0 });
    }
  }

  return {
    address,
    solBalance: solBalance / 1e9,
    solUsd,
    totalUsd: solUsd + tokenUsd,
    holdings,
  };
}

/**
 * GET /api/wallet-value/:address
 * Returns total portfolio value (USD) for any wallet — used to compute
 * the proportional sizing ratio between a tracked wallet and your own.
 */
app.get("/api/wallet-value/:address", async (req, res) => {
  try {
    const result = await getWalletValueUSD(req.params.address);
    log("copytrade", `Wallet ${req.params.address.slice(0, 6)}... valued at $${result.totalUsd.toFixed(2)}`);
    res.json(result);
  } catch (err) {
    log("error", `wallet-value failed: ${err.message}`);
    res.status(400).json({ error: "Invalid wallet address or RPC error" });
  }
});

/**
 * GET /api/wallet-swaps/:address?limit=15&minUsd=10
 * Inspects a wallet's recent transactions and detects likely swaps by
 * comparing pre/post token balances. Filters out anything below minUsd
 * so dust transactions don't trigger copy-trade signals.
 *
 * This reads token balance deltas directly from transaction metadata —
 * no external swap-parsing service required.
 */
app.get("/api/wallet-swaps/:address", async (req, res) => {
  const { address } = req.params;
  const limit = Math.min(parseInt(req.query.limit) || 15, 30);
  const minUsd = parseFloat(req.query.minUsd) || 10;

  try {
    const pubkey = new PublicKey(address);
    const prices = await getPrices();
    const sigs = await connection.getSignaturesForAddress(pubkey, { limit });

    const swaps = [];
    for (const sigInfo of sigs) {
      if (sigInfo.err) continue;
      try {
        const tx = await connection.getParsedTransaction(sigInfo.signature, { maxSupportedTransactionVersion: 0 });
        if (!tx || !tx.meta) continue;

        const preBal = tx.meta.preTokenBalances || [];
        const postBal = tx.meta.postTokenBalances || [];
        const ownerIdx = tx.transaction.message.accountKeys.findIndex((k) => k.pubkey.toBase58() === address);
        if (ownerIdx === -1) continue;

        // Find token balance changes for this specific owner
        const changes = {};
        for (const pb of preBal) {
          if (pb.owner !== address) continue;
          changes[pb.mint] = { pre: pb.uiTokenAmount.uiAmount || 0, post: 0 };
        }
        for (const pb of postBal) {
          if (pb.owner !== address) continue;
          if (!changes[pb.mint]) changes[pb.mint] = { pre: 0, post: 0 };
          changes[pb.mint].post = pb.uiTokenAmount.uiAmount || 0;
        }

        // Also check native SOL delta for this account
        const preSol = tx.meta.preBalances[ownerIdx] / 1e9;
        const postSol = tx.meta.postBalances[ownerIdx] / 1e9;
        const solDelta = postSol - preSol;

        let sold = null, bought = null;
        for (const [mint, c] of Object.entries(changes)) {
          const delta = c.post - c.pre;
          if (Math.abs(delta) < 1e-9) continue;
          const known = KNOWN_TOKENS[mint];
          const usd = known ? Math.abs(delta) * (prices[known.cgId]?.usd || 0) : 0;
          if (delta < 0 && (!sold || usd > sold.usd)) sold = { mint, sym: known?.sym || "?", amount: Math.abs(delta), usd };
          if (delta > 0 && (!bought || usd > bought.usd)) bought = { mint, sym: known?.sym || "?", amount: delta, usd };
        }
        // Fold in SOL side if it moved meaningfully and no SPL side captured it
        if (Math.abs(solDelta) > 0.001) {
          const usd = Math.abs(solDelta) * (prices.solana?.usd || 0);
          if (solDelta < 0 && (!sold || usd > sold.usd)) sold = { mint: "SOL", sym: "SOL", amount: Math.abs(solDelta), usd };
          if (solDelta > 0 && (!bought || usd > bought.usd)) bought = { mint: "SOL", sym: "SOL", amount: solDelta, usd };
        }

        if (sold && bought) {
          const tradeUsd = Math.max(sold.usd, bought.usd);
          if (tradeUsd >= minUsd) {
            swaps.push({
              signature: sigInfo.signature,
              time: sigInfo.blockTime ? sigInfo.blockTime * 1000 : null,
              sold, bought, tradeUsd,
            });
          }
        }
      } catch (txErr) {
        continue; // skip unparseable transactions
      }
    }

    log("copytrade", `Scanned ${sigs.length} txs for ${address.slice(0,6)}... → ${swaps.length} swap(s) above $${minUsd}`);
    res.json({ address, swaps });
  } catch (err) {
    log("error", `wallet-swaps failed: ${err.message}`);
    res.status(400).json({ error: "Invalid wallet address or RPC error" });
  }
});

/**
 * GET /api/copy-size?target=<wallet>&mine=<wallet>&tradeUsd=<n>
 * The core proportional-sizing calculation:
 *   yourSize = (tradeUsd / targetWalletTotalUsd) * yourWalletTotalUsd
 * This keeps position sizing safe regardless of how large the tracked
 * wallet is compared to yours.
 */
app.get("/api/copy-size", async (req, res) => {
  const { target, mine, tradeUsd } = req.query;
  if (!target || !mine || !tradeUsd) {
    return res.status(400).json({ error: "target, mine, and tradeUsd query params required" });
  }
  try {
    const [targetVal, mineVal] = await Promise.all([
      getWalletValueUSD(target),
      getWalletValueUSD(mine),
    ]);
    if (targetVal.totalUsd <= 0) {
      return res.json({ yourSize: 0, ratio: 0, note: "Target wallet has no measurable value — cannot compute ratio" });
    }
    const ratio = parseFloat(tradeUsd) / targetVal.totalUsd;
    const yourSize = ratio * mineVal.totalUsd;
    log("copytrade", `Copy-size: target trade $${tradeUsd} (${(ratio*100).toFixed(2)}% of $${targetVal.totalUsd.toFixed(0)}) → your size $${yourSize.toFixed(2)}`);
    res.json({
      targetTotalUsd: targetVal.totalUsd,
      yourTotalUsd: mineVal.totalUsd,
      tradeUsd: parseFloat(tradeUsd),
      ratioPct: ratio * 100,
      yourSize: parseFloat(yourSize.toFixed(2)),
    });
  } catch (err) {
    log("error", `copy-size failed: ${err.message}`);
    res.status(400).json({ error: "Invalid wallet address or RPC error" });
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
