const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    credentials: true
}));

// Environment variables
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const SLAPGOLD_MINT = process.env.SLAPGOLD_MINT || '4R7Hbdhh3YeVqZaESRA3qPJ8Z3xh3Qedsw88RDjxL1Q9';
const MY_WALLET = process.env.MY_WALLET || '12zvhb36t8PtharwW6ZyvEXsbW13be7foQYPutZ2gGZ7';
const MIN_HOLD_AMOUNT = parseInt(process.env.MIN_HOLD_AMOUNT) || 1;
const TRADING_FEE_PERCENT = 0.5; // 0.5% fee to wallet

// In-memory trade cache
const tradeCache = new Map();
const walletMonitoring = new Set();

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ===== WALLET ACTIVITY ENDPOINT =====
app.get('/api/wallet-trades', async (req, res) => {
    try {
        const wallet = req.query.wallet?.trim();

        if (!wallet || wallet.length < 43) {
            return res.status(400).json({ error: 'Invalid wallet address' });
        }

        // Fetch wallet's recent transactions from Solana blockchain
        const trades = await fetchWalletTrades(wallet);
        
        res.json({
            wallet,
            trades,
            cached: false,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error in /wallet-trades:', error.message);
        res.status(500).json({ 
            error: 'Failed to fetch wallet trades',
            details: error.message 
        });
    }
});

// ===== EXECUTE TRADE ENDPOINT =====
app.post('/api/execute-trade', async (req, res) => {
    try {
        const { tokenMint, amount, type, slippage, targetWallet } = req.body;

        if (!tokenMint || !amount || !type) {
            return res.status(400).json({ 
                error: 'Missing required fields: tokenMint, amount, type' 
            });
        }

        // Validate trade parameters
        if (amount <= 0 || amount > 1000) {
            return res.status(400).json({ 
                error: 'Invalid trade amount. Must be between 0 and 1000 SOL' 
            });
        }

        if (!['buy', 'sell'].includes(type)) {
            return res.status(400).json({ 
                error: 'Invalid trade type. Must be "buy" or "sell"' 
            });
        }

        // Simulate trade execution
        const tradeResult = await simulateTradeExecution({
            tokenMint,
            amount,
            type,
            slippage: slippage || 2,
            targetWallet,
            timestamp: new Date().toISOString()
        });

        res.json(tradeResult);
    } catch (error) {
        console.error('Error in /execute-trade:', error.message);
        res.status(500).json({ 
            error: 'Trade execution failed',
            details: error.message 
        });
    }
});

// ===== GET WALLET BALANCE =====
app.get('/api/wallet-balance', async (req, res) => {
    try {
        const wallet = req.query.wallet?.trim();

        if (!wallet) {
            return res.status(400).json({ error: 'Wallet address required' });
        }

        const balance = await getWalletBalance(wallet);
        
        res.json({
            wallet,
            balance: balance.toString(),
            unit: 'lamports',
            inSOL: (balance / 1e9).toFixed(4)
        });
    } catch (error) {
        console.error('Error in /wallet-balance:', error.message);
        res.status(500).json({ 
            error: 'Failed to fetch wallet balance',
            details: error.message 
        });
    }
});

// ===== GET TOKEN INFO =====
app.get('/api/token-info', async (req, res) => {
    try {
        const mint = req.query.mint?.trim();

        if (!mint) {
            return res.status(400).json({ error: 'Mint address required' });
        }

        const tokenInfo = await getTokenInfo(mint);
        
        res.json(tokenInfo);
    } catch (error) {
        console.error('Error in /token-info:', error.message);
        res.status(500).json({ 
            error: 'Failed to fetch token info',
            details: error.message 
        });
    }
});

// ===== GET PRICE DATA =====
app.get('/api/price', async (req, res) => {
    try {
        const mint = req.query.mint?.trim();

        if (!mint) {
            return res.status(400).json({ error: 'Mint address required' });
        }

        // Use Jupiter API for price data
        const prices = await axios.get(`https://price.jup.ag/v4/price?ids=${mint}`);
        
        res.json(prices.data);
    } catch (error) {
        console.error('Error in /price:', error.message);
        res.status(500).json({ 
            error: 'Failed to fetch price',
            details: error.message 
        });
    }
});

// ===== START WALLET MONITORING =====
app.post('/api/monitor-wallet', (req, res) => {
    try {
        const { wallet } = req.body;

        if (!wallet || wallet.length < 43) {
            return res.status(400).json({ error: 'Invalid wallet address' });
        }

        walletMonitoring.add(wallet);

        res.json({
            status: 'monitoring_started',
            wallet,
            monitoredWallets: Array.from(walletMonitoring)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to start monitoring' });
    }
});

// ===== STOP WALLET MONITORING =====
app.post('/api/stop-monitoring', (req, res) => {
    try {
        const { wallet } = req.body;

        walletMonitoring.delete(wallet);

        res.json({
            status: 'monitoring_stopped',
            wallet,
            monitoredWallets: Array.from(walletMonitoring)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop monitoring' });
    }
});

// ===== HELPER FUNCTIONS =====

async function fetchWalletTrades(wallet) {
    try {
        // Check cache first
        if (tradeCache.has(wallet)) {
            return tradeCache.get(wallet);
        }

        // Fetch wallet's signatures
        const response = await axios.post(SOLANA_RPC_URL, {
            jsonrpc: '2.0',
            id: 1,
            method: 'getSignaturesForAddress',
            params: [wallet, { limit: 20 }]
        });

        const signatures = response.data.result || [];

        // Parse transactions to find trades
        const trades = await Promise.all(
            signatures.slice(0, 10).map(sig => parseTransaction(sig.signature, wallet))
        );

        const validTrades = trades.filter(t => t !== null);

        // Cache for 30 seconds
        tradeCache.set(wallet, validTrades);
        setTimeout(() => tradeCache.delete(wallet), 30000);

        return validTrades;
    } catch (error) {
        console.error('Error fetching wallet trades:', error.message);
        return [];
    }
}

// Real trade detection: reads actual pre/post token + SOL balances from the
// transaction and computes what the wallet actually gained/lost. No mock data.
async function parseTransaction(signature, wallet) {
    try {
        const response = await axios.post(SOLANA_RPC_URL, {
            jsonrpc: '2.0',
            id: 1,
            method: 'getTransaction',
            params: [signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]
        });

        const tx = response.data.result;
        if (!tx || !tx.meta) return null;

        const { meta, blockTime } = tx;
        const accountKeys = tx.transaction.message.accountKeys.map(
            k => (typeof k === 'string' ? k : k.pubkey)
        );
        const walletIndex = accountKeys.indexOf(wallet);
        if (walletIndex === -1) return null;

        // ---- SOL balance change (lamports -> SOL) for this wallet ----
        const preSol = (meta.preBalances?.[walletIndex] ?? 0) / 1e9;
        const postSol = (meta.postBalances?.[walletIndex] ?? 0) / 1e9;
        const solDelta = postSol - preSol;

        // ---- SPL token balance changes for this wallet ----
        const preTok = (meta.preTokenBalances || []).filter(b => b.owner === wallet);
        const postTok = (meta.postTokenBalances || []).filter(b => b.owner === wallet);

        let tokenDeltas = [];
        const mints = new Set([...preTok.map(b => b.mint), ...postTok.map(b => b.mint)]);
        mints.forEach(mint => {
            const pre = preTok.find(b => b.mint === mint);
            const post = postTok.find(b => b.mint === mint);
            const preAmt = pre ? parseFloat(pre.uiTokenAmount.uiAmountString || 0) : 0;
            const postAmt = post ? parseFloat(post.uiTokenAmount.uiAmountString || 0) : 0;
            const delta = postAmt - preAmt;
            if (Math.abs(delta) > 0) {
                tokenDeltas.push({ mint, delta, decimals: (post || pre).uiTokenAmount.decimals });
            }
        });

        // No real balance movement for this wallet = not a trade we care about
        if (tokenDeltas.length === 0 && Math.abs(solDelta) < 0.0001) return null;

        // Determine buy vs sell: token increased + SOL decreased = BUY. Reverse = SELL.
        const primaryToken = tokenDeltas.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta))[0];
        const type = primaryToken
            ? (primaryToken.delta > 0 ? 'buy' : 'sell')
            : (solDelta > 0 ? 'sell' : 'buy');

        const solAmount = Math.abs(solDelta);
        const tokenAmount = primaryToken ? Math.abs(primaryToken.delta) : null;

        return {
            signature,
            type,
            amount: solAmount.toFixed(4),
            tokenMint: primaryToken ? primaryToken.mint : null,
            tokenAmount: tokenAmount ? tokenAmount.toFixed(4) : null,
            tokenSymbol: primaryToken ? primaryToken.mint.slice(0, 4) + '...' + primaryToken.mint.slice(-4) : 'SOL',
            status: meta.err ? 'failed' : 'executed',
            timestamp: new Date(blockTime * 1000).toISOString(),
            solscanUrl: `https://solscan.io/tx/${signature}`
        };
    } catch (error) {
        console.error('Error parsing transaction:', error.message);
        return null;
    }
}

async function getWalletBalance(wallet) {
    try {
        const response = await axios.post(SOLANA_RPC_URL, {
            jsonrpc: '2.0',
            id: 1,
            method: 'getBalance',
            params: [wallet]
        });

        return response.data.result?.value || 0;
    } catch (error) {
        console.error('Error fetching balance:', error.message);
        return 0;
    }
}

async function getTokenInfo(mint) {
    try {
        const response = await axios.get(
            `https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY || 'test'}`,
            {
                method: 'POST',
                data: {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'getAsset',
                    params: { id: mint }
                }
            }
        );

        return response.data.result || {};
    } catch (error) {
        console.error('Error fetching token info:', error.message);
        return { mint, error: 'Unable to fetch token data' };
    }
}

// IMPORTANT: This does NOT execute a real on-chain trade. Real execution requires
// the user's wallet to sign the transaction (Phantom/Solflare connect + sign),
// which is not wired into this backend. This function returns a REAL Jupiter
// quote (real market price, real route) so you can see what a trade WOULD do,
// but it never touches the chain and never spends real funds.
const SOL_MINT = 'So11111111111111111111111111111111111111112';

async function simulateTradeExecution(tradeParams) {
    const { tokenMint, amount, type, slippage, targetWallet, timestamp } = tradeParams;

    try {
        const lamports = Math.floor(amount * 1e9);
        const inputMint = type === 'buy' ? SOL_MINT : tokenMint;
        const outputMint = type === 'buy' ? tokenMint : SOL_MINT;
        const slippageBps = Math.floor((slippage || 2) * 100);

        const quoteRes = await axios.get('https://quote-api.jup.ag/v6/quote', {
            params: {
                inputMint,
                outputMint,
                amount: lamports,
                slippageBps
            }
        });

        const quote = quoteRes.data;
        const feeAmount = (amount * TRADING_FEE_PERCENT) / 100;

        return {
            status: 'quote_only',
            note: 'This is a real market quote, NOT an executed trade. On-chain execution requires wallet signing, which is not yet connected.',
            tokenMint,
            type,
            requestedAmount: amount,
            fee: feeAmount.toFixed(4),
            slippage,
            targetWallet,
            timestamp,
            realQuote: {
                inAmount: quote.inAmount,
                outAmount: quote.outAmount,
                priceImpactPct: quote.priceImpactPct,
                routePlan: (quote.routePlan || []).map(r => r.swapInfo?.label).filter(Boolean)
            },
            error: null
        };
    } catch (error) {
        return {
            status: 'quote_failed',
            note: 'Could not fetch a real quote from Jupiter. No trade was simulated or executed.',
            tokenMint,
            type,
            requestedAmount: amount,
            targetWallet,
            timestamp,
            error: error.message
        };
    }
}

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: err.message 
    });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 BIG MOUF SLAPBOT Backend running on port ${PORT}`);
    console.log(`📡 Solana RPC: ${SOLANA_RPC_URL}`);
    console.log(`💎 SLAPGOLD Mint: ${SLAPGOLD_MINT}`);
    console.log(`👛 My Wallet: ${MY_WALLET}`);
    console.log(`⚙️  Min Hold Amount: ${MIN_HOLD_AMOUNT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully...');
    process.exit(0);
});
