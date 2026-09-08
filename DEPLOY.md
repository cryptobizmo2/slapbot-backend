# Deploying the BIG MOUF SLAPBOT Backend

This is a real, always-on server — it checks your SLAP GOLD wallet balance,
proxies price data, and never touches your private keys or funds.

## Step 1 — Get your wallet address

Open Phantom, tap your account name at the top, copy your wallet address.
It looks like: `7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`

## Step 2 — Deploy to Railway (free to start)

1. Go to **railway.app** and sign up (GitHub login is fastest)
1. Tap **New Project → Deploy from GitHub repo**
1. Create a NEW repo (separate from SLAPBOT) called `slapbot-backend`
1. Upload these 3 files to it: `server.js`, `package.json`, this file
1. Back in Railway, select that repo, click Deploy

## Step 3 — Set your environment variables

In Railway, go to your project → **Variables** tab, add these:

|Variable         |Value                                              |
|-----------------|---------------------------------------------------|
|`SOLANA_RPC_URL` |`https://api.mainnet-beta.solana.com`              |
|`SLAPGOLD_MINT`  |`4R7Hbdhh3YeVqZaESRA3qPJ8Z3xh3Qedsw88RDjxL1Q9`     |
|`MY_WALLET`      |*your Phantom wallet address from Step 1*          |
|`MIN_HOLD_AMOUNT`|`1` (or however many SLAP GOLD you want to require)|
|`ALLOWED_ORIGIN` |`https://cryptobizmo2.github.io`                   |

Railway will redeploy automatically after you save these.

## Step 4 — Get your live backend URL

Railway gives you a URL like:
`https://slapbot-backend-production.up.railway.app`

Test it works by visiting:
`https://slapbot-backend-production.up.railway.app/api/health`

You should see JSON like:

```json
{"status":"ok","mint":"4R7Hbdhh...","minHold":1,"time":"..."}
```

## Step 5 — Tell me the URL

Once you have that live URL, send it to me and I’ll wire the frontend
(index.html) to call it — that’s what actually locks the bot to your
wallet only.

## What this backend does NOT do

- Does not hold your private key
- Does not hold your funds
- Does not execute trades on its own — your wallet signs every trade
- Cannot be used by someone else unless they hold your SLAP GOLD token
  (and even then, only YOUR wallet address bypasses the token check entirely)

## Cost

Railway free tier: $5 of usage credit per month, resets monthly.
This server is lightweight — should comfortably fit in the free tier
unless you get serious traffic.