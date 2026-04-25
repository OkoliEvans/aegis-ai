# Aegis Guard

Aegis Guard is an Initia wallet protection Agent that screens outbound transactions before broadcast, evaluates risk across multiple detectors, records incidents onchain through a Guardian policy contract, and exposes the full protection history in a  dashboard.

## Initia Hackathon Submission

- **Project Name**: Aegis Guard

### Project Overview

Aegis Guard is an Initia-native wallet protection layer for users, operators, and treasury teams that want suspicious transactions screened before funds leave the wallet. It detects malicious contract interactions, stale approvals, address poisoning, dust attacks, slippage, and liquidity risk in real time, then allows, warns, confirms, or blocks the action while preserving a full onchain and offchain audit trail.

### Implementation Detail

- **The Custom Implementation**: We built a Guardian RPC proxy, a multi-signal risk engine, live contract analysis, simulation-driven threat walkthroughs, incident persistence, professional alerting, and an onchain Guardian policy contract that tracks trust, incidents, and quarantines. This is original product logic beyond the base rollup scaffold and turns the appchain into a pre-broadcast security decision layer.
- **The Native Feature**: We use `interwoven-bridge` through `InterwovenKit`, so a connected user can open the Initia bridge directly from onboarding and bring assets into the protected Aegis Guard flow without leaving the app.

### How to Run Locally

1. Copy `.env.example` to `.env` and fill in your Postgres, RPC, SMTP, and optional analysis settings.
2. Run `diesel migration run` from the repository root.
3. Start the backend with `cargo run -p guardian-app`.
4. Start the frontend with `cd frontend && pnpm install && pnpm dev`, then connect a wallet and use `Get Started` to activate protection or open the Initia bridge.

## Core Flow

- Wallet traffic is routed through the Guardian RPC proxy.
- The backend evaluates approvals, poisoning, suspicious contracts, reentrancy patterns, ICA actions, and behavioral anomalies.
- Guardian allows, warns, requires confirmation, or blocks.
- Findings are stored in Postgres, streamed to the dashboard, and synced to the onchain `guardian-policy` contract as incidents and quarantine entries.

## Workspace Layout

- `crates/app`: backend entrypoint and migration command
- `crates/api`: dashboard APIs, SSE feed, and guarded RPC proxy
- `crates/agent`: decision engine and analyzer orchestration
- `crates/analyzer`: threat detectors
- `crates/core`: shared config, Diesel models, policy client, and repository layer
- `crates/notifier`: persistence, alert fanout, and onchain policy sync
- `contracts/guardian-policy`: onchain policy, incident, and quarantine registry
- `contracts/guardian-risk-lab`: safe demo contract for blocked contract-call walkthroughs
- `frontend`: protected dashboard built with `@initia/interwovenkit-react`
- `simulations`: reusable attack scenarios for drills and demo runs

## Quick Start

1. Copy `.env.example` into `.env` and fill in the values you want to run locally.
2. Run Diesel migrations:

```bash
diesel migration run
```

3. Start the backend:

```bash
cargo run -p guardian-app
```

4. Start the frontend:

```bash
cd frontend
pnpm install
pnpm dev
```

## Environment Notes

Backend/runtime values:

- `DATABASE_URL`: Postgres connection used by Diesel
- `ANTHROPIC_API_KEY`: optional today for analyzer paths; later this can also power richer narrative email summaries beyond the current deterministic templates
- `INITIA_CHAIN_ID`, `INITIA_LCD`, `INITIA_RPC`, `INITIA_WS`: Initia or local rollup endpoints
- `INITIA_JSON_RPC`: optional MiniEVM JSON-RPC endpoint used for `0x...` contract inspection via `eth_getCode`
- `SEPOLIA_JSON_RPC`: optional Sepolia JSON-RPC endpoint used when the simulation UI is switched to Sepolia analysis
- `GUARDIAN_POLICY_CONTRACT_ADDRESS`: deployed `guardian-policy` contract address
- `GUARDIAN_POLICY_REPORTER_KEY`: local key name allowed to write incidents/quarantines onchain
- `GUARDIAN_POLICY_KEYRING_BACKEND`: usually `test` for local development
- `GUARDIAN_POLICY_CLI`: optional explicit path to `minitiad`

Frontend values:

- `VITE_API_BASE_URL`: dashboard/backend origin
- `VITE_GUARDIAN_RPC`: RPC endpoint wallets should use for screened broadcasts
- `VITE_BRIDGE_SOURCE_CHAIN_ID`: source chain ID used when opening the Interwoven bridge
- `VITE_BRIDGE_SOURCE_DENOM`: source denom used when opening the Interwoven bridge
- `VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS`: surfaced in the UI
- `VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS`: optional demo contract address for the guarded-call walkthrough

## Vercel Deployment

- The Vercel setup in `vercel.json` deploys the Vite frontend from `frontend/` and serves `frontend/dist`.
- The Rust Guardian backend does not run on Vercel in this setup. Host it separately, then point the frontend at that public backend.
- Set these Vercel environment variables before deploying:
  - `VITE_API_BASE_URL`
  - `VITE_GUARDIAN_RPC`
  - `VITE_CHAIN_ID`
  - `VITE_CHAIN_NAME`
  - `VITE_CHAIN_PRETTY_NAME`
  - `VITE_CHAIN_RPC`
  - `VITE_CHAIN_REST`
  - `VITE_CHAIN_INDEXER`
  - `VITE_CHAIN_VM`
  - `VITE_CHAIN_DENOM`
  - `VITE_CHAIN_ASSET_NAME`
  - `VITE_CHAIN_ASSET_SYMBOL`
  - `VITE_CHAIN_ASSET_DECIMALS`
  - `VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS`
  - `VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS`
  - `VITE_DEMO_LIQUIDITY_LAB_CONTRACT_ADDRESS`
  - `VITE_DEMO_APPROVAL_LAB_CONTRACT_ADDRESS`
  - `VITE_DEMO_APPROVAL_SPENDER_ADDRESS`

Restart the backend after changing backend env values like `INITIA_JSON_RPC`, and restart the Vite dev server after changing `VITE_*` values.

## Alert Emails

- If a wallet owner adds an email address in the dashboard, Guardian now sends professional alert emails for simulations, guarded transaction blocks or warnings, scheduled approval reviews, and live security updates such as dust detections.
- The current email content is template-based and derived directly from the findings so it is stable for demos and MVP use.
- Later, once the LLM path is enabled with `ANTHROPIC_API_KEY`, these emails can be upgraded with richer narrative summaries and remediation guidance.

## Useful Commands

```bash
cargo test --workspace
cargo check --workspace
cd frontend && pnpm build
```

## Demo Paths

- Use `Run Simulation` in the dashboard to publish a full safety drill.
- Use `Attempt Demo Contract Call` to show Guardian blocking a suspicious contract interaction before broadcast.
- Review `Activity Feed`, `Protection history`, and `Onchain Policy` to show local persistence plus onchain incident/quarantine sync.

---

Built by Mist Labs

---

License: MIT