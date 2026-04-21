# Guardian

Guardian is an AI-assisted wallet protection appchain project built on Initia protocol. It combines a Rust backend that intercepts and evaluates transactions with a Wasm-appchain-facing frontend built with `@initia/interwovenkit-react`.

## What It Does

- Screens transactions before forwarding them upstream
- Flags address poisoning, stale approvals, anomalies, and suspicious contracts
- Streams risk events to a dashboard in real time
- Lets users register watched addresses and then get Telegram messages when a transaction is flagged as high risk explaining the reason for blocking the transaction and the kind of attack identified.
- Uses an Initia-native feature through Interwoven Bridge support in the frontend

## Architecture

- `crates/app`: backend entrypoint and migration command
- `crates/api`: RPC proxy, SSE feed, and dashboard APIs
- `crates/agent`: orchestration and decision engine
- `crates/analyzer`: threat detection modules
- `crates/simulator`: transaction simulation integration
- `crates/core`: shared types, config, and repository layer
- `contracts/guardian-policy`: CosmWasm policy, quarantine, and incident registry contract
- `frontend`: InterwovenKit frontend for the Guardian dashboard

## Backend Commands

```bash
cargo run -p guardian-app -- migrate
cargo run -p guardian-app
```

## Contract Commands

```bash
cd contracts/guardian-policy
cargo test
```

## Frontend Commands

```bash
cd frontend
pnpm install
pnpm dev
```

## Hackathon Requirements

- Track: Agents
- Deployment target: Initia appchain / rollup using the Wasm VM
- Wallet UX: `@initia/interwovenkit-react`
- Initia-native feature: Interwoven Bridge

## Initia-Native Feature

Guardian implements Initia's Interwoven Bridge flow through `@initia/interwovenkit-react`.

- The frontend mounts `InterwovenKitProvider` with the local custom appchain in [frontend/src/main.tsx](/Users/MAC/Rust/aegis_guard/frontend/src/main.tsx).
- The dashboard uses `useInterwovenKit()` and calls `openBridge()` in [frontend/src/App.tsx](/Users/MAC/Rust/aegis_guard/frontend/src/App.tsx).
- The current bridge invocation opens the Initia-native bridge with:
  - `srcChainId = initiation-2`
  - `srcDenom = uinit`

This satisfies the hackathon requirement to implement at least one Initia-native feature.

## Deployment Evidence

The final submission must include the deployed rollup evidence below:

- Rollup chain ID: `aegis-guard`
- Deployment link: `https://scan.testnet.initia.xyz/custom-network/add/link?config=eyJ2bSI6Indhc20iLCJjaGFpbklkIjoiYWVnaXMtZ3VhcmQiLCJtaW5HYXNQcmljZSI6MCwiZGVub20iOiJ1bWluIiwibGNkIjoiaHR0cDovL2xvY2FsaG9zdDoxMzE3IiwicnBjIjoiaHR0cDovL2xvY2FsaG9zdDoyNjY1NyJ9`
- L1 funding transaction: `1905A67ACE190BA33C8EE392EB7BCF025641F5A640115754DEA2320C207E4084`
- Demo video: `TBD_ADD_VIDEO_LINK`

## Notes

- The repo now includes safe local rollup metadata at `.initia/local-rollup.json`.
- The frontend and backend defaults in `.env.example` target the local `aegis-guard` Wasm rollup.
- The appchain-native contract layer now lives in `contracts/guardian-policy`; it stores user policy thresholds, trusted contracts, quarantined addresses, authorized reporters, and incident history.
- `VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS` remains a placeholder until the Guardian policy contract is stored and instantiated on `aegis-guard`.
