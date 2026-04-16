# Guardian — Onchain Account Protection Agent

> Real-time wallet guardian for the Initia chain. Intercepts transactions before broadcast, detects threats, and acts — not just informs.

---

## Overview

Guardian is an account protection agent that sits between the user's wallet and the Initia network. By routing transactions through a local RPC proxy, Guardian silently screens every transaction attempt in real-time, runs parallel risk analysis, and either allows, warns, or blocks — with one-click remediation for detected threats.

It is not a scanner. It acts.

---

## The Problem

Onchain users face threats that existing tools don't catch:

- **Address poisoning** — attackers flood wallets with dust from visually identical addresses. Users copy the wrong address from history and send funds to an attacker.
- **Stale approvals** — unlimited token approvals granted months ago to contracts that may now be malicious or abandoned remain active indefinitely.
- **Malicious contracts** — unverified contracts deployed hours ago disguised as legitimate protocols.
- **Blind transactions** — users confirm transactions with no visibility into what will actually happen to their balances.
- **ICA abuse** — Initia's Interchain Account system allows cross-chain account control; malicious dApps exploit this attack surface.
- **Behavioral anomalies** — sudden large transfers to new addresses outside normal patterns.

---

## Solution

Guardian provides a **3-layer protection pipeline**:

```
Intercept Layer          Analysis Layer           Action Layer
─────────────────   →    ──────────────────   →   ──────────────────
RPC proxy                Simulate tx               Allow
WebSocket monitor        Score contract            Warn + explain
Event streaming          Detect poisoning          Block + notify
                         Scan approvals            Auto-revoke (1-click)
                         Anomaly check             Telegram alert
```

---

## Core Features

### 1. RPC Proxy Interceptor
User points their wallet RPC to Guardian's proxy endpoint. Every `broadcast_tx` and `simulate` call is intercepted, analyzed, and either forwarded or blocked before it reaches the Initia node. Zero wallet changes beyond a single RPC URL update.

### 2. Transaction Pre-Execution Simulator
Before any tx is broadcast, Guardian calls Initia's `SimulateTx` endpoint and surfaces the exact balance delta — token movements, INIT changes, estimated gas — so the user sees "you will lose 500 INIT" before signing.

### 3. Address Poisoning Detector
Incoming transactions are checked for visual similarity to known addresses. Levenshtein distance + prefix/suffix matching catches the classic poisoning pattern: same first 6 and last 4 characters with a different middle. Poisoned addresses are tagged in the local registry and warned on any future paste.

### 4. Approval Scanner + Auto-Revoke
Continuous scan of all outstanding token allowances across the user's accounts. Scores each approval on: amount (unlimited = high risk), spender identity (known protocol vs. unknown), and age (stale = risky). Surfaced on the dashboard with a single "Revoke" button that submits a pre-built revocation tx.

### 5. Contract Risk Scorer
Any contract being called is evaluated through a layered analysis pipeline that cannot be bypassed by renaming functions:

- **Simulation delta (ground truth)** — `SimulateTx` reveals what the contract actually does, not what it claims. A function named `claimRewards()` that drains 500 INIT will show that in the balance delta regardless of its label.
- **Bytecode/opcode analysis** — dangerous opcode patterns are matched directly: arbitrary `CALL`/`DELEGATECALL` to dynamic addresses, loops with token transfers to caller-controlled destinations, `SELFDESTRUCT`, unrestricted writes to critical storage slots. These patterns are present regardless of function names.
- **Token flow graph** — after simulation, the analyzer checks whether value leaves the user's address to an address that is not the stated protocol. Unexpected fund routing is flagged independent of ABI labels.
- **Proxy and upgrade detection** — contracts with `upgradeTo` or `implementation()` slots can swap logic after audit. These are flagged unconditionally since the code the user sees today may not be the code that runs tomorrow.
- **LLM decompilation analysis** — for ambiguous cases, contract bytecode is decompiled to pseudocode and sent to Claude with a prompt asking it to identify any paths where user funds could be moved to an attacker-controlled address. This catches obfuscated logic that pattern matching misses.
- **Name-based heuristics** — matching known dangerous function names (`drain`, `withdraw_all`, `sweep`, `migrate`) is retained as a minor signal boost only. It is not a primary detector.

Score 0–100. Contracts above 70 trigger a warning; above 85 trigger a block.

### 6. Behavioral Anomaly Detector
Guardian builds a baseline of normal transaction behavior per address: typical value range, known recipients, typical hours. Transactions that deviate significantly trigger an alert — particularly large transfers to first-time recipients.

### 7. ICA Abuse Monitor
Initia-specific. Interchain Account registrations from unknown controller addresses are flagged immediately. Unauthorized cross-chain account control is one of the most dangerous and least-understood attack surfaces in the Cosmos/Initia ecosystem.

### 8. Real-Time Alert Delivery
- **Dashboard** — live risk feed via SSE, full finding details, action buttons
- **Telegram bot** — out-of-browser alerts; user registers with `/register <address>`
- **Audit log** — every risk event stored with full payload for historical review

---

## Integration

Guardian requires a single setup step from the user:

1. Visit the Guardian dashboard
2. Connect wallet (read-only — for address registration)
3. Change wallet RPC URL to `https://guardian.yourdomain.com/rpc`

From that point, every transaction is silently screened. No extension install. No wallet SDK. No dApp cooperation required.

---

## Architecture

```
guardian/
├── crates/
│   ├── core/        # shared types, DB models, risk structs
│   ├── monitor/     # WebSocket event streaming from Initia node
│   ├── analyzer/    # all feature modules (poison, approval, anomaly, etc.)
│   ├── simulator/   # SimulateTx integration + balance delta extraction
│   ├── agent/       # orchestrator, parallel execution, decision engine
│   ├── api/         # REST + SSE endpoints for dashboard and proxy
│   └── notifier/    # SSE push, Telegram bot, DB audit log
├── frontend/        # Next.js dashboard
├── migrations/      # Diesel DB schema
└── Cargo.toml
```

**Stack:**
- Runtime: Rust (tokio, axum, diesel-async)
- Database: PostgreSQL
- Chain interface: Initia LCD REST + Tendermint WebSocket
- LLM (ambiguous cases): Claude API (claude-sonnet-4-20250514)
- Frontend: Next.js 14
- Alerts: teloxide (Telegram), SSE

---

## Risk Decision Engine

All analysis modules run in parallel. Scores are summed and mapped to a decision:

| Score | Decision |
|-------|----------|
| 0–29 | Allow — tx forwarded silently |
| 30–59 | Warn — user sees findings, can proceed |
| 60–79 | Require confirmation — explicit user override required |
| 80+ | Block — tx dropped, alert fired, auto-revoke offered if applicable |

---

## Threat Coverage Matrix

| Threat | Detection Method | Can Block | Can Auto-Remediate |
|--------|-----------------|-----------|-------------------|
| Address poisoning | Levenshtein + prefix/suffix match | ✅ | ✅ Tag + warn |
| Stale approvals | Allowance scan + age scoring | ⚠️ Warn | ✅ One-click revoke |
| Malicious contract | Simulation delta + bytecode opcodes + token flow graph + proxy detection + LLM decompile | ✅ | ❌ |
| Blind tx / balance drain | SimulateTx delta | ✅ | ❌ |
| Behavioral anomaly | Baseline deviation | ✅ | ❌ |
| ICA unauthorized controller | Controller whitelist check | ✅ | ❌ |

---

## Positioning

Guardian is infrastructure, not a UI widget. The RPC proxy model means it works with any wallet on Initia without SDK integration or browser extension distribution. This is the same model used by Flashbots Protect and MEV Blocker on EVM — proven in production, immediately legible to technical evaluators.

**"Change one setting. Every transaction you make is now screened."**
