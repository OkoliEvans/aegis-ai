# Guardian — Implementation Guide

> Build sequence, code patterns, and integration details for the Initia hackathon.

---

## 0. Prerequisites

```toml
# Cargo.toml workspace deps
tokio = { version = "1", features = ["full"] }
axum = "0.7"
diesel = { version = "2", features = ["postgres", "uuid", "chrono"] }
diesel-async = { version = "0.4", features = ["postgres", "bb8"] }
reqwest = { version = "0.11", features = ["json"] }
tokio-tungstenite = "0.21"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
teloxide = { version = "0.12", features = ["macros"] }
tracing = "0.1"
tracing-subscriber = "0.3"
base64 = "0.21"
```

```
.env
DATABASE_URL=postgres://user:pass@localhost:5432/guardian
INITIA_LCD=https://lcd.testnet.initia.xyz
INITIA_WS=wss://rpc.testnet.initia.xyz/websocket
ANTHROPIC_API_KEY=sk-ant-...
TELEGRAM_BOT_TOKEN=...
```

---

## 1. Workspace Structure

```
guardian/
├── crates/
│   ├── core/
│   │   ├── src/
│   │   │   ├── models.rs       # DB structs
│   │   │   ├── types.rs        # ChainEvent, RiskEvent, GuardianDecision
│   │   │   └── schema.rs       # Diesel schema (generated)
│   ├── monitor/
│   │   └── src/streamer.rs     # WebSocket event streaming
│   ├── analyzer/
│   │   └── src/
│   │       ├── poison.rs
│   │       ├── approvals.rs
│   │       ├── contract.rs
│   │       ├── anomaly.rs
│   │       ├── ica.rs
│   │       └── llm.rs
│   ├── simulator/
│   │   └── src/lib.rs          # SimulateTx wrapper
│   ├── agent/
│   │   └── src/orchestrator.rs # decision engine
│   ├── api/
│   │   └── src/
│   │       ├── proxy.rs        # RPC proxy handler
│   │       ├── dashboard.rs    # REST + SSE endpoints
│   │       └── telegram.rs     # bot handlers
│   └── notifier/
│       └── src/lib.rs
├── migrations/
├── frontend/                   # Next.js (optional)
└── Cargo.toml
```

---

## 2. Database Schema

```sql
-- migrations/001_initial.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE watched_addresses (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address         TEXT NOT NULL UNIQUE,
    label           TEXT,
    is_poisoned     BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE approval_records (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner               TEXT NOT NULL,
    spender             TEXT NOT NULL,
    token_denom         TEXT NOT NULL,
    amount              TEXT NOT NULL,        -- u128 as string
    granted_at_height   BIGINT NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE risk_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address     TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,               -- low | medium | high | critical
    tx_hash     TEXT,
    payload     JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tx_patterns (
    address             TEXT PRIMARY KEY,
    avg_value_uinit     BIGINT NOT NULL DEFAULT 0,
    typical_recipients  JSONB NOT NULL DEFAULT '[]',
    typical_hour_utc    INTEGER NOT NULL DEFAULT 12,
    sample_count        INTEGER NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE registered_users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address         TEXT NOT NULL UNIQUE,
    telegram_chat_id BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_events_address ON risk_events(address);
CREATE INDEX idx_risk_events_created ON risk_events(created_at DESC);
CREATE INDEX idx_approvals_owner ON approval_records(owner);
```

---

## 3. Core Types

```rust
// crates/core/src/types.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingTx {
    pub sender: String,
    pub recipient: String,
    pub amount: String,
    pub denom: String,
    pub contract_address: Option<String>,
    pub function_name: Option<String>,
    pub raw_bytes: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub module: String,       // "poison" | "approval" | "anomaly" | "contract" | "ica"
    pub severity: Severity,
    pub weight: i32,          // contributes to total_risk score
    pub description: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardianDecision {
    Allow,
    Warn     { findings: Vec<RiskFinding> },
    Confirm  { findings: Vec<RiskFinding> },  // require explicit override
    Block    { findings: Vec<RiskFinding>, auto_revoke: bool },
}
```

---

## 4. Monitor — WebSocket Event Streaming

```rust
// crates/monitor/src/streamer.rs

use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use guardian_core::types::ChainEvent;

pub async fn stream_events(ws_url: &str, tx: mpsc::Sender<ChainEvent>) {
    let (mut ws, _) = connect_async(ws_url).await
        .expect("WebSocket connection failed");

    // Subscribe to all transactions
    let sub = json!({
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": 1,
        "params": { "query": "tm.event='Tx'" }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(sub.to_string()))
        .await.unwrap();

    while let Some(msg) = ws.next().await {
        if let Ok(tokio_tungstenite::tungstenite::Message::Text(text)) = msg {
            if let Ok(event) = parse_chain_event(&text) {
                let _ = tx.send(event).await;
            }
        }
    }
}

fn parse_chain_event(raw: &str) -> anyhow::Result<ChainEvent> {
    let v: serde_json::Value = serde_json::from_str(raw)?;
    let events = &v["result"]["events"];

    Ok(ChainEvent {
        tx_hash: events["tx.hash"][0].as_str().unwrap_or("").to_string(),
        sender:  events["message.sender"][0].as_str().unwrap_or("").to_string(),
        height:  events["tx.height"][0].as_str()
                    .and_then(|h| h.parse().ok())
                    .unwrap_or(0),
        raw: raw.to_string(),
    })
}
```

---

## 5. Analyzer Modules

### 5.1 Address Poisoning

```rust
// crates/analyzer/src/poison.rs

use guardian_core::types::{RiskFinding, Severity};

pub fn check_poison(
    incoming: &str,
    known_addresses: &[String],
) -> Option<RiskFinding> {
    for known in known_addresses {
        if incoming == known { continue; }

        let prefix_match = incoming.len() >= 10
            && known.len() >= 10
            && incoming[..10] == known[..10];
        let suffix_match = incoming.len() >= 6
            && known.len() >= 6
            && incoming[incoming.len()-6..] == known[known.len()-6..];
        let distance = levenshtein(incoming, known);

        if prefix_match && suffix_match && distance < 10 {
            return Some(RiskFinding {
                module: "poison".into(),
                severity: Severity::Critical,
                weight: 85,
                description: format!(
                    "Address {} visually mimics your known address {}",
                    shorten(incoming), shorten(known)
                ),
                payload: serde_json::json!({
                    "suspicious": incoming,
                    "mimics": known,
                    "levenshtein_distance": distance,
                }),
            });
        }
    }
    None
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len(); let n = b.len();
    let mut dp = vec![vec![0usize; n+1]; m+1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i-1] == b[j-1] { dp[i-1][j-1] }
                       else { 1 + dp[i-1][j].min(dp[i][j-1]).min(dp[i-1][j-1]) };
        }
    }
    dp[m][n]
}

fn shorten(addr: &str) -> String {
    if addr.len() < 12 { return addr.to_string(); }
    format!("{}...{}", &addr[..8], &addr[addr.len()-6..])
}
```

### 5.2 Approval Scanner

```rust
// crates/analyzer/src/approvals.rs

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct MoveResource {
    #[serde(rename = "type")]
    type_: String,
    data: serde_json::Value,
}

pub async fn scan_approvals(
    lcd: &str,
    owner: &str,
) -> anyhow::Result<Vec<ApprovalRecord>> {
    let url = format!("{}/initia/move/v1/accounts/{}/resources", lcd, owner);
    let resources: Vec<MoveResource> = Client::new()
        .get(&url)
        .send().await?
        .json().await?;

    let approvals = resources.iter()
        .filter(|r| r.type_.contains("Allowance") || r.type_.contains("allowance"))
        .filter_map(|r| parse_allowance(r, owner))
        .collect();

    Ok(approvals)
}

pub fn score_approval(approval: &ApprovalRecord, current_height: i64) -> i32 {
    let mut score = 0;

    // Unlimited amount = maximum risk
    if approval.amount == u128::MAX.to_string() { score += 40; }

    // Unknown spender
    if !is_known_protocol(&approval.spender) { score += 30; }

    // Stale approval (> 30 days of blocks, ~14400 blocks/day on Initia)
    let age_blocks = current_height - approval.granted_at_height;
    if age_blocks > 432_000 { score += 20; }  // ~30 days

    score  // 0–90; flag at 50+, auto-revoke suggestion at 80+
}

fn is_known_protocol(addr: &str) -> bool {
    // Maintain a static list of known safe spenders: DEXes, lending protocols, etc.
    const KNOWN: &[&str] = &[
        "init1<dex_address>",
        "init1<lending_address>",
    ];
    KNOWN.contains(&addr)
}
```

### 5.3 Transaction Simulator

```rust
// crates/simulator/src/lib.rs

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct SimulateRequest {
    tx_bytes: String,  // base64
}

#[derive(Debug, Deserialize)]
struct SimulateResponse {
    gas_info: GasInfo,
    result:   TxResult,
}

#[derive(Debug, Deserialize)]
struct GasInfo {
    gas_used:   String,
    gas_wanted: String,
}

#[derive(Debug, Deserialize)]
struct TxResult {
    log:    String,
    events: Vec<serde_json::Value>,
}

#[derive(Debug)]
pub struct SimulationResult {
    pub will_fail:       bool,
    pub fail_reason:     Option<String>,
    pub gas_estimate:    u64,
    pub balance_deltas:  Vec<BalanceDelta>,
}

#[derive(Debug)]
pub struct BalanceDelta {
    pub address: String,
    pub denom:   String,
    pub delta:   i128,  // negative = loss
}

pub async fn simulate(lcd: &str, tx_bytes: &[u8]) -> anyhow::Result<SimulationResult> {
    let resp: SimulateResponse = Client::new()
        .post(format!("{}/cosmos/tx/v1beta1/simulate", lcd))
        .json(&SimulateRequest { tx_bytes: base64::encode(tx_bytes) })
        .send().await?
        .json().await?;

    let will_fail = resp.result.log.contains("failed")
        || resp.result.log.contains("error");

    let fail_reason = if will_fail {
        extract_revert_reason(&resp.result.log)
    } else { None };

    let balance_deltas = extract_deltas(&resp.result.events);

    Ok(SimulationResult {
        will_fail,
        fail_reason,
        gas_estimate: resp.gas_info.gas_used.parse().unwrap_or(0),
        balance_deltas,
    })
}

fn extract_deltas(events: &[serde_json::Value]) -> Vec<BalanceDelta> {
    let mut deltas = vec![];
    for event in events {
        if event["type"] == "coin_received" || event["type"] == "coin_spent" {
            // parse attributes: receiver/sender, amount, denom
            // build BalanceDelta with sign based on event type
        }
    }
    deltas
}

fn extract_revert_reason(log: &str) -> Option<String> {
    // Pull the human-readable reason from the Cosmos log string
    log.split("error:")
       .nth(1)
       .map(|s| s.trim().to_string())
}
```

### 5.4 Contract Risk Scorer

Name-based detection (matching `drain`, `sweep`, etc.) is trivially bypassed by renaming functions. The scorer uses a layered pipeline where simulation and bytecode analysis are the primary signals — name matching is a low-weight bonus only.

**Detection layers, in priority order:**
1. **Simulation delta** — ground truth; `SimulateTx` reveals what the contract actually does regardless of function names (handled in the orchestrator, feeds into scoring here)
2. **Opcode/bytecode patterns** — dangerous patterns in the compiled bytecode: dynamic `CALL` targets, token loops to caller-controlled addresses, `SELFDESTRUCT`, unrestricted critical storage writes
3. **Token flow graph** — post-simulation check: does value leave the user's address to an address that is not the stated protocol?
4. **Proxy/upgrade detection** — contracts with upgrade slots are flagged unconditionally; logic can be swapped after any audit
5. **Name-based heuristics** — retained as a minor signal only; not a primary detector

```rust
// crates/analyzer/src/contract.rs

pub struct ContractRisk {
    pub score:             i32,
    pub age_blocks:        i64,
    pub is_verified:       bool,
    pub is_upgradeable:    bool,
    pub suspicious_opcodes: Vec<String>,
    pub unexpected_flow:   bool,           // token flow goes to non-protocol address
    pub drain_fn_names:    Vec<String>,    // low-weight; name matching only
}

/// Dangerous opcode sequences — present regardless of function naming
const DANGEROUS_OPCODES: &[&str] = &[
    "DELEGATECALL",    // arbitrary logic execution
    "SELFDESTRUCT",    // contract destruction + fund drain
    "CALLVALUE_LOOP",  // transfer in a loop (drain pattern)
];

/// Known upgrade slot selectors (EVM-style; adapt for Move module upgrades)
const UPGRADE_SIGNATURES: &[&str] = &[
    "upgradeTo", "upgradeToAndCall", "implementation",
];

/// Name-based hints — low weight only, not primary signal
const DRAIN_NAME_HINTS: &[&str] = &[
    "withdraw_all", "drain", "sweep", "migrate",
    "emergency_exit", "rug", "set_owner",
];

pub async fn score_contract(
    lcd: &str,
    module_addr: &str,
    current_height: i64,
    sim_balance_delta: Option<i128>,  // from SimulateTx — negative = user loses funds
    sim_fund_destination: Option<&str>, // address funds flow to post-simulation
) -> anyhow::Result<ContractRisk> {
    let deploy_height = get_deploy_height(lcd, module_addr).await?;
    let age_blocks = current_height - deploy_height;

    let is_verified = check_verified(module_addr).await;
    let bytecode = fetch_module_bytecode(lcd, module_addr).await?;
    let abi = fetch_module_abi(lcd, module_addr).await?;

    // Layer 2: opcode analysis — name-independent
    let suspicious_opcodes: Vec<String> = DANGEROUS_OPCODES.iter()
        .filter(|op| bytecode_contains_pattern(&bytecode, op))
        .map(|s| s.to_string())
        .collect();

    // Layer 3: token flow — does sim show funds going somewhere unexpected?
    let unexpected_flow = sim_fund_destination
        .map(|dest| !is_known_protocol(dest))
        .unwrap_or(false);

    // Layer 4: proxy/upgrade detection
    let is_upgradeable = abi.functions.iter()
        .any(|f| UPGRADE_SIGNATURES.iter().any(|sig| f.name.contains(sig)));

    // Layer 5: name hints (low weight)
    let drain_fn_names: Vec<String> = abi.functions.iter()
        .filter(|f| DRAIN_NAME_HINTS.iter().any(|sig| f.name.contains(sig)))
        .map(|f| f.name.clone())
        .collect();

    let mut score = 0i32;

    // Age scoring
    if age_blocks < 2_880   { score += 40; }  // < ~6 hours old
    else if age_blocks < 14_400 { score += 20; }  // < ~1 day

    // Verification
    if !is_verified { score += 25; }

    // Layer 2: dangerous opcode patterns (high weight — behavior-based)
    score += (suspicious_opcodes.len() as i32) * 20;

    // Layer 3: unexpected fund flow post-simulation (highest weight)
    if unexpected_flow { score += 50; }

    // Layer 4: upgradeable proxy (moderate weight — not always malicious)
    if is_upgradeable { score += 20; }

    // Layer 5: name hints (low weight — easily gamed)
    if !drain_fn_names.is_empty() { score += 10; }

    Ok(ContractRisk {
        score: score.min(100),
        age_blocks,
        is_verified,
        is_upgradeable,
        suspicious_opcodes,
        unexpected_flow,
        drain_fn_names,
    })
}

/// Check for dangerous opcode sequences in raw bytecode
fn bytecode_contains_pattern(bytecode: &[u8], pattern: &str) -> bool {
    // For Move modules on Initia: scan the compiled bytecode blob for
    // known dangerous instruction patterns. Exact matching depends on
    // Move VM bytecode format — replace with Move bytecode parser for production.
    match pattern {
        "DELEGATECALL"   => contains_sequence(bytecode, &[0xf4]),          // EVM opcode ref
        "SELFDESTRUCT"   => contains_sequence(bytecode, &[0xff]),
        "CALLVALUE_LOOP" => detect_transfer_loop(bytecode),
        _                => false,
    }
}

fn contains_sequence(bytecode: &[u8], seq: &[u8]) -> bool {
    bytecode.windows(seq.len()).any(|w| w == seq)
}

fn detect_transfer_loop(_bytecode: &[u8]) -> bool {
    // TODO: implement loop + transfer pattern detection for Move bytecode
    false
}

async fn fetch_module_bytecode(lcd: &str, addr: &str) -> anyhow::Result<Vec<u8>> {
    let url = format!("{}/initia/move/v1/accounts/{}/modules", lcd, addr);
    let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
    let b64 = resp["modules"][0]["raw_bytes"].as_str().unwrap_or("");
    Ok(base64::decode(b64).unwrap_or_default())
}

async fn get_deploy_height(lcd: &str, addr: &str) -> anyhow::Result<i64> {
    let url = format!("{}/initia/move/v1/accounts/{}/modules", lcd, addr);
    let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
    Ok(resp["modules"][0]["raw_source"]["version"].as_i64().unwrap_or(0))
}

async fn check_verified(_addr: &str) -> bool {
    // Cross-reference Initia explorer API or local registry of verified modules
    // For hackathon: maintain a hardcoded known-safe list + assume unrecognized = unverified
    false
}

fn is_known_protocol(addr: &str) -> bool {
    const KNOWN: &[&str] = &[
        "init1<dex_address>",
        "init1<lending_address>",
    ];
    KNOWN.contains(&addr)
}
```

### 5.5 Behavioral Anomaly Detector

```rust
// crates/analyzer/src/anomaly.rs

use guardian_core::models::TxPattern;
use guardian_core::types::{IncomingTx, RiskFinding, Severity};

pub fn detect_anomaly(tx: &IncomingTx, baseline: &TxPattern) -> Option<RiskFinding> {
    let mut score = 0i32;
    let mut flags = vec![];

    let value: i64 = tx.amount.parse().unwrap_or(0);

    if baseline.sample_count < 10 {
        return None; // not enough history to baseline — skip
    }

    if value > baseline.avg_value_uinit * 10 {
        score += 35;
        flags.push(format!("Value {}x above baseline", value / baseline.avg_value_uinit.max(1)));
    }

    let known: Vec<String> = serde_json::from_value(baseline.typical_recipients.clone())
        .unwrap_or_default();
    if !known.contains(&tx.recipient) {
        score += 25;
        flags.push("First-time recipient".into());
    }

    let tx_hour = tx.timestamp.hour() as i32;
    if (tx_hour - baseline.typical_hour_utc).abs() > 8 {
        score += 15;
        flags.push("Unusual time of day".into());
    }

    if score >= 40 {
        Some(RiskFinding {
            module: "anomaly".into(),
            severity: if score >= 70 { Severity::High } else { Severity::Medium },
            weight: score,
            description: flags.join("; "),
            payload: serde_json::json!({
                "flags": flags,
                "tx_value": value,
                "baseline_avg": baseline.avg_value_uinit,
            }),
        })
    } else { None }
}

/// Call this after every confirmed safe tx to update the baseline
pub fn update_baseline(pattern: &mut TxPattern, tx: &IncomingTx) {
    let value: i64 = tx.amount.parse().unwrap_or(0);
    let n = pattern.sample_count as i64;

    // Rolling average
    pattern.avg_value_uinit = (pattern.avg_value_uinit * n + value) / (n + 1);
    pattern.sample_count += 1;

    let mut recipients: Vec<String> =
        serde_json::from_value(pattern.typical_recipients.clone()).unwrap_or_default();
    if !recipients.contains(&tx.recipient) {
        recipients.push(tx.recipient.clone());
        if recipients.len() > 50 { recipients.remove(0); } // cap at 50
    }
    pattern.typical_recipients = serde_json::to_value(recipients).unwrap();
    pattern.updated_at = chrono::Utc::now();
}
```

### 5.6 ICA Abuse Monitor

```rust
// crates/analyzer/src/ica.rs

use guardian_core::types::{RiskFinding, Severity};

// Known safe ICA controller chain IDs — expand as needed
const SAFE_CONTROLLERS: &[&str] = &[
    "initiation-2",   // Initia testnet
];

pub fn check_ica(msg_type: &str, controller_chain: &str) -> Option<RiskFinding> {
    if !msg_type.contains("interchain_account") && !msg_type.contains("RegisterInterchainAccount") {
        return None;
    }

    if !SAFE_CONTROLLERS.contains(&controller_chain) {
        return Some(RiskFinding {
            module: "ica".into(),
            severity: Severity::High,
            weight: 75,
            description: format!(
                "Unknown chain '{}' is requesting Interchain Account control over your address",
                controller_chain
            ),
            payload: serde_json::json!({
                "controller_chain": controller_chain,
                "msg_type": msg_type,
                "warning": "Cross-chain account control — verify this is intentional",
            }),
        });
    }
    None
}
```

### 5.7 LLM Analyzer (Ambiguous Cases + Bytecode Decompilation)

The LLM module serves two roles:

1. **Ambiguous score triage** — called when `total_risk` is in the 35–65 range to break ties
2. **Bytecode decompilation analysis** — called for any unverified contract to identify obfuscated fund-drain logic that opcode pattern matching may miss

```rust
// crates/analyzer/src/llm.rs

use reqwest::Client;
use serde_json::json;

pub struct TxContext {
    pub sender:               String,
    pub recipient:            String,
    pub is_first_interaction: bool,
    pub value_uinit:          u64,
    pub contract_age_blocks:  Option<i64>,
    pub is_verified:          Option<bool>,
    pub function_name:        Option<String>,
    pub user_baseline_avg:    i64,
}

/// Role 1: ambiguous score triage (total_risk 35–65)
pub async fn llm_assess(ctx: &TxContext, api_key: &str) -> anyhow::Result<String> {
    let prompt = format!(
        r#"You are a blockchain security analyst for the Initia chain.

Transaction:
- Sender: {}
- Recipient: {} (first interaction: {})
- Value: {} uINIT
- Contract age: {} blocks, verified: {}
- Function: {}
- User baseline avg: {} uINIT

Respond ONLY with a JSON object, no other text:
{{"risk_level":"low|medium|high|critical","primary_concern":"...","recommended_action":"allow|warn|block","reasoning":"..."}}"#,
        ctx.sender,
        ctx.recipient,
        ctx.is_first_interaction,
        ctx.value_uinit,
        ctx.contract_age_blocks.map(|v| v.to_string()).unwrap_or("unknown".into()),
        ctx.is_verified.map(|v| v.to_string()).unwrap_or("unknown".into()),
        ctx.function_name.as_deref().unwrap_or("transfer"),
        ctx.user_baseline_avg,
    );

    call_claude(&prompt, api_key, 256).await
}

/// Role 2: decompiled bytecode analysis for unverified contracts
/// Pass in pseudocode from a bytecode decompiler (e.g. heimdall-rs output)
pub async fn llm_analyze_bytecode(
    pseudocode: &str,
    contract_addr: &str,
    api_key: &str,
) -> anyhow::Result<BytecodeRiskAssessment> {
    let prompt = format!(
        r#"You are a smart contract security auditor. Analyze this decompiled Move/EVM pseudocode for contract {}.

Identify any execution paths where:
1. User funds (tokens or native assets) could be transferred to an address controlled by the contract deployer or a third party
2. The caller (user) loses assets beyond what a legitimate operation would require
3. There are backdoors: owner-only functions that can drain balances, pause/freeze user funds, or change critical parameters

Decompiled pseudocode:
{}

Respond ONLY with a JSON object, no other text:
{{
  "has_drain_path": true|false,
  "confidence": "low|medium|high",
  "suspicious_paths": ["description of each suspicious path"],
  "recommended_action": "allow|warn|block",
  "reasoning": "..."
}}"#,
        contract_addr,
        pseudocode,
    );

    let raw = call_claude(&prompt, api_key, 512).await?;
    let assessment: BytecodeRiskAssessment = serde_json::from_str(&raw)
        .unwrap_or(BytecodeRiskAssessment::unknown());
    Ok(assessment)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct BytecodeRiskAssessment {
    pub has_drain_path:    bool,
    pub confidence:        String,
    pub suspicious_paths:  Vec<String>,
    pub recommended_action: String,
    pub reasoning:         String,
}

impl BytecodeRiskAssessment {
    fn unknown() -> Self {
        Self {
            has_drain_path: false,
            confidence: "low".into(),
            suspicious_paths: vec![],
            recommended_action: "warn".into(),
            reasoning: "Could not parse LLM response".into(),
        }
    }
}

async fn call_claude(prompt: &str, api_key: &str, max_tokens: u32) -> anyhow::Result<String> {
    let resp: serde_json::Value = Client::new()
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "messages": [{ "role": "user", "content": prompt }]
        }))
        .send().await?
        .json().await?;

    Ok(resp["content"][0]["text"].as_str().unwrap_or("{}").to_string())
}
```

---

## 6. Agent Orchestrator

```rust
// crates/agent/src/orchestrator.rs

use guardian_core::types::*;
use guardian_analyzer::{poison, approvals, contract, anomaly, ica};
use guardian_simulator::simulate;

pub struct GuardianAgent {
    pub lcd:        String,
    pub db:         DbPool,
    pub api_key:    String,
}

impl GuardianAgent {
    pub async fn evaluate(&self, tx: &IncomingTx, raw_bytes: &[u8]) -> GuardianDecision {
        // Load user data from DB
        let known_addrs = self.load_known_addresses(&tx.sender).await;
        let baseline    = self.load_pattern(&tx.sender).await;
        let height      = self.get_current_height().await;

        // Simulation runs first — its output feeds contract scoring
        let sim_result = simulate(&self.lcd, raw_bytes).await;

        // Extract per-address balance deltas from simulation for contract scorer
        let sim_delta: Option<i128> = sim_result.as_ref().ok()
            .and_then(|s| s.balance_deltas.iter().find(|d| d.address == tx.sender))
            .map(|d| d.delta);
        let sim_fund_dest: Option<String> = sim_result.as_ref().ok()
            .and_then(|s| s.balance_deltas.iter()
                .find(|d| d.delta > 0 && d.address != tx.sender))
            .map(|d| d.address.clone());

        // Contract scoring (with sim context) + other checks run in parallel
        let contract_risk = if let Some(addr) = &tx.contract_address {
            contract::score_contract(
                &self.lcd, addr, height,
                sim_delta, sim_fund_dest.as_deref(),
            ).await.ok()
        } else { None };

        let mut findings: Vec<RiskFinding> = vec![];

        // Poisoning check
        if let Some(f) = poison::check_poison(&tx.recipient, &known_addrs) {
            findings.push(f);
        }

        // Anomaly check
        if let Some(baseline) = &baseline {
            if let Some(f) = anomaly::detect_anomaly(tx, baseline) {
                findings.push(f);
            }
        }

        // Contract risk — includes bytecode + token flow analysis, not just name matching
        if let Some(risk) = &contract_risk {
            if risk.score >= 50 {
                let mut desc = format!(
                    "Contract risk score {}/100 — age {} blocks, verified: {}",
                    risk.score, risk.age_blocks, risk.is_verified
                );
                if risk.unexpected_flow {
                    desc.push_str(" — FUNDS FLOW TO UNKNOWN ADDRESS");
                }
                if !risk.suspicious_opcodes.is_empty() {
                    desc.push_str(&format!(" — dangerous opcodes: {}", risk.suspicious_opcodes.join(", ")));
                }
                if risk.is_upgradeable {
                    desc.push_str(" — contract is upgradeable (logic can change)");
                }
                findings.push(RiskFinding {
                    module: "contract".into(),
                    severity: if risk.score >= 80 { Severity::Critical } else { Severity::High },
                    weight: risk.score,
                    description: desc,
                    payload: serde_json::json!(risk),
                });
            }

            // For unverified contracts: run LLM bytecode decompilation analysis
            if !risk.is_verified {
                if let Ok(bytecode) = contract::fetch_module_bytecode_pub(&self.lcd,
                    tx.contract_address.as_deref().unwrap_or("")).await {
                    let pseudocode = decompile_to_pseudocode(&bytecode);
                    if let Ok(assessment) = llm::llm_analyze_bytecode(
                        &pseudocode,
                        tx.contract_address.as_deref().unwrap_or(""),
                        &self.api_key,
                    ).await {
                        if assessment.has_drain_path {
                            findings.push(RiskFinding {
                                module: "contract_llm".into(),
                                severity: Severity::Critical,
                                weight: if assessment.confidence == "high" { 80 }
                                        else if assessment.confidence == "medium" { 50 } else { 25 },
                                description: format!(
                                    "LLM bytecode analysis: potential drain path detected — {}",
                                    assessment.reasoning
                                ),
                                payload: serde_json::json!(assessment),
                            });
                        }
                    }
                }
            }
        }

        // Simulation: will this fail or drain funds?
        if let Ok(sim) = sim_result {
            if sim.will_fail {
                findings.push(RiskFinding {
                    module: "simulator".into(),
                    severity: Severity::High,
                    weight: 60,
                    description: format!(
                        "Transaction will revert: {}",
                        sim.fail_reason.unwrap_or("unknown reason".into())
                    ),
                    payload: serde_json::json!({}),
                });
            }
            for delta in &sim.balance_deltas {
                if delta.delta < -1_000_000 { // > 1 INIT loss
                    findings.push(RiskFinding {
                        module: "simulator".into(),
                        severity: Severity::Medium,
                        weight: 20,
                        description: format!(
                            "You will lose {} {}", delta.delta.abs(), delta.denom
                        ),
                        payload: serde_json::json!(delta),
                    });
                }
            }
        }

        // Score and decide
        let total: i32 = findings.iter().map(|f| f.weight).sum();
        let auto_revoke = findings.iter().any(|f| f.module == "approval") && total > 80;

        match total {
            0..=29  => GuardianDecision::Allow,
            30..=59 => GuardianDecision::Warn    { findings },
            60..=79 => GuardianDecision::Confirm { findings },
            _       => GuardianDecision::Block   { findings, auto_revoke },
        }
    }
}
```

---

## 7. RPC Proxy

```rust
// crates/api/src/proxy.rs

use axum::{extract::State, response::Json, routing::any, Router};
use serde_json::Value;

pub fn proxy_router(state: AppState) -> Router {
    Router::new()
        .route("/rpc", any(proxy_handler))
        .with_state(state)
}

async fn proxy_handler(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Json<Value> {
    let req: Value = serde_json::from_slice(&body).unwrap_or_default();

    // Only intercept broadcast_tx — pass everything else through
    let method = req["method"].as_str().unwrap_or("");
    if method != "broadcast_tx_sync" && method != "broadcast_tx_async" {
        return forward_to_node(&state.lcd, &body).await;
    }

    // Decode tx bytes
    let tx_b64 = req["params"]["tx"].as_str().unwrap_or("");
    let tx_bytes = base64::decode(tx_b64).unwrap_or_default();

    // Parse into IncomingTx (decode Cosmos tx protobuf)
    let tx = parse_cosmos_tx(&tx_bytes);

    // Evaluate
    let decision = state.agent.evaluate(&tx, &tx_bytes).await;

    match decision {
        GuardianDecision::Allow => {
            forward_to_node(&state.lcd, &body).await
        },
        GuardianDecision::Warn { findings } => {
            // Forward but fire alert
            state.notifier.fire(&tx.sender, &findings).await;
            forward_to_node(&state.lcd, &body).await
        },
        GuardianDecision::Confirm { findings } | GuardianDecision::Block { findings, .. } => {
            // Block — return RPC error, fire alert
            state.notifier.fire(&tx.sender, &findings).await;
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": "Transaction blocked by Guardian",
                    "data": {
                        "findings": findings,
                        "dashboard": "https://guardian.yourdomain.com"
                    }
                }
            }))
        }
    }
}

async fn forward_to_node(lcd: &str, body: &[u8]) -> Json<Value> {
    let resp: Value = reqwest::Client::new()
        .post(format!("{}/", lcd))  // Tendermint RPC port
        .body(body.to_vec())
        .send().await
        .and_then(|r| r.json().await)  // compile note: use .await outside closure
        .unwrap_or_default();
    Json(resp)
}
```

---

## 8. Notifier + Telegram Bot

```rust
// crates/notifier/src/lib.rs

use teloxide::prelude::*;
use tokio::sync::broadcast;

pub struct Notifier {
    pub bot:        Bot,
    pub sse_tx:     broadcast::Sender<String>,
    pub db:         DbPool,
}

impl Notifier {
    pub async fn fire(&self, address: &str, findings: &[RiskFinding]) {
        let payload = serde_json::json!({
            "address": address,
            "findings": findings,
            "timestamp": chrono::Utc::now(),
        });

        // Store in DB
        self.store_events(address, findings).await;

        // Push to SSE dashboard
        let _ = self.sse_tx.send(payload.to_string());

        // Send Telegram if registered
        if let Some(chat_id) = self.get_telegram_id(address).await {
            let msg = format_telegram_alert(findings);
            let _ = self.bot.send_message(ChatId(chat_id), msg).await;
        }
    }
}

fn format_telegram_alert(findings: &[RiskFinding]) -> String {
    let top = &findings[0];
    format!(
        "🚨 *Guardian Alert*\n\n*{}* — {}\n\n{}\n\n_Open dashboard for details_",
        format!("{:?}", top.severity).to_uppercase(),
        top.module,
        top.description,
    )
}

// Telegram bot command handler
pub async fn run_bot(bot: Bot, db: DbPool) {
    teloxide::repl(bot, move |bot: Bot, msg: Message| {
        let db = db.clone();
        async move {
            if let Some(text) = msg.text() {
                if let Some(addr) = text.strip_prefix("/register ") {
                    register_address(addr.trim(), msg.chat.id.0, &db).await;
                    bot.send_message(msg.chat.id,
                        format!("✅ Monitoring {}", shorten(addr))).await?;
                }
            }
            respond(())
        }
    }).await;
}
```

---

## 9. SSE Dashboard Feed

```rust
// crates/api/src/dashboard.rs

use axum::{
    extract::State,
    response::sse::{Event, Sse},
};
use tokio_stream::wrappers::BroadcastStream;

pub async fn sse_feed(
    State(state): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.notifier.sse_tx.subscribe();
    let stream = BroadcastStream::new(rx)
        .filter_map(|msg| async move {
            msg.ok().map(|data| Ok(Event::default().data(data)))
        });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
    )
}
```

---

## 10. Build Sequence

Attack in this order to have a working demo fastest:

```
Day 1   DB schema + Diesel models + core types
        WebSocket streamer (connect, parse events, channel send)

Day 2   Address poisoning detector (highest visual impact)
        Approval scanner (query Move resources + score)

Day 3   SimulateTx wrapper + balance delta extraction
        RPC proxy (intercept → evaluate → block/forward)

Day 4   Contract scorer
        Agent orchestrator (wire all modules, parallel tokio::join!)

Day 5   Notifier (SSE + Telegram bot)
        REST API (risk feed, approval list, registration endpoints)

Day 6   Next.js dashboard:
          - Live risk event feed (SSE)
          - Approval manager table + revoke button
          - Address book with poison tags

Day 7   LLM analyzer integration (ambiguous score cases)
        End-to-end demo flow rehearsal
        Telegram bot polish
```

---

## 11. Demo Script (3 Minutes)

Structure the demo around this exact flow — it's immediately legible to any judge:

1. **Setup (30s)** — Show user changing RPC URL in Compass wallet to Guardian proxy. "That's the entire setup."

2. **Poisoning catch (45s)** — Send a dust tx from a visually similar address to the test wallet. Dashboard lights up: "⚠️ Address poisoning detected — this address mimics init1ab...f3c2 in your contacts."

3. **Tx block (60s)** — Attempt to send funds to an unverified contract deployed 1 hour ago. Wallet shows RPC error. Dashboard shows: contract score 87/100, "deployed 1 hour ago, unverified — simulation shows funds routed to unknown address, dangerous DELEGATECALL opcode detected, LLM bytecode analysis: potential drain path with high confidence."

4. **Simulation (30s)** — Simulate a legitimate DEX swap. Dashboard shows "you will receive 142.3 USDC, lose 50 INIT, gas ~0.003 INIT." Let it through.

5. **One-click revoke (15s)** — Pull up stale approval dashboard. Show unlimited approval to unknown contract, 180 days old. Hit "Revoke." Tx broadcast, confirmation.

Total: under 3 minutes, every core feature shown, every decision the agent makes is visible to the audience.
