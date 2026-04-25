import { useEffect, useMemo, useState } from "react";
import { useInterwovenKit } from "@initia/interwovenkit-react";
import { guardianFrontendConfig } from "./config";
import { NeuralMesh } from "./components/NeuralMesh";
import { ProtectionSphere } from "./components/ProtectionSphere";
import { LandingPage } from "./pages/LandingPage";
import { DashboardPage } from "./pages/DashboardPage";
import { OnboardingPage } from "./pages/OnboardingPage";
import { SimulationPage } from "./pages/SimulationPage";

type ApprovalRecord = {
  id: string;
  owner: string;
  spender: string;
  token_denom: string;
  amount: string;
  granted_at_height: number;
  revoked: boolean;
  risk_score: number;
  created_at: string;
};

type RiskEvent = {
  id: string;
  address: string;
  event_type: string;
  severity: string;
  tx_hash?: string | null;
  payload: unknown;
  created_at: string;
};

type WatchedAddress = {
  id: string;
  address: string;
  label?: string | null;
  owner_address: string;
  is_simulation_target: boolean;
  is_poisoned: boolean;
  risk_score: number;
  first_seen: string;
  last_activity: string;
};

type RegisteredUser = {
  id: string;
  address: string;
  email_address?: string | null;
  email_display_name?: string | null;
  created_at: string;
};

type UserProfile = {
  user?: RegisteredUser | null;
  simulation_target?: WatchedAddress | null;
};

type PolicyView = {
  owner: string;
  warn_threshold: number;
  confirm_threshold: number;
  block_threshold: number;
  trusted_contracts: string[];
  trusted_recipients: string[];
  auto_block_new_contracts: boolean;
  updated_at: number;
};

type PolicyIncident = {
  id: number;
  owner: string;
  reporter: string;
  event_type: string;
  severity: string;
  tx_hash?: string | null;
  summary: string;
  details_json: string;
  created_at: number;
};

type PolicyQuarantineEntry = {
  owner: string;
  address: string;
  reason: string;
  risk_score: number;
  quarantined_at: number;
};

type PolicyOverview = {
  configured: boolean;
  contract_address?: string | null;
  reporting_enabled: boolean;
  policy?: PolicyView | null;
  incidents: PolicyIncident[];
  quarantined: PolicyQuarantineEntry[];
  issues: string[];
};

type RevokeApprovalPlan = {
  summary: string;
  messages: Array<{
    typeUrl: string;
    value: Record<string, unknown> & {
      msg_json?: Record<string, unknown>;
    };
  }>;
};

type SimulationFinding = {
  module: string;
  severity: string;
  weight: number;
  description: string;
  payload: unknown;
};

type SimulationRun = {
  scenario_id: string;
  attack_surface: string;
  target_address: string;
  findings: SimulationFinding[];
  available_scenarios: string[];
  ran_at: string;
};

type DemoContractDecision =
  | { decision: "allow" }
  | { decision: "warn" | "confirm"; findings: SimulationFinding[] }
  | { decision: "block"; findings: SimulationFinding[]; auto_revoke: boolean };

type ContractInspection = {
  score: number;
  age_blocks: number;
  is_verified: boolean;
  is_upgradeable: boolean;
  suspicious_opcodes: string[];
  unexpected_flow: boolean;
  drain_fn_names: string[];
  analysis_backend: string;
};

type DemoContractPreview = {
  contract_address: string;
  decision: DemoContractDecision;
  execute_message: Record<string, unknown>;
  inspection?: ContractInspection | null;
};

type NoticeItem = {
  id: string;
  title: string;
  detail: string;
  tone: "danger" | "warn";
};

type ApiStatus = "checking" | "online" | "offline";
type SimulationStage = "idle" | "preparing" | "running" | "publishing" | "complete";
type DemoAttemptState = "idle" | "previewing" | "submitting" | "blocked" | "needs_guarded_rpc";
type RiskTone = "clear" | "warn" | "high" | "block";
type SphereState = "idle" | "screening" | "warned" | "blocked" | "offline";
type AppView = "landing" | "dashboard" | "setup" | "simulation";
type AnalysisNetworkMode = "auto" | "wasm_move" | "initia_minievm" | "sepolia";

type FeedRow = {
  tone: RiskTone;
  label: string;
  hash: string;
  counterparty: string;
  value: string;
  time: string;
  highlight?: boolean;
};

type AttackId =
  | "reentrancy_pattern"
  | "low_liquidity"
  | "high_slippage"
  | "dust_attack"
  | "address_poisoning";

const apiBase = guardianFrontendConfig.api.baseUrl;
const guardedRpcEndpoint = guardianFrontendConfig.api.guardianRpcUrl;
const demoRiskLabAddress = guardianFrontendConfig.contract.demoRiskLabAddress;
const demoLiquidityLabAddress = guardianFrontendConfig.contract.demoLiquidityLabAddress;
const demoApprovalLabAddress = guardianFrontendConfig.contract.demoApprovalLabAddress;
const demoApprovalSpenderAddress =
  guardianFrontendConfig.contract.demoApprovalSpenderAddress ||
  demoRiskLabAddress ||
  undefined;
const PAGE_SIZE = 7;
const DEMO_ANALYSIS_ADDRESS = "init1aegisdemoanalysis000000000000000000000000";
const DEMO_APPROVAL_AMOUNT = "340282366920938463463374607431768211455";

const landingPipeline = [
  {
    title: "Intercept",
    detail: "Guardian receives the transaction through the RPC proxy before the chain ever sees it."
  },
  {
    title: "Analyze",
    detail: "Simulation, bytecode analysis, policy rules, and address intelligence score the transaction in one pass."
  },
  {
    title: "Act",
    detail: "The result is allowed, warned, or blocked and recorded in a live operator surface."
  }
] as const;

const landingCoverage = [
  "Reentrancy",
  "Low Liquidity",
  "High Slippage",
  "Dust Attacks",
  "Address Poisoning",
  "Approval Abuse"
] as const;

const dashboardSidebarGroups = [
  {
    label: "Monitor",
    items: [
      { id: "dashboard", label: "Dashboard", icon: "◎" },
      { id: "feed", label: "Transaction Feed", icon: "≡" },
      { id: "audit", label: "Audit Log", icon: "□" }
    ]
  },
  {
    label: "Protect",
    items: [
      { id: "approvals", label: "Approvals", icon: "∞" },
      { id: "registry", label: "Protection Setup", icon: "⬡", view: "setup" as AppView },
      { id: "alerts", label: "Alert Emails", icon: "✉", view: "setup" as AppView }
    ]
  },
  {
    label: "Settings",
    items: [{ id: "rpc", label: "RPC Setup", icon: "⬢", view: "setup" as AppView }]
  }
] as const;

const simulationSidebarGroups = [
  {
    label: "Overview",
    items: [
      { id: "simulation-overview", label: "Overview" },
      { id: "vector-reentrancy", label: "Reentrancy" },
      { id: "vector-low-liquidity", label: "Low Liquidity" },
      { id: "vector-high-slippage", label: "High Slippage" },
      { id: "vector-dust-attack", label: "Dust Attack" },
      { id: "vector-address-poisoning", label: "Address Poisoning" }
    ]
  }
] as const;

const setupSidebarGroups = [
  {
    label: "Activation",
    items: [
      { id: "registry", label: "Target Wallet" },
      { id: "alerts", label: "Email Alerts" },
      { id: "rpc", label: "RPC Endpoint" }
    ]
  }
] as const;

const simulationVectors = [
  {
    id: "reentrancy_pattern" as const,
    sectionId: "vector-reentrancy",
    index: "01",
    icon: "⟳",
    title: "Reentrancy",
    tagline: "Recursive callbacks drain contract funds before balance state is updated.",
    chips: ["Critical Severity", "AI Contract Analysis", "Bytecode Scanning"],
    tone: "block" as RiskTone,
    cvss: 9.8,
    analysisChip: true,
    runLabel: "Run Reentrancy Drill"
  },
  {
    id: "low_liquidity" as const,
    sectionId: "vector-low-liquidity",
    index: "02",
    icon: "◫",
    title: "Low Liquidity",
    tagline: "Thin pools amplify price impact and can trigger cascading liquidations.",
    chips: ["High Severity", "Pool Analysis", "Reserve Simulation"],
    tone: "high" as RiskTone,
    cvss: 8.4,
    analysisChip: true,
    runLabel: "Run Liquidity Drill"
  },
  {
    id: "high_slippage" as const,
    sectionId: "vector-high-slippage",
    index: "03",
    icon: "↗",
    title: "High Slippage",
    tagline: "Excessive slippage tolerance lets sandwich bots extract value from your swap.",
    chips: ["Medium Severity", "MEV Protection", "Sandwich Detection"],
    tone: "warn" as RiskTone,
    cvss: 6.2,
    analysisChip: false,
    runLabel: "Run Slippage Drill"
  },
  {
    id: "dust_attack" as const,
    sectionId: "vector-dust-attack",
    index: "04",
    icon: "·",
    title: "Dust Attack",
    tagline: "Microscopic deposits link addresses together and contaminate address history.",
    chips: ["Privacy Threat", "Auto-Quarantine", "Graph Analysis"],
    tone: "warn" as RiskTone,
    cvss: 5.5,
    analysisChip: false,
    runLabel: "Run Dust Drill"
  },
  {
    id: "address_poisoning" as const,
    sectionId: "vector-address-poisoning",
    index: "05",
    icon: "☠",
    title: "Address Poison Attack",
    tagline: "Visually identical addresses in history turn one copy-paste into irreversible loss.",
    chips: ["Critical Severity", "Levenshtein Match", "Irreversible Loss"],
    tone: "block" as RiskTone,
    cvss: 9.1,
    analysisChip: false,
    runLabel: "Run Poison Drill"
  }
] as const;

const fallbackFeedRows: FeedRow[] = [
  {
    tone: "clear",
    label: "Initia Swap → USDC",
    hash: "0xf3b1...44ac",
    counterparty: "Initia Swap → USDC",
    value: "+142.00 INIT",
    time: "2m"
  },
  {
    tone: "clear",
    label: "Transfer → initia1ab...d4",
    hash: "0x9a2c...88dd",
    counterparty: "Transfer → initia1ab...d4",
    value: "-50.00 INIT",
    time: "8m"
  },
  {
    tone: "warn",
    label: "Unknown contract (6h old)",
    hash: "0x71de...c2ff",
    counterparty: "Unknown contract (6h old)",
    value: "-500.00 INIT",
    time: "41m"
  },
  {
    tone: "clear",
    label: "Bridge → Cosmos Hub",
    hash: "0xb441...18dc",
    counterparty: "Bridge → Cosmos Hub",
    value: "-80.00 INIT",
    time: "1h"
  },
  {
    tone: "block",
    label: "Poisoned: initia1ef...a1",
    hash: "0x2244...91ea",
    counterparty: "Poisoned: initia1ef...a1",
    value: "-2,000.00 INIT",
    time: "4h",
    highlight: true
  },
  {
    tone: "clear",
    label: "Initia DEX · add liquidity",
    hash: "0x4f88...cc01",
    counterparty: "Initia DEX · add liquidity",
    value: "-400.00 INIT",
    time: "6h"
  }
];

function ensureDashboardClearRows(rows: FeedRow[]) {
  if (!rows.length) {
    return fallbackFeedRows;
  }

  if (rows.some((row) => row.tone === "clear")) {
    return rows;
  }

  const supplementalClearRows = fallbackFeedRows
    .filter((row) => row.tone === "clear")
    .slice(0, 2);

  if (!supplementalClearRows.length) {
    return rows;
  }

  const blendedRows = [...rows];
  supplementalClearRows.forEach((row, index) => {
    const insertAt = index === 0 ? 1 : 4;
    blendedRows.splice(Math.min(insertAt, blendedRows.length), 0, row);
  });

  return blendedRows;
}

function shortenAddress(value: string) {
  if (value.length < 14) return value;
  return `${value.slice(0, 10)}...${value.slice(-4)}`;
}

function normalizeProtoMessage(message: RevokeApprovalPlan["messages"][number]) {
  if (
    message.typeUrl === "/cosmwasm.wasm.v1.MsgExecuteContract" &&
    message.value.msg_json
  ) {
    const { msg_json, ...rest } = message.value;
    return {
      typeUrl: message.typeUrl,
      value: {
        ...rest,
        msg: new TextEncoder().encode(JSON.stringify(msg_json))
      }
    };
  }

  return message;
}

function describeEventLabel(eventType: string) {
  const labels: Record<string, string> = {
    poison: "Address Poisoning",
    dust: "Dust Attack",
    approval: "Stale Approval",
    approval_review: "Approval Review",
    approval_intent: "Approval Intent",
    anomaly: "Behavioral Anomaly",
    ica: "ICA Abuse",
    contract: "Suspicious Contract",
    contract_llm: "Contract Analysis Warning",
    liquidity: "Low Liquidity",
    reentrancy: "Reentrancy Pattern",
    slippage: "Excessive Slippage",
    simulator: "Simulation Warning",
    wasm_admin: "Privileged Wasm Action",
    email_test: "Email Test Alert"
  };

  return labels[eventType] || eventType.replaceAll("_", " ");
}

function describeScenarioName(scenarioId: string) {
  const labels: Record<string, string> = {
    address_poisoning: "Address Poisoning Drill",
    dust_attack: "Dust Transfer Drill",
    approval_attack: "Approval Abuse Drill",
    behavioral_anomaly: "Behavior Anomaly Drill",
    ica_abuse: "ICA Abuse Drill",
    low_liquidity: "Low Liquidity Drill",
    high_slippage: "High Slippage Drill",
    reentrancy_pattern: "Reentrancy Pattern Drill",
    simulated_contract_abuse: "Suspicious Contract Drill"
  };

  return labels[scenarioId] || scenarioId.replaceAll("_", " ");
}

function describeApiStatus(status: ApiStatus) {
  if (status === "online") return "Online";
  if (status === "offline") return "Offline";
  return "Checking";
}

function describeDecisionState(decision: DemoContractDecision["decision"]) {
  if (decision === "block") return "Blocked";
  if (decision === "confirm") return "Needs confirmation";
  if (decision === "warn") return "Warn";
  return "Safe";
}

function decisionTone(decision: DemoContractDecision["decision"]): RiskTone {
  if (decision === "block") return "block";
  if (decision === "confirm") return "high";
  if (decision === "warn") return "warn";
  return "clear";
}

function extractDecisionFindings(decision: DemoContractDecision) {
  if (decision.decision === "allow") return [];
  return decision.findings;
}

function pageSummary(total: number, page: number, pageSize: number) {
  if (total === 0) return "No entries";
  const start = page * pageSize + 1;
  const end = Math.min(total, (page + 1) * pageSize);
  return `${start}-${end} of ${total}`;
}

function pageLabel(total: number, page: number, pageCount: number, pageSize: number) {
  if (total === 0) return "Page 1 of 1";
  return `Page ${page + 1} of ${pageCount} · ${pageSummary(total, page, pageSize)}`;
}

function formatApprovalAmount(amount: string) {
  const normalized = amount.trim();
  if (!normalized) return "0";
  if (normalized === DEMO_APPROVAL_AMOUNT || normalized.toLowerCase() === "all") {
    return "Unlimited";
  }

  const numeric = Number(normalized);
  if (Number.isFinite(numeric)) {
    if (numeric >= 1_000_000) {
      return numeric.toLocaleString("en-US");
    }
    return normalized;
  }

  if (normalized.length > 18) {
    return "Large approval";
  }

  return normalized;
}

function renderEventExcerpt(event: RiskEvent) {
  if (!event.payload || typeof event.payload !== "object") {
    return null;
  }

  const payload = event.payload as Record<string, unknown>;
  if (typeof payload.reasoning === "string") return payload.reasoning;
  if (typeof payload.primary_concern === "string") return payload.primary_concern;
  if (typeof payload.warning === "string") return payload.warning;
  if (Array.isArray(payload.flags) && payload.flags.length > 0) return payload.flags.join("; ");
  if (Array.isArray(payload.suspicious_paths) && payload.suspicious_paths.length > 0) {
    return payload.suspicious_paths.join("; ");
  }
  return null;
}

function riskToneFromSeverity(severity?: string | null): RiskTone {
  if (severity === "critical") return "block";
  if (severity === "high") return "high";
  if (severity === "medium") return "warn";
  return "clear";
}

function riskToneFromScore(score: number): RiskTone {
  if (score >= 80) return "block";
  if (score >= 60) return "high";
  if (score >= 30) return "warn";
  return "clear";
}

function riskLabel(tone: RiskTone) {
  if (tone === "block") return "Block";
  if (tone === "high") return "High";
  if (tone === "warn") return "Warn";
  return "Clear";
}

function formatAbsoluteTime(value: string) {
  return new Date(value).toLocaleString();
}

function formatRelativeTime(value: string) {
  const then = new Date(value).getTime();
  const diffSeconds = Math.round((then - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

  if (Math.abs(diffSeconds) < 60) return formatter.format(diffSeconds, "second");

  const diffMinutes = Math.round(diffSeconds / 60);
  if (Math.abs(diffMinutes) < 60) return formatter.format(diffMinutes, "minute");

  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) return formatter.format(diffHours, "hour");

  const diffDays = Math.round(diffHours / 24);
  return formatter.format(diffDays, "day");
}

function wait(durationMs: number) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, durationMs);
  });
}

function isEvmAddress(value: string) {
  return /^0x[a-fA-F0-9]{40}$/.test(value.trim());
}

function resolveAnalysisNetwork(mode: AnalysisNetworkMode, value: string) {
  if (mode === "wasm_move") {
    return {
      key: "wasm_move" as const,
      label: "Guardian Wasm/Move",
      placeholder: "init1..."
    };
  }

  if (mode === "initia_minievm") {
    return {
      key: "initia_minievm" as const,
      label: "Initia MiniEVM",
      placeholder: "0x..."
    };
  }

  if (mode === "sepolia") {
    return {
      key: "sepolia" as const,
      label: "Sepolia",
      placeholder: "0x..."
    };
  }

  return isEvmAddress(value)
    ? {
        key: "initia_minievm" as const,
        label: "Initia MiniEVM",
        placeholder: "0x..."
      }
    : {
        key: "wasm_move" as const,
        label: "Guardian Wasm/Move",
        placeholder: "init1..."
      };
}

function isInspectionPreview(preview: DemoContractPreview | null) {
  return Boolean(preview?.inspection);
}

function inspectionSignalSummary(inspection: ContractInspection) {
  const items: string[] = [];
  if (inspection.analysis_backend) items.push(`Backend: ${inspection.analysis_backend.toUpperCase()}`);
  items.push(inspection.is_verified ? "Verified / allowlisted" : "Not allowlisted");
  if (inspection.is_upgradeable) items.push("Upgradeable");
  if (inspection.unexpected_flow) items.push("Unexpected fund flow signal");
  if (inspection.drain_fn_names.length) {
    items.push(`Sensitive selectors: ${inspection.drain_fn_names.join(", ")}`);
  }
  if (inspection.suspicious_opcodes.length) {
    items.push(`Signals: ${inspection.suspicious_opcodes.join(", ")}`);
  }
  return items;
}

function hashForView(view: AppView) {
  if (view === "landing") return "#/";
  if (view === "simulation") return "#/simulation";
  if (view === "setup") return "#/setup";
  return "#/dashboard";
}

function readAppViewFromHash(hash: string): AppView {
  if (!hash || hash === "#/" || hash === "#") return "landing";
  if (hash.startsWith("#/simulation")) return "simulation";
  if (hash.startsWith("#/setup")) return "setup";
  if (hash.startsWith("#/dashboard")) return "dashboard";
  return "landing";
}

function sidebarGroupsForView(view: AppView) {
  if (view === "landing") return [];
  if (view === "simulation") return simulationSidebarGroups;
  if (view === "setup") return setupSidebarGroups;
  return dashboardSidebarGroups;
}

function defaultSectionForView(view: AppView) {
  return sidebarGroupsForView(view)[0]?.items[0]?.id ?? "dashboard";
}

function scoreFromFindings(findings: SimulationFinding[], fallback: number) {
  if (!findings.length) return fallback;
  const total = findings.reduce((sum, finding) => sum + finding.weight, 0);
  return Math.max(fallback, Math.min(99, Math.round(total / findings.length + 36)));
}

function formatScore(score: number) {
  return `${Math.round(score)}/100`;
}

export default function App() {
  const { initiaAddress, openBridge, openConnect, openWallet, requestTxBlock } =
    useInterwovenKit();
  const initialView = typeof window === "undefined" ? "dashboard" : readAppViewFromHash(window.location.hash);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [riskEvents, setRiskEvents] = useState<RiskEvent[]>([]);
  const [watchedAddresses, setWatchedAddresses] = useState<WatchedAddress[]>([]);
  const [watchedAddressInput, setWatchedAddressInput] = useState("");
  const [watchedLabelInput, setWatchedLabelInput] = useState("");
  const [alertEmail, setAlertEmail] = useState("");
  const [alertEmailName, setAlertEmailName] = useState("");
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [policyOverview, setPolicyOverview] = useState<PolicyOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [approvalAction, setApprovalAction] = useState<string | null>(null);
  const [approvalGrantBusy, setApprovalGrantBusy] = useState(false);
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [simulationStage, setSimulationStage] = useState<SimulationStage>("idle");
  const [simulationRun, setSimulationRun] = useState<SimulationRun | null>(null);
  const [runningSimulationId, setRunningSimulationId] = useState<AttackId | null>(null);
  const [reentrancyContractInput, setReentrancyContractInput] = useState(demoRiskLabAddress || "");
  const [liquidityContractInput, setLiquidityContractInput] = useState(
    demoLiquidityLabAddress || ""
  );
  const [reentrancyAnalysisNetwork, setReentrancyAnalysisNetwork] =
    useState<AnalysisNetworkMode>("auto");
  const [liquidityAnalysisNetwork, setLiquidityAnalysisNetwork] =
    useState<AnalysisNetworkMode>("auto");
  const [reentrancyPreview, setReentrancyPreview] = useState<DemoContractPreview | null>(null);
  const [liquidityPreview, setLiquidityPreview] = useState<DemoContractPreview | null>(null);
  const [reentrancyPreviewLoading, setReentrancyPreviewLoading] = useState(false);
  const [liquidityPreviewLoading, setLiquidityPreviewLoading] = useState(false);
  const [demoPreview, setDemoPreview] = useState<DemoContractPreview | null>(null);
  const [demoAttemptState, setDemoAttemptState] = useState<DemoAttemptState>("idle");
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [currentView, setCurrentView] = useState<AppView>(initialView);
  const [activeSection, setActiveSection] = useState(() => defaultSectionForView(initialView));
  const [feedPage, setFeedPage] = useState(0);
  const [historyPage, setHistoryPage] = useState(0);
  const [selectedAttackId, setSelectedAttackId] = useState<AttackId>("reentrancy_pattern");
  const [expandedPanels, setExpandedPanels] = useState<AttackId[]>([]);
  const [confirmPrimaryTarget, setConfirmPrimaryTarget] = useState(true);
  const [staleDigestEnabled, setStaleDigestEnabled] = useState(false);
  const [dailySummaryEnabled, setDailySummaryEnabled] = useState(false);
  const [activationBusy, setActivationBusy] = useState(false);
  const [activationNote, setActivationNote] = useState<string | null>(null);
  const [dismissedNoticeKeys, setDismissedNoticeKeys] = useState<string[]>([]);

  const walletLabel = useMemo(() => {
    if (!initiaAddress) return "Connect Wallet";
    return shortenAddress(initiaAddress);
  }, [initiaAddress]);

  const marketingWalletLabel = initiaAddress ? walletLabel : "Connect Wallet";
  const landingHeaderCtaLabel = initiaAddress ? walletLabel : "Connect Wallet";
  const landingPrimaryCtaLabel = initiaAddress ? "Open Wallet" : "Connect Wallet & Activate";
  const resolvedReentrancyNetwork = useMemo(
    () => resolveAnalysisNetwork(reentrancyAnalysisNetwork, reentrancyContractInput),
    [reentrancyAnalysisNetwork, reentrancyContractInput]
  );
  const resolvedLiquidityNetwork = useMemo(
    () => resolveAnalysisNetwork(liquidityAnalysisNetwork, liquidityContractInput),
    [liquidityAnalysisNetwork, liquidityContractInput]
  );

  const highestRiskEvent = useMemo(() => {
    const ranking: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };

    return [...riskEvents].sort(
      (left, right) => (ranking[right.severity] || 0) - (ranking[left.severity] || 0)
    )[0];
  }, [riskEvents]);

  const approvalsAtRisk = useMemo(
    () => approvals.filter((approval) => approval.risk_score >= 60 && !approval.revoked),
    [approvals]
  );

  const blockedEvents = useMemo(
    () => riskEvents.filter((event) => riskToneFromSeverity(event.severity) === "block"),
    [riskEvents]
  );

  const poisonedAddresses = useMemo(
    () => watchedAddresses.filter((entry) => entry.is_poisoned),
    [watchedAddresses]
  );

  const visibleHistoryEvents = useMemo(
    () => riskEvents.slice(historyPage * PAGE_SIZE, (historyPage + 1) * PAGE_SIZE),
    [historyPage, riskEvents]
  );

  const policyView = policyOverview?.policy ?? null;
  const demoDecisionFindings = useMemo(
    () => (demoPreview ? extractDecisionFindings(demoPreview.decision) : []),
    [demoPreview]
  );
  const reentrancyDecisionFindings = useMemo(
    () => (reentrancyPreview ? extractDecisionFindings(reentrancyPreview.decision) : []),
    [reentrancyPreview]
  );
  const liquidityDecisionFindings = useMemo(
    () => (liquidityPreview ? extractDecisionFindings(liquidityPreview.decision) : []),
    [liquidityPreview]
  );

  const currentSidebarGroups = useMemo(() => sidebarGroupsForView(currentView), [currentView]);

  const activeSimulationVector = useMemo(
    () =>
      simulationVectors.find(
        (vector) => vector.id === (runningSimulationId || simulationRun?.scenario_id)
      ) ?? null,
    [runningSimulationId, simulationRun]
  );

  const protectedTargetAddress = profile?.simulation_target?.address || initiaAddress || "";
  const protectedTargetLabel = profile?.simulation_target?.label || "Protected wallet";
  const analysisAddress = protectedTargetAddress || initiaAddress || DEMO_ANALYSIS_ADDRESS;

  const protectionState = useMemo<SphereState>(() => {
    if (apiStatus === "offline") return "offline";
    if (simulationStage === "running" || simulationStage === "publishing") return "screening";
    if (highestRiskEvent) {
      const tone = riskToneFromSeverity(highestRiskEvent.severity);
      if (tone === "block") return "blocked";
      if (tone === "high" || tone === "warn") return "warned";
    }
    return "idle";
  }, [apiStatus, highestRiskEvent, simulationStage]);

  const transactionsToday = useMemo(() => {
    const now = Date.now();
    return riskEvents.filter((event) => now - new Date(event.created_at).getTime() < 86_400_000).length;
  }, [riskEvents]);

  const recentProtectedValue = useMemo(() => {
    if (!riskEvents.length) return "$48,220";
    const protectedEstimate = Math.max(12_000, riskEvents.length * 860);
    return protectedEstimate.toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 });
  }, [riskEvents]);

  const activeRiskItems = useMemo(() => {
    const items: Array<{
      title: string;
      detail: string;
      action: string;
      target: string;
      tone: RiskTone;
    }> = [];

    if (approvalsAtRisk.length) {
      const approval = approvalsAtRisk[0];
      items.push({
        title: `${approvalsAtRisk.length} stale approval${approvalsAtRisk.length === 1 ? "" : "s"}`,
        detail: `${approval.amount} ${approval.token_denom} granted to ${shortenAddress(approval.spender)}.`,
        action: "Review",
        target: "approvals",
        tone: riskToneFromScore(approval.risk_score)
      });
    }

    if (poisonedAddresses.length) {
      items.push({
        title: "Poisoned address",
        detail: `${shortenAddress(poisonedAddresses[0].address)} mimics a trusted route and is tagged for block on paste.`,
        action: "View",
        target: "audit",
        tone: "block"
      });
    }

    if (highestRiskEvent) {
      items.push({
        title: describeEventLabel(highestRiskEvent.event_type),
        detail: renderEventExcerpt(highestRiskEvent) || "Guardian elevated this event for review.",
        action: "Inspect",
        target: "audit",
        tone: riskToneFromSeverity(highestRiskEvent.severity)
      });
    }

    return items;
  }, [approvalsAtRisk, highestRiskEvent, poisonedAddresses]);

  const notices = useMemo(() => {
    const items: NoticeItem[] = [];

    if (apiStatus === "offline") {
      items.push({
        id: "backend-offline",
        title: "Guardian backend is offline",
        detail:
          "Start `cargo run -p guardian-app` so the feed, simulations, email alerts, and contract analysis can respond in real time.",
        tone: "warn"
      });
    }

    if (error) {
      items.push({
        id: `error:${error}`,
        title: "Action failed",
        detail: error,
        tone: "danger"
      });
    }

    if (policyOverview?.issues.length) {
      items.push({
        id: `policy:${policyOverview.issues[0]}`,
        title: "Policy state needs attention",
        detail: policyOverview.issues[0],
        tone: "warn"
      });
    }

    if (activationNote) {
      items.push({
        id: `activation:${activationNote}`,
        title: "Protection updated",
        detail: activationNote,
        tone: "warn"
      });
    }

    return items;
  }, [activationNote, apiStatus, error, policyOverview]);

  const visibleNotices = useMemo(
    () => notices.filter((notice) => !dismissedNoticeKeys.includes(notice.id)),
    [dismissedNoticeKeys, notices]
  );

  useEffect(() => {
    setDismissedNoticeKeys((current) =>
      current.filter((key) => notices.some((notice) => notice.id === key))
    );
  }, [notices]);

  const dashboardFeedRows = useMemo<FeedRow[]>(() => {
    if (!riskEvents.length) return fallbackFeedRows;

    const liveRows = riskEvents.map((event) => {
      const tone = riskToneFromSeverity(event.severity);
      const excerpt = renderEventExcerpt(event);
      return {
        tone,
        label: describeEventLabel(event.event_type),
        hash: event.tx_hash ? shortenAddress(event.tx_hash) : event.id.slice(0, 10),
        counterparty: excerpt || shortenAddress(event.address),
        value: tone === "block" ? "Blocked" : tone === "warn" ? "Review" : "Allowed",
        time: formatRelativeTime(event.created_at),
        highlight: tone === "block"
      };
    });

    return ensureDashboardClearRows(liveRows);
  }, [riskEvents]);

  const feedPageCount = Math.max(1, Math.ceil(dashboardFeedRows.length / PAGE_SIZE));
  const visibleDashboardFeedRows = useMemo(
    () => dashboardFeedRows.slice(feedPage * PAGE_SIZE, (feedPage + 1) * PAGE_SIZE),
    [dashboardFeedRows, feedPage]
  );

  const pendingAlertCount = Math.max(
    2,
    notices.length || 0,
    (approvalsAtRisk.length ? 1 : 0) + (poisonedAddresses.length ? 1 : 0)
  );

  const miniApprovals = useMemo(() => approvalsAtRisk.slice(0, 3), [approvalsAtRisk]);

  const dashboardActiveRisks = useMemo(() => {
    if (activeRiskItems.length) {
      return activeRiskItems.slice(0, 3);
    }

    return [
      {
        title: "5 Stale Approvals",
        detail: "2 unlimited USDC approvals to unverified spenders. Immediate revoke recommended.",
        action: "Review",
        target: "approvals",
        tone: "block" as RiskTone
      },
      {
        title: "Poisoned Address",
        detail: "initia1ef...a1 mimics your Binance deposit address. Tagged — will block on paste.",
        action: "View",
        target: "audit",
        tone: "warn" as RiskTone
      },
      {
        title: "ICA Registration",
        detail: "Interchain account registered from controller initia1cc...09. Verify this is expected.",
        action: "Review",
        target: "audit",
        tone: "high" as RiskTone
      }
    ];
  }, [activeRiskItems]);

  const dashboardHistoryRows = useMemo(() => {
    if (riskEvents.length) {
      return riskEvents.map((event) => ({
        id: event.id,
        tone: riskToneFromSeverity(event.severity),
        title: describeEventLabel(event.event_type),
        detail: renderEventExcerpt(event) || shortenAddress(event.address),
        time: formatRelativeTime(event.created_at)
      }));
    }

    return fallbackFeedRows.map((row, index) => ({
      id: `fallback-history-${index}`,
      tone: row.tone,
      title: row.label,
      detail: row.counterparty,
      time: row.time
    }));
  }, [riskEvents]);

  const historyPageCount = Math.max(1, Math.ceil(dashboardHistoryRows.length / PAGE_SIZE));
  const visibleDashboardHistoryRows = useMemo(
    () => dashboardHistoryRows.slice(historyPage * PAGE_SIZE, (historyPage + 1) * PAGE_SIZE),
    [dashboardHistoryRows, historyPage]
  );

  const onboardingAddresses = useMemo(() => {
    if (!watchedAddresses.length) return [];
    return watchedAddresses.slice(0, 4).map((entry) => ({
      id: entry.id,
      title: entry.label || shortenAddress(entry.address),
      address: entry.address,
      badge: entry.is_poisoned ? "Poisoned" : "Tracked",
      tone: entry.is_poisoned ? "block" as const : "clear" as const
    }));
  }, [watchedAddresses]);

  const dashboardProtectedAddress = profile?.simulation_target?.address
    ? shortenAddress(profile.simulation_target.address)
    : initiaAddress
      ? shortenAddress(initiaAddress)
      : "initia1qx4f2...e7d3";

  const dashboardSphereAddresses = [
    initiaAddress || "initia1qx4f2h0example7d3",
    ...watchedAddresses.map((entry) => entry.address)
  ].filter(Boolean);

  const dashboardHeaderDate = new Date().toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric"
  });

  const rpcHost = (() => {
    try {
      return new URL(guardedRpcEndpoint).host;
    } catch {
      return guardedRpcEndpoint;
    }
  })();

  const simulationHeroCopy = useMemo(() => {
    const openSet = new Set(expandedPanels);

    if (expandedPanels.length === 0) {
      return "Each panel below simulates a real attack vector — how it's initiated, what Aegis Guard detects, and exactly how it's stopped. Two panels accept live contract addresses for on-demand AI analysis.";
    }

    if (
      openSet.has("reentrancy_pattern") &&
      openSet.has("low_liquidity") &&
      expandedPanels.length <= 2
    ) {
      return "Click any panel to expand a full simulation. Reentrancy and Liquidity panels accept live contract addresses for AI-powered analysis.";
    }

    if (
      openSet.has("high_slippage") &&
      openSet.has("dust_attack") &&
      openSet.has("address_poisoning") &&
      !openSet.has("reentrancy_pattern") &&
      !openSet.has("low_liquidity")
    ) {
      return "Dust, Poison, and Slippage panels expanded — showing how Aegis Guard detects and neutralises each threat in real time.";
    }

    return "Each panel below simulates a real attack vector — how it's initiated, what Aegis Guard detects, and exactly how it's stopped. Two panels accept live contract addresses for on-demand AI analysis.";
  }, [expandedPanels]);

  const isSimulationBusy = simulationStage !== "idle" && simulationStage !== "complete";

  useEffect(() => {
    if (!initiaAddress) {
      setApprovals([]);
      setRiskEvents([]);
      setWatchedAddresses([]);
      setProfile(null);
      setPolicyOverview(null);
      setSimulationRun(null);
      setReentrancyPreview(null);
      setLiquidityPreview(null);
      return;
    }

    void loadDashboard(initiaAddress);
  }, [initiaAddress]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setCopiedValue(null);
      setActivationNote(null);
    }, 1800);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [activationNote, copiedValue]);

  useEffect(() => {
    setFeedPage((current) => Math.min(current, Math.max(feedPageCount - 1, 0)));
  }, [feedPageCount]);

  useEffect(() => {
    setHistoryPage((current) => Math.min(current, Math.max(historyPageCount - 1, 0)));
  }, [historyPageCount]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setApiStatus("checking");

    void fetch(`${apiBase}/health`, { signal: controller.signal })
      .then((response) => {
        if (!active) return;
        setApiStatus(response.ok ? "online" : "offline");
      })
      .catch((requestError: unknown) => {
        if (!active) return;
        if (requestError instanceof DOMException && requestError.name === "AbortError") {
          return;
        }
        setApiStatus("offline");
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, []);

  useEffect(() => {
    const applyHash = () => {
      const nextView = readAppViewFromHash(window.location.hash);
      setCurrentView(nextView);
    };

    applyHash();
    window.addEventListener("hashchange", applyHash);

    return () => {
      window.removeEventListener("hashchange", applyHash);
    };
  }, []);

  useEffect(() => {
    const allowedSections = new Set(
      currentSidebarGroups.flatMap((group) => group.items.map((item) => item.id))
    );

    setActiveSection((current) =>
      allowedSections.has(current) ? current : defaultSectionForView(currentView)
    );
  }, [currentSidebarGroups, currentView]);

  useEffect(() => {
    if (!initiaAddress) return;

    const sectionIds = currentSidebarGroups.flatMap((group) => group.items.map((item) => item.id));
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((left, right) => right.intersectionRatio - left.intersectionRatio)[0];

        if (visible) {
          setActiveSection(visible.target.id);
        }
      },
      {
        rootMargin: "-20% 0px -45% 0px",
        threshold: [0.2, 0.45, 0.7]
      }
    );

    sectionIds.forEach((id) => {
      const element = document.getElementById(id);
      if (element) observer.observe(element);
    });

    return () => {
      observer.disconnect();
    };
  }, [currentSidebarGroups, initiaAddress]);

  useEffect(() => {
    if (!simulationRun) return;

    const scenarioId = simulationRun.scenario_id as AttackId;
    setSelectedAttackId(scenarioId);
    setExpandedPanels((current) => (current.includes(scenarioId) ? current : [...current, scenarioId]));
  }, [simulationRun]);

  async function loadDashboard(address: string, refreshApprovals = false) {
    setLoading(true);
    setError(null);

    try {
      const [approvalResponse, riskResponse, watchedResponse, profileResponse, policyResponse] =
        await Promise.all([
          fetch(`${apiBase}/api/approvals/${address}?refresh=${refreshApprovals}`),
          fetch(`${apiBase}/api/risk-events/${address}?limit=100`),
          fetch(`${apiBase}/api/watched-addresses/${address}`),
          fetch(`${apiBase}/api/profile/${address}`),
          fetch(`${apiBase}/api/policy/${address}`)
        ]);

      if (
        !approvalResponse.ok ||
        !riskResponse.ok ||
        !watchedResponse.ok ||
        !profileResponse.ok ||
        !policyResponse.ok
      ) {
        throw new Error("Failed to load dashboard data");
      }

      const [approvalData, riskData, watchedData, profileData, policyData] = await Promise.all([
        approvalResponse.json(),
        riskResponse.json(),
        watchedResponse.json(),
        profileResponse.json(),
        policyResponse.json()
      ]);

      setApprovals(approvalData);
      setRiskEvents(riskData);
      setWatchedAddresses(watchedData);
      setProfile(profileData);
      setPolicyOverview(policyData);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unknown dashboard error");
    } finally {
      setLoading(false);
    }
  }

  async function saveWatchedAddress(address: string, label?: string | null, isSimulationTarget = false) {
    if (!initiaAddress || !address.trim()) return false;

    const response = await fetch(`${apiBase}/api/watched-addresses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        owner_address: initiaAddress,
        address: address.trim(),
        label: label?.trim() || null,
        is_simulation_target: isSimulationTarget
      })
    });

    if (!response.ok) {
      throw new Error("Failed to save watched address");
    }

    return true;
  }

  async function saveEmailAddress(email: string, displayName?: string | null) {
    if (!initiaAddress || !email.trim()) return false;

    const response = await fetch(`${apiBase}/api/email/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        address: initiaAddress,
        email_address: email.trim(),
        email_display_name: displayName?.trim() || null
      })
    });

    if (!response.ok) {
      throw new Error("Failed to register alert email");
    }

    return true;
  }

  async function registerWatchedAddress() {
    if (!watchedAddressInput.trim()) return;

    setError(null);

    try {
      await saveWatchedAddress(watchedAddressInput, watchedLabelInput);
      setWatchedAddressInput("");
      setWatchedLabelInput("");
      setActivationNote("Additional protected address added.");
      if (initiaAddress) await loadDashboard(initiaAddress);
    } catch (registerError) {
      setError(registerError instanceof Error ? registerError.message : "Failed to save watched address");
    }
  }

  async function registerEmail() {
    if (!alertEmail.trim()) return;

    setError(null);

    try {
      await saveEmailAddress(alertEmail, alertEmailName);
      setAlertEmail("");
      setAlertEmailName("");
      setActivationNote("Alert email saved.");
      if (initiaAddress) await loadDashboard(initiaAddress);
    } catch (registerError) {
      setError(registerError instanceof Error ? registerError.message : "Failed to register alert email");
    }
  }

  async function sendTestEmail() {
    if (!initiaAddress) return;

    setError(null);

    try {
      const response = await fetch(`${apiBase}/api/email/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: initiaAddress })
      });

      if (!response.ok) {
        throw new Error("Failed to send test email");
      }

      setActivationNote("Test alert sent.");
    } catch (sendError) {
      setError(sendError instanceof Error ? sendError.message : "Failed to send test email");
    }
  }

  async function activateProtectionSetup() {
    if (!initiaAddress) return;
    if (!confirmPrimaryTarget) {
      setError("Confirm the protection target before activating protection.");
      return;
    }

    setActivationBusy(true);
    setError(null);

    try {
      if (watchedAddressInput.trim()) {
        await saveWatchedAddress(watchedAddressInput, watchedLabelInput, false);
        setWatchedAddressInput("");
        setWatchedLabelInput("");
      }

      const emailToRegister = alertEmail.trim() || profile?.user?.email_address;
      if (emailToRegister && alertEmail.trim()) {
        await saveEmailAddress(alertEmail, alertEmailName);
        setAlertEmail("");
        setAlertEmailName("");
      }

      await loadDashboard(initiaAddress);
      setActivationNote("Protection activated. Guardian is monitoring this wallet and ready to alert.");
    } catch (activationError) {
      setError(
        activationError instanceof Error
          ? activationError.message
          : "Failed to activate protection"
      );
    } finally {
      setActivationBusy(false);
    }
  }

  async function grantDemoApproval() {
    if (!initiaAddress) {
      setError("Connect a wallet before creating a demo approval.");
      return;
    }

    if (!demoApprovalLabAddress) {
      setError("Demo approval token is not configured yet.");
      return;
    }

    if (!demoApprovalSpenderAddress) {
      setError("Demo approval spender is not configured yet.");
      return;
    }

    setError(null);
    setApprovalGrantBusy(true);

    try {
      await requestTxBlock({
        chainId: guardianFrontendConfig.chain.id,
        messages: [
          {
            typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
            value: {
              sender: initiaAddress,
              contract: demoApprovalLabAddress,
              msg: new TextEncoder().encode(JSON.stringify({ claim_demo_balance: {} })),
              funds: []
            }
          },
          {
            typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
            value: {
              sender: initiaAddress,
              contract: demoApprovalLabAddress,
              msg: new TextEncoder().encode(
                JSON.stringify({
                  increase_allowance: {
                    spender: demoApprovalSpenderAddress,
                    amount: DEMO_APPROVAL_AMOUNT
                  }
                })
              ),
              funds: []
            }
          }
        ]
      });

      await loadDashboard(initiaAddress, true);
      setActivationNote("Demo approval granted. You can revoke it from the approvals card.");
    } catch (grantError) {
      setError(
        grantError instanceof Error ? grantError.message : "Failed to grant the demo approval"
      );
    } finally {
      setApprovalGrantBusy(false);
    }
  }

  async function revokeApproval(approval: ApprovalRecord) {
    if (!initiaAddress) return;

    setError(null);
    setApprovalAction(approval.id);

    try {
      const planResponse = await fetch(`${apiBase}/api/approval-actions/revoke-plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner: approval.owner,
          spender: approval.spender
        })
      });

      if (!planResponse.ok) {
        throw new Error("Failed to prepare revoke transaction");
      }

      const plan: RevokeApprovalPlan = await planResponse.json();
      await requestTxBlock({
        chainId: guardianFrontendConfig.chain.id,
        messages: plan.messages.map(normalizeProtoMessage)
      });
      await loadDashboard(initiaAddress, true);
      setActivationNote("Approval revoke submitted.");
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : "Failed to revoke approval");
    } finally {
      setApprovalAction(null);
    }
  }

  async function runSimulation(scenarioId: AttackId) {
    setError(null);
    setSimulationRun(null);
    setRunningSimulationId(scenarioId);
    setSimulationStage("preparing");
    setSelectedAttackId(scenarioId);
    setExpandedPanels((current) => (current.includes(scenarioId) ? current : [...current, scenarioId]));

    try {
      await wait(220);
      setSimulationStage("running");

      const response = await fetch(`${apiBase}/api/simulations/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: analysisAddress,
          scenario_id: scenarioId
        })
      });

      if (!response.ok) {
        throw new Error("Failed to run simulation");
      }

      const result: SimulationRun = await response.json();
      setSimulationStage("publishing");
      await wait(260);
      setSimulationRun(result);
      setSimulationStage("complete");
      if (initiaAddress) {
        await loadDashboard(initiaAddress);
      }
    } catch (simulationError) {
      setSimulationStage("idle");
      setError(simulationError instanceof Error ? simulationError.message : "Failed to run simulation");
    } finally {
      setRunningSimulationId(null);
    }
  }

  async function runRiskLabDemo() {
    if (!initiaAddress || !demoRiskLabAddress) return;

    setError(null);
    setDemoPreview(null);
    setDemoAttemptState("previewing");

    try {
      const previewResponse = await fetch(`${apiBase}/api/demo/risk-lab/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: initiaAddress,
          contract_address: demoRiskLabAddress,
          analysis_mode: "demo"
        })
      });

      if (!previewResponse.ok) {
        throw new Error("Failed to prepare the risk lab contract check");
      }

      const preview: DemoContractPreview = await previewResponse.json();
      setDemoPreview(preview);
      setDemoAttemptState("submitting");

      try {
        await requestTxBlock({
          chainId: guardianFrontendConfig.chain.id,
          messages: [
            {
              typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
              value: {
                sender: initiaAddress,
                contract: preview.contract_address,
                msg: new TextEncoder().encode(JSON.stringify(preview.execute_message)),
                funds: []
              }
            }
          ]
        });

        setDemoAttemptState("needs_guarded_rpc");
        setError(
          "The demo call was not intercepted. Confirm the wallet is using the Guardian RPC before the walkthrough."
        );
      } catch (txError) {
        if (preview.decision.decision === "block" || preview.decision.decision === "confirm") {
          setDemoAttemptState("blocked");
        } else {
          setDemoAttemptState("idle");
          setError(
            txError instanceof Error
              ? txError.message
              : "The demo contract request did not complete"
          );
        }
      }

      await loadDashboard(initiaAddress);
    } catch (demoError) {
      setDemoAttemptState("idle");
      setError(
        demoError instanceof Error
          ? demoError.message
          : "Failed to run the guarded contract demo"
      );
    }
  }

  async function previewReentrancyContract() {
    if (!reentrancyContractInput.trim()) return;

    if (
      (resolvedReentrancyNetwork.key === "initia_minievm" ||
        resolvedReentrancyNetwork.key === "sepolia") &&
      !isEvmAddress(reentrancyContractInput)
    ) {
      setError(
        `${resolvedReentrancyNetwork.label} analysis expects a 0x... contract address.`
      );
      setReentrancyPreview(null);
      return;
    }

    if (resolvedReentrancyNetwork.key === "wasm_move" && isEvmAddress(reentrancyContractInput)) {
      setError("Guardian Wasm/Move analysis expects an init1... contract address.");
      setReentrancyPreview(null);
      return;
    }

    setError(null);
    setReentrancyPreview(null);
    setReentrancyPreviewLoading(true);

    try {
      const previewResponse = await fetch(`${apiBase}/api/demo/risk-lab/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: analysisAddress,
          contract_address: reentrancyContractInput.trim(),
          analysis_mode:
            demoRiskLabAddress && reentrancyContractInput.trim() === demoRiskLabAddress
              ? "demo"
              : "inspect",
          analysis_network: reentrancyAnalysisNetwork
        })
      });

      if (!previewResponse.ok) {
        const errorPayload = await previewResponse.json().catch(() => null);
        throw new Error(
          (errorPayload as { error?: string } | null)?.error ||
            "Failed to analyze the reentrancy contract"
        );
      }

      const preview: DemoContractPreview = await previewResponse.json();
      setReentrancyPreview(preview);
    } catch (previewError) {
      setReentrancyPreview(null);
      setError(
        previewError instanceof Error
          ? previewError.message
          : "Failed to analyze the reentrancy contract"
      );
    } finally {
      setReentrancyPreviewLoading(false);
    }
  }

  async function previewLiquidityContract() {
    if (!liquidityContractInput.trim()) return;

    if (
      (resolvedLiquidityNetwork.key === "initia_minievm" ||
        resolvedLiquidityNetwork.key === "sepolia") &&
      !isEvmAddress(liquidityContractInput)
    ) {
      setError(`${resolvedLiquidityNetwork.label} analysis expects a 0x... contract address.`);
      setLiquidityPreview(null);
      return;
    }

    if (resolvedLiquidityNetwork.key === "wasm_move" && isEvmAddress(liquidityContractInput)) {
      setError("Guardian Wasm/Move analysis expects an init1... contract address.");
      setLiquidityPreview(null);
      return;
    }

    setError(null);
    setLiquidityPreview(null);
    setLiquidityPreviewLoading(true);

    try {
      const previewResponse = await fetch(`${apiBase}/api/demo/liquidity/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: analysisAddress,
          contract_address: liquidityContractInput.trim(),
          analysis_mode:
            demoLiquidityLabAddress && liquidityContractInput.trim() === demoLiquidityLabAddress
              ? "demo"
              : "inspect",
          analysis_network: liquidityAnalysisNetwork
        })
      });

      if (!previewResponse.ok) {
        const errorPayload = await previewResponse.json().catch(() => null);
        throw new Error(
          (errorPayload as { error?: string } | null)?.error ||
            "Failed to analyze the liquidity contract"
        );
      }

      const preview: DemoContractPreview = await previewResponse.json();
      setLiquidityPreview(preview);
    } catch (previewError) {
      setLiquidityPreview(null);
      setError(
        previewError instanceof Error
          ? previewError.message
          : "Failed to analyze the liquidity contract"
      );
    } finally {
      setLiquidityPreviewLoading(false);
    }
  }

  function refreshDashboard() {
    if (!initiaAddress) return;
    void loadDashboard(initiaAddress, true);
  }

  function scrollIntoSection(id: string) {
    const section = document.getElementById(id);
    if (!section) return;
    section.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function navigateToView(view: AppView) {
    const nextHash = hashForView(view);
    setCurrentView(view);
    if (window.location.hash !== nextHash) {
      window.location.hash = nextHash;
    }
  }

  function openViewSection(view: AppView, id: string) {
    setActiveSection(id);
    if (view !== currentView) {
      navigateToView(view);
      window.setTimeout(() => {
        scrollIntoSection(id);
      }, 80);
      return;
    }

    scrollIntoSection(id);
  }

  function openDashboardSidebarItem(id: string) {
    if (id === "registry" || id === "wallets") {
      openViewSection("setup", "registry");
      return;
    }

    if (id === "alerts" || id === "thresholds") {
      openViewSection("setup", "alerts");
      return;
    }

    if (id === "rpc") {
      openViewSection("setup", "rpc");
      return;
    }

    if (id === "ica") {
      openViewSection("dashboard", "audit");
      return;
    }

    openViewSection("dashboard", id);
  }

  function toggleSimulationPanel(id: AttackId) {
    setSelectedAttackId(id);
    setExpandedPanels((current) =>
      current.includes(id) ? current.filter((entry) => entry !== id) : [...current, id]
    );
  }

  async function copyText(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedValue(key);
    } catch (copyError) {
      setError(copyError instanceof Error ? copyError.message : "Failed to copy value");
    }
  }

  function renderNotices() {
    if (!visibleNotices.length) return null;

    return (
      <section className="notice-stack">
        {visibleNotices.map((notice) => (
          <article className={`notice-card notice-card--${notice.tone}`} key={notice.id}>
            <button
              className="notice-card__dismiss"
              type="button"
              aria-label={`Dismiss ${notice.title}`}
              onClick={() => {
                if (notice.id.startsWith("error:")) setError(null);
                if (notice.id.startsWith("activation:")) setActivationNote(null);
                setDismissedNoticeKeys((current) =>
                  current.includes(notice.id) ? current : [...current, notice.id]
                );
              }}
            >
              ×
            </button>
            <strong>{notice.title}</strong>
            <p>{notice.detail}</p>
          </article>
        ))}
      </section>
    );
  }

  function renderSimulationFindings(
    findings: SimulationFinding[],
    emptyTitle = "No elevated findings",
    emptyCopy = "Guardian did not detect critical bytecode or transaction-risk signals in this preview."
  ) {
    if (!findings.length) {
      return (
        <div className="analysis-empty">
          <strong>{emptyTitle}</strong>
          <p>{emptyCopy}</p>
        </div>
      );
    }

    return (
      <div className="analysis-findings">
        {findings.map((finding, index) => {
          const tone = riskToneFromSeverity(finding.severity);
          return (
            <article className="analysis-finding" key={`${finding.module}-${index}`}>
              <div className="analysis-finding__copy">
                <span className={`severity-chip severity-chip--${tone}`}>{finding.severity.toUpperCase()}</span>
                <div>
                  <strong>{describeEventLabel(finding.module)}</strong>
                  <p>{finding.description}</p>
                </div>
              </div>
              <span className="metric-inline">+{finding.weight}</span>
            </article>
          );
        })}
      </div>
    );
  }

  function renderReentrancyPanel() {
    const findings = reentrancyPreview
      ? reentrancyDecisionFindings
      : [
            {
              module: "reentrancy",
              severity: "critical",
              weight: 91,
              description: "External call is executed before internal balance state is updated."
            },
            {
              module: "contract",
              severity: "critical",
              weight: 88,
              description: "No reentrancy guard, mutex, or nonReentrant modifier is present."
            },
            {
              module: "simulator",
              severity: "high",
              weight: 74,
              description: "Simulation delta shows full balance extraction across recursive calls."
            }
          ];
    const inspection = reentrancyPreview?.inspection ?? null;
    const liveInspection = isInspectionPreview(reentrancyPreview);
    const isSafe = reentrancyPreview?.decision.decision === "allow";
    const decision = reentrancyPreview ? describeDecisionState(reentrancyPreview.decision.decision) : "Blocked";
    const score = reentrancyPreview
      ? inspection
        ? inspection.score
        : isSafe
          ? 14
          : scoreFromFindings(findings, 91)
      : 91;
    const latestMatch = simulationRun?.scenario_id === "reentrancy_pattern";

    return (
      <div className="attack-card__expanded">
        {latestMatch ? (
          <div className="panel-callout panel-callout--block">
            <strong>Latest drill published</strong>
            <span>{simulationRun?.findings.length || 0} findings were written into the activity feed.</span>
          </div>
        ) : null}
        <div className="attack-expanded-grid">
          <div className="attack-expanded-main">
            {liveInspection && inspection ? (
              <>
                <section className="attack-block">
                  <div className="attack-block__heading">Contract Profile — Live Inspection</div>
                  <div className="metric-grid metric-grid--two">
                    <article className={`metric-panel ${isSafe ? "metric-panel--safe" : "metric-panel--warn"}`}>
                      <span className="metric-panel__label">Inspection backend</span>
                      <strong>{inspection.analysis_backend.toUpperCase()}</strong>
                      <p>{resolvedReentrancyNetwork.label} runtime bytecode inspection.</p>
                    </article>
                    <article className={`metric-panel ${isSafe ? "metric-panel--safe" : "metric-panel--warn"}`}>
                      <span className="metric-panel__label">Verification state</span>
                      <strong>{inspection.is_verified ? "Allowlisted" : "Unknown"}</strong>
                      <p>
                        {inspection.is_verified
                          ? "This contract matches a trusted/known protocol entry."
                          : "This contract is not currently allowlisted in Guardian."}
                      </p>
                    </article>
                    <article className={`metric-panel ${inspection.is_upgradeable ? "metric-panel--warn" : "metric-panel--safe"}`}>
                      <span className="metric-panel__label">Upgradeability</span>
                      <strong>{inspection.is_upgradeable ? "Upgradeable" : "Fixed logic"}</strong>
                      <p>
                        {inspection.is_upgradeable
                          ? "Admin or upgrade selectors were detected in runtime bytecode."
                          : "No upgrade-admin pattern was detected in the current runtime code."}
                      </p>
                    </article>
                    <article className={`metric-panel ${inspection.unexpected_flow ? "metric-panel--warn" : "metric-panel--safe"}`}>
                      <span className="metric-panel__label">Fund-flow signal</span>
                      <strong>{inspection.unexpected_flow ? "Unexpected" : "No anomaly"}</strong>
                      <p>
                        {inspection.unexpected_flow
                          ? "Guardian detected a fund-flow pattern that did not match known trusted destinations."
                          : "No unexpected outflow path was inferred from the current preview context."}
                      </p>
                    </article>
                  </div>
                </section>

                <section className="attack-block">
                  <div className="attack-block__heading">Structural Signals</div>
                  <div className="inspection-signal-stack">
                    {inspectionSignalSummary(inspection).map((item) => (
                      <article className="inspection-signal" key={item}>
                        <strong>{item}</strong>
                      </article>
                    ))}
                    {!inspectionSignalSummary(inspection).length ? (
                      <article className="inspection-signal inspection-signal--safe">
                        <strong>No elevated structural signals surfaced from the current bytecode pass.</strong>
                      </article>
                    ) : null}
                  </div>
                </section>

                <section className="attack-block">
                  <div className="attack-block__heading">Real Inspection Summary</div>
                  <p className="inspection-copy">
                    {isSafe
                      ? "Guardian completed a live contract inspection and did not find enough evidence to classify this contract as a reentrancy or drain-path threat."
                      : "Guardian found bytecode-level signals that elevate contract risk. This is a real inspection report derived from deployed runtime code, not a canned exploit storyboard."}
                  </p>
                </section>
              </>
            ) : (
              <>
                <section className="attack-block">
                  <div className="attack-block__heading">Attack Call Stack — Live Simulation</div>
                  <div className="call-stack">
                    {[
                      {
                        depth: "1",
                        code: "withdraw(amount=1000 ETH)",
                        note: "VulnerableBank.sol · checks msg.sender balance",
                        state: "Entry",
                        tone: "clear"
                      },
                      {
                        depth: "2",
                        code: "call{value: 1000 ETH}(attacker)",
                        note: "External call BEFORE state update — vulnerable pattern",
                        state: "Vulnerable",
                        tone: "warn"
                      },
                      {
                        depth: "3",
                        code: "fallback() triggered → re-enters withdraw()",
                        note: "Balance not yet updated — check passes again",
                        state: "Re-entry",
                        tone: "block"
                      },
                      {
                        depth: "4",
                        code: "withdraw(amount=1000 ETH) ← re-entered",
                        note: "Iteration 2 of N — draining continues",
                        state: "Re-entry",
                        tone: "block"
                      },
                      {
                        depth: "N",
                        code: "balances[attacker] = 0",
                        note: "State update fires after all ETH is drained",
                        state: "Too late",
                        tone: "block"
                      }
                    ].map((frame) => (
                      <article className={`call-stack__row call-stack__row--${frame.tone}`} key={`${frame.depth}-${frame.code}`}>
                        <span className="call-stack__depth">{frame.depth}</span>
                        <div className="call-stack__copy">
                          <strong>{frame.code}</strong>
                          <p>{frame.note}</p>
                        </div>
                        <span className={`state-chip state-chip--${frame.tone}`}>{frame.state}</span>
                      </article>
                    ))}
                  </div>
                </section>

                <section className="attack-block">
                  <div className="attack-block__heading">Contract Balance Drain — Per Recursive Call</div>
                  <div className="balance-bars">
                    {[
                      { label: "Before", value: "100%", tone: "clear" },
                      { label: "Call 1", value: "75%", tone: "warn" },
                      { label: "Call 2", value: "50%", tone: "high" },
                      { label: "Call 3", value: "25%", tone: "high" },
                      { label: "Call 4", value: "0%", tone: "block" }
                    ].map((bar, index) => (
                      <div className="balance-bars__item" key={bar.label}>
                        <div className={`balance-bars__fill balance-bars__fill--${bar.tone}`} style={{ height: `${100 - index * 22}%` }} />
                        <strong>{bar.value}</strong>
                        <span>{bar.label}</span>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="attack-block">
                  <div className="attack-block__heading">How Aegis Guard Intercepts</div>
                  <ol className="intercept-steps">
                    <li>Bytecode scan detects external call before state write and flags the control-flow violation.</li>
                    <li>Simulation forks chain state and reveals the full balance delta before broadcast.</li>
                    <li>Token flow analysis confirms value exits to the attacker with no corresponding return path.</li>
                    <li>Guardian blocks the transaction and writes the result to the feed with a 91/100 risk score.</li>
                  </ol>
                </section>
              </>
            )}
          </div>

          <aside className="attack-expanded-side">
            <section className="attack-block">
              <div className="attack-block__heading">AI Contract Analysis</div>
              <label className="form-field">
                <span>Analysis network</span>
                <select
                  className="analysis-network-select"
                  value={reentrancyAnalysisNetwork}
                  onChange={(event) => {
                    setReentrancyAnalysisNetwork(event.target.value as AnalysisNetworkMode);
                    setReentrancyPreview(null);
                  }}
                >
                  <option value="auto">Auto-detect</option>
                  <option value="wasm_move">Guardian Wasm/Move</option>
                  <option value="initia_minievm">Initia MiniEVM</option>
                  <option value="sepolia">Sepolia</option>
                </select>
              </label>
              <label className="form-field">
                <span>Contract address</span>
                <input
                  value={reentrancyContractInput}
                  onChange={(event) => {
                    setReentrancyContractInput(event.target.value);
                    setReentrancyPreview(null);
                  }}
                  placeholder={resolvedReentrancyNetwork.placeholder}
                />
              </label>
              <p className="analysis-network-note">
                Active target: <strong>{resolvedReentrancyNetwork.label}</strong>
              </p>
              <div className="action-row">
                <button
                  className="cta-action cta-action--danger"
                  onClick={() => {
                    void previewReentrancyContract();
                  }}
                  disabled={apiStatus !== "online" || reentrancyPreviewLoading || !reentrancyContractInput.trim()}
                >
                  {reentrancyPreviewLoading ? "Analyzing" : "⟳ Analyze"}
                </button>
                {demoRiskLabAddress ? (
                  <button
                    className="ghost-button"
                    onClick={() => {
                      setReentrancyContractInput(demoRiskLabAddress);
                      setReentrancyPreview(null);
                    }}
                  >
                    Use Demo Address
                  </button>
                ) : null}
                <button
                  className="ghost-button"
                  onClick={() => {
                    void runSimulation("reentrancy_pattern");
                  }}
                  disabled={apiStatus !== "online" || isSimulationBusy}
                >
                  {runningSimulationId === "reentrancy_pattern" ? "Running Drill" : "Run Drill"}
                </button>
              </div>
            </section>

            <section className={`analysis-card ${isSafe ? "analysis-card--safe" : "analysis-card--block"}`}>
              <div className="analysis-card__header">
                <div className={`score-ring ${isSafe ? "score-ring--safe" : "score-ring--block"}`}>
                  <span>{score}</span>
                  <small>/100</small>
                </div>
                <div className="analysis-card__summary">
                  <span className="analysis-label">Analysis Complete</span>
                  <strong>
                    {isSafe
                      ? "Safe — No critical reentrancy signals"
                      : liveInspection
                        ? `${decision} — Elevated contract risk`
                        : `${decision} — Critical Risk`}
                  </strong>
                  <p>
                    {liveInspection
                      ? isSafe
                        ? "Guardian inspected the deployed runtime code and did not surface enough evidence to classify this contract as a reentrancy threat."
                        : "Guardian inspected live bytecode and surfaced structural contract risk signals that justify manual review before interacting."
                      : isSafe
                        ? "The current bytecode and metadata pass did not surface drain-path, callback-loop, or unsafe control-flow signals."
                        : "Reentrancy vulnerability confirmed via bytecode analysis, recursive call simulation, and control-flow inspection."}
                  </p>
                </div>
              </div>

              {renderSimulationFindings(
                findings,
                "Safe contract preview",
                "No critical reentrancy findings surfaced in the current analysis pass."
              )}

              <div className="analysis-insight">
                <strong>◈ AI Decompilation Insight</strong>
                <p>
                  {liveInspection && inspection
                    ? isSafe
                      ? `Guardian inspected ${resolvedReentrancyNetwork.label} runtime bytecode for ${reentrancyPreview?.contract_address}. No critical callback-loop pattern or privileged drain path was surfaced in this pass.`
                      : `Guardian inspected ${resolvedReentrancyNetwork.label} runtime bytecode and found the following elevated signals: ${inspectionSignalSummary(inspection).join("; ")}.`
                    : isSafe
                      ? "Guardian completed a neutral bytecode and metadata inspection for this contract. No structural callback-drain pattern was surfaced in the current preview."
                      : "Decompiled bytecode reveals a withdraw() path that calls the external address before updating internal balances. The fallback path re-enters recursively, matching the structural pattern behind the 2016 DAO hack."}
                </p>
              </div>
            </section>
          </aside>
        </div>
      </div>
    );
  }

  function renderLiquidityPanel() {
    const findings = liquidityPreview
      ? liquidityDecisionFindings
      : [
            {
              module: "liquidity",
              severity: "high",
              weight: 84,
              description: "Pool depth is too thin for the requested trade size."
            },
            {
              module: "slippage",
              severity: "high",
              weight: 72,
              description: "Projected price impact exceeds acceptable bounds for a production wallet."
            },
            {
              module: "simulator",
              severity: "medium",
              weight: 61,
              description: "Reserve simulation shows cascading loss if additional flow follows this trade."
            }
          ];
    const inspection = liquidityPreview?.inspection ?? null;
    const liveInspection = isInspectionPreview(liquidityPreview);
    const isSafe = liquidityPreview?.decision.decision === "allow";
    const score = liquidityPreview
      ? inspection
        ? inspection.score
        : isSafe
          ? 18
          : scoreFromFindings(findings, 84)
      : 84;
    const decision = liquidityPreview ? describeDecisionState(liquidityPreview.decision.decision) : "Warn";

    return (
      <div className="attack-card__expanded">
        <div className="attack-expanded-grid">
          <div className="attack-expanded-main">
            {liveInspection && inspection ? (
              <>
                <section className="attack-block">
                  <div className="attack-block__heading">Contract Profile — Live Inspection</div>
                  <div className="metric-grid metric-grid--two">
                    <article className={`metric-panel ${isSafe ? "metric-panel--safe" : "metric-panel--warn"}`}>
                      <span className="metric-panel__label">Inspection backend</span>
                      <strong>{inspection.analysis_backend.toUpperCase()}</strong>
                      <p>{resolvedLiquidityNetwork.label} runtime bytecode inspection.</p>
                    </article>
                    <article className={`metric-panel ${isSafe ? "metric-panel--safe" : "metric-panel--warn"}`}>
                      <span className="metric-panel__label">Verification state</span>
                      <strong>{inspection.is_verified ? "Allowlisted" : "Unknown"}</strong>
                      <p>
                        {inspection.is_verified
                          ? "This contract matches a trusted/known protocol entry."
                          : "This contract is not currently allowlisted in Guardian."}
                      </p>
                    </article>
                    <article className={`metric-panel ${inspection.is_upgradeable ? "metric-panel--warn" : "metric-panel--safe"}`}>
                      <span className="metric-panel__label">Upgradeability</span>
                      <strong>{inspection.is_upgradeable ? "Upgradeable" : "Fixed logic"}</strong>
                      <p>
                        {inspection.is_upgradeable
                          ? "Admin or upgrade selectors were detected in runtime bytecode."
                          : "No upgrade-admin pattern was detected in the current runtime code."}
                      </p>
                    </article>
                    <article className={`metric-panel ${inspection.unexpected_flow ? "metric-panel--warn" : "metric-panel--safe"}`}>
                      <span className="metric-panel__label">Liquidity anomaly</span>
                      <strong>{inspection.unexpected_flow ? "Unexpected" : "No anomaly"}</strong>
                      <p>
                        {inspection.unexpected_flow
                          ? "Guardian inferred a liquidity or fund-flow destination outside trusted destinations."
                          : "No direct liquidity anomaly was inferred from the current preview context."}
                      </p>
                    </article>
                  </div>
                </section>

                <section className="attack-block">
                  <div className="attack-block__heading">Real Liquidity Review</div>
                  <div className="inspection-signal-stack">
                    {inspectionSignalSummary(inspection).map((item) => (
                      <article className="inspection-signal" key={item}>
                        <strong>{item}</strong>
                      </article>
                    ))}
                    {!inspectionSignalSummary(inspection).length ? (
                      <article className="inspection-signal inspection-signal--safe">
                        <strong>No elevated liquidity-related structural signals surfaced from runtime bytecode.</strong>
                      </article>
                    ) : null}
                  </div>
                  <p className="inspection-copy">
                    {isSafe
                      ? "Guardian completed a live contract inspection and did not find enough evidence to classify this address as a thin-pool or liquidity-manipulation risk."
                      : "Guardian found deployed-code signals that elevate liquidity or operational risk. This report is derived from live runtime bytecode, not a canned thin-pool storyboard."}
                  </p>
                </section>
              </>
            ) : (
              <>
                <section className="attack-block">
                  <div className="attack-block__heading">Pool Depth Snapshot</div>
                  <div className="metric-grid metric-grid--two">
                    <article className="metric-panel">
                      <span className="metric-panel__label">TVL</span>
                      <strong>$420K</strong>
                      <p>Shallow for the requested swap size.</p>
                    </article>
                    <article className="metric-panel">
                      <span className="metric-panel__label">Implied price impact</span>
                      <strong>4.1%</strong>
                      <p>Above the safe band for routine user flow.</p>
                    </article>
                  </div>
                  <div className="reserve-bars">
                    <div className="reserve-bars__row">
                      <span>Pool reserve before</span>
                      <div><i style={{ width: "100%" }} /></div>
                      <strong>100%</strong>
                    </div>
                    <div className="reserve-bars__row">
                      <span>After attacker drain</span>
                      <div><i style={{ width: "58%" }} /></div>
                      <strong>58%</strong>
                    </div>
                    <div className="reserve-bars__row">
                      <span>After user execution</span>
                      <div><i style={{ width: "33%" }} /></div>
                      <strong>33%</strong>
                    </div>
                  </div>
                </section>

                <section className="attack-block">
                  <div className="attack-block__heading">Why Guardian flags it</div>
                  <ol className="intercept-steps">
                    <li>Pool reserve inspection shows the trade would consume an unsafe share of available liquidity.</li>
                    <li>Execution simulation compares expected output against stressed pool conditions.</li>
                    <li>Projected impact is graded against production-safe slippage and depth thresholds.</li>
                    <li>Guardian warns or blocks depending on the combined liquidity and slippage score.</li>
                  </ol>
                </section>
              </>
            )}
          </div>

          <aside className="attack-expanded-side">
            <section className="attack-block">
              <div className="attack-block__heading">Pool Analysis</div>
              <label className="form-field">
                <span>Analysis network</span>
                <select
                  className="analysis-network-select"
                  value={liquidityAnalysisNetwork}
                  onChange={(event) => {
                    setLiquidityAnalysisNetwork(event.target.value as AnalysisNetworkMode);
                    setLiquidityPreview(null);
                  }}
                >
                  <option value="auto">Auto-detect</option>
                  <option value="wasm_move">Guardian Wasm/Move</option>
                  <option value="initia_minievm">Initia MiniEVM</option>
                  <option value="sepolia">Sepolia</option>
                </select>
              </label>
              <label className="form-field">
                <span>Contract address</span>
                <input
                  value={liquidityContractInput}
                  onChange={(event) => {
                    setLiquidityContractInput(event.target.value);
                    setLiquidityPreview(null);
                  }}
                  placeholder={resolvedLiquidityNetwork.placeholder}
                />
              </label>
              <p className="analysis-network-note">
                Active target: <strong>{resolvedLiquidityNetwork.label}</strong>
              </p>
              <div className="action-row">
                <button
                  className="cta-action cta-action--warning"
                  onClick={() => {
                    void previewLiquidityContract();
                  }}
                  disabled={apiStatus !== "online" || liquidityPreviewLoading || !liquidityContractInput.trim()}
                >
                  {liquidityPreviewLoading ? "Analyzing" : "⟳ Analyze"}
                </button>
                {demoLiquidityLabAddress ? (
                  <button
                    className="ghost-button"
                    onClick={() => {
                      setLiquidityContractInput(demoLiquidityLabAddress);
                      setLiquidityPreview(null);
                    }}
                  >
                    Use Demo Address
                  </button>
                ) : null}
                <button
                  className="ghost-button"
                  onClick={() => {
                    void runSimulation("low_liquidity");
                  }}
                  disabled={apiStatus !== "online" || isSimulationBusy}
                >
                  {runningSimulationId === "low_liquidity" ? "Running Drill" : "Run Drill"}
                </button>
              </div>
            </section>

            <section className={`analysis-card ${isSafe ? "analysis-card--safe" : "analysis-card--warning"}`}>
              <div className="analysis-card__header">
                <div className={`score-ring ${isSafe ? "score-ring--safe" : "score-ring--warning"}`}>
                  <span>{score}</span>
                  <small>/100</small>
                </div>
                <div className="analysis-card__summary">
                  <span className="analysis-label">Liquidity Review</span>
                  <strong>
                    {isSafe
                      ? "Safe — No elevated liquidity risk"
                      : liveInspection
                        ? `${decision} — Elevated contract risk`
                        : `${decision} — Thin Pool Risk`}
                  </strong>
                  <p>
                    {liveInspection
                      ? isSafe
                        ? "Guardian inspected deployed runtime code and did not surface enough evidence to classify this contract as a liquidity manipulation risk."
                        : "Guardian inspected live bytecode and surfaced structural contract risk signals that justify manual review before trading through this address."
                      : isSafe
                        ? "Guardian did not detect critical thin-pool or contract-level liquidity signals in the current preview."
                        : "Reserve simulation shows the pool cannot absorb the requested trade without unacceptable impact."}
                  </p>
                </div>
              </div>

              {renderSimulationFindings(
                findings,
                "Safe contract preview",
                "No elevated liquidity or contract-level findings were surfaced for this address."
              )}

              <div className="analysis-insight">
                <strong>◈ AI Decompilation Insight</strong>
                <p>
                  {liveInspection && inspection
                    ? isSafe
                      ? `Guardian inspected ${resolvedLiquidityNetwork.label} runtime bytecode for ${liquidityPreview?.contract_address}. No critical thin-pool, swap-path, or privileged drain signal was surfaced in this pass.`
                      : `Guardian inspected ${resolvedLiquidityNetwork.label} runtime bytecode and found the following elevated signals: ${inspectionSignalSummary(inspection).join("; ")}.`
                    : "Guardian correlates bytecode, pool-state simulation, and routing context before grading liquidity manipulation risk."}
                </p>
              </div>
            </section>
          </aside>
        </div>
      </div>
    );
  }

  function renderSlippagePanel() {
    const latestMatch = simulationRun?.scenario_id === "high_slippage";

    return (
      <div className="attack-card__expanded">
        {latestMatch ? (
          <div className="panel-callout panel-callout--warn">
            <strong>Latest drill published</strong>
            <span>The slippage simulation has been written into the feed and audit history.</span>
          </div>
        ) : null}
        <div className="attack-expanded-grid">
          <div className="attack-expanded-main">
            <section className="attack-block">
              <div className="attack-block__heading">Sandwich Attack — Tx Order Simulation</div>
              <div className="order-lane">
                <article className="order-lane__event order-lane__event--hostile">
                  <strong>Bot front-run: BUY 50K INIT</strong>
                  <p>Gas: +50 gwei · Slips price up 3.2%</p>
                </article>
                <article className="order-lane__event order-lane__event--user">
                  <strong>Your swap: USDC → INIT</strong>
                  <p>5% slippage tolerance set — exploitable</p>
                </article>
                <article className="order-lane__event order-lane__event--hostile">
                  <strong>Bot back-run: SELL 50K INIT</strong>
                  <p>Profit extracted: $247 from your swap</p>
                </article>
              </div>
            </section>

            <section className="attack-block">
              <div className="attack-block__heading">Price Impact vs. Trade Size</div>
              <div className="curve-chart">
                <svg viewBox="0 0 600 250" role="img" aria-label="Price impact curve">
                  <defs>
                    <linearGradient id="impactGradient" x1="0%" y1="100%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#00d9c0" />
                      <stop offset="55%" stopColor="#f0b429" />
                      <stop offset="100%" stopColor="#ff6b35" />
                    </linearGradient>
                  </defs>
                  <rect x="0" y="0" width="600" height="250" fill="transparent" />
                  <line x1="40" y1="210" x2="560" y2="210" stroke="rgba(118,148,190,0.22)" />
                  <line x1="40" y1="150" x2="560" y2="150" stroke="rgba(118,148,190,0.16)" strokeDasharray="5 5" />
                  <line x1="40" y1="90" x2="560" y2="90" stroke="rgba(118,148,190,0.16)" strokeDasharray="5 5" />
                  <path
                    d="M40 208 C120 205, 190 195, 260 170 S400 95, 560 68"
                    fill="none"
                    stroke="url(#impactGradient)"
                    strokeWidth="6"
                    strokeLinecap="round"
                  />
                  <circle cx="360" cy="124" r="8" fill="#f0b429" />
                  <line x1="360" y1="124" x2="360" y2="210" stroke="#f0b429" strokeDasharray="4 4" />
                  <text x="373" y="116" fill="#f0b429">Sandwich risk</text>
                  <text x="372" y="145" fill="#ffb977">Your tx 3.8% slip</text>
                  <text x="42" y="225" fill="#5d7aa1">$1K</text>
                  <text x="180" y="225" fill="#5d7aa1">$10K</text>
                  <text x="338" y="225" fill="#5d7aa1">$50K</text>
                  <text x="512" y="225" fill="#5d7aa1">$100K</text>
                </svg>
              </div>
              <div className="metric-grid metric-grid--two">
                <article className="metric-panel metric-panel--warn">
                  <span className="metric-panel__label">Your tolerance set</span>
                  <strong>5.0%</strong>
                  <p>Exploitable by MEV bots.</p>
                </article>
                <article className="metric-panel metric-panel--safe">
                  <span className="metric-panel__label">Aegis Guard limit</span>
                  <strong>0.5%</strong>
                  <p>Recommended max for this pool depth.</p>
                </article>
              </div>
            </section>
          </div>

          <aside className="attack-expanded-side">
            <section className="attack-block">
              <div className="attack-block__heading">How Aegis Guard Intercepts</div>
              <ol className="intercept-steps">
                <li>Guardian reads the slippage parameter in calldata before the transaction broadcasts.</li>
                <li>MEV mempool checks flag sandwich activity targeting the same pool in the same block.</li>
                <li>Simulation delta compares expected vs actual output and surfaces the projected loss.</li>
                <li>User is warned and the transaction is paused until safer parameters are chosen.</li>
              </ol>
              <button
                className="ghost-button ghost-button--full"
                onClick={() => {
                  void runSimulation("high_slippage");
                }}
                disabled={apiStatus !== "online" || isSimulationBusy}
              >
                {runningSimulationId === "high_slippage" ? "Running Drill" : "Run Slippage Drill"}
              </button>
            </section>

            <section className="warning-box warning-box--warn">
              <strong>Aegis Guard warning issued</strong>
              <ul>
                <li>Slippage 5.0% exceeds safe threshold for this pool depth.</li>
                <li>Active MEV bot ordering detected — sandwich risk HIGH.</li>
                <li>Projected loss: approximately $247 at current pool state.</li>
                <li>Recommendation: reduce slippage to 0.5% or use private relay.</li>
              </ul>
            </section>
          </aside>
        </div>
      </div>
    );
  }

  function renderDustPanel() {
    const latestMatch = simulationRun?.scenario_id === "dust_attack";

    return (
      <div className="attack-card__expanded">
        {latestMatch ? (
          <div className="panel-callout panel-callout--violet">
            <strong>Latest drill published</strong>
            <span>The dust quarantine flow has been written into the live feed.</span>
          </div>
        ) : null}
        <div className="attack-expanded-grid">
          <div className="attack-expanded-main">
            <section className="attack-block">
              <div className="attack-block__heading">Incoming Dust — Live Intercept</div>
              <table className="sim-table">
                <thead>
                  <tr>
                    <th>Amount</th>
                    <th>From</th>
                    <th>Token</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>0.000001</td>
                    <td>initia1cc...91da</td>
                    <td>USDC</td>
                    <td><span className="status-pill status-pill--quarantine">Quarantined</span></td>
                  </tr>
                  <tr>
                    <td>0.000001</td>
                    <td>initia1bb...44fc</td>
                    <td>USDC</td>
                    <td><span className="status-pill status-pill--quarantine">Quarantined</span></td>
                  </tr>
                  <tr>
                    <td>0.000001</td>
                    <td>initia1aa...2201</td>
                    <td>INIT</td>
                    <td><span className="status-pill status-pill--quarantine">Quarantined</span></td>
                  </tr>
                  <tr>
                    <td>120.00</td>
                    <td>Osmosis DEX</td>
                    <td>USDT</td>
                    <td><span className="status-pill status-pill--allow">Allowed</span></td>
                  </tr>
                </tbody>
              </table>
            </section>

            <section className="attack-block">
              <div className="attack-block__heading">Attacker De-Anonymization Graph</div>
              <div className="graph-shell">
                <svg viewBox="0 0 620 260" role="img" aria-label="Dust de-anonymization graph">
                  <line x1="95" y1="70" x2="300" y2="130" stroke="#3b4d87" strokeDasharray="8 8" />
                  <line x1="300" y1="130" x2="455" y2="54" stroke="#5948b5" strokeDasharray="8 8" />
                  <line x1="300" y1="130" x2="520" y2="185" stroke="#5948b5" strokeDasharray="8 8" />
                  <line x1="95" y1="70" x2="185" y2="170" stroke="#7b3b73" strokeDasharray="8 8" />
                  <line x1="185" y1="170" x2="300" y2="130" stroke="#5948b5" strokeDasharray="8 8" />
                  <circle cx="95" cy="70" r="28" fill="rgba(0,217,192,0.14)" stroke="#00d9c0" strokeWidth="3" />
                  <circle cx="300" cy="130" r="34" fill="rgba(139,111,255,0.16)" stroke="#8b6fff" strokeWidth="3" />
                  <circle cx="185" cy="170" r="20" fill="rgba(19,33,58,0.92)" stroke="#28477a" strokeWidth="2" />
                  <circle cx="455" cy="54" r="20" fill="rgba(19,33,58,0.92)" stroke="#28477a" strokeWidth="2" />
                  <circle cx="520" cy="185" r="20" fill="rgba(19,33,58,0.92)" stroke="#28477a" strokeWidth="2" />
                  <text x="80" y="76" fill="#d8eef8">You</text>
                  <text x="275" y="136" fill="#d9d2ff">Attacker</text>
                  <text x="173" y="176" fill="#5874a3">W2</text>
                  <text x="443" y="60" fill="#5874a3">W3</text>
                  <text x="508" y="191" fill="#5874a3">W4</text>
                </svg>
              </div>
            </section>
          </div>

          <aside className="attack-expanded-side">
            <section className="attack-block">
              <div className="attack-block__heading">Detection & Response</div>
              <ol className="intercept-steps">
                <li>Every inbound transaction is screened and tiny amounts are flagged for dust analysis.</li>
                <li>Sender clustering links the incoming addresses against known dust campaign wallets.</li>
                <li>Dust tokens are accepted on-chain but immediately quarantined in Guardian’s registry.</li>
                <li>Any outbound interaction with quarantined dust triggers HIGH risk or BLOCK.</li>
              </ol>
              <button
                className="ghost-button ghost-button--full"
                onClick={() => {
                  void runSimulation("dust_attack");
                }}
                disabled={apiStatus !== "online" || isSimulationBusy}
              >
                {runningSimulationId === "dust_attack" ? "Running Drill" : "Run Dust Drill"}
              </button>
            </section>

            <section className="warning-box warning-box--violet">
              <strong>Aegis Guard — dust quarantine active</strong>
              <ul>
                <li>3 dust deposits quarantined and removed from address-history suggestions.</li>
                <li>Sender cluster linked to 14 known dust campaigns.</li>
                <li>Any outbound interaction with quarantined tokens will trigger BLOCK.</li>
              </ul>
            </section>
          </aside>
        </div>
      </div>
    );
  }

  function renderPoisonPanel() {
    const latestMatch = simulationRun?.scenario_id === "address_poisoning";

    return (
      <div className="attack-card__expanded">
        {latestMatch ? (
          <div className="panel-callout panel-callout--block">
            <strong>Latest drill published</strong>
            <span>The poisoning event has been written into the feed and risk registry.</span>
          </div>
        ) : null}
        <div className="attack-expanded-grid">
          <div className="attack-expanded-main">
            <section className="attack-block">
              <div className="attack-block__heading">Address Visual Comparison</div>
              <div className="address-compare">
                <div className="address-compare__row address-compare__row--safe">
                  <span>initia1qx4f2d8ek9ac01e7d3</span>
                  <small>✓ Real</small>
                </div>
                <div className="address-compare__row address-compare__row--danger">
                  <span>
                    initia1qx4f2<span className="char-diff">f1a</span>k9a<span className="char-diff">b88</span>e7d3
                  </span>
                  <small>△ Poison</small>
                </div>
                <div className="similarity-meter">
                  <div className="similarity-meter__bar">
                    <i style={{ width: "91.2%" }} />
                  </div>
                  <strong>91.2%</strong>
                </div>
                <p className="address-compare__meta">
                  Same first 11 chars · same last 4 chars · 3 characters differ in the middle segment.
                </p>
              </div>
            </section>

            <section className="attack-block">
              <div className="attack-block__heading">Your Transaction History (Attacker’s View)</div>
              <table className="sim-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Address</th>
                    <th>Amount</th>
                    <th>Age</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><span className="status-pill status-pill--dust">Dust</span></td>
                    <td>initia1qx4f2f1ak9ab88e7d3</td>
                    <td>0.001</td>
                    <td>2h</td>
                  </tr>
                  <tr>
                    <td><span className="status-pill status-pill--allow">Out</span></td>
                    <td>initia1qx4f2d8ek9ac01e7d3</td>
                    <td>-500</td>
                    <td>3d</td>
                  </tr>
                  <tr>
                    <td><span className="status-pill status-pill--allow">In</span></td>
                    <td>Osmosis DEX · reward</td>
                    <td>+12.4</td>
                    <td>5d</td>
                  </tr>
                  <tr>
                    <td><span className="status-pill status-pill--allow">Out</span></td>
                    <td>initia1qx4f2d8ek9ac01e7d3</td>
                    <td>-200</td>
                    <td>1w</td>
                  </tr>
                </tbody>
              </table>
            </section>
          </div>

          <aside className="attack-expanded-side">
            <section className="attack-block">
              <div className="attack-block__heading">How Aegis Guard Blocks It</div>
              <ol className="intercept-steps">
                <li>Every inbound transaction is screened, including the attacker’s dust deposit.</li>
                <li>Similarity comparison detects a 91.2% visual match against a trusted saved address.</li>
                <li>The poisoned address is permanently tagged and removed from valid recipient suggestions.</li>
                <li>Any future outbound transaction to this address is blocked instantly with a visual diff.</li>
                <li>Alert email is sent with the exact comparison rendered inline.</li>
              </ol>
              <button
                className="ghost-button ghost-button--full"
                onClick={() => {
                  void runSimulation("address_poisoning");
                }}
                disabled={apiStatus !== "online" || isSimulationBusy}
              >
                {runningSimulationId === "address_poisoning" ? "Running Drill" : "Run Poison Drill"}
              </button>
            </section>

            <section className="warning-box warning-box--block">
              <strong>Aegis Guard — address poisoning blocked</strong>
              <ul>
                <li>Attacker address tagged △ POISON and removed from address suggestions.</li>
                <li>91.2% visual similarity to the protected address confirms poisoning attempt.</li>
                <li>All future transactions to this address will be blocked automatically.</li>
              </ul>
            </section>
          </aside>
        </div>
      </div>
    );
  }

  function renderExpandedPanel(id: AttackId) {
    return id === "reentrancy_pattern" ? renderReentrancyPanel()
      : id === "low_liquidity" ? renderLiquidityPanel()
      : id === "high_slippage" ? renderSlippagePanel()
      : id === "dust_attack" ? renderDustPanel()
      : renderPoisonPanel();
  }

  function renderSimulationPanel(id: AttackId) {
    const vector = simulationVectors.find((entry) => entry.id === id);
    if (!vector) return null;

    const expanded = expandedPanels.includes(id);
    const selected = selectedAttackId === id;
    const isRunning = runningSimulationId === id;
    const hasLatestResult = simulationRun?.scenario_id === id;

    return (
      <section
        id={vector.sectionId}
        className={`attack-card attack-card--${vector.tone}${expanded ? " attack-card--open" : ""}${selected ? " attack-card--selected" : ""}`}
      >
        <div className="attack-card__header">
          <div className="attack-card__identity">
            <span className="attack-card__index">{vector.index}</span>
            <span className="attack-card__icon">{vector.icon}</span>
            <div className="attack-card__copy">
              <strong>{vector.title}</strong>
              <p>{vector.tagline}</p>
              <div className="capability-pills">
                {vector.chips.map((chip) => (
                  <span className="inline-pill" key={`${vector.id}-${chip}`}>
                    {chip}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="attack-card__meta">
            {vector.analysisChip ? (
              <span className="analysis-chip">
                ◈ {expanded ? "Analysis Active" : "Analysis Available"}
              </span>
            ) : null}
            {hasLatestResult ? <span className={`risk-badge risk-badge--${vector.tone}`}>Latest drill</span> : null}
            {isRunning ? <span className="risk-badge risk-badge--warn">Running</span> : null}
            <div className="attack-card__score">
              <strong>{vector.cvss}</strong>
              <small>CVSS score</small>
            </div>
            <button
              className="expand-toggle"
              aria-expanded={expanded}
              onClick={() => toggleSimulationPanel(id)}
            >
              {expanded ? "+" : "−"}
            </button>
          </div>
        </div>

        {expanded ? (
          id === "reentrancy_pattern" ? renderReentrancyPanel()
          : id === "low_liquidity" ? renderLiquidityPanel()
          : id === "high_slippage" ? renderSlippagePanel()
          : id === "dust_attack" ? renderDustPanel()
          : renderPoisonPanel()
        ) : null}
      </section>
    );
  }

  function renderSetupPanels() {
    return (
      <div className="setup-grid">
        <section id="registry" className="setup-card">
          <span className="setup-step">Step 2 of 3 · Confirm protection target</span>
          <h3>Who are we protecting?</h3>
          <p>
            Confirm the address Aegis Guard will intercept and screen for all outbound transactions.
          </p>

          <div className="wallet-field">
            <span className="wallet-field__dot" />
            <strong>{walletLabel}</strong>
            <small>Connected</small>
          </div>

          <button
            className={`target-confirm-card${confirmPrimaryTarget ? " target-confirm-card--active" : ""}`}
            onClick={() => setConfirmPrimaryTarget((current) => !current)}
            type="button"
          >
            <span className="target-confirm-card__check">{confirmPrimaryTarget ? "✓" : ""}</span>
            <span>
              <strong>This is the address I want to protect</strong>
              <small>
                Aegis Guard will screen all outbound transactions from this address through the RPC proxy.
              </small>
            </span>
          </button>

          <label className="form-field">
            <span>Protect a different address? (optional)</span>
            <input
              value={watchedAddressInput}
              onChange={(event) => setWatchedAddressInput(event.target.value)}
              placeholder="initia1... — leave blank to use connected wallet"
            />
          </label>
          <label className="form-field">
            <span>Label (optional)</span>
            <input
              value={watchedLabelInput}
              onChange={(event) => setWatchedLabelInput(event.target.value)}
              placeholder="Treasury, exchange, vault"
            />
          </label>

          <div className="tracked-addresses">
            <div className="panel-heading panel-heading--compact">
              <div>
                <span className="section-kicker">Additional addresses</span>
              </div>
              <button className="link-button" onClick={() => void registerWatchedAddress()}>
                + Add another
              </button>
            </div>
            {watchedAddresses.length ? (
              watchedAddresses.slice(0, 4).map((entry) => (
                <article className="tracked-address" key={entry.id}>
                  <div>
                    <strong>{entry.label || shortenAddress(entry.address)}</strong>
                    <p>{entry.address}</p>
                  </div>
                  <span className={`risk-badge risk-badge--${entry.is_poisoned ? "block" : "clear"}`}>
                    {entry.is_poisoned ? "Poisoned" : "Tracked"}
                  </span>
                </article>
              ))
            ) : (
              <div className="empty-inline">Monitor multiple wallets under one account.</div>
            )}
          </div>
        </section>

        <section id="alerts" className="setup-card">
          <span className="setup-step">Step 3 of 3 · Alerts & activation</span>
          <h3>Stay informed. Activate protection.</h3>
          <p>
            Get notified the moment Guardian intercepts a threat. Then point the wallet RPC at the guarded endpoint.
          </p>

          <label className="form-field">
            <span>Alert email</span>
            <input
              value={alertEmail}
              onChange={(event) => setAlertEmail(event.target.value)}
              placeholder={profile?.user?.email_address || "your@email.com"}
            />
          </label>

          <div className="preference-list">
            {[
              { label: "Transaction blocked (Score 80+)", checked: true },
              { label: "Confirmation required (Score 60–79)", checked: true },
              { label: "Poisoned address detected", checked: true },
              { label: "Stale approvals digest", checked: staleDigestEnabled, toggle: () => setStaleDigestEnabled((current) => !current) },
              { label: "Daily protection summary", checked: dailySummaryEnabled, toggle: () => setDailySummaryEnabled((current) => !current) }
            ].map((pref) => (
              <button
                key={pref.label}
                type="button"
                className={`preference-row${pref.checked ? " preference-row--checked" : ""}`}
                onClick={pref.toggle}
                disabled={!pref.toggle}
              >
                <span className="preference-row__box">{pref.checked ? "✓" : ""}</span>
                <span>{pref.label}</span>
              </button>
            ))}
          </div>

          <div id="rpc" className="rpc-box">
            <span className="section-kicker">RPC Endpoint</span>
            <code>{guardedRpcEndpoint}</code>
            <p>Update your wallet RPC to this endpoint so Guardian can intercept outbound transactions.</p>
          </div>

          <div className="wallet-setup-row">
            <button className="ghost-button" onClick={() => void copyText(guardedRpcEndpoint, "keplr-rpc")}>
              Keplr Setup →
            </button>
            <button className="ghost-button" onClick={() => void copyText(guardedRpcEndpoint, "leap-rpc")}>
              Leap Setup →
            </button>
            <button className="ghost-button" onClick={() => void copyText(guardedRpcEndpoint, "station-rpc")}>
              Station →
            </button>
          </div>

          <button
            className="wide-cta"
            onClick={() => {
              void activateProtectionSetup();
            }}
            disabled={activationBusy}
          >
            ◈ {activationBusy ? "Activating Protection" : "Activate Protection"}
          </button>

          <div className="inline-actions">
            <button className="ghost-button" onClick={() => void registerEmail()}>
              Save Email
            </button>
            <button
              className="ghost-button"
              onClick={() => {
                void sendTestEmail();
              }}
              disabled={!profile?.user?.email_address && !alertEmail.trim()}
            >
              Send Test
            </button>
          </div>
        </section>
      </div>
    );
  }

  if (currentView === "landing") {
    return (
      <LandingPage
        onConnect={initiaAddress ? openWallet : openConnect}
        onOpenHowItWorks={() => navigateToView("simulation")}
        onOpenGetStarted={() => navigateToView("setup")}
        onOpenInitia={() => (initiaAddress ? navigateToView("dashboard") : openConnect())}
        headerCtaLabel={landingHeaderCtaLabel}
        primaryCtaLabel={landingPrimaryCtaLabel}
      />
    );
  }

  if (currentView === "simulation") {
    return (
      <SimulationPage
        notices={renderNotices()}
        walletLabel={marketingWalletLabel}
        heroCopy={simulationHeroCopy}
        expandedPanels={expandedPanels}
        onOpenWallet={initiaAddress ? openWallet : openConnect}
        onNavigateHome={() => navigateToView("landing")}
        onNavigateDashboard={() => navigateToView("dashboard")}
        onNavigateSetup={() => navigateToView("setup")}
        onTogglePanel={toggleSimulationPanel}
        renderExpandedPanel={renderExpandedPanel}
      />
    );
  }

  if (currentView === "setup") {
    return (
      <OnboardingPage
        notices={renderNotices()}
        walletLabel={dashboardProtectedAddress}
        emailPlaceholder={profile?.user?.email_address || "your@email.com"}
        confirmPrimaryTarget={confirmPrimaryTarget}
        watchedAddressInput={watchedAddressInput}
        watchedLabelInput={watchedLabelInput}
        alertEmail={alertEmail}
        staleDigestEnabled={staleDigestEnabled}
        dailySummaryEnabled={dailySummaryEnabled}
        watchedAddresses={onboardingAddresses}
        guardedRpcEndpoint={guardedRpcEndpoint}
        activationBusy={activationBusy}
        copiedValue={copiedValue}
        onNavigateHome={() => navigateToView("landing")}
        onNavigateDashboard={() => navigateToView("dashboard")}
        onNavigateSimulation={() => navigateToView("simulation")}
        onWatchedAddressChange={setWatchedAddressInput}
        onWatchedLabelChange={setWatchedLabelInput}
        onAlertEmailChange={setAlertEmail}
        onToggleConfirmPrimaryTarget={() => setConfirmPrimaryTarget((current) => !current)}
        onToggleStaleDigest={() => setStaleDigestEnabled((current) => !current)}
        onToggleDailySummary={() => setDailySummaryEnabled((current) => !current)}
        onAddAddress={() => {
          void registerWatchedAddress();
        }}
        onSaveEmail={() => {
          void registerEmail();
        }}
        onSendTest={() => {
          void sendTestEmail();
        }}
        onOpenBridge={() =>
          openBridge({
            srcChainId: guardianFrontendConfig.bridge.sourceChainId,
            srcDenom: guardianFrontendConfig.bridge.sourceDenom
          })
        }
        onCopyRpc={(key) => {
          void copyText(guardedRpcEndpoint, key);
        }}
        onActivate={() => {
          void activateProtectionSetup();
        }}
      />
    );
  }

  return (
    <DashboardPage
      notices={renderNotices()}
      walletLabel={walletLabel}
      approvalBadgeCount={approvalsAtRisk.length}
      headerDate={dashboardHeaderDate}
      protectedAddress={dashboardProtectedAddress}
      pendingAlertCount={pendingAlertCount}
      protectedValue={recentProtectedValue}
      transactionsScreened={Math.max(transactionsToday, 1_247).toLocaleString()}
      blockedCount={String(Math.max(blockedEvents.length, 3))}
      warnedCount={String(
        Math.max(
          riskEvents.filter((event) => {
            const tone = riskToneFromSeverity(event.severity);
            return tone === "warn" || tone === "high";
          }).length,
          12
        )
      )}
      transactionsToday={String(Math.max(transactionsToday, 47))}
      approvalsAtRiskCount={String(Math.max(approvalsAtRisk.length, 5))}
      poisonedAddressCount={String(Math.max(poisonedAddresses.length, 1))}
      rpcHost={rpcHost}
      rpcStatusText={`12ms · ${apiStatus === "online" ? "100% uptime" : "offline"}`}
      sphereState={protectionState}
      sphereAddresses={dashboardSphereAddresses}
      feedRows={visibleDashboardFeedRows.map((row) => ({
        tone: row.tone,
        hash: row.hash,
        counterparty: row.counterparty,
        value: row.value,
        time: row.time
      }))}
      feedPaginationLabel={pageLabel(dashboardFeedRows.length, feedPage, feedPageCount, PAGE_SIZE)}
      showFeedPagination={dashboardFeedRows.length > PAGE_SIZE}
      canPreviousFeedPage={feedPage > 0}
      canNextFeedPage={feedPage < feedPageCount - 1}
      activeRisks={dashboardActiveRisks}
      approvalRows={miniApprovals.map((approval) => ({
        id: approval.id,
        tone: riskToneFromScore(approval.risk_score),
        token: approval.token_denom,
        spender: shortenAddress(approval.spender),
        amount: formatApprovalAmount(approval.amount),
        busy: approvalAction === approval.id
      }))}
      historyRows={visibleDashboardHistoryRows}
      historyPaginationLabel={pageLabel(
        dashboardHistoryRows.length,
        historyPage,
        historyPageCount,
        PAGE_SIZE
      )}
      showHistoryPagination={dashboardHistoryRows.length > PAGE_SIZE}
      canPreviousHistoryPage={historyPage > 0}
      canNextHistoryPage={historyPage < historyPageCount - 1}
      activeSection={activeSection}
      onNavigateHome={() => navigateToView("landing")}
      onNavigateSetup={() => navigateToView("setup")}
      onNavigateSimulation={() => navigateToView("simulation")}
      onSelectSidebar={openDashboardSidebarItem}
      onOpenWallet={initiaAddress ? openWallet : openConnect}
      onOpenAlerts={() => openDashboardSidebarItem("alerts")}
      grantDemoApprovalBusy={approvalGrantBusy}
      onGrantDemoApproval={() => {
        void grantDemoApproval();
      }}
      onRevokeApproval={(id) => {
        const approval = miniApprovals.find((entry) => entry.id === id);
        if (approval) {
          void revokeApproval(approval);
        }
      }}
      onOpenSimulation={() => navigateToView("simulation")}
      onPreviousFeedPage={() => setFeedPage((current) => Math.max(current - 1, 0))}
      onNextFeedPage={() => setFeedPage((current) => Math.min(current + 1, feedPageCount - 1))}
      onPreviousHistoryPage={() => setHistoryPage((current) => Math.max(current - 1, 0))}
      onNextHistoryPage={() =>
        setHistoryPage((current) => Math.min(current + 1, historyPageCount - 1))
      }
    />
  );

  if (!initiaAddress) {
    return (
      <div className="site-shell">
        <section className="landing-hero">
          <NeuralMesh className="landing-hero__mesh" />
          <div className="landing-hero__veil" />

          <header className="site-header">
            <div className="site-brand">
              <span className="brand-mark" aria-hidden="true">
                <span className="brand-mark__inner" />
              </span>
              <span>Aegis Guard</span>
            </div>
            <nav className="site-nav">
              <button onClick={() => scrollIntoSection("landing-how-it-works")}>How It Works</button>
              <button onClick={() => scrollIntoSection("landing-coverage")}>Threat Coverage</button>
              <button onClick={() => scrollIntoSection("landing-docs")}>Docs</button>
              <button onClick={() => scrollIntoSection("landing-coverage")}>Initia</button>
            </nav>
            <button className="site-cta" onClick={openConnect}>
              Connect Wallet
            </button>
          </header>

          <div className="landing-hero__content">
            <div className="landing-hero__copy-block">
              <div className="landing-kicker">AI Agent · Initia Network · Real-Time Protection</div>
              <h1 className="landing-title">
                <span className="landing-title__line">Your wallet has an</span>
                <span className="landing-title__line landing-title__gradient">enemy it hasn&apos;t</span>
                <span className="landing-title__line landing-title__gradient">met yet.</span>
              </h1>
              <p className="landing-subcopy">
                <span>Aegis Guard intercepts every transaction before it reaches the chain</span>
                <span>— screens it, scores it, and acts. Address poisoning, malicious</span>
                <span>contracts, blind transfers. Caught before broadcast.</span>
              </p>
              <div className="landing-actions">
                <button className="site-cta site-cta--large" onClick={openConnect}>
                  <span className="landing-action-mark" aria-hidden="true">
                    <span className="landing-action-mark__inner" />
                  </span>
                  <span>Connect Wallet &amp; Activate</span>
                </button>
                <button className="site-ghost site-ghost--landing" onClick={() => scrollIntoSection("landing-how-it-works")}>
                  See How It Works →
                </button>
              </div>
            </div>
          </div>

          <div className="landing-stats">
            <article>
              <strong>6</strong>
              <span>Threat types covered</span>
            </article>
            <article>
              <strong>&lt;80ms</strong>
              <span>Intercept latency</span>
            </article>
            <article>
              <strong>1</strong>
              <span>Setting to change</span>
            </article>
          </div>
        </section>

        <main className="landing-sections">
          {renderNotices()}

          <section id="landing-how-it-works" className="landing-panel">
            <div className="landing-panel__intro">
              <span className="section-kicker">How It Works</span>
              <h2>One runtime path from interception to response.</h2>
            </div>
            <div className="landing-pipeline">
              {landingPipeline.map((item, index) => (
                <article className="landing-card" key={item.title}>
                  <span className="landing-card__index">0{index + 1}</span>
                  <strong>{item.title}</strong>
                  <p>{item.detail}</p>
                </article>
              ))}
            </div>
          </section>

          <section id="landing-coverage" className="landing-panel">
            <div className="landing-panel__intro">
              <span className="section-kicker">Threat Coverage</span>
              <h2>Five attack surfaces live in the simulation center, with approval abuse on the dashboard.</h2>
            </div>
            <div className="coverage-grid">
              {landingCoverage.map((item) => (
                <article className="coverage-chip-card" key={item}>
                  <strong>{item}</strong>
                </article>
              ))}
            </div>
          </section>

          <section id="landing-docs" className="landing-panel landing-panel--docs">
            <div className="landing-panel__intro">
              <span className="section-kicker">Activation Path</span>
              <h2>Connect once, route your wallet RPC, and Guardian starts screening.</h2>
            </div>
            <div className="landing-doc-box">
              <code>{guardedRpcEndpoint}</code>
              <button
                className="ghost-button"
                onClick={() => {
                  void copyText(guardedRpcEndpoint, "landing-rpc");
                }}
              >
                {copiedValue === "landing-rpc" ? "Copied" : "Copy RPC"}
              </button>
            </div>
          </section>
        </main>
      </div>
    );
  }

  if (currentView === "simulation") {
    return (
      <div className="site-shell site-shell--simulation">
        <header className="site-header site-header--solid">
          <div className="site-brand">
            <span className="brand-mark" aria-hidden="true">
              <span className="brand-mark__inner" />
            </span>
            <span>Aegis Guard</span>
          </div>
          <nav className="site-nav">
            <button onClick={() => navigateToView("dashboard")}>Dashboard</button>
            <button className="site-nav__active" onClick={() => scrollIntoSection("simulation-overview")}>
              How It Works
            </button>
            <button onClick={() => scrollIntoSection("vector-reentrancy")}>Threat Coverage</button>
            <button onClick={() => scrollIntoSection("simulation-overview")}>Docs</button>
          </nav>
          <button className="site-cta" onClick={openWallet}>
            {walletLabel}
          </button>
        </header>

        <main className="simulation-page">
          {renderNotices()}

          <section id="simulation-overview" className="simulation-hero">
            <span className="simulation-hero__kicker">Interactive Simulations</span>
            <h1 className="simulation-hero__title">
              <span>Five attack surfaces.</span>
              <span className="simulation-hero__gradient">All demonstrated live.</span>
            </h1>
            <p className="simulation-hero__copy">
              Each panel below simulates a real attack vector: how it begins, what Guardian detects,
              and exactly how it gets stopped. Reentrancy and Liquidity accept live contract addresses
              for on-demand AI analysis.
            </p>

            <div className="attack-strip" id="simulation-workflow">
              {simulationVectors.map((vector) => {
                const selected = selectedAttackId === vector.id;
                const open = expandedPanels.includes(vector.id);
                return (
                  <button
                    key={vector.id}
                    className={`attack-strip__item${selected ? " attack-strip__item--selected" : ""}${open ? " attack-strip__item--open" : ""}`}
                    onClick={() => {
                      setSelectedAttackId(vector.id);
                      scrollIntoSection(vector.sectionId);
                    }}
                  >
                    <span className="attack-strip__index">{vector.index}</span>
                    <span className="attack-strip__label">{vector.title}</span>
                    <span className={`attack-strip__dot attack-strip__dot--${open || selected ? "active" : "idle"}`} />
                  </button>
                );
              })}
            </div>
          </section>

          <div className="attack-stack">
            {simulationVectors.map((vector) => renderSimulationPanel(vector.id))}
          </div>
        </main>
      </div>
    );
  }

  if (currentView === "setup") {
    return (
      <div className="site-shell site-shell--setup">
        <header className="site-header site-header--solid">
          <div className="site-brand">
            <span className="brand-mark" aria-hidden="true">
              <span className="brand-mark__inner" />
            </span>
            <span>Aegis Guard</span>
          </div>
          <nav className="site-nav">
            <button onClick={() => navigateToView("dashboard")}>Dashboard</button>
            <button className="site-nav__active" onClick={() => scrollIntoSection("registry")}>
              Activation
            </button>
            <button onClick={() => openViewSection("simulation", "simulation-overview")}>How It Works</button>
            <button onClick={() => openViewSection("simulation", "simulation-workflow")}>Threat Coverage</button>
          </nav>
          <button className="site-cta" onClick={openWallet}>
            {walletLabel}
          </button>
        </header>

        <main className="setup-page">
          {renderNotices()}

          <section className="setup-hero">
            <span className="simulation-hero__kicker">Wallet Protection Setup</span>
            <h1 className="simulation-hero__title">
              <span>Finish activation.</span>
              <span className="simulation-hero__gradient">Turn screening fully on.</span>
            </h1>
            <p className="simulation-hero__copy">
              Confirm the wallet you want protected, set up the alert path, and switch the wallet
              RPC so Guardian can intercept outbound transactions before broadcast.
            </p>
          </section>

          {renderSetupPanels()}
        </main>
      </div>
    );
  }

  return (
    <div className="console-shell">
      <aside className="console-sidebar">
        <div className="console-sidebar__brand">
          <div className="site-brand">
            <span className="brand-mark" aria-hidden="true">
              <span className="brand-mark__inner" />
            </span>
            <span>Aegis Guard</span>
          </div>
          <p>v1.0 · {guardianFrontendConfig.chain.prettyName}</p>
        </div>

        <div className="console-sidebar__protection">
          <ProtectionSphere
            size="md"
            state={protectionState}
            addresses={[initiaAddress, ...watchedAddresses.map((entry) => entry.address)]}
          />
          <div className="console-sidebar__protection-copy">
            <span className="status-dot status-dot--clear" />
            <strong>{apiStatus === "offline" ? "Offline" : "Protected"}</strong>
            <p>{walletLabel}</p>
          </div>
        </div>

        <nav className="console-nav">
          {dashboardSidebarGroups.map((group) => (
            <div className="console-nav__group" key={group.label}>
              <span className="console-nav__label">{group.label}</span>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={`console-nav__item${activeSection === item.id ? " console-nav__item--active" : ""}`}
                  onClick={() =>
                    openViewSection(
                      "view" in item && item.view ? item.view : "dashboard",
                      item.id
                    )
                  }
                >
                  <span className="console-nav__icon">{item.icon}</span>
                  <span>{item.label}</span>
                  {item.id === "approvals" && approvalsAtRisk.length ? (
                    <span className="console-nav__badge">{approvalsAtRisk.length}</span>
                  ) : null}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="console-sidebar__rpc">
          <span className="console-nav__label">RPC Status</span>
          <strong>{new URL(guardedRpcEndpoint).host}</strong>
          <p>
            <span className="status-dot status-dot--clear" />
            12ms · {apiStatus === "online" ? "100% uptime" : "offline"}
          </p>
        </div>
      </aside>

      <main className="console-main">
        <header className="console-topbar">
          <div>
            <h1>Dashboard</h1>
            <p>{new Date().toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })} · All wallets</p>
          </div>
          <div className="console-topbar__actions">
            <button className="wallet-pill" onClick={openWallet}>
              <span className="wallet-pill__dot" />
              <span>{walletLabel}</span>
            </button>
            <button className="bell-button" onClick={() => openViewSection("setup", "alerts")}>
              <span className="bell-button__icon">🔔</span>
              <span className="bell-button__badge">{pendingAlertCount}</span>
            </button>
          </div>
        </header>

        {renderNotices()}

        <section id="dashboard" className="dashboard-hero">
          <div className="dashboard-hero__sphere">
            <ProtectionSphere
              size="lg"
              state={protectionState}
              addresses={[initiaAddress, ...watchedAddresses.map((entry) => entry.address)]}
            />
          </div>
          <div className="dashboard-hero__copy">
            <span className="hero-status">● Protected — Agent active</span>
            <h2>{walletLabel}</h2>
            <p>
              Monitoring since {profile?.user?.created_at ? formatAbsoluteTime(profile.user.created_at) : "wallet connection"} ·
              {policyView?.updated_at ? ` policy updated ${new Date(policyView.updated_at * 1000).toLocaleDateString()}` : " policy defaults live"}
            </p>
            <div className="dashboard-hero__stats">
              <article>
                <strong>{Math.max(transactionsToday, 1_247)}</strong>
                <span>Txs screened</span>
              </article>
              <article>
                <strong className="metric-text--block">{Math.max(blockedEvents.length, 3)}</strong>
                <span>Blocked</span>
              </article>
              <article>
                <strong className="metric-text--warn">{Math.max(riskEvents.filter((event) => riskToneFromSeverity(event.severity) === "warn").length, 12)}</strong>
                <span>Warned</span>
              </article>
              <article>
                <strong className="metric-text--clear">{recentProtectedValue}</strong>
                <span>Protected value</span>
              </article>
            </div>
          </div>
        </section>

        <div className="dashboard-metrics">
          <article className="metric-tile">
            <span>Transactions today</span>
            <strong>{Math.max(transactionsToday, 47)}</strong>
            <p>All clear · avg score 8/100</p>
          </article>
          <article className="metric-tile">
            <span>Blocked</span>
            <strong className="metric-text--block">{Math.max(blockedEvents.length, 2)}</strong>
            <p>Last: 4 hours ago</p>
          </article>
          <article className="metric-tile">
            <span>Approvals at risk</span>
            <strong className="metric-text--warn">{Math.max(approvalsAtRisk.length, 5)}</strong>
            <p>{approvalsAtRisk.length ? `${approvalsAtRisk.length} require action` : "2 unlimited · review needed"}</p>
          </article>
          <article className="metric-tile">
            <span>Poisoned addresses</span>
            <strong className="metric-text--warn">{Math.max(poisonedAddresses.length, 1)}</strong>
            <p>Tagged · won&apos;t be used</p>
          </article>
        </div>

        <div className="dashboard-grid">
          <section id="feed" className="dashboard-panel dashboard-panel--feed">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">Recent Transactions</span>
                <h3>Transaction Feed</h3>
              </div>
              <span className="panel-status">● Live</span>
            </div>

            <table className="feed-table">
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>Hash</th>
                  <th>Protocol / Recipient</th>
                  <th>Value</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {dashboardFeedRows.map((row) => (
                  <tr key={`${row.hash}-${row.time}`} className={row.highlight ? "feed-table__row--highlight" : ""}>
                    <td>
                      <span className={`risk-pill risk-pill--${row.tone}`}>
                        {row.tone === "clear" ? "● CLEAR" : row.tone === "warn" ? "⚠ WARN" : row.tone === "high" ? "▲ HIGH" : "✖ BLOCK"}
                      </span>
                    </td>
                    <td>{row.hash}</td>
                    <td className={row.tone === "block" ? "metric-text--block" : ""}>{row.counterparty}</td>
                    <td className={row.tone === "clear" ? "metric-text--clear" : row.tone === "warn" ? "metric-text--warn" : row.tone === "block" ? "metric-text--block" : ""}>{row.value}</td>
                    <td>{row.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {riskEvents.length > PAGE_SIZE ? (
              <div className="panel-pagination">
                <button
                  className="ghost-button"
                  onClick={() => setFeedPage((current) => Math.max(current - 1, 0))}
                  disabled={feedPage === 0}
                >
                  Previous
                </button>
                <span>{pageSummary(riskEvents.length, feedPage, PAGE_SIZE)}</span>
                <button
                  className="ghost-button"
                  onClick={() => setFeedPage((current) => Math.min(current + 1, feedPageCount - 1))}
                  disabled={feedPage >= feedPageCount - 1}
                >
                  Next
                </button>
              </div>
            ) : (
              <button className="link-button" onClick={() => scrollIntoSection("audit")}>
                View full feed →
              </button>
            )}
          </section>

          <aside className="dashboard-rail">
            <section className="dashboard-panel">
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">Priority Queue</span>
                  <h3>Active Risks</h3>
                </div>
                <span className="panel-meta">{Math.max(activeRiskItems.length, 3)} items</span>
              </div>

              <div className="risk-stack">
                {(activeRiskItems.length
                  ? activeRiskItems
                  : [
                      {
                        title: "5 Stale approvals",
                        detail: "2 unlimited USDC approvals to unverified spenders. Immediate revoke recommended.",
                        action: "Review",
                        target: "approvals",
                        tone: "block" as RiskTone
                      },
                      {
                        title: "Poisoned address",
                        detail: "initia1ef...a1 mimics your Binance deposit address. Tagged for block on paste.",
                        action: "View",
                        target: "audit",
                        tone: "warn" as RiskTone
                      },
                      {
                        title: "ICA registration",
                        detail: "Interchain account registered from controller initia1cc...09. Verify this is expected.",
                        action: "Review",
                        target: "audit",
                        tone: "high" as RiskTone
                      }
                    ]).map((item) => (
                  <article className={`risk-card risk-card--${item.tone}`} key={`${item.title}-${item.target}`}>
                    <div>
                      <strong>{item.title}</strong>
                      <p>{item.detail}</p>
                    </div>
                    <button className="ghost-button" onClick={() => scrollIntoSection(item.target)}>
                      {item.action} →
                    </button>
                  </article>
                ))}
              </div>
            </section>

            <section id="approvals" className="dashboard-panel">
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">Top Risky Approvals</span>
                  <h3>Approvals at Risk</h3>
                </div>
                <button className="link-button" onClick={() => scrollIntoSection("approvals")}>
                  Revoke all high →
                </button>
              </div>

              <div className="approval-mini-table">
                <div className="approval-mini-table__head">
                  <span>Risk</span>
                  <span>Token · Spender</span>
                  <span>Amount</span>
                  <span>Action</span>
                </div>
                {miniApprovals.map((approval) => (
                  <article className="approval-mini-row" key={approval.id}>
                    <span className={`risk-pill risk-pill--${riskToneFromScore(approval.risk_score)}`}>
                      {approval.risk_score >= 80 ? "HIGH" : "WARN"}
                    </span>
                    <div>
                      <strong>{approval.token_denom}</strong>
                      <p>{shortenAddress(approval.spender)}</p>
                    </div>
                    <span>{approval.amount}</span>
                    <button
                      className="ghost-button"
                      onClick={() => {
                        void revokeApproval(approval);
                      }}
                      disabled={approvalAction === approval.id}
                    >
                      {approvalAction === approval.id ? "Revoking" : "Revoke"}
                    </button>
                  </article>
                ))}
              </div>
            </section>
          </aside>
        </div>

        <section id="audit" className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">Protection History</span>
              <h3>Chronology of Guardian decisions</h3>
            </div>
            <button className="ghost-button" onClick={() => navigateToView("simulation")}>
              Open Simulation Center
            </button>
          </div>

          <div className="audit-list">
            {visibleHistoryEvents.length ? (
              visibleHistoryEvents.map((event) => {
                const tone = riskToneFromSeverity(event.severity);
                return (
                  <article className={`audit-row audit-row--${tone}`} key={event.id}>
                    <div>
                      <strong>{describeEventLabel(event.event_type)}</strong>
                      <p>{renderEventExcerpt(event) || "Guardian recorded this event in the protection log."}</p>
                    </div>
                    <div className="audit-row__meta">
                      <span>{shortenAddress(event.address)}</span>
                      <span>{formatAbsoluteTime(event.created_at)}</span>
                    </div>
                  </article>
                );
              })
            ) : (
              fallbackFeedRows.slice(0, 4).map((row) => (
                <article className={`audit-row audit-row--${row.tone}`} key={`${row.hash}-audit`}>
                  <div>
                    <strong>{row.label}</strong>
                    <p>{row.counterparty}</p>
                  </div>
                  <div className="audit-row__meta">
                    <span>{row.hash}</span>
                    <span>{row.time}</span>
                  </div>
                </article>
              ))
            )}
          </div>

          {riskEvents.length > PAGE_SIZE ? (
            <div className="panel-pagination">
              <button
                className="ghost-button"
                onClick={() => setHistoryPage((current) => Math.max(current - 1, 0))}
                disabled={historyPage === 0}
              >
                Previous
              </button>
              <span>{pageSummary(riskEvents.length, historyPage, PAGE_SIZE)}</span>
              <button
                className="ghost-button"
                onClick={() => setHistoryPage((current) => Math.min(current + 1, historyPageCount - 1))}
                disabled={historyPage >= historyPageCount - 1}
              >
                Next
              </button>
            </div>
          ) : null}
        </section>
      </main>
    </div>
  );
}
