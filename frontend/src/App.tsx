import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { useInterwovenKit } from "@initia/interwovenkit-react";
import { guardianFrontendConfig } from "./config";
import { NeuralMesh } from "./components/NeuralMesh";
import { ProtectionSphere } from "./components/ProtectionSphere";

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

type DemoContractPreview = {
  contract_address: string;
  decision: DemoContractDecision;
  execute_message: Record<string, unknown>;
};

type ApiStatus = "checking" | "online" | "offline";
type SimulationStage = "idle" | "preparing" | "running" | "publishing" | "complete";
type DemoAttemptState = "idle" | "previewing" | "submitting" | "blocked" | "needs_guarded_rpc";
type RiskTone = "clear" | "warn" | "high" | "block";
type SphereState = "idle" | "screening" | "warned" | "blocked" | "offline";

const apiBase = guardianFrontendConfig.api.baseUrl;
const guardedRpcEndpoint = guardianFrontendConfig.api.guardianRpcUrl;
const demoRiskLabAddress = guardianFrontendConfig.contract.demoRiskLabAddress;
const PAGE_SIZE = 10;

const landingPipeline = [
  {
    title: "Intercept",
    detail: "Aegis receives outbound transactions through the guarded RPC before broadcast.",
    items: ["RPC proxy", "WebSocket monitor", "Event stream"]
  },
  {
    title: "Analyze",
    detail: "Simulation and policy checks produce a single risk assessment with supporting evidence.",
    items: ["Simulate tx", "Score contract", "Detect poisoning"]
  },
  {
    title: "Act",
    detail: "The service allows, warns, or blocks and records the outcome for review.",
    items: ["Allow silently", "Warn with detail", "Block and alert"]
  }
] as const;

const threatCoverage = [
  {
    title: "Address Poisoning",
    detail: "Visual matching and registry checks stop look-alike recipients before broadcast.",
    capabilities: ["Block", "Tag", "Explain"]
  },
  {
    title: "Stale Approvals",
    detail: "Unlimited or aging approvals are ranked and ready to revoke from one surface.",
    capabilities: ["Warn", "Review", "Revoke"]
  },
  {
    title: "Malicious Contracts",
    detail: "Contract behavior is simulated and summarized before the user signs blind.",
    capabilities: ["Simulate", "Score", "Block"]
  },
  {
    title: "Blind Transactions",
    detail: "The product shows likely balance deltas so the wallet action is legible.",
    capabilities: ["Preview", "Compare", "Protect"]
  },
  {
    title: "Behavioral Anomaly",
    detail: "Outbound activity is checked against the wallet's own normal transaction rhythm.",
    capabilities: ["Baseline", "Alert", "Triage"]
  },
  {
    title: "ICA Abuse",
    detail: "Initia-native controller actions are surfaced before they become silent drain paths.",
    capabilities: ["Inspect", "Whitelist", "Alert"]
  }
] as const;

const landingFeedPreview = [
  {
    tone: "clear" as RiskTone,
    title: "Initia swap executed",
    meta: "0xf3b1…44",
    value: "+142 INIT",
    time: "2m ago"
  },
  {
    tone: "warn" as RiskTone,
    title: "Unknown contract requires review",
    meta: "0x71de…c2",
    value: "-500 INIT",
    time: "41m ago"
  },
  {
    tone: "block" as RiskTone,
    title: "Poisoned recipient blocked",
    meta: "0x2244…91",
    value: "-2000 INIT",
    time: "4h ago"
  }
];

const sidebarGroups = [
  {
    label: "Monitor",
    items: [
      { id: "dashboard", label: "Dashboard" },
      { id: "feed", label: "Activity Feed" },
      { id: "audit", label: "Audit Log" }
    ]
  },
  {
    label: "Protect",
    items: [
      { id: "simulation", label: "Simulation Lab" },
      { id: "approvals", label: "Approvals" },
      { id: "registry", label: "Address Registry" }
    ]
  },
  {
    label: "Settings",
    items: [
      { id: "alerts", label: "Alert Emails" },
      { id: "rpc", label: "RPC Setup" }
    ]
  }
] as const;

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
    approval_intent: "Approval Intent",
    anomaly: "Behavioral Anomaly",
    ica: "ICA Abuse",
    contract: "Suspicious Contract",
    contract_llm: "Contract Analysis Warning",
    reentrancy: "Reentrancy Pattern",
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
  return "Allowed";
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

function updateGlowPosition(event: MouseEvent<HTMLElement>) {
  const target = event.currentTarget;
  const rect = target.getBoundingClientRect();
  target.style.setProperty("--mouse-x", `${event.clientX - rect.left}px`);
  target.style.setProperty("--mouse-y", `${event.clientY - rect.top}px`);
}

export default function App() {
  const { initiaAddress, openConnect, openWallet, requestTxBlock } = useInterwovenKit();
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [riskEvents, setRiskEvents] = useState<RiskEvent[]>([]);
  const [watchedAddresses, setWatchedAddresses] = useState<WatchedAddress[]>([]);
  const [watchedAddressInput, setWatchedAddressInput] = useState("");
  const [watchedLabelInput, setWatchedLabelInput] = useState("");
  const [watchAsSimulationTarget, setWatchAsSimulationTarget] = useState(false);
  const [alertEmail, setAlertEmail] = useState("");
  const [alertEmailName, setAlertEmailName] = useState("");
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [approvalAction, setApprovalAction] = useState<string | null>(null);
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [simulationStage, setSimulationStage] = useState<SimulationStage>("idle");
  const [simulationRun, setSimulationRun] = useState<SimulationRun | null>(null);
  const [demoPreview, setDemoPreview] = useState<DemoContractPreview | null>(null);
  const [demoAttemptState, setDemoAttemptState] = useState<DemoAttemptState>("idle");
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState("dashboard");
  const [feedPage, setFeedPage] = useState(0);
  const [historyPage, setHistoryPage] = useState(0);

  const walletLabel = useMemo(() => {
    if (!initiaAddress) return "Connect Wallet";
    return shortenAddress(initiaAddress);
  }, [initiaAddress]);

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

  const drillTarget = useMemo(() => {
    if (profile?.simulation_target?.label) return profile.simulation_target.label;
    if (profile?.simulation_target?.address) return shortenAddress(profile.simulation_target.address);
    if (initiaAddress) return shortenAddress(initiaAddress);
    return "Connect a wallet to choose a drill target";
  }, [initiaAddress, profile]);

  const approvalsAtRisk = useMemo(
    () => approvals.filter((approval) => approval.risk_score >= 60),
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

  const recentEvents = useMemo(() => riskEvents.slice(0, 10), [riskEvents]);
  const feedPageCount = Math.max(1, Math.ceil(riskEvents.length / PAGE_SIZE));
  const historyPageCount = Math.max(1, Math.ceil(riskEvents.length / PAGE_SIZE));
  const visibleFeedEvents = useMemo(
    () => riskEvents.slice(feedPage * PAGE_SIZE, (feedPage + 1) * PAGE_SIZE),
    [feedPage, riskEvents]
  );
  const visibleHistoryEvents = useMemo(
    () => riskEvents.slice(historyPage * PAGE_SIZE, (historyPage + 1) * PAGE_SIZE),
    [historyPage, riskEvents]
  );
  const protectedTargetAddress =
    profile?.simulation_target?.address || initiaAddress;
  const protectedTargetLabel =
    profile?.simulation_target?.label || "Protected wallet";
  const demoDecisionFindings = useMemo(
    () => (demoPreview ? extractDecisionFindings(demoPreview.decision) : []),
    [demoPreview]
  );

  const transactionsToday = useMemo(() => {
    const now = Date.now();
    return riskEvents.filter((event) => now - new Date(event.created_at).getTime() < 86_400_000).length;
  }, [riskEvents]);

  const stageIndex =
    simulationStage === "idle"
      ? -1
      : simulationStage === "preparing"
        ? 0
        : simulationStage === "running"
          ? 1
          : 2;

  const simulationSteps = [
    {
      key: "preparing",
      label: "Prepare target",
      detail: "Load the protected address and current runtime context."
    },
    {
      key: "running",
      label: "Run analyzers",
      detail: "Execute the safety drill and collect detector findings."
    },
    {
      key: "publishing",
      label: "Publish result",
      detail: "Write the outcome into the feed for review."
    }
  ] as const;

  const notices = useMemo(() => {
    const items: Array<{ title: string; detail: string; tone: "danger" | "warn" }> = [];

    if (apiStatus === "offline") {
      items.push({
        title: "Backend is offline",
        detail:
          "Start `cargo run -p guardian-app` so the product can load approvals, alerts, and simulation results.",
        tone: "warn"
      });
    }

    if (error) {
      items.push({
        title: "Action failed",
        detail: error,
        tone: "danger"
      });
    }

    return items;
  }, [apiStatus, error]);

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
        title: `${approvalsAtRisk.length} approval${approvalsAtRisk.length === 1 ? "" : "s"} need review`,
        detail: `${approval.amount} ${approval.token_denom} granted to ${shortenAddress(approval.spender)}.`,
        action: "Review approvals",
        target: "approvals",
        tone: riskToneFromScore(approval.risk_score)
      });
    }

    if (poisonedAddresses.length) {
      items.push({
        title: "Poisoned address detected",
        detail: `${shortenAddress(poisonedAddresses[0].address)} is flagged inside your registry.`,
        action: "Inspect registry",
        target: "registry",
        tone: "block"
      });
    }

    if (highestRiskEvent) {
      items.push({
        title: describeEventLabel(highestRiskEvent.event_type),
        detail: renderEventExcerpt(highestRiskEvent) || "Guardian elevated this event for operator review.",
        action: "Open audit log",
        target: "audit",
        tone: riskToneFromSeverity(highestRiskEvent.severity)
      });
    }

    if (simulationRun?.findings.length) {
      items.push({
        title: describeScenarioName(simulationRun.scenario_id),
        detail: `${simulationRun.findings.length} finding${simulationRun.findings.length === 1 ? "" : "s"} published from the latest drill.`,
        action: "Review simulation",
        target: "simulation",
        tone: riskToneFromSeverity(simulationRun.findings[0]?.severity)
      });
    }

    return items.slice(0, 4);
  }, [approvalsAtRisk, highestRiskEvent, poisonedAddresses, simulationRun]);

  useEffect(() => {
    if (!initiaAddress) {
      setApprovals([]);
      setRiskEvents([]);
      setWatchedAddresses([]);
      setProfile(null);
      setSimulationRun(null);
      return;
    }

    void loadDashboard(initiaAddress);
  }, [initiaAddress]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setCopiedValue(null);
    }, 1800);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [copiedValue]);

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
    if (!initiaAddress) return;

    const sectionIds = sidebarGroups.flatMap((group) => group.items.map((item) => item.id));
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
  }, [initiaAddress]);

  async function loadDashboard(address: string, refreshApprovals = false) {
    setLoading(true);
    setError(null);

    try {
      const [approvalResponse, riskResponse, watchedResponse, profileResponse] =
        await Promise.all([
          fetch(`${apiBase}/api/approvals/${address}?refresh=${refreshApprovals}`),
          fetch(`${apiBase}/api/risk-events/${address}?limit=100`),
          fetch(`${apiBase}/api/watched-addresses/${address}`),
          fetch(`${apiBase}/api/profile/${address}`)
        ]);

      if (!approvalResponse.ok || !riskResponse.ok || !watchedResponse.ok || !profileResponse.ok) {
        throw new Error("Failed to load dashboard data");
      }

      const [approvalData, riskData, watchedData, profileData] = await Promise.all([
        approvalResponse.json(),
        riskResponse.json(),
        watchedResponse.json(),
        profileResponse.json()
      ]);

      setApprovals(approvalData);
      setRiskEvents(riskData);
      setWatchedAddresses(watchedData);
      setProfile(profileData);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unknown dashboard error");
    } finally {
      setLoading(false);
    }
  }

  async function registerWatchedAddress() {
    if (!initiaAddress || !watchedAddressInput.trim()) return;

    setError(null);

    try {
      const response = await fetch(`${apiBase}/api/watched-addresses`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner_address: initiaAddress,
          address: watchedAddressInput.trim(),
          label: watchedLabelInput.trim() || null,
          is_simulation_target: watchAsSimulationTarget
        })
      });

      if (!response.ok) {
        throw new Error("Failed to save watched address");
      }

      setWatchedAddressInput("");
      setWatchedLabelInput("");
      setWatchAsSimulationTarget(false);
      await loadDashboard(initiaAddress);
    } catch (registerError) {
      setError(registerError instanceof Error ? registerError.message : "Failed to save watched address");
    }
  }

  async function registerEmail() {
    if (!initiaAddress || !alertEmail.trim()) return;

    setError(null);

    try {
      const response = await fetch(`${apiBase}/api/email/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: initiaAddress,
          email_address: alertEmail.trim(),
          email_display_name: alertEmailName.trim() || null
        })
      });

      if (!response.ok) {
        throw new Error("Failed to register alert email");
      }

      setAlertEmail("");
      setAlertEmailName("");
      await loadDashboard(initiaAddress);
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
    } catch (sendError) {
      setError(sendError instanceof Error ? sendError.message : "Failed to send test email");
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
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : "Failed to revoke approval");
    } finally {
      setApprovalAction(null);
    }
  }

  async function runSimulation() {
    if (!initiaAddress) return;

    setError(null);
    setSimulationRun(null);
    setSimulationStage("preparing");

    try {
      await wait(240);
      setSimulationStage("running");

      const response = await fetch(`${apiBase}/api/simulations/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: initiaAddress
        })
      });

      if (!response.ok) {
        throw new Error("Failed to run simulation");
      }

      const result: SimulationRun = await response.json();
      setSimulationStage("publishing");
      await wait(280);
      setSimulationRun(result);
      setSimulationStage("complete");
      await loadDashboard(initiaAddress);
    } catch (simulationError) {
      setSimulationStage("idle");
      setError(simulationError instanceof Error ? simulationError.message : "Failed to run simulation");
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
          contract_address: demoRiskLabAddress
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

  function refreshDashboard() {
    if (!initiaAddress) return;
    void loadDashboard(initiaAddress, true);
  }

  function scrollToSection(id: string) {
    const section = document.getElementById(id);
    if (!section) return;
    setActiveSection(id);
    section.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function copyText(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedValue(key);
    } catch (copyError) {
      setError(copyError instanceof Error ? copyError.message : "Failed to copy value");
    }
  }

  const isSimulationBusy = simulationStage !== "idle" && simulationStage !== "complete";

  if (!initiaAddress) {
    return (
      <div className="app-shell">
        <section className="landing-shell">
          <header className="landing-hero">
            <NeuralMesh className="hero-mesh" />
            <div className="hero-overlay" />
            <div className="hero-copy">
              <div className="hero-brand">
                <span className="brand-mark">◈</span>
                <span className="hero-brand-name">Aegis Guard</span>
              </div>
              <p className="hero-kicker">Initia Wallet Security</p>
              <h1>Transaction screening and policy controls for wallets.</h1>
              <p className="hero-lede">
                Aegis Guard reviews contract calls, approvals, recipient changes, and transaction
                patterns before broadcast, then records the result in a single monitoring surface.
              </p>
              <div className="hero-cta-row">
                <button className="cta-primary" onClick={openConnect}>
                  Connect Wallet
                </button>
                <button className="cta-secondary" onClick={() => scrollToSection("pipeline")}>
                  View Workflow
                </button>
              </div>
              <div className="hero-footnote">
                <span>Securing {guardianFrontendConfig.chain.prettyName}</span>
                <span>API {describeApiStatus(apiStatus)}</span>
              </div>
            </div>

            <div className="hero-side-panel">
              <div className="hero-status-card">
                <span className="label">Protected Chain</span>
                <strong>{guardianFrontendConfig.chain.prettyName}</strong>
                <p>{guardianFrontendConfig.chain.id}</p>
              </div>
              <div className="hero-status-card">
                <span className="label">Policy Contract</span>
                <strong>
                  {guardianFrontendConfig.contract.guardianPolicyAddress
                    ? shortenAddress(guardianFrontendConfig.contract.guardianPolicyAddress)
                    : "Pending"}
                </strong>
                <p>
                  {guardianFrontendConfig.contract.guardianPolicyAddress
                    ? "Connected to runtime"
                    : "Set the policy contract address to enable onchain controls."}
                </p>
              </div>
              <div className="hero-status-card">
                <span className="label">Guarded RPC</span>
                <strong>{shortenAddress(guardedRpcEndpoint)}</strong>
                <p>Use the Guardian RPC in wallet setup to route outbound transactions through screening.</p>
              </div>
            </div>
          </header>

          {notices.length ? (
            <section className="notice-stack">
              {notices.map((notice) => (
                <article className={`notice-card notice-card--${notice.tone}`} key={`${notice.title}-${notice.detail}`}>
                  <strong>{notice.title}</strong>
                  <p>{notice.detail}</p>
                </article>
              ))}
            </section>
          ) : null}

          <section id="pipeline" className="landing-section">
            <div className="section-intro">
              <span className="section-kicker">Pipeline</span>
              <h2>A single workflow for screening, analysis, and response.</h2>
            </div>
            <div className="pipeline-grid">
              {landingPipeline.map((column, index) => (
                <article className="pipeline-card" key={column.title}>
                  <span className="pipeline-index">0{index + 1}</span>
                  <h3>{column.title}</h3>
                  <p>{column.detail}</p>
                  <ul className="capability-list">
                    {column.items.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          </section>

          <section className="landing-section">
            <div className="section-intro">
              <span className="section-kicker">Threat Coverage</span>
              <h2>Coverage for the wallet risks teams need to review.</h2>
            </div>
            <div className="threat-grid">
              {threatCoverage.map((threat) => (
                <article
                  className="threat-card"
                  key={threat.title}
                  onMouseMove={updateGlowPosition}
                >
                  <h3>{threat.title}</h3>
                  <p>{threat.detail}</p>
                  <div className="capability-pills">
                    {threat.capabilities.map((capability) => (
                      <span className="inline-pill" key={capability}>
                        {capability}
                      </span>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="landing-section">
            <div className="setup-band">
              <div>
                <span className="section-kicker">RPC Setup</span>
                <h2>Route wallet traffic through the guarded endpoint.</h2>
                <p>
                  Change your wallet&apos;s RPC URL to the Guardian RPC and every
                  outbound transaction can be screened before broadcast.
                </p>
              </div>
              <div className="endpoint-box">
                <code>{guardedRpcEndpoint}</code>
                <button
                  className="cta-secondary cta-compact"
                  onClick={() => {
                    void copyText(guardedRpcEndpoint, "rpc");
                  }}
                >
                  {copiedValue === "rpc" ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
          </section>

          <section className="landing-section">
            <div className="section-intro">
              <span className="section-kicker">Live Feed Preview</span>
              <h2>A clear event log for routine review and escalation.</h2>
            </div>
            <div className="preview-feed">
              {landingFeedPreview.map((item) => (
                <article className="preview-row" key={`${item.meta}-${item.time}`}>
                  <span className={`risk-badge risk-badge--${item.tone}`}>{riskLabel(item.tone)}</span>
                  <div className="preview-copy">
                    <strong>{item.title}</strong>
                    <p>{item.meta}</p>
                  </div>
                  <div className="preview-metrics">
                    <strong>{item.value}</strong>
                    <span>{item.time}</span>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="cta-footer">
            <p className="section-kicker">Get Started</p>
            <h2>Connect a wallet to begin protected monitoring.</h2>
            <button className="cta-primary" onClick={openConnect}>
              Connect Wallet & Activate
            </button>
            <p className="cta-caption">
              Runs alongside the wallet flow without custody or additional extension overhead.
            </p>
          </section>
        </section>
      </div>
    );
  }

  return (
    <div className="app-shell dashboard-app">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark">◈</span>
          <div>
            <strong>Aegis Guard</strong>
            <p>{guardianFrontendConfig.chain.prettyName}</p>
          </div>
        </div>

        <div className="sidebar-protection-card">
          <ProtectionSphere
            size="sm"
            state={protectionState}
            addresses={[initiaAddress, ...watchedAddresses.map((entry) => entry.address)]}
          />
          <div className="sidebar-protection-copy">
            <span className="label">Protection State</span>
            <strong>{apiStatus === "offline" ? "Offline" : "Guard Active"}</strong>
            <p className="sidebar-protection-address">{shortenAddress(initiaAddress)}</p>
            <p className="sidebar-protection-risk">
              Current risk:{" "}
              {highestRiskEvent ? riskLabel(riskToneFromSeverity(highestRiskEvent.severity)) : "Clear"}
            </p>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Primary">
          {sidebarGroups.map((group) => (
            <div className="sidebar-group" key={group.label}>
              <span className="sidebar-group-label">{group.label}</span>
              {group.items.map((item) => (
                <button
                  className={`sidebar-link${activeSection === item.id ? " sidebar-link--active" : ""}`}
                  key={item.id}
                  onClick={() => scrollToSection(item.id)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-status-card">
          <div className="sidebar-status-copy">
            <span className="label">Service Status</span>
            <div className="sidebar-status-indicator">
              <span className={`status-blinker status-blinker--${apiStatus}`} aria-hidden="true" />
              <strong>{describeApiStatus(apiStatus)}</strong>
            </div>
            <p>{guardedRpcEndpoint}</p>
          </div>
        </div>
      </aside>

      <main className="workspace">
        <header className="workspace-topbar">
          <div>
            <p className="section-kicker">Dashboard</p>
            <h1>Active Guard</h1>
          </div>
          <div className="topbar-actions">
            <button className="cta-secondary cta-compact" onClick={refreshDashboard} disabled={loading}>
              {loading ? "Refreshing" : "Refresh"}
            </button>
            <button className="cta-primary cta-compact" onClick={openWallet}>
              {walletLabel}
            </button>
          </div>
        </header>

        {notices.length ? (
          <section className="notice-stack">
            {notices.map((notice) => (
              <article className={`notice-card notice-card--${notice.tone}`} key={`${notice.title}-${notice.detail}`}>
                <strong>{notice.title}</strong>
                <p>{notice.detail}</p>
              </article>
            ))}
          </section>
        ) : null}

        <section id="dashboard" className="panel panel-hero" data-section>
          <div className="hero-panel-copy">
            <span className={`status-dot status-dot--${protectionState === "blocked" ? "block" : protectionState === "warned" ? "warn" : protectionState === "screening" ? "info" : apiStatus === "offline" ? "offline" : "clear"}`} />
            <div>
              <p className="section-kicker">{apiStatus === "offline" ? "Protection sleeping" : "Guard active"}</p>
              <h2>{protectedTargetLabel}</h2>
              <p className="hero-panel-address">{shortenAddress(protectedTargetAddress)}</p>
              <p className="hero-panel-meta">
                Monitoring since{" "}
                {profile?.user?.created_at ? formatAbsoluteTime(profile.user.created_at) : "registration"}
              </p>
            </div>
          </div>

          <div className="hero-panel-sphere">
            <ProtectionSphere
              size="lg"
              state={protectionState}
              addresses={[initiaAddress, ...watchedAddresses.map((entry) => entry.address)]}
            />
          </div>

          <div className="stat-row">
            <article className="metric-card">
              <span className="label">Txs Today</span>
              <strong>{transactionsToday}</strong>
              <p>{recentEvents.length ? "Screened by the active stack" : "No feed activity yet"}</p>
            </article>
            <article className="metric-card">
              <span className="label">Blocked</span>
              <strong className={blockedEvents.length ? "metric-block" : ""}>{blockedEvents.length}</strong>
              <p>{blockedEvents.length ? "Recent events escalated to block" : "No blocks in recent feed"}</p>
            </article>
            <article className="metric-card">
              <span className="label">Approvals At Risk</span>
              <strong className={approvalsAtRisk.length ? "metric-high" : ""}>{approvalsAtRisk.length}</strong>
              <p>{approvals.length} total approval record{approvals.length === 1 ? "" : "s"}</p>
            </article>
            <article className="metric-card">
              <span className="label">Poisoned Addresses</span>
              <strong className={poisonedAddresses.length ? "metric-warn" : ""}>{poisonedAddresses.length}</strong>
              <p>{watchedAddresses.length} tracked address{watchedAddresses.length === 1 ? "" : "es"}</p>
            </article>
          </div>
        </section>

        <div className="workspace-grid">
          <section id="feed" className="panel" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Recent Transactions</span>
                <h2>Activity Feed</h2>
              </div>
              <span className="panel-meta">{pageSummary(riskEvents.length, feedPage, PAGE_SIZE)}</span>
            </div>
            <div className="feed-list">
              {visibleFeedEvents.length ? (
                visibleFeedEvents.map((event) => {
                  const tone = riskToneFromSeverity(event.severity);
                  return (
                    <article className={`feed-row feed-row--${tone}`} key={event.id}>
                      <span className={`risk-badge risk-badge--${tone}`}>{riskLabel(tone)}</span>
                      <div className="feed-row-main">
                        <strong>{describeEventLabel(event.event_type)}</strong>
                        <p>{renderEventExcerpt(event) || "Guardian recorded this event in the protection log."}</p>
                      </div>
                      <div className="feed-row-meta">
                        <span>{event.tx_hash ? shortenAddress(event.tx_hash) : "No tx hash"}</span>
                        <span>{formatRelativeTime(event.created_at)}</span>
                      </div>
                    </article>
                  );
                })
              ) : (
                <div className="empty-card">
                  <strong>No transactions recorded yet</strong>
                  <p>Run a simulation or refresh the backend feed once the wallet is active.</p>
                </div>
              )}
            </div>
            {riskEvents.length > PAGE_SIZE ? (
              <div className="panel-pagination">
                <button
                  className="cta-secondary cta-compact"
                  onClick={() => setFeedPage((current) => Math.max(current - 1, 0))}
                  disabled={feedPage === 0}
                >
                  Previous
                </button>
                <span>
                  Page {feedPage + 1} of {feedPageCount}
                </span>
                <button
                  className="cta-secondary cta-compact"
                  onClick={() => setFeedPage((current) => Math.min(current + 1, feedPageCount - 1))}
                  disabled={feedPage >= feedPageCount - 1}
                >
                  Next
                </button>
              </div>
            ) : null}
          </section>

          <section className="panel" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Priority Queue</span>
                <h2>Active Risks</h2>
              </div>
              <span className="panel-meta">{activeRiskItems.length || 0} item(s)</span>
            </div>
            <div className="risk-stack">
              {activeRiskItems.length ? (
                activeRiskItems.map((item) => (
                  <article className={`risk-item risk-item--${item.tone}`} key={`${item.title}-${item.target}`}>
                    <div>
                      <strong>{item.title}</strong>
                      <p>{item.detail}</p>
                    </div>
                    <button className="text-link" onClick={() => scrollToSection(item.target)}>
                      {item.action}
                    </button>
                  </article>
                ))
              ) : (
                <div className="empty-card">
                  <strong>No new risks in the current window</strong>
                  <p>The protection layer is calm. Keep the simulation panel handy for drills.</p>
                </div>
              )}
            </div>
          </section>

          <section id="simulation" className="panel panel-wide" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Simulation Lab</span>
                <h2>Run a controlled safety drill</h2>
              </div>
              <span className="panel-meta">{drillTarget}</span>
            </div>

            <div className="simulation-toolbar">
              <p>
                Trigger the existing backend simulation to validate the detection path and publish
                the result into the dashboard feed.
              </p>
              <button
                className="cta-primary"
                onClick={() => {
                  void runSimulation();
                }}
                disabled={apiStatus !== "online" || isSimulationBusy}
              >
                {isSimulationBusy ? "Simulation Running" : "Run Simulation"}
              </button>
            </div>

            <div className="detail-card detail-card--strong demo-lab-card">
              <div className="panel-header panel-header--compact">
                <div>
                  <span className="section-kicker">Interactive Contract Demo</span>
                  <h2>Attempt a guarded risk-lab call</h2>
                </div>
                <span className="panel-meta">
                  {demoPreview ? describeDecisionState(demoPreview.decision.decision) : "Ready"}
                </span>
              </div>
              <p>
                This is a harmless contract interaction designed for judge walkthroughs. Guardian
                should classify the `execute_attack` payload as a reentrancy-style drain pattern and
                stop it before broadcast when the wallet is using the guarded RPC.
              </p>
              <div className="demo-lab-meta">
                <span className="inline-pill">
                  Contract {demoRiskLabAddress ? shortenAddress(demoRiskLabAddress) : "Not configured"}
                </span>
                <span className="inline-pill">RPC {shortenAddress(guardedRpcEndpoint)}</span>
              </div>
              <div className="button-row">
                <button
                  className="cta-secondary"
                  onClick={() => {
                    void runRiskLabDemo();
                  }}
                  disabled={
                    !demoRiskLabAddress ||
                    apiStatus !== "online" ||
                    demoAttemptState === "previewing" ||
                    demoAttemptState === "submitting"
                  }
                >
                  {demoAttemptState === "previewing"
                    ? "Preparing Analysis"
                    : demoAttemptState === "submitting"
                      ? "Submitting Demo Call"
                      : "Attempt Demo Contract Call"}
                </button>
                <button
                  className="cta-secondary cta-compact"
                  onClick={() => {
                    if (!demoRiskLabAddress) return;
                    void copyText(demoRiskLabAddress, "demo-contract");
                  }}
                  disabled={!demoRiskLabAddress}
                >
                  {copiedValue === "demo-contract" ? "Copied" : "Copy Contract"}
                </button>
              </div>

              {demoPreview ? (
                <div className="simulation-results simulation-results--compact">
                  <div className="simulation-summary">
                    <article className="summary-chip">
                      <span className="label">Decision</span>
                      <strong>{describeDecisionState(demoPreview.decision.decision)}</strong>
                    </article>
                    <article className="summary-chip">
                      <span className="label">Contract</span>
                      <strong>{shortenAddress(demoPreview.contract_address)}</strong>
                    </article>
                    <article className="summary-chip">
                      <span className="label">Guarded RPC</span>
                      <strong>{shortenAddress(guardedRpcEndpoint)}</strong>
                    </article>
                    <article className="summary-chip">
                      <span className="label">Findings</span>
                      <strong>{demoDecisionFindings.length}</strong>
                    </article>
                  </div>
                  <div className={`detail-card demo-outcome demo-outcome--${decisionTone(demoPreview.decision.decision)}`}>
                    <strong>
                      {demoAttemptState === "blocked"
                        ? "Guardian blocked the contract call before broadcast."
                        : demoAttemptState === "needs_guarded_rpc"
                          ? "The contract call was not intercepted."
                          : "Preview analysis prepared for the next contract attempt."}
                    </strong>
                    <p>
                      {demoAttemptState === "needs_guarded_rpc"
                        ? "Update the wallet RPC to the Guardian endpoint above, then rerun the demo."
                        : "Use the findings below to explain exactly why the contract interaction is unsafe."}
                    </p>
                  </div>
                  <div className="finding-list">
                    {demoDecisionFindings.map((finding, index) => {
                      const tone = riskToneFromSeverity(finding.severity);
                      return (
                        <article className="finding-card" key={`${finding.module}-${finding.description}-${index}`}>
                          <div>
                            <strong>{describeEventLabel(finding.module)}</strong>
                            <p>{finding.description}</p>
                          </div>
                          <div className="finding-meta">
                            <span className={`risk-badge risk-badge--${tone}`}>{riskLabel(tone)}</span>
                            <span className="inline-pill">+{finding.weight}</span>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="stage-track">
              {simulationSteps.map((step, index) => {
                const completed = simulationStage === "complete" || index < stageIndex;
                const active = simulationStage !== "idle" && index === stageIndex && simulationStage !== "complete";

                return (
                  <article
                    className={`stage-card${completed ? " stage-card--complete" : ""}${active ? " stage-card--active" : ""}`}
                    key={step.key}
                  >
                    <span className="stage-index">{index + 1}</span>
                    <div>
                      <strong>{step.label}</strong>
                      <p>{step.detail}</p>
                    </div>
                  </article>
                );
              })}
            </div>

            {simulationRun ? (
              <div className="simulation-results">
                <div className="simulation-summary">
                  <article className="summary-chip">
                    <span className="label">Scenario</span>
                    <strong>{describeScenarioName(simulationRun.scenario_id)}</strong>
                  </article>
                  <article className="summary-chip">
                    <span className="label">Target</span>
                    <strong>{shortenAddress(simulationRun.target_address)}</strong>
                  </article>
                  <article className="summary-chip">
                    <span className="label">Surface</span>
                    <strong>{simulationRun.attack_surface.replaceAll("_", " ")}</strong>
                  </article>
                  <article className="summary-chip">
                    <span className="label">Findings</span>
                    <strong>{simulationRun.findings.length}</strong>
                  </article>
                </div>

                <div className="finding-list">
                  {simulationRun.findings.map((finding, index) => {
                    const tone = riskToneFromSeverity(finding.severity);
                    return (
                      <article className="finding-card" key={`${finding.module}-${finding.description}-${index}`}>
                        <div>
                          <strong>{describeEventLabel(finding.module)}</strong>
                          <p>{finding.description}</p>
                        </div>
                        <div className="finding-meta">
                          <span className={`risk-badge risk-badge--${tone}`}>{riskLabel(tone)}</span>
                          <span className="inline-pill">+{finding.weight}</span>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="empty-card">
                <strong>No simulation result yet</strong>
                <p>Run the drill once and the result will stay visible here and in the audit surfaces.</p>
              </div>
            )}
          </section>

          <section id="approvals" className="panel panel-wide" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Approval Scanner</span>
                <h2>Outstanding token approvals</h2>
              </div>
              <span className="panel-meta">{approvals.length} record(s)</span>
            </div>

            <div className="table-shell">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Risk</th>
                    <th>Spender</th>
                    <th>Amount</th>
                    <th>Granted</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {approvals.length ? (
                    approvals.map((approval) => {
                      const tone = riskToneFromScore(approval.risk_score);
                      return (
                        <tr key={approval.id}>
                          <td>
                            <span className={`risk-badge risk-badge--${tone}`}>{riskLabel(tone)}</span>
                          </td>
                          <td>
                            <strong>{shortenAddress(approval.spender)}</strong>
                          </td>
                          <td>
                            {approval.amount} {approval.token_denom}
                          </td>
                          <td>Height {approval.granted_at_height}</td>
                          <td>
                            <button
                              className="cta-secondary cta-compact"
                              disabled={approvalAction === approval.id}
                              onClick={() => {
                                void revokeApproval(approval);
                              }}
                            >
                              {approvalAction === approval.id ? "Revoking" : "Revoke"}
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={5}>
                        <div className="empty-card empty-card--table">
                          <strong>No approval records available</strong>
                          <p>Refresh the workspace after the backend scans the connected address.</p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section id="registry" className="panel" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Address Registry</span>
                <h2>Protected addresses</h2>
              </div>
              <span className="panel-meta">{watchedAddresses.length} tracked</span>
            </div>

            <div className="form-stack">
              <label className="form-field">
                <span>Address</span>
                <input
                  value={watchedAddressInput}
                  onChange={(event) => setWatchedAddressInput(event.target.value)}
                  placeholder="init1..."
                />
              </label>
              <label className="form-field">
                <span>Label</span>
                <input
                  value={watchedLabelInput}
                  onChange={(event) => setWatchedLabelInput(event.target.value)}
                  placeholder="Treasury, exchange, vault"
                />
              </label>
              <button
                className={`opt-in-checkbox${watchAsSimulationTarget ? " opt-in-checkbox--checked" : ""}`}
                type="button"
                onClick={() => setWatchAsSimulationTarget((current) => !current)}
              >
                <span className="opt-in-checkbox__mark">{watchAsSimulationTarget ? "✓" : ""}</span>
                <span>
                  <strong>Set as primary protected address</strong>
                  <small>
                    Use this address as the default focus for monitoring, analysis, and
                    security actions in the app.
                  </small>
                </span>
              </button>
              <button
                className="cta-secondary"
                onClick={() => {
                  void registerWatchedAddress();
                }}
              >
                Save Watched Address
              </button>
            </div>

            <div className="entity-stack">
              {watchedAddresses.length ? (
                watchedAddresses.map((entry) => (
                  <article className="entity-row" key={entry.id}>
                    <div>
                      <strong>{entry.label || shortenAddress(entry.address)}</strong>
                      <p>{entry.address}</p>
                    </div>
                    <div className="entity-tags">
                      {entry.is_simulation_target ? <span className="inline-pill">Simulation Target</span> : null}
                      <span className={`risk-badge risk-badge--${entry.is_poisoned ? "block" : "clear"}`}>
                        {entry.is_poisoned ? "Poisoned" : "Tracked"}
                      </span>
                    </div>
                  </article>
                ))
              ) : (
                <div className="empty-card">
                  <strong>No watched addresses saved yet</strong>
                  <p>Add registry entries to protect cold wallets, exchanges, or treasury routes.</p>
                </div>
              )}
            </div>
          </section>

          <section id="alerts" className="panel" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Alert Email Settings</span>
                <h2>Set up email alerts</h2>
              </div>
              <span className="panel-meta">
                {profile?.user?.email_address ? "Configured" : "Not configured"}
              </span>
            </div>

            <div className="form-stack">
              <label className="form-field">
                <span>Email</span>
                <input
                  value={alertEmail}
                  onChange={(event) => setAlertEmail(event.target.value)}
                  placeholder="name@example.com"
                />
              </label>
              <label className="form-field">
                <span>Display Name</span>
                <input
                  value={alertEmailName}
                  onChange={(event) => setAlertEmailName(event.target.value)}
                  placeholder="Aegis Alerts"
                />
              </label>
              <div className="button-row">
                <button
                  className="cta-secondary"
                  onClick={() => {
                    void registerEmail();
                  }}
                >
                  Save Email
                </button>
                <button
                  className="cta-secondary"
                  onClick={() => {
                    void sendTestEmail();
                  }}
                  disabled={!profile?.user?.email_address}
                >
                  Send Test
                </button>
              </div>
            </div>

            <div className="detail-card">
              <strong>Current destination</strong>
              <p>
                {profile?.user?.email_address
                  ? `${profile.user.email_address}${profile.user.email_display_name ? ` (${profile.user.email_display_name})` : ""}`
                  : "No alert email has been registered yet."}
              </p>
            </div>
          </section>

          <section id="audit" className="panel panel-wide" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Audit Log</span>
                <h2>Protection history</h2>
              </div>
              <span className="panel-meta">{pageSummary(riskEvents.length, historyPage, PAGE_SIZE)}</span>
            </div>

            <div className="table-shell">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Event</th>
                    <th>Wallet</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleHistoryEvents.length ? (
                    visibleHistoryEvents.map((event) => {
                      const tone = riskToneFromSeverity(event.severity);
                      return (
                        <tr key={event.id}>
                          <td>{formatAbsoluteTime(event.created_at)}</td>
                          <td>
                            <strong>{describeEventLabel(event.event_type)}</strong>
                            <div className="table-note">{renderEventExcerpt(event) || "No additional detail captured."}</div>
                          </td>
                          <td>{shortenAddress(event.address)}</td>
                          <td>
                            <span className={`risk-badge risk-badge--${tone}`}>{riskLabel(tone)}</span>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={4}>
                        <div className="empty-card empty-card--table">
                          <strong>No audit events yet</strong>
                          <p>Once the monitor writes findings, the full history will appear here.</p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {riskEvents.length > PAGE_SIZE ? (
              <div className="panel-pagination">
                <button
                  className="cta-secondary cta-compact"
                  onClick={() => setHistoryPage((current) => Math.max(current - 1, 0))}
                  disabled={historyPage === 0}
                >
                  Previous
                </button>
                <span>
                  Page {historyPage + 1} of {historyPageCount}
                </span>
                <button
                  className="cta-secondary cta-compact"
                  onClick={() =>
                    setHistoryPage((current) => Math.min(current + 1, historyPageCount - 1))
                  }
                  disabled={historyPage >= historyPageCount - 1}
                >
                  Next
                </button>
              </div>
            ) : null}
          </section>

          <section id="rpc" className="panel panel-wide" data-section>
            <div className="panel-header">
              <div>
                <span className="section-kicker">Network Guide</span>
                <h2>Wallet RPC guide</h2>
              </div>
              <span className="panel-meta">Manual setup only</span>
            </div>

            <div className="rpc-grid">
              <div className="detail-card detail-card--strong">
                <strong>Guardian RPC endpoint</strong>
                <div className="endpoint-box endpoint-box--inline">
                  <code>{guardedRpcEndpoint}</code>
                  <button
                    className="cta-secondary cta-compact"
                    onClick={() => {
                      void copyText(guardedRpcEndpoint, "rpc-dashboard");
                    }}
                  >
                    {copiedValue === "rpc-dashboard" ? "Copied" : "Copy"}
                  </button>
                </div>
                <p>
                  This screen does not change your wallet automatically. It shows the Guardian RPC
                  that should sit in front of the chain for protected signing.
                </p>
              </div>

              <div className="instruction-list">
                <article className="instruction-card">
                  <strong>1. Open your wallet network settings</strong>
                  <p>Use the custom network editor in Keplr, Leap, or Station if you want to change RPCs.</p>
                </article>
                <article className="instruction-card">
                  <strong>2. Update it manually if needed</strong>
                  <p>Paste the Guardian RPC above into the wallet if you want transactions screened before broadcast.</p>
                </article>
                <article className="instruction-card">
                  <strong>3. Use the dashboard as your health check</strong>
                  <p>
                    The service status above reflects backend connectivity for this app. It still does
                    not change your wallet settings automatically.
                  </p>
                </article>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
