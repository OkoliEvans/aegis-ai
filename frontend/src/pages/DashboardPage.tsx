import { ReactNode } from "react";
import { ProtectionSphere } from "../components/ProtectionSphere";
import { SiteBrand } from "../components/SiteBrand";
import { SubpageHeader } from "../components/SubpageHeader";

type DashboardFeedRow = {
  tone: "clear" | "warn" | "high" | "block";
  hash: string;
  counterparty: string;
  value: string;
  time: string;
};

type DashboardRiskItem = {
  tone: "clear" | "warn" | "high" | "block";
  title: string;
  detail: string;
  action: string;
  target: string;
};

type DashboardApprovalRow = {
  id: string;
  tone: "clear" | "warn" | "high" | "block";
  token: string;
  spender: string;
  amount: string;
  busy: boolean;
};

type DashboardHistoryRow = {
  id: string;
  tone: "clear" | "warn" | "high" | "block";
  title: string;
  detail: string;
  time: string;
};

type DashboardPageProps = {
  notices?: ReactNode;
  walletLabel: string;
  approvalBadgeCount: number;
  headerDate: string;
  protectedAddress: string;
  pendingAlertCount: number;
  protectedValue: string;
  transactionsScreened: string;
  blockedCount: string;
  warnedCount: string;
  transactionsToday: string;
  approvalsAtRiskCount: string;
  poisonedAddressCount: string;
  rpcHost: string;
  rpcStatusText: string;
  sphereState: "idle" | "screening" | "warned" | "blocked" | "offline";
  sphereAddresses: string[];
  feedRows: DashboardFeedRow[];
  feedPaginationLabel: string;
  showFeedPagination: boolean;
  canPreviousFeedPage: boolean;
  canNextFeedPage: boolean;
  activeRisks: DashboardRiskItem[];
  approvalRows: DashboardApprovalRow[];
  historyRows: DashboardHistoryRow[];
  historyPaginationLabel: string;
  showHistoryPagination: boolean;
  canPreviousHistoryPage: boolean;
  canNextHistoryPage: boolean;
  activeSection: string;
  onNavigateHome: () => void;
  onNavigateSetup: () => void;
  onNavigateSimulation: () => void;
  onSelectSidebar: (id: string) => void;
  onOpenWallet: () => void;
  onOpenAlerts: () => void;
  grantDemoApprovalBusy: boolean;
  onGrantDemoApproval: () => void;
  onRevokeApproval: (id: string) => void;
  onOpenSimulation: () => void;
  onPreviousFeedPage: () => void;
  onNextFeedPage: () => void;
  onPreviousHistoryPage: () => void;
  onNextHistoryPage: () => void;
};

function feedRiskLabel(tone: DashboardFeedRow["tone"]) {
  if (tone === "block") return "✕ Block";
  if (tone === "high") return "▲ High";
  if (tone === "warn") return "△ Warn";
  return "● Clear";
}

const sidebarGroups = [
  {
    label: "Monitor",
    items: [
      { id: "dashboard", icon: "◎", label: "Dashboard" },
      { id: "feed", icon: "≡", label: "Transaction Feed" },
      { id: "audit", icon: "□", label: "Audit Log" }
    ]
  },
  {
    label: "Protect",
    items: [
      { id: "approvals", icon: "∞", label: "Approvals", badge: true },
      { id: "registry", icon: "⬡", label: "Address Registry" },
      { id: "ica", icon: "⬟", label: "ICA Monitor" }
    ]
  },
  {
    label: "Settings",
    items: [
      { id: "wallets", icon: "◈", label: "Wallets" },
      { id: "alerts", icon: "✉", label: "Alert Emails" },
      { id: "thresholds", icon: "⚙", label: "Risk Thresholds" },
      { id: "rpc", icon: "⬢", label: "RPC Setup" }
    ]
  }
] as const;

export function DashboardPage({
  notices,
  walletLabel,
  approvalBadgeCount,
  headerDate,
  protectedAddress,
  pendingAlertCount,
  protectedValue,
  transactionsScreened,
  blockedCount,
  warnedCount,
  transactionsToday,
  approvalsAtRiskCount,
  poisonedAddressCount,
  rpcHost,
  rpcStatusText,
  sphereState,
  sphereAddresses,
  feedRows,
  feedPaginationLabel,
  showFeedPagination,
  canPreviousFeedPage,
  canNextFeedPage,
  activeRisks,
  approvalRows,
  historyRows,
  historyPaginationLabel,
  showHistoryPagination,
  canPreviousHistoryPage,
  canNextHistoryPage,
  activeSection,
  onNavigateHome,
  onNavigateSetup,
  onNavigateSimulation,
  onSelectSidebar,
  onOpenWallet,
  onOpenAlerts,
  grantDemoApprovalBusy,
  onGrantDemoApproval,
  onRevokeApproval,
  onOpenSimulation,
  onPreviousFeedPage,
  onNextFeedPage,
  onPreviousHistoryPage,
  onNextHistoryPage
}: DashboardPageProps) {
  return (
    <div className="dashboard-screen">
      <aside className="dashboard-screen__sidebar">
        <div className="dashboard-screen__brand">
          <SiteBrand />
          <p>v1.0 · Initia Testnet</p>
        </div>

        <div className="dashboard-screen__guard">
          <ProtectionSphere size="md" state={sphereState} addresses={sphereAddresses} />
          <div className="dashboard-screen__guard-copy">
            <div className="dashboard-screen__guard-status">● Protected</div>
            <strong>{protectedAddress}</strong>
          </div>
        </div>

        <nav className="dashboard-screen__nav">
          {sidebarGroups.map((group) => (
            <div className="dashboard-screen__nav-group" key={group.label}>
              <span className="dashboard-screen__nav-label">{group.label}</span>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={`dashboard-screen__nav-item${activeSection === item.id ? " is-active" : ""}`}
                  onClick={() => onSelectSidebar(item.id)}
                >
                  <span className="dashboard-screen__nav-icon">{item.icon}</span>
                  <span>{item.label}</span>
                  {item.badge ? <span className="dashboard-screen__nav-badge">{approvalBadgeCount}</span> : null}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="dashboard-screen__rpc">
          <span>RPC Status</span>
          <strong>{rpcHost}</strong>
          <p>{rpcStatusText}</p>
        </div>
      </aside>

      <main className="dashboard-screen__main">
        <SubpageHeader
          active="dashboard"
          onBackHome={onNavigateHome}
          onNavigateDashboard={() => onSelectSidebar("dashboard")}
          onNavigateSimulation={onNavigateSimulation}
          onNavigateSetup={onNavigateSetup}
        />

        <header className="dashboard-screen__topbar">
          <div>
            <h1>Dashboard</h1>
            <p>{headerDate} · All wallets</p>
          </div>
          <div className="dashboard-screen__topbar-actions">
            <button className="dashboard-wallet-pill" onClick={onOpenWallet}>
              <span className="dashboard-wallet-pill__dot" />
              <span>{walletLabel}</span>
              <span>▾</span>
            </button>
            <button className="dashboard-bell" onClick={onOpenAlerts}>
              <span>🔔</span>
              <span className="dashboard-bell__badge">{pendingAlertCount}</span>
            </button>
          </div>
        </header>

        {notices}

        <section className="dashboard-hero-card" id="dashboard">
          <div className="dashboard-hero-card__orb">
            <ProtectionSphere size="lg" state={sphereState} addresses={sphereAddresses} />
          </div>
          <div className="dashboard-hero-card__copy">
            <span className="dashboard-hero-card__status">● Protected — Agent Active</span>
            <h2>{protectedAddress}</h2>
            <p>Monitoring since block #8,241,003 · Connected 14 days</p>
            <div className="dashboard-hero-card__stats">
              <article>
                <strong>{transactionsScreened}</strong>
                <span>Txs Screened</span>
              </article>
              <article>
                <strong className="is-pink">{blockedCount}</strong>
                <span>Blocked</span>
              </article>
              <article>
                <strong className="is-gold">{warnedCount}</strong>
                <span>Warned</span>
              </article>
              <article>
                <strong className="is-teal">{protectedValue}</strong>
                <span>Protected Value</span>
              </article>
            </div>
          </div>
        </section>

        <section className="dashboard-metric-row">
          <article className="dashboard-stat-card">
            <span>Transactions Today</span>
            <strong>{transactionsToday}</strong>
            <p>All clear · avg score 8/100</p>
          </article>
          <article className="dashboard-stat-card">
            <span>Blocked</span>
            <strong className="is-pink">2</strong>
            <p>Last: 4 hours ago</p>
          </article>
          <article className="dashboard-stat-card">
            <span>Approvals at Risk</span>
            <strong className="is-gold">{approvalsAtRiskCount}</strong>
            <p>2 unlimited · review needed</p>
          </article>
          <article className="dashboard-stat-card">
            <span>Poisoned Addresses</span>
            <strong className="is-gold">{poisonedAddressCount}</strong>
            <p>Tagged · won&apos;t be used</p>
          </article>
        </section>

        <div className="dashboard-layout-grid">
          <section className="dashboard-panel-main" id="feed">
            <div className="dashboard-panel-main__head">
              <h3>Recent Transactions</h3>
              <div className="dashboard-panel-main__actions">
                {showFeedPagination ? (
                  <div className="dashboard-pagination">
                    <button
                      className="dashboard-pagination__button"
                      onClick={onPreviousFeedPage}
                      disabled={!canPreviousFeedPage}
                    >
                      Previous
                    </button>
                    <span className="dashboard-pagination__label">{feedPaginationLabel}</span>
                    <button
                      className="dashboard-pagination__button"
                      onClick={onNextFeedPage}
                      disabled={!canNextFeedPage}
                    >
                      Next
                    </button>
                  </div>
                ) : null}
                <button className="dashboard-link-button" onClick={onOpenSimulation}>
                  View full feed →
                </button>
              </div>
            </div>

            <div className="dashboard-feed-table">
              <div className="dashboard-feed-table__head">
                <span>Risk</span>
                <span>Hash</span>
                <span>Protocol / Recipient</span>
                <span>Value</span>
                <span>Time</span>
              </div>
              {feedRows.map((row) => (
                <article className={`dashboard-feed-row dashboard-feed-row--${row.tone}`} key={`${row.hash}-${row.time}`}>
                  <span className={`dashboard-risk-pill dashboard-risk-pill--${row.tone}`}>
                    {feedRiskLabel(row.tone)}
                  </span>
                  <span>{row.hash}</span>
                  <span>{row.counterparty}</span>
                  <span>{row.value}</span>
                  <span>{row.time}</span>
                </article>
              ))}
            </div>
          </section>

          <aside className="dashboard-rail">
            <section className="dashboard-rail-card">
              <div className="dashboard-rail-card__head">
                <h3>Active Risks</h3>
                <span>{Math.max(activeRisks.length, 3)} items</span>
              </div>
              <div className="dashboard-risk-stack">
                {activeRisks.map((item) => (
                  <article className={`dashboard-risk-card dashboard-risk-card--${item.tone}`} key={`${item.title}-${item.target}`}>
                    <div>
                      <strong>{item.title}</strong>
                      <p>{item.detail}</p>
                    </div>
                    <button className="dashboard-rail-button" onClick={() => onSelectSidebar(item.target)}>
                      {item.action} →
                    </button>
                  </article>
                ))}
              </div>
            </section>

            <section className="dashboard-rail-card" id="approvals">
              <div className="dashboard-rail-card__head">
                <h3>Top Risky Approvals</h3>
                <div className="dashboard-rail-card__actions">
                  <button
                    className="dashboard-rail-button dashboard-rail-button--wide"
                    onClick={onGrantDemoApproval}
                    disabled={grantDemoApprovalBusy}
                  >
                    {grantDemoApprovalBusy ? "Granting..." : "Grant Demo Approval"}
                  </button>
                  <button className="dashboard-link-button" onClick={() => onSelectSidebar("approvals")}>
                    Revoke All High →
                  </button>
                </div>
              </div>
              <div className="dashboard-approval-table">
                <div className="dashboard-approval-table__head">
                  <span>Risk</span>
                  <span>Token · Spender</span>
                  <span>Amount</span>
                  <span />
                </div>
                {approvalRows.map((approval) => (
                  <article className="dashboard-approval-row" key={approval.id}>
                    <span className={`dashboard-risk-pill dashboard-risk-pill--${approval.tone}`}>
                      {approval.tone === "block" ? "HIGH" : "WARN"}
                    </span>
                    <div className="dashboard-approval-row__meta">
                      <strong>{approval.token}</strong>
                      <p className="dashboard-approval-row__spender">{approval.spender}</p>
                    </div>
                    <span className="dashboard-approval-row__amount">{approval.amount}</span>
                    <button className="dashboard-revoke-button" onClick={() => onRevokeApproval(approval.id)}>
                      {approval.busy ? "Revoking" : "Revoke"}
                    </button>
                  </article>
                ))}
                {!approvalRows.length ? (
                  <article className="dashboard-approval-empty">
                    <strong>No active demo approvals</strong>
                    <p>Grant one approval to load a live revoke action into the dashboard.</p>
                  </article>
                ) : null}
              </div>
            </section>
          </aside>
        </div>

        <section className="dashboard-history" id="audit">
          <div className="dashboard-history__head">
            <h3>Protection History</h3>
            <div className="dashboard-history__actions">
              {showHistoryPagination ? (
                <div className="dashboard-pagination">
                  <button
                    className="dashboard-pagination__button"
                    onClick={onPreviousHistoryPage}
                    disabled={!canPreviousHistoryPage}
                  >
                    Previous
                  </button>
                  <span className="dashboard-pagination__label">{historyPaginationLabel}</span>
                  <button
                    className="dashboard-pagination__button"
                    onClick={onNextHistoryPage}
                    disabled={!canNextHistoryPage}
                  >
                    Next
                  </button>
                </div>
              ) : null}
              <button className="dashboard-link-button" onClick={onOpenSimulation}>
                Open Simulation Center
              </button>
            </div>
          </div>
          <div className="dashboard-history__list">
            {historyRows.map((row) => (
              <article className={`dashboard-history-row dashboard-history-row--${row.tone}`} key={row.id}>
                <div>
                  <strong>{row.title}</strong>
                  <p>{row.detail}</p>
                </div>
                <span>{row.time}</span>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
