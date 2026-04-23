import { ReactNode } from "react";
import { SubpageHeader } from "../components/SubpageHeader";

type SimulationAttackId =
  | "reentrancy_pattern"
  | "low_liquidity"
  | "high_slippage"
  | "dust_attack"
  | "address_poisoning";

type SimulationPageProps = {
  notices?: ReactNode;
  walletLabel: string;
  heroCopy: string;
  expandedPanels: SimulationAttackId[];
  onOpenWallet: () => void;
  onNavigateHome: () => void;
  onNavigateDashboard: () => void;
  onNavigateSetup: () => void;
  onTogglePanel: (id: SimulationAttackId) => void;
  renderExpandedPanel: (id: SimulationAttackId) => ReactNode;
};

const vectors = [
  {
    id: "reentrancy_pattern" as const,
    index: "01",
    title: "Reentrancy",
    icon: "⟳",
    subtitle: "Recursive callbacks drain contract funds before balance state is updated.",
    chips: ["Critical Severity", "AI Contract Analysis", "Bytecode Scanning", "Call Stack Simulation"],
    cvss: "9.8",
    tone: "pink",
    analysis: true
  },
  {
    id: "low_liquidity" as const,
    index: "02",
    title: "Liquidity Pool Manipulation",
    icon: "◫",
    subtitle: "Thin pools amplify price impact. Attackers drain reserves via flash loans, triggering cascading liquidations.",
    chips: ["High Severity", "Pool Analysis", "Reserve Simulation"],
    cvss: "8.4",
    tone: "gold",
    analysis: true
  },
  {
    id: "high_slippage" as const,
    index: "03",
    title: "High Slippage Exploitation",
    icon: "↗",
    subtitle: "Excessive slippage tolerance lets sandwich bots extract value from your swap.",
    chips: ["Medium Severity", "MEV Protection", "Sandwich Detection"],
    cvss: "6.2",
    tone: "orange",
    analysis: false
  },
  {
    id: "dust_attack" as const,
    index: "04",
    title: "Dust Attack",
    icon: "·",
    subtitle: "Microscopic token amounts link addresses together for de-anonymization.",
    chips: ["Privacy Threat", "Auto-Quarantine", "Graph Analysis"],
    cvss: "5.5",
    tone: "violet",
    analysis: false
  },
  {
    id: "address_poisoning" as const,
    index: "05",
    title: "Address Poisoning",
    icon: "☠",
    subtitle: "Visually identical addresses flood your transaction history. One copy-paste sends funds to the wrong wallet — forever.",
    chips: ["Critical Severity", "Levenshtein Match", "Irreversible Loss"],
    cvss: "9.1",
    tone: "pink",
    analysis: false
  }
] as const;

export function SimulationPage({
  notices,
  walletLabel,
  heroCopy,
  expandedPanels,
  onOpenWallet,
  onNavigateHome,
  onNavigateDashboard,
  onNavigateSetup,
  onTogglePanel,
  renderExpandedPanel
}: SimulationPageProps) {
  return (
    <div className="simulation-screen">
      <SubpageHeader
        active="simulation"
        onBackHome={onNavigateHome}
        onNavigateDashboard={onNavigateDashboard}
        onNavigateSimulation={() => undefined}
        onNavigateSetup={onNavigateSetup}
        rightSlot={
          <button className="subpage-header__action" onClick={onOpenWallet}>
            {walletLabel || "Connect Wallet"}
          </button>
        }
      />

      <main className="simulation-screen__content">
        {notices}
        <section className="simulation-screen__hero">
          <span className="simulation-screen__kicker">Interactive Simulations</span>
          <h1 className="simulation-screen__title">
            <span>Five attack surfaces.</span>
            <span className="simulation-screen__title-gradient">All demonstrated live.</span>
          </h1>
          <p className="simulation-screen__copy">{heroCopy}</p>

          <div className="simulation-strip">
            {vectors.map((vector) => {
              const isOpen = expandedPanels.includes(vector.id);
              return (
                <button
                  key={vector.id}
                  className={`simulation-strip__item${isOpen ? " is-open" : ""}`}
                  onClick={() => onTogglePanel(vector.id)}
                >
                  <span className="simulation-strip__index">{vector.index}</span>
                  <span className="simulation-strip__label">{vector.title}</span>
                  <span className="simulation-strip__dot" />
                </button>
              );
            })}
          </div>
        </section>

        <div className="simulation-screen__stack">
          {vectors.map((vector) => {
            const isOpen = expandedPanels.includes(vector.id);

            return (
              <section
                className={`simulation-card simulation-card--${vector.tone}${isOpen ? " is-open" : ""}`}
                key={vector.id}
              >
                <div className="simulation-card__head">
                  <div className="simulation-card__identity">
                    <span className="simulation-card__index">{vector.index}</span>
                    <span className="simulation-card__icon">{vector.icon}</span>
                    <div>
                      <h2>{vector.title}</h2>
                      <p>{vector.subtitle}</p>
                      <div className="simulation-card__chips">
                        {vector.chips.map((chip) => (
                          <span className={`simulation-chip simulation-chip--${vector.tone}`} key={`${vector.id}-${chip}`}>
                            {chip}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="simulation-card__score">
                    {vector.analysis ? (
                      <span className="simulation-card__analysis">
                        ◈ {isOpen ? "Analysis Active" : "Analysis Available"}
                      </span>
                    ) : null}
                    <div className="simulation-card__score-value">
                      <strong>{vector.cvss}</strong>
                      <span>CVSS Score</span>
                    </div>
                    <button
                      className={`simulation-card__toggle simulation-card__toggle--${vector.tone}`}
                      onClick={() => onTogglePanel(vector.id)}
                    >
                      {isOpen ? "−" : "+"}
                    </button>
                  </div>
                </div>

                {isOpen ? <div className="simulation-card__expanded">{renderExpandedPanel(vector.id)}</div> : null}
              </section>
            );
          })}
        </div>
      </main>
    </div>
  );
}
