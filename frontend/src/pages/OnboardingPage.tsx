import { ReactNode } from "react";
import { SubpageHeader } from "../components/SubpageHeader";

type OnboardingAddress = {
  id: string;
  title: string;
  address: string;
  badge: string;
  tone: "clear" | "block";
};

type OnboardingPageProps = {
  notices?: ReactNode;
  walletLabel: string;
  emailPlaceholder: string;
  confirmPrimaryTarget: boolean;
  watchedAddressInput: string;
  watchedLabelInput: string;
  alertEmail: string;
  staleDigestEnabled: boolean;
  dailySummaryEnabled: boolean;
  watchedAddresses: OnboardingAddress[];
  guardedRpcEndpoint: string;
  activationBusy: boolean;
  copiedValue: string | null;
  onNavigateHome: () => void;
  onNavigateDashboard: () => void;
  onNavigateSimulation: () => void;
  onWatchedAddressChange: (value: string) => void;
  onWatchedLabelChange: (value: string) => void;
  onAlertEmailChange: (value: string) => void;
  onToggleConfirmPrimaryTarget: () => void;
  onToggleStaleDigest: () => void;
  onToggleDailySummary: () => void;
  onAddAddress: () => void;
  onSaveEmail: () => void;
  onSendTest: () => void;
  onCopyRpc: (key: string) => void;
  onActivate: () => void;
};

const preferenceRows = [
  { key: "blocked", label: "Transaction blocked (Score 80+)", forced: true },
  { key: "confirm", label: "Confirmation required (Score 60–79)", forced: true },
  { key: "poison", label: "Poisoned address detected", forced: true }
] as const;

export function OnboardingPage({
  notices,
  walletLabel,
  emailPlaceholder,
  confirmPrimaryTarget,
  watchedAddressInput,
  watchedLabelInput,
  alertEmail,
  staleDigestEnabled,
  dailySummaryEnabled,
  watchedAddresses,
  guardedRpcEndpoint,
  activationBusy,
  copiedValue,
  onNavigateHome,
  onNavigateDashboard,
  onNavigateSimulation,
  onWatchedAddressChange,
  onWatchedLabelChange,
  onAlertEmailChange,
  onToggleConfirmPrimaryTarget,
  onToggleStaleDigest,
  onToggleDailySummary,
  onAddAddress,
  onSaveEmail,
  onSendTest,
  onCopyRpc,
  onActivate
}: OnboardingPageProps) {
  return (
    <div className="onboarding-screen">
      <SubpageHeader
        active="setup"
        onBackHome={onNavigateHome}
        onNavigateDashboard={onNavigateDashboard}
        onNavigateSimulation={onNavigateSimulation}
        onNavigateSetup={() => undefined}
        rightSlot={
          <div className="onboarding-screen__progress" aria-label="Onboarding progress">
            <span />
            <span className="is-active" />
            <span />
          </div>
        }
      />

      <main className="onboarding-screen__body">
        {notices}
        <section className="onboarding-card onboarding-card--primary" id="registry">
          <div className="onboarding-card__step">
            <span className="accent">Step 2 of 3</span>
            <span>· Confirm protection target</span>
          </div>
          <h1 className="onboarding-card__title">Who are we protecting?</h1>
          <p className="onboarding-card__copy">
            Confirm the address Aegis Guard will intercept and screen all outbound transactions for.
          </p>

          <div className="onboarding-label">Connected Wallet</div>
          <div className="wallet-pill-large">
            <span className="wallet-pill-large__dot" />
            <strong>{walletLabel}</strong>
            <span className="wallet-pill-large__status">Connected</span>
          </div>

          <button
            type="button"
            className={`target-card${confirmPrimaryTarget ? " target-card--active" : ""}`}
            onClick={onToggleConfirmPrimaryTarget}
          >
            <span className="target-card__check">{confirmPrimaryTarget ? "✓" : ""}</span>
            <span>
              <strong>This is the address I want to protect</strong>
              <small>
                Aegis Guard will screen all outbound transactions from this address via the RPC proxy.
                You can add additional addresses below.
              </small>
            </span>
          </button>

          <div className="onboarding-label">Protect a different address? (optional)</div>
          <input
            className="onboarding-input"
            value={watchedAddressInput}
            onChange={(event) => onWatchedAddressChange(event.target.value)}
            placeholder="initia1... — leave blank to use connected wallet"
          />

          <div className="onboarding-label onboarding-label--spaced">Additional addresses</div>
          <button className="onboarding-link" onClick={onAddAddress}>
            + Add another
          </button>

          <div className="address-registry-box">
            {watchedAddresses.length ? (
              watchedAddresses.map((entry) => (
                <article className="address-registry-box__row" key={entry.id}>
                  <div>
                    <strong>{entry.title}</strong>
                    <p>{entry.address}</p>
                  </div>
                  <span className={`address-registry-box__badge address-registry-box__badge--${entry.tone}`}>
                    {entry.badge}
                  </span>
                </article>
              ))
            ) : (
              <span>Monitor multiple wallets under one account</span>
            )}
          </div>

          <input
            className="onboarding-input onboarding-input--secondary"
            value={watchedLabelInput}
            onChange={(event) => onWatchedLabelChange(event.target.value)}
            placeholder="Treasury, exchange, vault"
          />
        </section>

        <aside className="onboarding-card onboarding-card--secondary" id="alerts">
          <div className="onboarding-card__step">
            <span className="accent">Step 3 of 3</span>
            <span>· Alerts &amp; activation</span>
          </div>
          <h2 className="onboarding-card__title onboarding-card__title--compact">
            Stay informed.
            <br />
            Activate protection.
          </h2>
          <p className="onboarding-card__copy onboarding-card__copy--narrow">
            Get notified the moment Aegis Guard intercepts a threat. Then point the wallet RPC at the guarded endpoint.
          </p>

          <div className="onboarding-label">Alert Email</div>
          <input
            className="onboarding-input"
            value={alertEmail}
            onChange={(event) => onAlertEmailChange(event.target.value)}
            placeholder={emailPlaceholder}
          />

          <div className="preference-box">
            {preferenceRows.map((row) => (
              <article className="preference-box__row" key={row.key}>
                <span className="preference-box__check">✓</span>
                <span>{row.label}</span>
              </article>
            ))}
            <button className="preference-box__row" type="button" onClick={onToggleStaleDigest}>
              <span className={`preference-box__check preference-box__check--optional${staleDigestEnabled ? " is-on" : ""}`}>
                {staleDigestEnabled ? "✓" : ""}
              </span>
              <span>Stale approvals digest</span>
            </button>
            <button className="preference-box__row" type="button" onClick={onToggleDailySummary}>
              <span className={`preference-box__check preference-box__check--optional${dailySummaryEnabled ? " is-on" : ""}`}>
                {dailySummaryEnabled ? "✓" : ""}
              </span>
              <span>Daily protection summary</span>
            </button>
          </div>

          <div className="onboarding-label" id="rpc">RPC Endpoint</div>
          <div className="rpc-highlight">{guardedRpcEndpoint}</div>
          <p className="rpc-copy">Not yet connected — update your wallet RPC, status will auto-confirm</p>

          <div className="rpc-actions">
            <button className="rpc-actions__button" onClick={() => onCopyRpc("keplr-rpc")}>
              {copiedValue === "keplr-rpc" ? "Copied" : "Keplr Setup →"}
            </button>
            <button className="rpc-actions__button" onClick={() => onCopyRpc("leap-rpc")}>
              {copiedValue === "leap-rpc" ? "Copied" : "Leap Setup →"}
            </button>
            <button className="rpc-actions__button" onClick={() => onCopyRpc("station-rpc")}>
              {copiedValue === "station-rpc" ? "Copied" : "Station →"}
            </button>
          </div>

          <button className="activation-cta" onClick={onActivate} disabled={activationBusy}>
            <span className="landing-screen__primary-mark" aria-hidden="true">
              <span className="landing-screen__primary-mark-inner" />
            </span>
            <span>{activationBusy ? "Activating Protection" : "Activate Protection"}</span>
          </button>

          <div className="onboarding-secondary-actions">
            <button className="rpc-actions__button" onClick={onSaveEmail}>
              Save Email
            </button>
            <button className="rpc-actions__button" onClick={onSendTest}>
              Send Test
            </button>
          </div>
        </aside>
      </main>
    </div>
  );
}
