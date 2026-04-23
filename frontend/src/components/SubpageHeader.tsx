import { ReactNode } from "react";
import { SiteBrand } from "./SiteBrand";

type SubpageHeaderProps = {
  active: "dashboard" | "simulation" | "setup";
  onBackHome: () => void;
  onNavigateDashboard: () => void;
  onNavigateSimulation: () => void;
  onNavigateSetup: () => void;
  rightSlot?: ReactNode;
};

export function SubpageHeader({
  active,
  onBackHome,
  onNavigateDashboard,
  onNavigateSimulation,
  onNavigateSetup,
  rightSlot
}: SubpageHeaderProps) {
  return (
    <header className="subpage-header">
      <div className="subpage-header__left">
        <button className="subpage-header__back" onClick={onBackHome}>
          ← Home
        </button>
        <SiteBrand />
      </div>

      <nav className="subpage-header__nav">
        <button
          className={active === "dashboard" ? "is-active" : undefined}
          onClick={onNavigateDashboard}
        >
          Dashboard
        </button>
        <button
          className={active === "simulation" ? "is-active" : undefined}
          onClick={onNavigateSimulation}
        >
          How It Works
        </button>
        <button
          className={active === "setup" ? "is-active" : undefined}
          onClick={onNavigateSetup}
        >
          Get Started
        </button>
      </nav>

      <div className="subpage-header__right">{rightSlot}</div>
    </header>
  );
}
