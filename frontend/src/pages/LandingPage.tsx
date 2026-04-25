import { NeuralMesh } from "../components/NeuralMesh";
import { SiteBrand } from "../components/SiteBrand";

type LandingPageProps = {
  onConnect: () => void;
  onOpenHowItWorks: () => void;
  onOpenGetStarted: () => void;
  onOpenInitia: () => void;
  headerCtaLabel: string;
  primaryCtaLabel: string;
};

export function LandingPage({
  onConnect,
  onOpenHowItWorks,
  onOpenGetStarted,
  onOpenInitia,
  headerCtaLabel,
  primaryCtaLabel
}: LandingPageProps) {
  return (
    <div className="landing-screen">
      <NeuralMesh className="landing-screen__mesh" />
      <div className="landing-screen__veil" />

      <header className="marketing-header">
        <SiteBrand />
        <nav className="marketing-header__nav">
          <button onClick={onOpenHowItWorks}>How It Works</button>
          <button onClick={onOpenGetStarted}>Get Started</button>
          <button onClick={onOpenInitia}>Initia</button>
        </nav>
        <button className="marketing-header__cta" onClick={onConnect}>
          {headerCtaLabel}
        </button>
      </header>

      <main className="landing-screen__content">
        <div className="landing-screen__hero-copy">
          <span className="landing-screen__kicker">AI Agent · Initia Network · Real-Time Protection</span>
          <h1 className="landing-screen__title">
            <span>Every transaction.</span>
            <span className="landing-screen__title-gradient">Screened before it</span>
            <span className="landing-screen__title-gradient">reaches chain.</span>
          </h1>
          <p className="landing-screen__description">
            <span>Aegis Guard intercepts every transaction before it reaches the chain</span>
            <span>— screens it, scores it, and acts. Address poisoning, malicious</span>
            <span>contracts, blind transfers. Caught before broadcast.</span>
          </p>

          <div className="landing-screen__actions">
            <button className="landing-screen__primary" onClick={onConnect}>
              <span className="landing-screen__primary-mark" aria-hidden="true">
                <span className="landing-screen__primary-mark-inner" />
              </span>
              <span>{primaryCtaLabel}</span>
            </button>
            <button className="landing-screen__secondary" onClick={onOpenHowItWorks}>
              See How It Works →
            </button>
          </div>
        </div>

        <div className="landing-screen__stats">
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
      </main>
    </div>
  );
}
