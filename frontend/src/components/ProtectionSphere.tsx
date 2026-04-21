import { useEffect, useRef } from "react";

type SphereState = "idle" | "screening" | "warned" | "blocked" | "offline";
type SphereSize = "sm" | "md" | "lg";

type ProtectionSphereProps = {
  state: SphereState;
  size: SphereSize;
  addresses?: string[];
  className?: string;
};

type OrbitNode = {
  angle: number;
  radius: number;
  speed: number;
  tilt: number;
  phase: number;
};

const SIZE_MAP: Record<SphereSize, number> = {
  sm: 48,
  md: 132,
  lg: 220
};

const STATE_COLORS: Record<SphereState, { primary: string; secondary: string; flare: string }> = {
  idle: {
    primary: "#00D9C0",
    secondary: "#8B6FFF",
    flare: "rgba(0, 217, 192, 0.3)"
  },
  screening: {
    primary: "#3DB8F5",
    secondary: "#00D9C0",
    flare: "rgba(61, 184, 245, 0.32)"
  },
  warned: {
    primary: "#F0B429",
    secondary: "#8B6FFF",
    flare: "rgba(240, 180, 41, 0.3)"
  },
  blocked: {
    primary: "#FF3366",
    secondary: "#FF6B35",
    flare: "rgba(255, 51, 102, 0.34)"
  },
  offline: {
    primary: "#54708d",
    secondary: "#24384d",
    flare: "rgba(84, 112, 141, 0.2)"
  }
};

function prefersReducedMotion() {
  return typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function ProtectionSphere({
  state,
  size,
  addresses = [],
  className
}: ProtectionSphereProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const context = canvas.getContext("2d");
    if (!context) return;

    const reducedMotion = prefersReducedMotion();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const pixelSize = SIZE_MAP[size];
    const palette = STATE_COLORS[state];
    let animationFrame = 0;
    const orbitDots = Math.max(addresses.length, 1);
    const nodes: OrbitNode[] = Array.from({ length: 18 }, (_, index) => ({
      angle: (Math.PI * 2 * index) / 18,
      radius: 0.62 + Math.random() * 0.18,
      speed: 0.38 + Math.random() * 0.48,
      tilt: 0.6 + Math.random() * 0.45,
      phase: Math.random() * Math.PI * 2
    }));

    canvas.width = pixelSize * dpr;
    canvas.height = pixelSize * dpr;
    canvas.style.width = `${pixelSize}px`;
    canvas.style.height = `${pixelSize}px`;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);

    function draw(time: number) {
      const t = time * 0.001;
      const center = pixelSize / 2;
      const sphereRadius = pixelSize * 0.28;
      const pulseStrength =
        state === "screening" ? 1.14 : state === "warned" ? 1.1 : state === "blocked" ? 1.2 : 1.04;
      const pulse = reducedMotion ? 1 : 1 + Math.sin(t * (state === "screening" ? 3.8 : 2.2)) * 0.03 * pulseStrength;

      context.clearRect(0, 0, pixelSize, pixelSize);

      const glow = context.createRadialGradient(center, center, sphereRadius * 0.2, center, center, sphereRadius * 2.2);
      glow.addColorStop(0, palette.flare);
      glow.addColorStop(1, "rgba(0, 0, 0, 0)");
      context.fillStyle = glow;
      context.beginPath();
      context.arc(center, center, sphereRadius * 2.2, 0, Math.PI * 2);
      context.fill();

      for (let ring = 0; ring < 3; ring += 1) {
        const scale = 1 + ring * 0.22 + (!reducedMotion ? Math.sin(t * 1.6 + ring) * 0.015 : 0);
        context.strokeStyle = ring === 0 ? "rgba(255,255,255,0.14)" : `${palette.secondary}2a`;
        context.lineWidth = ring === 0 ? 1.2 : 0.9;
        context.beginPath();
        context.ellipse(center, center, sphereRadius * scale, sphereRadius * scale * (0.78 + ring * 0.04), 0.32 + ring * 0.52, 0, Math.PI * 2);
        context.stroke();
      }

      const points = nodes.map((node) => {
        const wobble = reducedMotion ? 0 : Math.sin(t * node.speed + node.phase) * sphereRadius * 0.12;
        const x = center + Math.cos(t * node.speed + node.angle) * sphereRadius * node.radius;
        const y = center + Math.sin(t * node.speed * node.tilt + node.angle + node.phase) * sphereRadius * 0.66 + wobble * 0.25;
        return { x, y };
      });

      for (let left = 0; left < points.length; left += 1) {
        for (let right = left + 1; right < points.length; right += 1) {
          const dx = points[right].x - points[left].x;
          const dy = points[right].y - points[left].y;
          const distance = Math.hypot(dx, dy);
          if (distance > sphereRadius * 0.95) continue;

          const alpha = 0.08 + (1 - distance / (sphereRadius * 0.95)) * 0.18;
          context.strokeStyle = `${palette.primary}${Math.round(alpha * 255).toString(16).padStart(2, "0")}`;
          context.lineWidth = 0.8;
          context.beginPath();
          context.moveTo(points[left].x, points[left].y);
          context.lineTo(points[right].x, points[right].y);
          context.stroke();
        }
      }

      points.forEach((point) => {
        const nodeGlow = context.createRadialGradient(point.x, point.y, 0, point.x, point.y, sphereRadius * 0.16);
        nodeGlow.addColorStop(0, "rgba(255,255,255,0.9)");
        nodeGlow.addColorStop(1, "rgba(255,255,255,0)");
        context.fillStyle = nodeGlow;
        context.beginPath();
        context.arc(point.x, point.y, sphereRadius * 0.16, 0, Math.PI * 2);
        context.fill();

        context.fillStyle = palette.primary;
        context.beginPath();
        context.arc(point.x, point.y, pixelSize * 0.01 + 1.1, 0, Math.PI * 2);
        context.fill();
      });

      const core = context.createRadialGradient(center, center, sphereRadius * 0.1, center, center, sphereRadius * 0.95 * pulse);
      core.addColorStop(0, "rgba(255,255,255,0.88)");
      core.addColorStop(0.25, palette.primary);
      core.addColorStop(0.7, `${palette.secondary}44`);
      core.addColorStop(1, "rgba(0,0,0,0)");
      context.fillStyle = core;
      context.beginPath();
      context.arc(center, center, sphereRadius * 0.95 * pulse, 0, Math.PI * 2);
      context.fill();

      for (let index = 0; index < orbitDots; index += 1) {
        const angle = reducedMotion ? (Math.PI * 2 * index) / orbitDots : t * 0.9 + (Math.PI * 2 * index) / orbitDots;
        const orbitRadius = sphereRadius * (1.22 + index * 0.04);
        const dotX = center + Math.cos(angle) * orbitRadius;
        const dotY = center + Math.sin(angle) * orbitRadius * 0.55;
        context.fillStyle = index === 0 ? "#E2EBF6" : palette.secondary;
        context.beginPath();
        context.arc(dotX, dotY, size === "sm" ? 1.8 : 2.4, 0, Math.PI * 2);
        context.fill();
      }

      if (state === "blocked") {
        context.strokeStyle = "rgba(255, 51, 102, 0.38)";
        context.lineWidth = 2;
        context.beginPath();
        context.arc(center, center, sphereRadius * (1.35 + (!reducedMotion ? Math.sin(t * 4.8) * 0.04 : 0)), 0, Math.PI * 2);
        context.stroke();
      }

      if (!reducedMotion) {
        animationFrame = window.requestAnimationFrame(draw);
      }
    }

    draw(0);

    return () => {
      window.cancelAnimationFrame(animationFrame);
    };
  }, [addresses.length, size, state]);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
