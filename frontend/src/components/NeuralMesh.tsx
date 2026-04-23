import { useEffect, useRef } from "react";

type NeuralMeshProps = {
  className?: string;
};

type MeshNode = {
  x: number;
  y: number;
  depth: number;
  offsetX: number;
  offsetY: number;
  phase: number;
  amplitude: number;
  speed: number;
  hue: number;
};

function prefersReducedMotion() {
  return typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function NeuralMesh({ className }: NeuralMeshProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const context = canvas.getContext("2d");
    if (!context) return;

    const reducedMotion = prefersReducedMotion();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let width = 0;
    let height = 0;
    let animationFrame = 0;
    let pointer = { x: Number.NaN, y: Number.NaN, active: false };

    const nodeCount = reducedMotion ? 88 : 144;
    const nodes: MeshNode[] = Array.from({ length: nodeCount }, (_, index) => ({
      x: Math.random(),
      y: Math.random(),
      depth: Math.random(),
      offsetX: (Math.random() - 0.5) * 0.1,
      offsetY: (Math.random() - 0.5) * 0.1,
      phase: Math.random() * Math.PI * 2,
      amplitude: 14 + Math.random() * 28,
      speed: 0.18 + Math.random() * 0.46,
      hue: index % 2 === 0 ? 174 + (index % 4) * 4 : 250 + (index % 3) * 8
    }));

    function resize() {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function draw(time: number) {
      const t = time * 0.00025;
      context.clearRect(0, 0, width, height);

      for (let index = 0; index < nodes.length; index += 1) {
        const node = nodes[index];
        const driftX = Math.sin(t * node.speed + node.phase) * node.amplitude;
        const driftY = Math.cos(t * (node.speed + 0.08) + node.phase) * node.amplitude * 0.8;

        const baseX = node.x * width + driftX + node.offsetX * width;
        const baseY = node.y * height + driftY + node.offsetY * height;

        let finalX = baseX;
        let finalY = baseY;

        if (pointer.active && !reducedMotion) {
          const dx = pointer.x - baseX;
          const dy = pointer.y - baseY;
          const distance = Math.hypot(dx, dy);
          const influenceRadius = 150;

          if (distance < influenceRadius) {
            const pull = (1 - distance / influenceRadius) * 26;
            finalX += (dx / Math.max(distance, 1)) * pull;
            finalY += (dy / Math.max(distance, 1)) * pull;
          }
        }

        (node as MeshNode & { drawX?: number; drawY?: number }).drawX = finalX;
        (node as MeshNode & { drawX?: number; drawY?: number }).drawY = finalY;
      }

      for (let left = 0; left < nodes.length; left += 1) {
        const source = nodes[left] as MeshNode & { drawX: number; drawY: number };
        for (let right = left + 1; right < nodes.length; right += 1) {
          const target = nodes[right] as MeshNode & { drawX: number; drawY: number };
          const dx = target.drawX - source.drawX;
          const dy = target.drawY - source.drawY;
          const distance = Math.hypot(dx, dy);
          const threshold = 128 + (source.depth + target.depth) * 44;

          if (distance > threshold) continue;

          const alpha = (1 - distance / threshold) * (0.07 + (1 - (source.depth + target.depth) * 0.5) * 0.11);
          const gradient = context.createLinearGradient(source.drawX, source.drawY, target.drawX, target.drawY);
          gradient.addColorStop(0, `hsla(${source.hue}, 90%, 68%, ${alpha})`);
          gradient.addColorStop(1, `hsla(${target.hue}, 90%, 72%, ${alpha * 0.82})`);

          context.strokeStyle = gradient;
          context.lineWidth = 0.45 + (1 - distance / threshold) * 0.38;
          context.beginPath();
          context.moveTo(source.drawX, source.drawY);
          context.lineTo(target.drawX, target.drawY);
          context.stroke();
        }
      }

      for (let index = 0; index < nodes.length; index += 1) {
        const node = nodes[index] as MeshNode & { drawX: number; drawY: number };
        const radius = 1 + (1 - node.depth) * 1.35;
        const glow = context.createRadialGradient(node.drawX, node.drawY, 0, node.drawX, node.drawY, radius * 4.2);
        glow.addColorStop(0, `hsla(${node.hue}, 100%, 78%, 0.42)`);
        glow.addColorStop(1, `hsla(${node.hue}, 100%, 60%, 0)`);

        context.fillStyle = glow;
        context.beginPath();
        context.arc(node.drawX, node.drawY, radius * 4.2, 0, Math.PI * 2);
        context.fill();

        context.fillStyle = `hsla(${node.hue}, 100%, 82%, 0.62)`;
        context.beginPath();
        context.arc(node.drawX, node.drawY, radius, 0, Math.PI * 2);
        context.fill();
      }

      const orbRadius = Math.min(width, height) * 0.12;
      const orbGradient = context.createRadialGradient(
        width * 0.74,
        height * 0.34,
        orbRadius * 0.2,
        width * 0.74,
        height * 0.34,
        orbRadius * 1.6
      );
      orbGradient.addColorStop(0, "rgba(0, 217, 192, 0.08)");
      orbGradient.addColorStop(1, "rgba(0, 217, 192, 0)");
      context.fillStyle = orbGradient;
      context.beginPath();
      context.arc(width * 0.74, height * 0.34, orbRadius * 1.6, 0, Math.PI * 2);
      context.fill();

      if (!reducedMotion) {
        animationFrame = window.requestAnimationFrame(draw);
      }
    }

    function handlePointerMove(event: PointerEvent) {
      const rect = canvas.getBoundingClientRect();
      pointer = {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        active: true
      };
    }

    function handlePointerLeave() {
      pointer.active = false;
    }

    resize();
    draw(0);

    canvas.addEventListener("pointermove", handlePointerMove);
    canvas.addEventListener("pointerleave", handlePointerLeave);
    window.addEventListener("resize", resize);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      canvas.removeEventListener("pointermove", handlePointerMove);
      canvas.removeEventListener("pointerleave", handlePointerLeave);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
