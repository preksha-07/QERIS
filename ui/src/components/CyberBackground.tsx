import React, { useEffect, useRef } from 'react';

/**
 * CyberBackground
 * Renders a subtle, high-performance, futuristic canvas background:
 * - Ambient gradient mesh shifting slowly in cyan and cool blue tones.
 * - Gentle floating micro-nodes and subtle connecting lines representing secure network communications.
 * - Reduced-motion accessibility compliant.
 * - Non-interactive (`pointer-events: none`), positioned strictly behind application content (`z-index: 0`).
 */
export const CyberBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Check for user reduced motion preference
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const prefersReducedMotion = mediaQuery.matches;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener('resize', handleResize);

    // Subtle network node representation
    const nodeCount = Math.min(32, Math.floor((width * height) / 45000));
    const nodes: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      baseAlpha: number;
    }> = [];

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.28,
        vy: (Math.random() - 0.5) * 0.28,
        radius: Math.random() * 1.5 + 1.0,
        baseAlpha: Math.random() * 0.25 + 0.15,
      });
    }

    let t = 0;

    const render = () => {
      if (!prefersReducedMotion) {
        t += 0.0025;
      }

      ctx.clearRect(0, 0, width, height);

      // 1. Shifting ambient radial glows (Cyan / Ice-Blue / Light Indigo)
      const g1X = width * 0.35 + Math.sin(t * 0.7) * (width * 0.08);
      const g1Y = height * 0.25 + Math.cos(t * 0.6) * (height * 0.06);
      const grad1 = ctx.createRadialGradient(g1X, g1Y, 10, g1X, g1Y, width * 0.55);
      grad1.addColorStop(0, 'rgba(224, 242, 254, 0.45)'); // Light sky/cyan
      grad1.addColorStop(0.6, 'rgba(240, 249, 255, 0.15)');
      grad1.addColorStop(1, 'rgba(248, 250, 252, 0)');
      ctx.fillStyle = grad1;
      ctx.fillRect(0, 0, width, height);

      const g2X = width * 0.75 + Math.cos(t * 0.5) * (width * 0.07);
      const g2Y = height * 0.75 + Math.sin(t * 0.8) * (height * 0.07);
      const grad2 = ctx.createRadialGradient(g2X, g2Y, 10, g2X, g2Y, width * 0.5);
      grad2.addColorStop(0, 'rgba(238, 242, 255, 0.40)'); // Soft indigo
      grad2.addColorStop(0.6, 'rgba(241, 245, 249, 0.12)');
      grad2.addColorStop(1, 'rgba(248, 250, 252, 0)');
      ctx.fillStyle = grad2;
      ctx.fillRect(0, 0, width, height);

      // 2. Subtle connection lines between proximate nodes
      const maxDist = 135;
      ctx.lineWidth = 0.65;

      for (let i = 0; i < nodes.length; i++) {
        const n1 = nodes[i];
        if (!prefersReducedMotion) {
          n1.x += n1.vx;
          n1.y += n1.vy;

          if (n1.x < 0) n1.x = width;
          else if (n1.x > width) n1.x = 0;
          if (n1.y < 0) n1.y = height;
          else if (n1.y > height) n1.y = 0;
        }

        for (let j = i + 1; j < nodes.length; j++) {
          const n2 = nodes[j];
          const dx = n1.x - n2.x;
          const dy = n1.y - n2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDist) {
            const alpha = (1 - dist / maxDist) * 0.14;
            ctx.strokeStyle = `rgba(2, 132, 199, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.stroke();
          }
        }
      }

      // 3. Draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(2, 132, 199, ${n.baseAlpha})`;
        ctx.fill();
      }

      if (!prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, []);

  return (
    <div
      className="cyber-bg-container"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        pointerEvents: 'none',
        zIndex: 0,
        overflow: 'hidden',
      }}
      aria-hidden="true"
    >
      <canvas
        ref={canvasRef}
        style={{
          display: 'block',
          width: '100%',
          height: '100%',
        }}
      />
    </div>
  );
};
