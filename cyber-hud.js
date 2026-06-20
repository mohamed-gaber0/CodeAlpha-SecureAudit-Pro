/* ════════════════════════════════════════════════════════════════
   SecureAudit Pro — Cyber HUD Interactive Engine
   Boot Sequence • Matrix Background (Lightweight) • Neon Mouse
   ════════════════════════════════════════════════════════════════ */
'use strict';

(() => {
  /* ══════════════════════════════════════
     1. BOOT SEQUENCE (shows every page load)
     ══════════════════════════════════════ */
  const BOOT_LINES = [
    { text: '> INITIALIZING SECUREAUDIT PRO ENGINE v2.4...', cls: '' },
    { text: '> LOADING VULNERABILITY SIGNATURES [55 RULES]...', cls: 'dim' },
    { text: '> ESTABLISHING SECURE CHANNEL [TLS 1.3]...', cls: 'dim' },
    { text: '> IMPORTING OWASP TOP 10 MODULE (2021)...', cls: 'dim' },
    { text: '> LOADING CVE DATABASE [PYTHON / NPM / GO]...', cls: 'dim' },
    { text: '> CONFIGURING STATIC ANALYSIS ENGINE (SAST)...', cls: 'dim' },
    { text: '⚠  WARNING: ALL ANALYSIS IS CLIENT-SIDE. NO DATA TRANSMITTED.', cls: 'warn' },
    { text: '✓ ALL MODULES ONLINE. BREACH DETECTION READY.', cls: 'success' },
    { text: '> ACCESS GRANTED ██████████████████████████████ 100%', cls: 'success' },
  ];

  function runBoot() {
    const overlay      = document.getElementById('boot-overlay');
    const terminal     = document.getElementById('boot-terminal');
    const progressFill = document.getElementById('boot-progress-fill');
    if (!overlay || !terminal) return;

    const STEP  = 280;          // ms between lines
    const total = BOOT_LINES.length;

    BOOT_LINES.forEach((item, i) => {
      setTimeout(() => {
        const line = document.createElement('div');
        line.className   = `boot-line ${item.cls}`;
        line.textContent = item.text;
        terminal.appendChild(line);

        if (progressFill) {
          progressFill.style.width = `${Math.round(((i + 1) / total) * 100)}%`;
        }

        // After last line, fade out and reveal app
        if (i === total - 1) {
          setTimeout(() => {
            overlay.classList.add('fade-out');
            setTimeout(() => { overlay.style.display = 'none'; }, 750);
          }, 500);
        }
      }, i * STEP);
    });
  }

  /* ══════════════════════════════════════
     2. MATRIX RAIN — lightweight (RAF, ~20fps, pauses when hidden)
     ══════════════════════════════════════ */
  function initMatrix() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize, { passive: true });

    const CHARS   = '01ABCDEF0123456789<>=+-/*!?{}[]';
    const fontSize = 14;
    let cols  = Math.floor(canvas.width  / fontSize);
    let drops = Array.from({ length: cols }, () => Math.random() * -(canvas.height / fontSize));

    window.addEventListener('resize', () => {
      cols  = Math.floor(canvas.width / fontSize);
      if (drops.length < cols) {
        while (drops.length < cols) drops.push(Math.random() * -50);
      }
    }, { passive: true });

    let tick  = 0;
    let rafId = 0;

    function draw() {
      tick++;
      if (tick % 3 === 0) {   // Draw every 3rd frame ≈ 20fps
        ctx.fillStyle = 'rgba(4, 8, 18, 0.18)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.font      = `${fontSize}px "JetBrains Mono", monospace`;
        ctx.fillStyle = 'rgba(0, 212, 255, 0.75)';

        for (let i = 0; i < drops.length; i++) {
          const char = CHARS[Math.floor(Math.random() * CHARS.length)];
          ctx.fillText(char, i * fontSize, drops[i] * fontSize);
          if (drops[i] * fontSize > canvas.height && Math.random() > 0.97) {
            drops[i] = 0;
          }
          drops[i] += 0.5;
        }
      }
      rafId = requestAnimationFrame(draw);
    }

    rafId = requestAnimationFrame(draw);

    // Pause when tab is hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        cancelAnimationFrame(rafId);
      } else {
        rafId = requestAnimationFrame(draw);
      }
    });
  }

  /* ══════════════════════════════════════
     3. NEON MOUSE GLOW (smooth lerp, no lag)
     ══════════════════════════════════════ */
  function initMouseGlow() {
    const glow = document.createElement('div');
    glow.id = 'neon-mouse-glow';
    Object.assign(glow.style, {
      position:     'fixed',
      width:        '380px',
      height:       '380px',
      borderRadius: '50%',
      background:   'radial-gradient(circle, rgba(0,212,255,0.045) 0%, transparent 70%)',
      pointerEvents:'none',
      zIndex:       '2',
      left:         '-500px',
      top:          '-500px',
      transform:    'translate(-50%, -50%)',
      mixBlendMode: 'screen',
      willChange:   'left, top',
    });
    document.body.appendChild(glow);

    let tx = -500, ty = -500;
    let cx = -500, cy = -500;

    document.addEventListener('mousemove', e => {
      tx = e.clientX; ty = e.clientY;
    }, { passive: true });

    (function animateGlow() {
      cx += (tx - cx) * 0.1;
      cy += (ty - cy) * 0.1;
      glow.style.left = `${cx}px`;
      glow.style.top  = `${cy}px`;
      requestAnimationFrame(animateGlow);
    })();
  }

  /* ══════════════════════════════════════
     4. SCAN BUTTON RIPPLE (visual only)
     ══════════════════════════════════════ */
  function initScanRipple() {
    const scanBtn = document.getElementById('scanBtn');
    if (!scanBtn) return;
    scanBtn.style.position = 'relative';
    scanBtn.style.overflow = 'hidden';

    scanBtn.addEventListener('click', function(e) {
      const old = this.querySelector('.scan-ripple');
      if (old) old.remove();

      const rect   = this.getBoundingClientRect();
      const size   = Math.max(rect.width, rect.height) * 2.5;
      const ripple = document.createElement('span');
      ripple.className = 'scan-ripple';
      ripple.style.cssText = `
        position:absolute; pointer-events:none; border-radius:50%;
        width:${size}px; height:${size}px; z-index:0;
        top:${e.clientY - rect.top - size/2}px;
        left:${e.clientX - rect.left - size/2}px;
        background:radial-gradient(circle, rgba(0,212,255,0.22) 0%, transparent 70%);
        animation:ripple-expand 0.7s ease-out forwards;
      `;
      this.appendChild(ripple);
      setTimeout(() => ripple.remove(), 800);
    });
  }

  /* ══════════════════════════════════════
     5. ROTATING BADGE TICKER
     ══════════════════════════════════════ */
  function initBadgeTicker() {
    const badge = document.querySelector('.badge-text');
    if (!badge) return;
    const labels = ['Engine v2.4', '55 RULES', 'OWASP 2021', '6 LANGS', 'CVE SCAN', 'SAST MODE'];
    let i = 0;
    setInterval(() => {
      i = (i + 1) % labels.length;
      badge.style.opacity = '0';
      setTimeout(() => {
        badge.textContent = labels[i];
        badge.style.transition = 'opacity 0.3s ease';
        badge.style.opacity    = '1';
      }, 200);
    }, 2500);
  }

  /* ══════════════════════════════════════
     6. INJECT KEYFRAMES
     ══════════════════════════════════════ */
  function injectStyles() {
    const s = document.createElement('style');
    s.textContent = `
      @keyframes ripple-expand {
        from { transform: scale(0); opacity: 1; }
        to   { transform: scale(1); opacity: 0; }
      }
    `;
    document.head.appendChild(s);
  }

  /* ══════════════════════════════════════
     INIT
     ══════════════════════════════════════ */
  document.addEventListener('DOMContentLoaded', () => {
    injectStyles();
    runBoot();
    initMatrix();
    initMouseGlow();
    initScanRipple();
    initBadgeTicker();
    // NOTE: NO parallax tilt (removed by user request)
    // NOTE: NO counter override (original animateGauge handles scores correctly)
  });
})();
