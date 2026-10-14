(function () {
  // --- Theme toggle: default system, user choice persisted ---
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const themeBtn = document.querySelector('.theme-toggle');
  const isDark = () => {
    const t = root.getAttribute('data-theme');
    return t ? t === 'dark' : media.matches;
  };
  const applyTheme = (dark) => {
    root.setAttribute('data-theme', dark ? 'dark' : 'light');
    if (themeBtn) {
      themeBtn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    }
  };
  applyTheme(isDark());
  // Follow the system while the user hasn't made an explicit choice.
  media.addEventListener('change', (e) => {
    if (!localStorage.getItem('theme')) applyTheme(e.matches);
  });
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next = !isDark();
      localStorage.setItem('theme', next ? 'dark' : 'light');
      applyTheme(next);
    });
  }

  const toggle = document.querySelector('.nav-toggle');
  const links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', () => {
      links.classList.toggle('open');
      const expanded = links.classList.contains('open');
      toggle.setAttribute('aria-expanded', String(expanded));
    });
    links.querySelectorAll('a').forEach((a) => {
      a.addEventListener('click', () => links.classList.remove('open'));
    });
  }

  // Mark current page nav link active based on filename
  const current = (location.pathname.split('/').pop() || 'index.html').toLowerCase();
  document.querySelectorAll('.nav-links a').forEach((a) => {
    const href = (a.getAttribute('href') || '').toLowerCase();
    if (href === current || (current === '' && href === 'index.html')) {
      a.classList.add('is-active');
    }
  });

  // Reveal on scroll
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add('in-view');
        observer.unobserve(e.target);
      }
    });
  }, { threshold: 0.12 });

  if (!reduceMotion) {
    document.querySelectorAll('.value-card, .service-card, .scope-tile, .case-card, .tl-phase, .price-card, .team-card, .location-card')
      .forEach((el) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(14px)';
        el.style.transition = 'opacity 450ms ease, transform 450ms ease';
        observer.observe(el);
      });

    // Infographics reveal via CSS animations keyed off .in-view
    document.querySelectorAll('.cycle-flow, .hex-grid, .clock').forEach((el) => observer.observe(el));

    const style = document.createElement('style');
    style.textContent = '.in-view{opacity:1!important;transform:none!important}';
    document.head.appendChild(style);
  }

  // Contact form: client-side feedback only (no backend)
  const form = document.querySelector('form.contact-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      if (btn) {
        btn.textContent = 'Thanks — we will reach out shortly';
        btn.disabled = true;
        btn.style.background = '#0F172A';
      }
      form.reset();
    });
  }
})();
