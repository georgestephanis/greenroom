// The tour's stand-in for /assets/app.js: same display touches, but nothing is ever sent.
(() => {
  const repo = 'https://github.com/georgestephanis/greenroom';
  const banner = document.createElement('div');
  banner.className = 'tour-banner';
  banner.innerHTML = `<b>Read-only tour.</b> These are real greenroom pages with sample data, saved as static files, so buttons and forms don't do anything. <a href="${repo}#run-it">Run your own</a> to try it for real.`;
  (document.querySelector('header') || document.body.firstElementChild).after(banner);

  let timer;
  const toast = (msg) => {
    let t = document.querySelector('.tour-toast');
    if (!t) { t = document.createElement('div'); t.className = 'tour-toast'; t.setAttribute('role', 'status'); document.body.append(t); }
    t.textContent = msg; t.classList.add('show');
    clearTimeout(timer); timer = setTimeout(() => t.classList.remove('show'), 3200);
  };
  document.addEventListener('submit', (e) => { e.preventDefault(); toast("This is a read-only tour, so nothing was saved. In a real greenroom, this would work."); }, true);
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-tour-off]');
    if (a) { e.preventDefault(); toast('That page is not part of the tour.'); }
  });
  for (const el of document.querySelectorAll('input[type=file]')) el.disabled = true;

  for (const a of document.querySelectorAll('header nav a')) {
    const target = new URL(a.getAttribute('href'), location.href).pathname.replace(/index\.html$/, '');
    const now = location.pathname.replace(/index\.html$/, '');
    if (target === now || (target.endsWith('/') && now.startsWith(target + 'spaces/') && a.textContent.trim() === 'Spaces')) a.setAttribute('aria-current', 'page');
  }
  for (const el of document.querySelectorAll('time[datetime]')) {
    const d = new Date(el.dateTime);
    if (isNaN(d)) continue;
    el.title = el.textContent;
    el.textContent = d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }
  for (const input of document.querySelectorAll('input[readonly].wide')) {
    const b = document.createElement('button'); b.type = 'button'; b.textContent = 'Copy';
    b.addEventListener('click', async () => { await navigator.clipboard.writeText(input.value); b.textContent = 'Copied'; });
    input.after(b);
  }
  for (const sel of document.querySelectorAll('select[data-expiry]')) {
    const local = sel.form.querySelector('[data-expiry-local]');
    sel.querySelector('[data-custom]').hidden = false;
    sel.addEventListener('change', () => { local.parentElement.hidden = !sel.selectedOptions[0].dataset.custom; });
  }
})();
