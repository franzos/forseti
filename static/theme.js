// Appearance control. Source of truth is the forseti_theme cookie (read
// server-side to render <html>); this writes it client-side + a localStorage
// mirror (survives cookie-stripped iframes), and tracks the OS in System mode.
(function () {
  'use strict';
  var KEY = 'forseti_theme';
  var COOKIE = 'forseti_theme';
  var mql = window.matchMedia('(prefers-color-scheme: dark)');

  function radios() {
    return Array.prototype.slice.call(
      document.querySelectorAll('[data-theme-toggle] [data-theme-value]'));
  }

  function pref() {
    var p = null;
    try { p = localStorage.getItem(KEY); } catch (e) {}
    if (p !== 'light' && p !== 'dark' && p !== 'system') {
      p = document.documentElement.getAttribute('data-theme') || 'system';
    }
    return p;
  }

  function apply(p) {
    var dark = p === 'dark' || (p === 'system' && mql.matches);
    var el = document.documentElement;
    el.classList.toggle('dark', dark);
    el.setAttribute('data-theme', p);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#131314' : '#fcf8fa');
    radios().forEach(function (b) {
      var on = b.getAttribute('data-theme-value') === p;
      b.setAttribute('aria-checked', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
    });
  }

  function set(p) {
    try { localStorage.setItem(KEY, p); } catch (e) {}
    var secure = location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = COOKIE + '=' + p +
      '; Path=/; Max-Age=31536000; SameSite=Lax' + secure;
    apply(p);
  }

  var btns = radios();
  btns.forEach(function (b, i) {
    b.addEventListener('click', function () { set(b.getAttribute('data-theme-value')); });
    // Radiogroup arrow-key navigation.
    b.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' &&
          e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      var fwd = e.key === 'ArrowRight' || e.key === 'ArrowDown';
      var next = btns[(i + (fwd ? 1 : btns.length - 1)) % btns.length];
      next.focus();
      set(next.getAttribute('data-theme-value'));
    });
  });

  mql.addEventListener('change', function () {
    if (pref() === 'system') apply('system');
  });

  apply(pref());
})();
