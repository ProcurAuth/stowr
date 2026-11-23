/* ProcurAuth family site script. Source: ProcurAuth/procurauth docs/assets/site.js. The pages work without it. */
/* Vanilla JavaScript. Do not edit a copy. */
(function () {
  "use strict";
  var root = document.documentElement;
  var KEY = "procurauth-theme";
  /* The browser bar colour of each theme: the --bg token of site.css. */
  var BAR = { light: "#fafafd", dark: "#0c0e15" };

  function readTheme() {
    try { return window.localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function saveTheme(value) {
    try { window.localStorage.setItem(KEY, value); } catch (e) { /* no storage: ignore */ }
  }
  function currentTheme() {
    var set = root.getAttribute("data-theme");
    if (set === "light" || set === "dark") { return set; }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  /* Make each meta[name=theme-color] agree with the theme of the page.
     A theme that the reader chose: one colour, no media query.
     No choice (the system theme): the media and content of the HTML file. */
  function syncThemeColor() {
    var set = root.getAttribute("data-theme");
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    Array.prototype.forEach.call(metas, function (meta) {
      if (!meta.hasAttribute("data-system-content")) {
        meta.setAttribute("data-system-content", meta.getAttribute("content") || "");
        if (meta.hasAttribute("media")) { meta.setAttribute("data-system-media", meta.getAttribute("media")); }
      }
      if (set === "light" || set === "dark") {
        meta.removeAttribute("media");
        meta.setAttribute("content", BAR[set]);
      } else {
        meta.setAttribute("content", meta.getAttribute("data-system-content"));
        if (meta.hasAttribute("data-system-media")) { meta.setAttribute("media", meta.getAttribute("data-system-media")); }
      }
    });
  }

  var stored = readTheme();
  if (stored === "light" || stored === "dark") { root.setAttribute("data-theme", stored); }
  root.classList.add("js");
  syncThemeColor();

  function ready(fn) {
    if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", fn); } else { fn(); }
  }

  ready(function () {
    /* The meta tags can come after this script in the head. */
    syncThemeColor();

    /* Theme toggle */
    var themeBtn = document.getElementById("theme-btn");
    if (themeBtn) {
      var label = function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        themeBtn.setAttribute("aria-label", "Switch to the " + next + " theme");
        themeBtn.setAttribute("title", "Switch to the " + next + " theme");
      };
      label();
      themeBtn.addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        saveTheme(next);
        syncThemeColor();
        label();
      });
    }

    /* Menu on a small screen */
    var menuBtn = document.getElementById("menu-btn");
    var nav = document.getElementById("site-nav");
    if (menuBtn && nav) {
      menuBtn.addEventListener("click", function () {
        var open = nav.classList.toggle("open");
        menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
      });
      /* Escape closes the open menu and gives the focus back to the menu button. */
      document.addEventListener("keydown", function (event) {
        if (event.key !== "Escape" && event.key !== "Esc") { return; }
        if (!nav.classList.contains("open")) { return; }
        nav.classList.remove("open");
        menuBtn.setAttribute("aria-expanded", "false");
        menuBtn.focus();
      });
    }

    /* Copy buttons on code blocks */
    var blocks = document.querySelectorAll("pre[data-copy]");
    Array.prototype.forEach.call(blocks, function (pre) {
      var wrap = pre.parentNode;
      if (!wrap.classList.contains("code-wrap")) { return; }
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "Copy";
      btn.setAttribute("aria-label", "Copy this code to the clipboard");
      btn.addEventListener("click", function () {
        var lines = pre.querySelectorAll(".ln");
        var text = lines.length
          ? Array.prototype.map.call(lines, function (l) { return l.textContent; }).join("\n")
          : pre.innerText.replace(/\n$/, "");
        var done = function (ok) {
          btn.textContent = ok ? "Copied" : "Press Ctrl+C";
          window.setTimeout(function () { btn.textContent = "Copy"; }, 1800);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallback(text)); });
        } else {
          done(fallback(text));
        }
      });
      wrap.appendChild(btn);
    });
    function fallback(text) {
      try {
        var area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(area);
        return ok;
      } catch (e) { return false; }
    }

    /* Table of contents: open on a wide screen, closed on a small one */
    var toc = document.querySelector("details.toc-details");
    if (toc && window.matchMedia) {
      var wide = window.matchMedia("(min-width: 1000px)");
      var sync = function () { if (wide.matches) { toc.setAttribute("open", ""); } else { toc.removeAttribute("open"); } };
      sync();
      if (wide.addEventListener) { wide.addEventListener("change", sync); }
    }

    /* Table of contents: mark the section in view */
    var links = document.querySelectorAll(".toc a[href^='#']");
    var heads = document.querySelectorAll(".doc h2[id]");
    if (links.length && heads.length) {
      var map = {};
      Array.prototype.forEach.call(links, function (a) { map[a.getAttribute("href").slice(1)] = a; });
      var current = null;
      var update = function () {
        var found = null;
        Array.prototype.forEach.call(heads, function (h) {
          if (h.getBoundingClientRect().top <= 140) { found = h.id; }
        });
        if (found === current) { return; }
        current = found;
        Array.prototype.forEach.call(links, function (a) { a.classList.remove("active"); a.removeAttribute("aria-current"); });
        if (found && map[found]) { map[found].classList.add("active"); map[found].setAttribute("aria-current", "true"); }
      };
      var ticking = false;
      window.addEventListener("scroll", function () {
        if (ticking) { return; }
        ticking = true;
        window.requestAnimationFrame(function () { ticking = false; update(); });
      }, { passive: true });
      update();
    }
  });
}());
