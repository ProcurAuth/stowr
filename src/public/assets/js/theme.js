// SPDX-License-Identifier: MIT OR Apache-2.0
/* Theme control: System (default), Dark or Light, saved in this browser only.
   The page loads this script without defer in <head>, so the theme applies before the first paint. The key is
   "stowr.theme": the tabs of the same origin share one choice.

   The control is the theme selector of ClickHouse Dash: one icon button that shows the current choice (CSS reads
   html[data-theme-mode]) and, under it, a menu of the three choices. Markup:
     <div class="themeSelect" data-theme-select>
       <button data-theme-trigger aria-haspopup="listbox" aria-expanded="false">...</button>
       <div class="themeSelect__menu" role="listbox" hidden>
         <button role="option" data-theme-value="system|dark|light" aria-selected="...">...</button>
       </div>
     </div>
   Without script, the control stays hidden. */
(function () {
  'use strict';
  var KEY = 'stowr.theme';
  var root = document.documentElement;
  var mode = 'system';
  try {
    var stored = window.localStorage.getItem(KEY);
    if (stored === 'dark' || stored === 'light') mode = stored;
  } catch (e) {}

  function apply(next) {
    if (next === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', next);
    root.setAttribute('data-theme-mode', next);
  }

  root.classList.add('js');
  apply(mode);

  function mark(select) {
    var options = select.querySelectorAll('[data-theme-value]');
    for (var i = 0; i < options.length; i += 1) {
      options[i].setAttribute('aria-selected', String(options[i].getAttribute('data-theme-value') === mode));
    }
    var trigger = select.querySelector('[data-theme-trigger]');
    if (trigger) trigger.setAttribute('aria-label', 'Theme: ' + mode);
  }

  function markAll() {
    var selects = document.querySelectorAll('[data-theme-select]');
    for (var i = 0; i < selects.length; i += 1) mark(selects[i]);
  }

  function choose(next) {
    mode = next === 'dark' || next === 'light' ? next : 'system';
    try {
      if (mode === 'system') window.localStorage.removeItem(KEY);
      else window.localStorage.setItem(KEY, mode);
    } catch (e) {}
    apply(mode);
    markAll();
  }

  // focusOption: the option that takes the focus on open. Without it, the selected option (or the first) takes it.
  function setOpen(select, open, focusTrigger, focusOption) {
    var trigger = select.querySelector('[data-theme-trigger]');
    var menu = select.querySelector('[role="listbox"]');
    if (!trigger || !menu) return;
    menu.hidden = !open;
    select.classList.toggle('is-open', open);
    trigger.setAttribute('aria-expanded', String(open));
    if (open) {
      var current = focusOption || menu.querySelector('[aria-selected="true"]') || menu.querySelector('[data-theme-value]');
      if (current) current.focus();
    } else if (focusTrigger) {
      trigger.focus();
    }
  }

  function bind(select) {
    var trigger = select.querySelector('[data-theme-trigger]');
    var menu = select.querySelector('[role="listbox"]');
    if (!trigger || !menu) return;
    trigger.addEventListener('click', function (event) {
      event.stopPropagation();
      setOpen(select, menu.hidden, false);
    });
    menu.addEventListener('click', function (event) {
      var option = event.target.closest('[data-theme-value]');
      if (!option) return;
      choose(option.getAttribute('data-theme-value'));
      setOpen(select, false, true);
    });
    // Keys: ArrowDown and ArrowUp on the closed trigger open the menu on the first or the last option. In the open
    // menu, ArrowDown and ArrowUp move and wrap, Home and PageUp go to the first option, End and PageDown go to the
    // last option, Escape closes the menu and gives the focus back to the trigger, Tab closes the menu.
    select.addEventListener('keydown', function (event) {
      var options = Array.prototype.slice.call(menu.querySelectorAll('[data-theme-value]'));
      if (menu.hidden) {
        if (event.target !== trigger || !options.length || event.altKey || event.ctrlKey || event.metaKey) return;
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
          event.preventDefault();
          setOpen(select, true, false, options[event.key === 'ArrowUp' ? options.length - 1 : 0]);
        }
        return;
      }
      var index = options.indexOf(document.activeElement);
      if (event.key === 'Home' || event.key === 'PageUp') {
        event.preventDefault();
        if (options.length) options[0].focus();
      } else if (event.key === 'End' || event.key === 'PageDown') {
        event.preventDefault();
        if (options.length) options[options.length - 1].focus();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        setOpen(select, false, true);
      } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        var step = event.key === 'ArrowDown' ? 1 : -1;
        var next = options[(index + step + options.length) % options.length];
        if (next) next.focus();
      } else if (event.key === 'Tab') {
        setOpen(select, false, false);
      }
    });
    document.addEventListener('click', function (event) {
      if (!menu.hidden && !select.contains(event.target)) setOpen(select, false, false);
    });
    mark(select);
  }

  // Another tab changed the choice: follow it.
  window.addEventListener('storage', function (event) {
    if (event.key !== KEY) return;
    var next = event.newValue === 'dark' || event.newValue === 'light' ? event.newValue : 'system';
    if (next !== mode) choose(next);
  });

  document.addEventListener('DOMContentLoaded', function () {
    var selects = document.querySelectorAll('[data-theme-select]');
    for (var i = 0; i < selects.length; i += 1) bind(selects[i]);
  });

  window.BB = window.BB || {};
  window.BB.theme = { get mode() { return mode; }, choose: choose };
})();
