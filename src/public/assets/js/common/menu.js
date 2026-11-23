// SPDX-License-Identifier: MIT OR Apache-2.0
/*!
 * BB.menu: a small popover for the kebab menus.
 * - Trigger: .bb-kebab (icon only). Its aria-expanded follows the menu.
 * - Container: .bb-menu (must contain .bb-menu-popover; the items are .bb-menu-item)
 * - The popover has position: fixed, below the icon and aligned to its right edge, or above the icon when
 *   the space below is too small. BB.menu.openAt puts it at the given point.
 *   An ancestor with overflow: hidden does not cut it.
 * - The menu closes on a pointer down outside it (capture), on an item click, on Escape, on Tab, on a scroll
 *   and when the window loses the focus. A resize moves the popover.
 * - Keys: a keyboard open (Enter or Space on the kebab) puts the focus on the first item. ArrowDown and ArrowUp
 *   on a closed kebab open the menu on the first or the last item. In an open menu, ArrowDown and ArrowUp move
 *   between the items and wrap; Home and PageUp go to the first item; End and PageDown go to the last item.
 *   Escape closes the menu and gives the focus back to the kebab. Tab closes the menu.
 */
(function () {
  const BB = (window.BB = window.BB || {});

  function kebabOf(menu) {
    return menu ? menu.querySelector('.bb-kebab') : null;
  }

  function setExpanded(menu, open) {
    const kebab = kebabOf(menu);
    if (kebab) kebab.setAttribute('aria-expanded', String(open));
  }

  function hidePopover(menu) {
    const pop = menu.querySelector('.bb-menu-popover');
    if (!pop) return;
    pop.style.display = 'none';
    pop.style.visibility = '';
    pop.style.left = '';
    pop.style.top = '';
    pop.style.position = '';
  }

  function closeAll() {
    document.querySelectorAll('.bb-menu.is-open').forEach((m) => {
      m.classList.remove('is-open');
      setExpanded(m, false);
      hidePopover(m);
    });
  }

  function getOpenMenu() {
    return document.querySelector('.bb-menu.is-open');
  }

  // The items that the keyboard can reach: visible and enabled.
  function menuItems(menu) {
    const pop = menu.querySelector('.bb-menu-popover');
    if (!pop) return [];
    return Array.from(pop.querySelectorAll('.bb-menu-item')).filter((item) =>
      !item.hidden
      && !item.disabled
      && item.getAttribute('aria-disabled') !== 'true'
      && getComputedStyle(item).display !== 'none'
    );
  }

  function focusElement(el) {
    if (!el) return;
    try {
      el.focus({ preventScroll: true });
    } catch (e) {
      /* detached */
    }
  }

  function positionPopover(menu, anchorPoint = null) {
    const icon = menu.querySelector('.bb-kebab');
    const pop = menu.querySelector('.bb-menu-popover');
    if (!icon || !pop) return;

    pop.style.display = 'block';
    pop.style.visibility = 'hidden';

    const r = BB.viewport?.rect(icon) || icon.getBoundingClientRect();
    const viewport = BB.viewport?.size() || { width: window.innerWidth, height: window.innerHeight };
    const pw = pop.offsetWidth || 220;
    const ph = pop.offsetHeight || 280;
    const point = anchorPoint && Number.isFinite(anchorPoint.x) && Number.isFinite(anchorPoint.y)
      ? {
          x: BB.viewport?.toLayoutPixels(anchorPoint.x) ?? anchorPoint.x,
          y: BB.viewport?.toLayoutPixels(anchorPoint.y) ?? anchorPoint.y
        }
      : null;

    let left = point ? point.x : r.right - pw;
    let top = point ? point.y : r.bottom + 8;

    const maxLeft = Math.max(8, viewport.width - pw - 8);
    left = Math.max(8, Math.min(left, maxLeft));
    const maxTop = Math.max(8, viewport.height - ph - 8);
    if (top > maxTop) top = point ? maxTop : Math.max(8, r.top - ph - 8);
    top = Math.max(8, top);

    pop.style.position = 'fixed';
    pop.style.left = left + 'px';
    pop.style.top = top + 'px';
    pop.style.visibility = 'visible';
  }

  // Opens one menu. focus: null (the focus stays where it is), "first" or "last" (that item takes the focus).
  function openMenu(menu, { anchorPoint = null, focus = null } = {}) {
    closeAll();
    menu.classList.add('is-open');
    setExpanded(menu, true);
    requestAnimationFrame(() => {
      // The menu closed before this frame: do not show its popover again.
      if (!menu.classList.contains('is-open')) return;
      positionPopover(menu, anchorPoint);
      if (focus === 'first' || focus === 'last') {
        const items = menuItems(menu);
        focusElement(focus === 'last' ? items[items.length - 1] : items[0]);
      }
    });
  }

  function eventInsideOpenMenu(e) {
    const open = getOpenMenu();
    if (!open) return false;

    const pop = open.querySelector('.bb-menu-popover');
    const t = e.target;

    if (open.contains(t)) return true;
    if (pop && pop.contains(t)) return true;

    if (e.composedPath) {
      const path = e.composedPath();
      if (path.includes(open)) return true;
      if (pop && path.includes(pop)) return true;
    }
    return false;
  }

  function onGlobalDown(e) {
    const open = getOpenMenu();
    if (!open) return;
    if (!eventInsideOpenMenu(e)) closeAll();
  }
  ['pointerdown', 'mousedown', 'touchstart'].forEach((type) =>
    document.addEventListener(type, onGlobalDown, true)
  );

  window.addEventListener(
    'scroll',
    () => {
      if (getOpenMenu()) closeAll();
    },
    true
  );
  window.addEventListener('blur', closeAll);

  document.addEventListener(
    'click',
    (e) => {
      const item = e.target.closest('.bb-menu-item');
      if (item) {
        // A click from the keyboard has detail 0. After such a pick, the focus goes back to the kebab,
        // unless the action moved the focus to another place (for example a dialog).
        const fromKeyboard = e.detail === 0;
        const owner = item.closest('.bb-menu');
        setTimeout(() => {
          closeAll();
          if (!fromKeyboard || !owner) return;
          const active = document.activeElement;
          if (!active || active === document.body || owner.contains(active)) focusElement(kebabOf(owner));
        }, 0);
        return;
      }

      const kebab = e.target.closest('.bb-kebab');
      const menu = e.target.closest('.bb-menu');
      if (kebab && menu) {
        const wasOpen = menu.classList.contains('is-open');
        closeAll();
        // Enter or Space on the kebab gives a click with detail 0: the first item takes the focus.
        if (!wasOpen) openMenu(menu, { focus: e.detail === 0 ? 'first' : null });
        e.preventDefault();
        e.stopPropagation();
        return;
      }

    },
    true
  );

  window.addEventListener('resize', () => {
    const open = getOpenMenu();
    if (open) positionPopover(open);
  });

  function isTextField(el) {
    if (!el) return false;
    if (el.isContentEditable) return true;
    if (el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') return true;
    if (el.tagName !== 'INPUT') return false;
    return !/^(button|checkbox|radio|submit|reset|image|file|color|range)$/i.test(el.type || '');
  }

  document.addEventListener('keydown', (e) => {
    const modified = e.altKey || e.ctrlKey || e.metaKey;
    const open = getOpenMenu();

    if (!open) {
      if (modified || (e.key !== 'ArrowDown' && e.key !== 'ArrowUp')) return;
      const kebab = e.target?.closest?.('.bb-kebab');
      const menu = kebab?.closest('.bb-menu');
      if (!menu) return;
      e.preventDefault();
      openMenu(menu, { focus: e.key === 'ArrowUp' ? 'last' : 'first' });
      return;
    }

    const kebab = kebabOf(open);
    const active = document.activeElement;
    const focusInside = !!active && open.contains(active);

    if (e.key === 'Escape') {
      // One Escape closes one layer: the other Escape handlers of the page do not see this key.
      e.preventDefault();
      e.stopImmediatePropagation();
      closeAll();
      focusElement(kebab);
      return;
    }

    if (e.key === 'Tab') {
      // From an item, the Tab order continues from the kebab: Tab goes to the element after it,
      // Shift+Tab stops on the kebab.
      if (focusInside && kebab && active !== kebab) {
        focusElement(kebab);
        if (e.shiftKey) e.preventDefault();
      }
      closeAll();
      return;
    }

    // The navigation keys do not move into the menu while the focus is in a text field outside it.
    if (modified || (!focusInside && isTextField(active))) return;

    const items = menuItems(open);
    if (!items.length) return;
    const at = items.indexOf(active);
    let next;
    switch (e.key) {
      case 'ArrowDown':
        next = at < 0 ? 0 : (at + 1) % items.length;
        break;
      case 'ArrowUp':
        next = at < 0 ? items.length - 1 : (at - 1 + items.length) % items.length;
        break;
      case 'Home':
      case 'PageUp':
        next = 0;
        break;
      case 'End':
      case 'PageDown':
        next = items.length - 1;
        break;
      default:
        return;
    }
    e.preventDefault();
    focusElement(items[next]);
  });

  function openAt(menu, x, y) {
    if (!menu) return false;
    openMenu(menu, { anchorPoint: { x: Number(x), y: Number(y) } });
    return true;
  }

  BB.menu = Object.assign(BB.menu || {}, { closeAll, openAt });
})();
