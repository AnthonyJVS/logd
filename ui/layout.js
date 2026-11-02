'use strict';
/*
 * Dockable panel layout (OBS / Resolve style) for a workspace section.
 * The layout is a tree: a leaf is a pane id, a node is
 *   { d: 'row' | 'col', s: [weights], c: [children] }.
 * Panes can be resized by gutters, dragged by their title bar onto another
 * pane's edge (dock beside it) or centre (swap), floated, and maximized.
 */
const Layout = (() => {
  const ANIM = { duration: 280, easing: 'cubic-bezier(.2,.8,.2,1)' };
  const MIN_W = 140, MIN_H = 70;
  const all = {};

  const clone = x => JSON.parse(JSON.stringify(x));
  const load = (k, d) => { try { const v = localStorage.getItem('logd.layout.' + k); return v ? JSON.parse(v) : d; } catch { return d; } };
  const save = (k, v) => { try { localStorage.setItem('logd.layout.' + k, JSON.stringify(v)); } catch { } };

  function leaves(n, out = []) { if (typeof n === 'string') out.push(n); else n.c.forEach(c => leaves(c, out)); return out; }

  /** Removes a pane from the tree; collapses nodes left with one child. */
  function remove(n, id) {
    if (n == null) return null;
    if (typeof n === 'string') return n === id ? null : n;
    const c = [], s = [];
    n.c.forEach((ch, i) => { const r = remove(ch, id); if (r != null) { c.push(r); s.push(n.s[i]); } });
    if (!c.length) return null;
    if (c.length === 1) return c[0];
    return { d: n.d, s, c };
  }

  /** Puts `id` on `side` of pane `target`. */
  function insert(n, target, id, side) {
    const d = side === 'left' || side === 'right' ? 'row' : 'col', before = side === 'left' || side === 'top';
    if (typeof n === 'string') {
      if (n !== target) return n;
      return { d, s: [1, 1], c: before ? [id, n] : [n, id] };
    }
    const i = n.c.indexOf(target);
    if (i >= 0 && n.d === d) {
      // same direction: become a sibling and split the target's share
      const half = n.s[i] / 2, c = n.c.slice(), s = n.s.slice();
      s[i] = half; c.splice(before ? i : i + 1, 0, id); s.splice(before ? i : i + 1, 0, half);
      return { d, s, c };
    }
    return { d: n.d, s: n.s.slice(), c: n.c.map(ch => insert(ch, target, id, side)) };
  }

  function swap(n, a, b) {
    if (typeof n === 'string') return n === a ? b : n === b ? a : n;
    return { d: n.d, s: n.s, c: n.c.map(ch => swap(ch, a, b)) };
  }

  function create(section, defaults, onChange) {
    const key = section.id;
    const panes = {};
    section.querySelectorAll(':scope > .pane[data-pane]').forEach(p => panes[p.dataset.pane] = p);
    const ids = Object.keys(panes);
    const fresh = () => ({ tree: clone(defaults), float: {}, max: null });
    let st = load(key, fresh());
    // a pane set that no longer matches the saved layout means the app changed: start over
    const known = [...leaves(st.tree || ''), ...Object.keys(st.float || {})];
    if (!st.tree || known.length !== ids.length || !ids.every(i => known.includes(i))) st = fresh();

    const root = document.createElement('div');
    root.className = 'dock-root';
    section.append(root);
    const overlay = document.createElement('div'); overlay.className = 'dock-zone'; section.append(overlay);

    for (const [id, p] of Object.entries(panes)) {
      const pt = p.querySelector('.pt');
      const ctl = document.createElement('span'); ctl.className = 'pctl';
      ctl.innerHTML = `<button title="Float / dock" data-act="float">⧉</button><button title="Maximize (double-click title)" data-act="max">⤢</button>`;
      pt.append(ctl);
      ctl.addEventListener('click', e => {
        const a = e.target.closest('button')?.dataset.act;
        if (a === 'float') toggleFloat(id);
        if (a === 'max') toggleMax(id);
      });
      pt.addEventListener('dblclick', e => { if (!e.target.closest('input,select,button,label')) toggleMax(id); });
      pt.addEventListener('pointerdown', e => startMove(e, id));
      new ResizeObserver(() => { if (p.classList.contains('floating')) remember(id); }).observe(p);
    }

    function rects() { const r = {}; for (const [id, p] of Object.entries(panes)) r[id] = p.getBoundingClientRect(); return r; }

    /** FLIP: render, then slide every pane from where it was. */
    function animate(before) {
      for (const [id, p] of Object.entries(panes)) {
        const a = before[id], b = p.getBoundingClientRect();
        if (!a || !b.width || !a.width) continue;
        const dx = a.left - b.left, dy = a.top - b.top, sx = a.width / b.width, sy = a.height / b.height;
        if (Math.abs(dx) < 1 && Math.abs(dy) < 1 && Math.abs(sx - 1) < .01 && Math.abs(sy - 1) < .01) continue;
        p.animate([{ transformOrigin: '0 0', transform: `translate(${dx}px,${dy}px) scale(${sx},${sy})` }, { transformOrigin: '0 0', transform: 'none' }], ANIM);
      }
    }

    function build(n) {
      if (typeof n === 'string') return panes[n];
      const box = document.createElement('div');
      box.className = 'split ' + n.d;
      n.c.forEach((ch, i) => {
        if (i) {
          const g = document.createElement('div');
          g.className = 'gutter';
          g.addEventListener('pointerdown', e => startResize(e, n, i, box));
          box.append(g);
        }
        const el = build(ch);
        el.style.flex = `${n.s[i]} 1 0px`;
        box.append(el);
      });
      return box;
    }

    function render(animated = true) {
      const before = animated ? rects() : null;
      root.replaceChildren();
      const tree = st.tree ? build(st.tree) : document.createElement('div');
      tree.style.flex = '1 1 0px';
      root.append(tree);
      for (const [id, p] of Object.entries(panes)) {
        const f = st.float[id];
        p.classList.toggle('floating', !!f);
        p.classList.toggle('maxed', st.max === id);
        if (f) {
          section.append(p);
          Object.assign(p.style, { left: f.x * 100 + '%', top: f.y * 100 + '%', width: f.w * 100 + '%', height: f.h * 100 + '%', flex: '' });
        } else {
          Object.assign(p.style, { left: '', top: '', width: '', height: '' });
        }
      }
      if (before) animate(before);
      save(key, st);
      onChange?.();
    }

    function remember(id) {
      const p = panes[id], s = section.getBoundingClientRect(), r = p.getBoundingClientRect();
      if (!s.width) return;
      st.float[id] = { x: (r.left - s.left) / s.width, y: (r.top - s.top) / s.height, w: r.width / s.width, h: r.height / s.height };
      save(key, st);
    }

    function startResize(e, node, i, box) {
      e.preventDefault();
      const row = node.d === 'row', kids = [...box.children].filter(x => !x.classList.contains('gutter'));
      const a = kids[i - 1], b = kids[i];
      const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
      const start = row ? e.clientX : e.clientY, pa = row ? ra.width : ra.height, pb = row ? rb.width : rb.height;
      const wsum = node.s[i - 1] + node.s[i], min = row ? MIN_W : MIN_H;
      const g = e.currentTarget; g.classList.add('on'); g.setPointerCapture(e.pointerId);
      document.body.classList.add(row ? 'resizing-x' : 'resizing-y');
      let raf = 0;
      const move = ev => {
        const d = (row ? ev.clientX : ev.clientY) - start;
        const na = Math.max(min, Math.min(pa + pb - min, pa + d));
        node.s[i - 1] = wsum * na / (pa + pb); node.s[i] = wsum - node.s[i - 1];
        a.style.flex = `${node.s[i - 1]} 1 0px`; b.style.flex = `${node.s[i]} 1 0px`;
        if (!raf) raf = requestAnimationFrame(() => { raf = 0; onChange?.(); });
      };
      const up = () => {
        g.classList.remove('on'); document.body.classList.remove('resizing-x', 'resizing-y');
        g.removeEventListener('pointermove', move);
        for (const t of ['pointerup', 'pointercancel', 'lostpointercapture']) g.removeEventListener(t, up);
        save(key, st); onChange?.();
      };
      g.addEventListener('pointermove', move);
      for (const t of ['pointerup', 'pointercancel', 'lostpointercapture']) g.addEventListener(t, up);
    }

    /** Which pane and which part of it the pointer is over. */
    function zoneAt(x, y, self) {
      for (const [id, p] of Object.entries(panes)) {
        if (id === self || st.float[id] || st.max) continue;
        const r = p.getBoundingClientRect();
        if (x < r.left || x > r.right || y < r.top || y > r.bottom) continue;
        const fx = (x - r.left) / r.width, fy = (y - r.top) / r.height;
        const edge = Math.min(fx, 1 - fx, fy, 1 - fy);
        let side = 'center';
        if (edge < .28) side = edge === fx ? 'left' : edge === 1 - fx ? 'right' : edge === fy ? 'top' : 'bottom';
        return { id, side, r };
      }
      return null;
    }

    function showZone(z) {
      if (!z) { overlay.style.opacity = 0; return; }
      const s = section.getBoundingClientRect(), r = z.r;
      let { left, top, width, height } = r;
      if (z.side === 'left') width /= 2; if (z.side === 'right') { left += width / 2; width /= 2; }
      if (z.side === 'top') height /= 2; if (z.side === 'bottom') { top += height / 2; height /= 2; }
      Object.assign(overlay.style, { opacity: 1, left: left - s.left + 'px', top: top - s.top + 'px', width: width + 'px', height: height + 'px' });
      overlay.dataset.side = z.side === 'center' ? 'swap' : 'dock ' + z.side;
    }

    function startMove(e, id) {
      if (e.button !== 0 || e.target.closest('input,select,button,label,.pctl') || st.max) return;
      const p = panes[id], x0 = e.clientX, y0 = e.clientY, r0 = p.getBoundingClientRect(), s = section.getBoundingClientRect();
      const floating = !!st.float[id];
      let ghost = null, zone = null;
      const move = ev => {
        const dx = ev.clientX - x0, dy = ev.clientY - y0;
        if (!ghost && Math.hypot(dx, dy) < 6) return;
        if (!ghost) {
          ghost = document.createElement('div');
          ghost.className = 'dock-ghost';
          ghost.textContent = p.querySelector('.pt b')?.textContent || id;
          Object.assign(ghost.style, { width: Math.min(r0.width, 420) + 'px', height: Math.min(r0.height, 260) + 'px' });
          document.body.append(ghost);
          p.classList.add('dragging');
        }
        Object.assign(ghost.style, { left: ev.clientX - 30 + 'px', top: ev.clientY - 12 + 'px' });
        zone = ev.shiftKey ? null : zoneAt(ev.clientX, ev.clientY, id);
        showZone(zone);
        ghost.classList.toggle('free', !zone);
      };
      let done = false;
      const up = ev => {
        if (done) return;
        done = true;
        document.removeEventListener('pointermove', move);
        for (const t of ['pointerup', 'pointercancel', 'mouseup']) document.removeEventListener(t, up);
        overlay.style.opacity = 0;
        if (!ghost) return;
        ghost.remove(); p.classList.remove('dragging');
        if (zone) {
          if (zone.side === 'center' && !floating) st.tree = swap(st.tree, id, zone.id);
          else {
            delete st.float[id];
            st.tree = insert(remove(st.tree, id) ?? zone.id, zone.id, id, zone.side === 'center' ? 'right' : zone.side);
          }
        } else {
          // dropped on empty space or with Shift: float where it was released
          const w = Math.min(r0.width, s.width * .6), h = Math.min(r0.height, s.height * .6);
          const nx = Math.max(0, Math.min(s.width - w, ev.clientX - s.left - 30)), ny = Math.max(0, Math.min(s.height - h, ev.clientY - s.top - 12));
          if (!floating) st.tree = remove(st.tree, id);
          st.float[id] = { x: nx / s.width, y: ny / s.height, w: w / s.width, h: h / s.height };
        }
        render();
      };
      document.addEventListener('pointermove', move);
      for (const t of ['pointerup', 'pointercancel', 'mouseup']) document.addEventListener(t, up);
    }

    function toggleFloat(id) {
      if (st.float[id]) {
        delete st.float[id];
        const first = st.tree ? leaves(st.tree)[0] : null;
        st.tree = first ? insert(st.tree, first, id, 'right') : id;
      } else {
        const r = panes[id].getBoundingClientRect(), s = section.getBoundingClientRect();
        st.tree = remove(st.tree, id);
        st.float[id] = { x: Math.min(.5, (r.left - s.left) / s.width + .03), y: Math.min(.5, (r.top - s.top) / s.height + .03), w: Math.min(.45, r.width / s.width), h: Math.min(.5, r.height / s.height) };
      }
      render();
    }

    function toggleMax(id) { st.max = st.max === id ? null : id; render(); }

    function reset() { st = fresh(); render(); }

    render(false);
    return { reset, toggleMax, get max() { return st.max; } };
  }

  return {
    init(section, defaults, onChange) { all[section.id] = create(section, defaults, onChange); return all[section.id]; },
    get: id => all[id],
    resetAll() { Object.values(all).forEach(l => l.reset()); },
  };
})();
