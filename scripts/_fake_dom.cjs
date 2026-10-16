"use strict";
// DOM falso mínimo partilhado pelos testes node:vm de table.js e kpi.js.
function matches(el, sel) {
  const m = /^([a-z0-9]+)(?:\[([a-z-]+)\])?$/.exec(sel);
  if (!m || el.tag !== m[1]) return false;
  return !m[2] || m[2] in el.attrs;
}
class FakeEl {
  constructor(tag) {
    this.tag = tag; this.attrs = {}; this.children = []; this.parent = null;
    this.className = ""; this._text = ""; this.innerHTML = ""; this.listeners = {};
  }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  replaceChildren(...c) { this.children = []; this._text = ""; c.forEach((x) => this.appendChild(x)); }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  contains(n) { for (let x = n; x; x = x.parent) if (x === this) return true; return false; }
  closest(sel) { for (let x = this; x; x = x.parent) if (matches(x, sel)) return x; return null; }
  querySelectorAll(sel) {
    const out = [];
    const walk = (e) => { for (const c of e.children) { if (matches(c, sel)) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
  dispatch(type, ev) {
    const e = Object.assign({ target: this, preventDefault() { e.prevented = true; } }, ev);
    for (let n = this; n; n = n.parent) for (const fn of n.listeners[type] || []) fn(e); // borbulha
    return e;
  }
}
const fakeDocument = { createElement: (t) => new FakeEl(t) };
module.exports = { FakeEl, fakeDocument };
