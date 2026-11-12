// A minimal DOM, just enough to run the AegisWin UI (src/ui) under Node for
// behaviour tests: elements, text nodes, attributes, classes, events, and
// simple selectors (tag, .class, #id, compound, descendant, comma lists).

class Node {
  constructor() {
    this.childNodes = [];
    this.parentNode = null;
  }
  get firstChild() {
    return this.childNodes[0] ?? null;
  }
  appendChild(child) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }
  removeChild(child) {
    const i = this.childNodes.indexOf(child);
    if (i >= 0) this.childNodes.splice(i, 1);
    child.parentNode = null;
    return child;
  }
  remove() {
    this.parentNode?.removeChild(this);
  }
  contains(other) {
    for (let n = other; n; n = n.parentNode) if (n === this) return true;
    return false;
  }
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }
  get isConnected() {
    let n = this;
    while (n.parentNode) n = n.parentNode;
    return n === globalThis.document;
  }
}

class Text extends Node {
  constructor(data) {
    super();
    this.nodeType = 3;
    this.data = data;
  }
  get textContent() {
    return this.data;
  }
}

class Element extends Node {
  constructor(tag) {
    super();
    this.nodeType = 1;
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.listeners = new Map();
    this.style = { setProperty() {} };
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.checked = false;
    const el = this;
    this.classList = {
      contains: (c) => el.className.split(/\s+/).includes(c),
      add: (c) => !el.classList.contains(c) && (el.className = `${el.className} ${c}`.trim()),
      remove: (c) => (el.className = el.className.split(/\s+/).filter((x) => x && x !== c).join(' ')),
      toggle: (c, force) => ((force ?? !el.classList.contains(c)) ? el.classList.add(c) : el.classList.remove(c)),
    };
    this.dataset = new Proxy({}, { get: (_, key) => el.getAttribute(`data-${String(key).replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`)}`) ?? undefined });
  }
  get className() {
    return this.getAttribute('class') ?? '';
  }
  set className(v) {
    this.setAttribute('class', v);
  }
  get id() {
    return this.getAttribute('id') ?? '';
  }
  setAttribute(k, v) {
    this.attributes.set(k, String(v));
  }
  getAttribute(k) {
    return this.attributes.has(k) ? this.attributes.get(k) : null;
  }
  hasAttribute(k) {
    return this.attributes.has(k);
  }
  removeAttribute(k) {
    this.attributes.delete(k);
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  removeEventListener(type, fn) {
    this.listeners.set(type, (this.listeners.get(type) ?? []).filter((f) => f !== fn));
  }
  dispatchEvent(event) {
    event.target ??= this;
    for (let n = this; n; n = n.parentNode) {
      for (const fn of n.listeners?.get(event.type) ?? []) fn.call(n, event);
    }
    return !event.defaultPrevented;
  }
  click() {
    if (this.disabled) return;
    this.dispatchEvent(new Event('click'));
  }
  focus() {}
  scrollIntoView() {}
  showModal() {
    this.open = true;
  }
  close() {
    this.open = false;
  }
  querySelectorAll(selector) {
    const out = [];
    const walk = (n) => {
      for (const c of n.childNodes) {
        if (c instanceof Element) {
          if (matches(c, selector, this)) out.push(c);
          walk(c);
        }
      }
    };
    walk(this);
    return out;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
}

class Event {
  constructor(type) {
    this.type = type;
    this.defaultPrevented = false;
  }
  preventDefault() {
    this.defaultPrevented = true;
  }
  stopPropagation() {}
}

function matchesCompound(el, compound) {
  const parts = compound.match(/^[a-z0-9-]+|\.[\w-]+|#[\w-]+/gi) ?? [];
  if (parts.join('') !== compound) throw new Error(`fake-dom: unsupported selector part '${compound}'`);
  return parts.every((p) =>
    p.startsWith('.') ? el.classList.contains(p.slice(1)) : p.startsWith('#') ? el.id === p.slice(1) : el.tagName === p.toUpperCase(),
  );
}

function matches(el, selector, scope) {
  return selector.split(',').some((alt) => {
    const chain = alt.trim().split(/\s+/);
    if (!matchesCompound(el, chain[chain.length - 1])) return false;
    let n = el.parentNode;
    for (let i = chain.length - 2; i >= 0; i--) {
      while (n && n !== scope && !(n instanceof Element && matchesCompound(n, chain[i]))) n = n.parentNode;
      if (!n || n === scope) return false;
      n = n.parentNode;
    }
    return true;
  });
}

class Document extends Element {
  constructor() {
    super('#document');
    this.documentElement = this.appendChild(new Element('html'));
    this.body = this.documentElement.appendChild(new Element('body'));
  }
  createElement(tag) {
    return new Element(tag);
  }
  createTextNode(text) {
    return new Text(text);
  }
  getElementById(id) {
    return this.querySelector(`#${id}`);
  }
}

/** Installs `document` and `window` globals with an `#app` root. */
export function installFakeDom() {
  const document = new Document();
  const app = document.createElement('div');
  app.setAttribute('id', 'app');
  document.body.appendChild(app);
  // `window` is its own object (falling back to Node's globals), so the
  // UI's timers and the Tauri bridge never replace anything Node itself uses.
  // The UI polls every 2 seconds; tests run a poll by calling the callback.
  const intervals = [];
  const own = { setInterval: (fn) => intervals.push(fn), clearInterval: () => {} };
  globalThis.document = document;
  globalThis.window = new Proxy(own, { get: (t, k) => (k in t ? t[k] : globalThis[k]), set: (t, k, v) => ((t[k] = v), true) });
  return { document, app, intervals };
}

/** Visible text of an element, one entry per block-ish element, for assertions. */
export function texts(el) {
  return el.querySelectorAll('h2, h3, h4, p, .hint, .notice, .badge, strong').map((e) => e.textContent.trim());
}
