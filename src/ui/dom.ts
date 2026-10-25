// Small DOM helpers. All text goes through text nodes, never parsed as HTML,
// so values from Windows (event messages, process names) or from MCP
// agents (ticket arguments) cannot inject markup.

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | number | boolean | EventListener | undefined | null>;

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === 'class') {
      el.className = String(value);
    } else if (key === 'value' && 'value' in el) {
      (el as HTMLInputElement).value = String(value);
    } else if (key === 'checked' && 'checked' in el) {
      (el as HTMLInputElement).checked = Boolean(value);
    } else if (value === true) {
      el.setAttribute(key, '');
    } else {
      el.setAttribute(key, String(value));
    }
  }
  append(el, ...children);
  return el;
}

export function append(parent: Node, ...children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
  }
}

export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function replace(el: Element, ...children: Child[]): void {
  clear(el);
  append(el, ...children);
}

let toastHost: HTMLElement | null = null;

export function toast(message: string, kind: 'info' | 'error' = 'info'): void {
  if (!toastHost) {
    toastHost = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastHost);
  }
  const el = h('div', { class: `toast ${kind === 'error' ? 'error' : ''}` }, message);
  toastHost.appendChild(el);
  setTimeout(() => el.remove(), kind === 'error' ? 7000 : 3500);
}

/** Opens a modal dialog; resolves with the value passed to close(), or null on cancel. */
export function modal<T>(build: (close: (value: T | null) => void) => Node): Promise<T | null> {
  return new Promise((resolve) => {
    const dialog = h('dialog');
    let settled = false;
    const close = (value: T | null) => {
      if (settled) return;
      settled = true;
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    dialog.addEventListener('cancel', (e) => {
      e.preventDefault();
      close(null);
    });
    dialog.appendChild(build(close));
    document.body.appendChild(dialog);
    dialog.showModal();
    const first = dialog.querySelector<HTMLElement>('input, textarea, select, button.primary');
    first?.focus();
  });
}

/** Asks for the PIN. The value is handed straight to one command and not kept. */
export function askPin(title: string, detail?: string, confirmLabel = 'Confirm'): Promise<string | null> {
  return modal<string>((close) => {
    const input = h('input', { type: 'password', autocomplete: 'off', 'aria-label': 'PIN', required: true });
    const form = h(
      'form',
      { class: 'stack' },
      h('h2', {}, title),
      detail ? h('p', { class: 'hint' }, detail) : null,
      h('label', {}, 'PIN'),
      input,
      h('div', { class: 'row end' }, h('button', { type: 'button', onclick: () => close(null) }, 'Cancel'), h('button', { type: 'submit', class: 'primary' }, confirmLabel)),
    );
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (input.value) close(input.value);
    });
    return form;
  });
}

export function confirmDialog(title: string, detail: string, confirmLabel: string): Promise<boolean> {
  return modal<boolean>((close) =>
    h(
      'div',
      { class: 'stack' },
      h('h2', {}, title),
      h('p', {}, detail),
      h('div', { class: 'row end' }, h('button', { onclick: () => close(false) }, 'Cancel'), h('button', { class: 'primary', onclick: () => close(true) }, confirmLabel)),
    ),
  ).then((v) => v === true);
}

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to the clipboard.');
  } catch {
    toast('Copy failed. Select the text and press Ctrl+C.', 'error');
  }
}

/** Disables a button and shows a spinner while `work` runs. */
export async function busy<T>(button: HTMLButtonElement, work: () => Promise<T>): Promise<T> {
  const label = Array.from(button.childNodes);
  button.disabled = true;
  replace(button, h('span', { class: 'spinner', 'aria-hidden': 'true' }), ' Working…');
  try {
    return await work();
  } finally {
    button.disabled = false;
    replace(button, ...label);
  }
}
