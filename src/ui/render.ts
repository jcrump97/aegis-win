// Generic tool forms (from the manifest's inputSchema) and result rendering.

import type { JsonSchema } from './api';
import { h } from './dom';

export interface SchemaForm {
  element: HTMLElement;
  /** Collected arguments, or an error message for the first invalid field. */
  read(): { args: Record<string, unknown> } | { error: string };
  hasDryRun: boolean;
}

function labelFor(name: string): string {
  return name.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase());
}

/** Builds inputs for every property except dryRun (that one gets its own button). */
export function schemaForm(schema: JsonSchema, idPrefix: string): SchemaForm {
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  const readers: Array<() => { name: string; value?: unknown; error?: string }> = [];
  const fields: HTMLElement[] = [];

  for (const [name, prop] of Object.entries(props)) {
    if (name === 'dryRun') continue;
    const id = `${idPrefix}-${name}`;
    const label = h('label', { for: id }, labelFor(name), required.has(name) ? ' *' : '');
    const hint = prop.description ? h('div', { class: 'hint' }, prop.description) : null;
    const type = prop.type ?? 'string';

    if (prop.enum) {
      const select = h('select', { id }, ...prop.enum.map((v) => h('option', { value: String(v) }, String(v))));
      if (prop.default !== undefined) select.value = String(prop.default);
      fields.push(h('div', {}, label, select, hint));
      readers.push(() => ({ name, value: prop.enum!.find((v) => String(v) === select.value) }));
    } else if (type === 'boolean') {
      const box = h('input', { id, type: 'checkbox', checked: prop.default === true });
      fields.push(h('div', {}, h('label', { class: 'inline', for: id }, box, labelFor(name)), hint));
      readers.push(() => ({ name, value: box.checked }));
    } else if (type === 'integer' || type === 'number') {
      const input = h('input', {
        id,
        type: 'number',
        step: type === 'integer' ? 1 : 'any',
        min: prop.minimum,
        max: prop.maximum,
        placeholder: prop.default !== undefined ? `default ${prop.default}` : '',
      });
      fields.push(h('div', {}, label, input, hint));
      readers.push(() => {
        if (input.value.trim() === '') return required.has(name) ? { name, error: `${labelFor(name)} is required.` } : { name };
        const n = Number(input.value);
        if (!Number.isFinite(n) || (type === 'integer' && !Number.isInteger(n))) return { name, error: `${labelFor(name)} must be a ${type}.` };
        return { name, value: n };
      });
    } else if (type === 'array' && (prop.items?.type === 'string' || prop.items?.type === 'integer')) {
      const input = h('input', { id, type: 'text', placeholder: 'comma-separated' });
      fields.push(h('div', {}, label, input, hint));
      readers.push(() => {
        const parts = input.value.split(',').map((s) => s.trim()).filter(Boolean);
        if (parts.length === 0) return { name };
        if (prop.items?.type === 'integer') {
          const nums = parts.map(Number);
          if (nums.some((n) => !Number.isInteger(n))) return { name, error: `${labelFor(name)} must be whole numbers.` };
          return { name, value: nums };
        }
        return { name, value: parts };
      });
    } else if (type === 'array' || type === 'object') {
      const area = h('textarea', { id, rows: 4, placeholder: type === 'array' ? '[ … ] (JSON)' : '{ … } (JSON)', class: 'mono' });
      fields.push(h('div', {}, label, area, hint));
      readers.push(() => {
        if (area.value.trim() === '') return required.has(name) ? { name, error: `${labelFor(name)} is required.` } : { name };
        try {
          return { name, value: JSON.parse(area.value) };
        } catch {
          return { name, error: `${labelFor(name)} must be valid JSON.` };
        }
      });
    } else {
      const long = (prop.maxLength ?? 0) > 2000;
      const input = long ? h('textarea', { id, rows: 6, class: 'mono' }) : h('input', { id, type: 'text', maxlength: prop.maxLength });
      if (typeof prop.default === 'string') input.value = prop.default;
      fields.push(h('div', {}, label, input, hint));
      readers.push(() => {
        const value = input.value;
        if (value.trim() === '') return required.has(name) ? { name, error: `${labelFor(name)} is required.` } : { name };
        return { name, value };
      });
    }
  }

  return {
    element: h('div', { class: 'grid2' }, ...fields),
    hasDryRun: 'dryRun' in props,
    read() {
      const args: Record<string, unknown> = {};
      for (const read of readers) {
        const r = read();
        if (r.error) return { error: r.error };
        if (r.value !== undefined) args[r.name] = r.value;
      }
      return { args };
    },
  };
}

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/** Shows the core's UTC timestamps in the user's local time. */
function display(value: unknown): string {
  const text = String(value);
  return ISO_UTC.test(text) ? new Date(text).toLocaleString() : text;
}

function cell(value: unknown): HTMLElement {
  if (value === null || value === undefined) return h('td', {}, '');
  if (typeof value === 'object') return h('td', { class: 'long mono' }, JSON.stringify(value));
  const text = display(value);
  return h('td', { class: text.length > 60 ? 'long' : '' }, text);
}

function isFlatObjectArray(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'object' && v !== null && !Array.isArray(v));
}

function table(rows: Record<string, unknown>[]): HTMLElement {
  const columns = Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
  return h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      {},
      h('thead', {}, h('tr', {}, ...columns.map((c) => h('th', { scope: 'col' }, labelFor(c))))),
      h('tbody', {}, ...rows.map((r) => h('tr', {}, ...columns.map((c) => cell(r[c]))))),
    ),
  );
}

/** Renders a tool result readably: LLM answers as text, lists as tables, the rest as key/value pairs. */
export function renderValue(value: unknown, depth = 0): HTMLElement {
  if (value === null || value === undefined) return h('span', { class: 'hint' }, 'none');
  if (typeof value !== 'object') {
    const text = display(value);
    return text.includes('\n') ? h('pre', {}, text) : h('span', {}, text);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return h('span', { class: 'hint' }, 'none');
    if (isFlatObjectArray(value)) return table(value);
    if (value.every((v) => typeof v !== 'object')) return h('span', {}, value.map(String).join(', '));
    return h('pre', {}, JSON.stringify(value, null, 2));
  }
  const obj = value as Record<string, unknown>;
  const answer = obj.analysis as { text?: string; model?: string; endpointHost?: string; offLan?: boolean; scrubbed?: boolean } | undefined;
  if (answer && typeof answer.text === 'string') {
    return h(
      'div',
      {},
      h('div', { class: 'answer' }, answer.text),
      h(
        'p',
        { class: 'hint' },
        `${answer.model ?? ''} at ${answer.endpointHost ?? ''}${answer.offLan ? ' (off-LAN; personal details were scrubbed first)' : ' (on your LAN)'}`,
      ),
    );
  }
  if (depth > 2) return h('pre', {}, JSON.stringify(value, null, 2));
  return h(
    'dl',
    { class: 'kv' },
    ...Object.entries(obj).flatMap(([k, v]) => [h('dt', {}, labelFor(k)), h('dd', {}, renderValue(v, depth + 1))]),
  );
}

export function rawJson(value: unknown): HTMLElement {
  return h('details', {}, h('summary', {}, 'Raw JSON'), h('pre', {}, JSON.stringify(value, null, 2)));
}
