// A small Markdown subset for LLM answers: headings, paragraphs, bullet and
// numbered lists, fenced code, **bold**, *italic* and `code`. It only parses
// into plain data; render.ts turns that into elements with text nodes, so an
// answer can never inject markup. Anything else stays as literal text.

export type Inline = { kind: 'text' | 'strong' | 'em' | 'code'; text: string };

export type Block =
  | { kind: 'heading'; level: number; inlines: Inline[] }
  | { kind: 'paragraph'; inlines: Inline[] }
  | { kind: 'list'; ordered: boolean; items: Inline[][] }
  | { kind: 'code'; text: string };

const INLINE = /\*\*(.+?)\*\*|`([^`]+)`|\*([^\s*](?:[^*]*[^\s*])?)\*/g;

export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  for (const m of text.matchAll(INLINE)) {
    if (m.index > last) out.push({ kind: 'text', text: text.slice(last, m.index) });
    if (m[1] !== undefined) out.push({ kind: 'strong', text: m[1] });
    else if (m[2] !== undefined) out.push({ kind: 'code', text: m[2] });
    else out.push({ kind: 'em', text: m[3] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ kind: 'text', text: text.slice(last) });
  return out;
}

const HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const BULLET = /^\s*[-*+]\s+(.*)$/;
const NUMBERED = /^\s*\d{1,3}[.)]\s+(.*)$/;
const FENCE = /^\s*```/;

export function parseMarkdown(source: string): Block[] {
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  let code: string[] | null = null;

  const flush = () => {
    if (paragraph.length) blocks.push({ kind: 'paragraph', inlines: parseInline(paragraph.join('\n')) });
    if (list) blocks.push({ kind: 'list', ordered: list.ordered, items: list.items.map(parseInline) });
    paragraph = [];
    list = null;
  };

  for (const line of source.replace(/\r\n?/g, '\n').split('\n')) {
    if (code) {
      if (FENCE.test(line)) {
        blocks.push({ kind: 'code', text: code.join('\n') });
        code = null;
      } else {
        code.push(line);
      }
      continue;
    }
    if (FENCE.test(line)) {
      flush();
      code = [];
      continue;
    }
    if (line.trim() === '') {
      flush();
      continue;
    }
    const heading = HEADING.exec(line);
    if (heading) {
      flush();
      blocks.push({ kind: 'heading', level: heading[1].length, inlines: parseInline(heading[2]) });
      continue;
    }
    const bullet = BULLET.exec(line);
    const numbered = bullet ? null : NUMBERED.exec(line);
    const item = bullet ?? numbered;
    if (item) {
      const ordered = numbered !== null;
      if (paragraph.length || (list && list.ordered !== ordered)) flush();
      list ??= { ordered, items: [] };
      list.items.push(item[1]);
      continue;
    }
    if (list && /^\s/.test(line)) {
      // An indented line continues the previous list item.
      list.items[list.items.length - 1] += ` ${line.trim()}`;
      continue;
    }
    if (list) flush();
    paragraph.push(line);
  }
  if (code) blocks.push({ kind: 'code', text: code.join('\n') });
  flush();
  return blocks;
}
