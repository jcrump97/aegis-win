// Generated passphrases for the vault key (ADR 0004 §3.2).
//
// Made here in the window, with the browser's cryptographic generator, so a
// new passphrase is never sent back in an `invoke` response. The words come
// from the EFF large wordlist (CC BY 3.0, Electronic Frontier Foundation),
// kept byte for byte as published.
import list from './assets/eff_large_wordlist.txt?raw';

/** Words in a generated passphrase: 5 from 7,772 is about 64.6 bits. */
export const GENERATED_WORDS = 5;

/** The list's words, without the 4 that contain a hyphen, so a passphrase splits back into its words. */
export const WORDS: readonly string[] = list
  .split('\n')
  .map((line) => line.split('\t')[1]?.trim() ?? '')
  .filter((w) => w !== '' && !w.includes('-'));

/** Picks words uniformly (rejection sampling) and joins them with hyphens. */
export function generatePassphrase(words: readonly string[] = WORDS, count = GENERATED_WORDS): string {
  const n = words.length;
  const limit = 2 ** 32 - (2 ** 32 % n);
  const out: string[] = [];
  const buf = new Uint32Array(1);
  while (out.length < count) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) out.push(words[buf[0] % n]);
  }
  return out.join('-');
}
