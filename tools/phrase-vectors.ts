// Writes tests/vectors/phrase/v1.json: keys made from phrases by version 1 of the derivation
// (src/core/phrase.ts). Run once; the file is then frozen — a test that fails against it means
// the derivation changed, and every key made from a phrase with it would be lost.
import { writeFileSync } from 'node:fs';
import { ed25519PublicKey } from '../src/core/crypto/ed25519.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { toHex } from '../src/core/bytes.ts';
import { normalizePhrase, secretsFromPhrase } from '../src/core/phrase.ts';

const cases = [
  { phrase: 'Я иду в лес и пою песню', email: ' Test@Example.org ' },
  { phrase: 'The quick  brown\tfox jumps over', email: 'test@example.org' },
  { phrase: '我今天去北京看朋友吃饭', email: 'zh@example.org' },
  { phrase: 'أنا ذاهب إلى السوق اليوم صباحا', email: 'ar@example.org' },
  { phrase: 'İstanbul’da güzel bir gün geçirdik', email: 'tr@example.org' },
];
const out = [];
for (const c of cases) {
  const s = await secretsFromPhrase(c.phrase, c.email);
  out.push({ ...c, normalized: normalizePhrase(c.phrase), ed25519: toHex(ed25519PublicKey(s.seed)), cv25519: toHex(x25519Base(s.scalar)) });
}
writeFileSync(new URL('../tests/vectors/phrase/v1.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out, null, 2));
