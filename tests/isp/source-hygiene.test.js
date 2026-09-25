import fs from 'node:fs';
import path from 'node:path';

// A tool that flags invisible payloads must not ship them in its own source.
const ROOT = path.resolve(__dirname, '../..');
const DIRECTORIES = ['src/lib/isp', 'src/components/lens', 'src/pages', 'netlify/functions', 'tests/isp', 'docs/spec'];
const INVISIBLE = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\uFE00-\uFE0F]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]/u;

function listFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) return listFiles(full);
    return /\.(js|jsx|mjs|md|css)$/.test(entry.name) ? [full] : [];
  });
}

const files = DIRECTORIES.flatMap((directory) => listFiles(path.join(ROOT, directory)));

test('finds the files it should check', () => {
  expect(files.length).toBeGreaterThan(20);
});

test.each(files.map((file) => [path.relative(ROOT, file)]))('%s has no literal invisible or bidirectional characters', (relative) => {
  const lines = fs.readFileSync(path.join(ROOT, relative), 'utf8').split('\n');
  const offending = lines.map((line, index) => (INVISIBLE.test(line) ? index + 1 : null)).filter(Boolean);
  expect(offending).toEqual([]);
});
