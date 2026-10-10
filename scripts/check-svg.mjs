import { spawnSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const skip = new Set(['node_modules', 'dist', 'coverage', '.git']);

function illegal(byte) {
  return byte <= 0x08 || byte === 0x0b || byte === 0x0c || (byte >= 0x0e && byte <= 0x1f);
}

async function collect(dir, out) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (skip.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collect(full, out);
      continue;
    }
    if (entry.isFile() && (entry.name.endsWith('.svg') || entry.name.endsWith('.xml'))) {
      out.push(full);
    }
  }
}

const files = [];
await collect('.', files);
if (files.length === 0) {
  console.error('No SVG or XML files found.');
  process.exit(1);
}

let failed = false;
for (const file of files) {
  const data = await readFile(file);
  for (let i = 0; i < data.length; i++) {
    if (!illegal(data[i])) continue;
    const line = data.subarray(0, i).filter((b) => b === 0x0a).length + 1;
    const lastNl = data.lastIndexOf(0x0a, i - 1);
    const column = i - lastNl;
    console.error(`${file}:${line}:${column} illegal XML control byte 0x${data[i].toString(16).padStart(2, '0')}`);
    failed = true;
  }
}

if (failed) process.exit(1);

const xmllint = spawnSync('xmllint', ['--noout', ...files], { encoding: 'utf8' });
if (xmllint.error) {
  console.error('xmllint is not installed. Install libxml2-utils and rerun.');
  process.exit(1);
}
if (xmllint.status !== 0) {
  if (xmllint.stderr) process.stderr.write(xmllint.stderr);
  process.exit(xmllint.status ?? 1);
}

console.log(`Validated ${files.length} SVG/XML file(s) with xmllint --noout.`);
