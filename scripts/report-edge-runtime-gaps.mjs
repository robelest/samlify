import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const sourceExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

const trackedSpecifiers = new Map([
  ['node-rsa', 'Replace with Oslo/WebCrypto wrapper'],
  ['xml-crypto', 'Replace with internal xmldsig implementation'],
  ['@authenio/xml-encryption', 'Replace with internal xmlenc implementation'],
  ['node-forge', 'Replace with Oslo ASN.1 + WebCrypto key handling'],
  ['xml', 'Replace with deterministic internal XML builders'],
  ['pako', 'Replace with edge-safe deflate/inflate strategy'],
  ['xpath', 'Validate edge compatibility and harden selector usage'],
]);

function collectFiles(dir, files = []) {
  if (!statSync(dir).isDirectory()) return files;

  for (const entry of readdirSync(dir)) {
    const fullPath = path.join(dir, entry);
    const stats = statSync(fullPath);
    if (stats.isDirectory()) {
      collectFiles(fullPath, files);
      continue;
    }
    if (sourceExtensions.has(path.extname(fullPath))) {
      files.push(fullPath);
    }
  }

  return files;
}

function packageSourceRoots(repoRoot) {
  const packagesRoot = path.join(repoRoot, 'packages');
  try {
    if (!statSync(packagesRoot).isDirectory()) return [];
  } catch {
    return [];
  }

  return readdirSync(packagesRoot)
    .map(name => ({
      name,
      srcPath: path.join(packagesRoot, name, 'src')
    }))
    .filter(({ srcPath }) => {
      try {
        return statSync(srcPath).isDirectory();
      } catch {
        return false;
      }
    });
}

function findFileHits(filePath) {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);
  const hits = [];

  const importRegex = /\bimport\s+(?:type\s+)?(?:[^'";]+\s+from\s+)?['"]([^'"]+)['"]/g;
  const requireRegex = /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;
  const bufferRegex = /\bBuffer\b/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const regex of [importRegex, requireRegex]) {
      regex.lastIndex = 0;
      let match = regex.exec(line);
      while (match) {
        const specifier = match[1];
        if (trackedSpecifiers.has(specifier)) {
          hits.push({
            type: 'module',
            specifier,
            line: i + 1,
            source: line.trim(),
          });
        }
        match = regex.exec(line);
      }
    }

    bufferRegex.lastIndex = 0;
    if (bufferRegex.test(line)) {
      hits.push({
        type: 'buffer',
        specifier: 'Buffer',
        line: i + 1,
        source: line.trim(),
      });
    }
  }

  return hits;
}

function main() {
  const repoRoot = process.cwd();
  const roots = packageSourceRoots(repoRoot);
  if (roots.length === 0) {
    console.log('No package src roots found.');
    process.exit(0);
  }

  const packageHits = new Map();

  for (const { name, srcPath } of roots) {
    const files = collectFiles(srcPath);
    const hits = [];
    for (const filePath of files) {
      const fileHits = findFileHits(filePath);
      for (const hit of fileHits) {
        hits.push({
          ...hit,
          filePath,
        });
      }
    }
    packageHits.set(name, hits);
  }

  console.log('Edge Runtime Gap Report');
  console.log('=======================');

  for (const [packageName, hits] of packageHits.entries()) {
    if (hits.length === 0) continue;
    console.log(`\n[${packageName}] ${hits.length} potential blockers`);
    for (const hit of hits) {
      const relative = path.relative(repoRoot, hit.filePath);
      if (hit.type === 'buffer') {
        console.log(`- ${relative}:${hit.line} uses Buffer`);
      } else {
        const replacement = trackedSpecifiers.get(hit.specifier);
        console.log(`- ${relative}:${hit.line} imports '${hit.specifier}'`);
        console.log(`  replacement: ${replacement}`);
      }
    }
  }

  const aggregate = new Map();
  for (const hits of packageHits.values()) {
    for (const hit of hits) {
      const key = hit.specifier;
      aggregate.set(key, (aggregate.get(key) || 0) + 1);
    }
  }

  console.log('\nAggregate');
  console.log('---------');
  for (const [specifier, count] of aggregate.entries()) {
    console.log(`- ${specifier}: ${count}`);
  }
}

main();
