import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const forbiddenModules = [
  'assert',
  'buffer',
  'child_process',
  'crypto',
  'dgram',
  'events',
  'fs',
  'http',
  'https',
  'net',
  'os',
  'path',
  'perf_hooks',
  'stream',
  'tls',
  'url',
  'util',
  'vm',
  'worker_threads',
  'zlib'
];

const sourceExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
const runtimePackages = new Set([
  'samlify',
  'core-xml',
  'c14n',
  'xmldsig-edge',
  'xmlenc-edge',
  'security'
]);

function isForbidden(specifier) {
  if (!specifier) return false;

  const normalized = specifier.startsWith('node:')
    ? specifier.slice('node:'.length)
    : specifier;

  return forbiddenModules.some(name => normalized === name || normalized.startsWith(name + '/'));
}

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

function runtimeSourceRoots(repoRoot) {
  const packagesRoot = path.join(repoRoot, 'packages');
  try {
    if (!statSync(packagesRoot).isDirectory()) return [];
  } catch {
    return [];
  }

  return readdirSync(packagesRoot)
    .filter(name => runtimePackages.has(name))
    .map(name => path.join(packagesRoot, name, 'src'))
    .filter(srcPath => {
      try {
        return statSync(srcPath).isDirectory();
      } catch {
        return false;
      }
    });
}

function findViolationsInFile(filePath) {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);
  const violations = [];

  const importRegex = /\bimport\s+(?:type\s+)?(?:[^'";]+\s+from\s+)?['"]([^'"]+)['"]/g;
  const requireRegex = /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const regex of [importRegex, requireRegex]) {
      regex.lastIndex = 0;
      let match = regex.exec(line);
      while (match) {
        const specifier = match[1];
        if (isForbidden(specifier)) {
          violations.push({
            filePath,
            line: i + 1,
            specifier,
            source: line.trim()
          });
        }
        match = regex.exec(line);
      }
    }
  }

  return violations;
}

function main() {
  const repoRoot = process.cwd();
  const roots = runtimeSourceRoots(repoRoot);
  if (roots.length === 0) {
    console.log('No workspace runtime packages found under packages/*/src. Guardrail skipped.');
    process.exit(0);
  }

  const files = roots.flatMap(root => collectFiles(root));
  if (files.length === 0) {
    console.log('No source files found under runtime package src directories. Guardrail skipped.');
    process.exit(0);
  }

  const violations = files.flatMap(filePath => findViolationsInFile(filePath));
  if (violations.length === 0) {
    console.log(`Runtime import guard passed (${files.length} files scanned).`);
    process.exit(0);
  }

  console.error('Forbidden Node builtin imports found in runtime packages:');
  for (const violation of violations) {
    console.error(`- ${path.relative(repoRoot, violation.filePath)}:${violation.line} imports '${violation.specifier}'`);
    console.error(`  ${violation.source}`);
  }

  console.error('\\nMove these imports behind non-runtime adapters or replace with edge-safe alternatives.');
  process.exit(1);
}

main();
