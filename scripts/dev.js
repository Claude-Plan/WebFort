import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const rootDir = path.resolve(path.dirname(__filename), '..');

console.log('\x1b[36m%s\x1b[0m', '🛡️  Starting PatchProof Services (API :4000 & Proxy :8080)...');

const apiProcess = spawn(process.execPath, [path.join(rootDir, 'apps/api/src/index.js')], {
  stdio: 'inherit',
  cwd: rootDir,
  env: process.env
});

const proxyProcess = spawn(process.execPath, [path.join(rootDir, 'apps/proxy/src/index.js')], {
  stdio: 'inherit',
  cwd: rootDir,
  env: process.env
});

function cleanup() {
  console.log('\nShutting down PatchProof services...');
  try { apiProcess.kill(); } catch {}
  try { proxyProcess.kill(); } catch {}
  process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
