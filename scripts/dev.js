// scripts/dev.js
// Master development orchestrator
import { spawn } from 'node:child_process';
import path from 'node:path';

const isWindows = process.platform === 'win32';
const npmCmd = isWindows ? 'npm.cmd' : 'npm';
const nodeCmd = process.execPath;

console.log('====================================================');
console.log('🛡️  STARTING PATCHPROOF SYSTEM (4 SERVICES)');
console.log('   - Victim Target:   http://localhost:3001');
console.log('   - API Control:     http://localhost:4000');
console.log('   - Proxy WAF:       http://localhost:8080');
console.log('   - Web Console:     http://localhost:5173');
console.log('====================================================\n');

// 1. Lab Target
const target = spawn('node', ['scripts/lab-target.js'], { shell: true, stdio: 'inherit' });

// 2. API
const api = spawn('node', ['apps/api/src/index.js'], { shell: true, stdio: 'inherit' });

// 3. Proxy
const proxy = spawn('node', ['apps/proxy/src/index.js'], { shell: true, stdio: 'inherit' });

// 4. Web Console
const web = spawn(npmCmd, ['--workspace=apps/web', 'run', 'dev'], { shell: true, stdio: 'inherit' });

function shutdown() {
  console.log('\n[PatchProof] Shutting down all services...');
  try { target.kill(); } catch {}
  try { api.kill(); } catch {}
  try { proxy.kill(); } catch {}
  try { web.kill(); } catch {}
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
