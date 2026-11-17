// scripts/verify-health.js
import { spawn } from 'node:child_process';

const cwd = process.cwd();
const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function run() {
  console.log('=== VERIFYING HEALTH CHECK STANDALONE ===\n');

  console.log('[1] Starting Lab Target (:3001)...');
  const targetProc = spawn('node', ['scripts/lab-target.js'], { cwd, shell: true, stdio: 'pipe' });
  targetProc.stdout.on('data', d => process.stdout.write('[target log] ' + d));
  await wait(1500);

  console.log('\n[2] Starting API Control Plane (:4000)...');
  const apiProc = spawn('node', ['apps/api/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
  apiProc.stdout.on('data', d => process.stdout.write('[api log] ' + d));
  apiProc.stderr.on('data', d => process.stderr.write('[api err] ' + d));
  await wait(2000);

  console.log('\n[3] Starting WAF Data-Plane Proxy (:8080)...');
  const proxyProc = spawn('node', ['apps/proxy/src/index.js'], { cwd, shell: true, stdio: 'pipe' });
  proxyProc.stdout.on('data', d => process.stdout.write('[proxy log] ' + d));
  proxyProc.stderr.on('data', d => process.stderr.write('[proxy err] ' + d));
  await wait(2000);

  console.log('\n[4] Querying ports directly:');
  try {
    const tRes = await fetch('http://localhost:3001/rest/admin/application-version');
    console.log('  - Target :3001 reachable:', tRes.status === 200);
  } catch (e) { console.log('  - Target :3001 error:', e.message); }

  try {
    const aRes = await fetch('http://localhost:4000/api/v1/targets');
    console.log('  - API :4000 reachable:', aRes.status === 200);
  } catch (e) { console.log('  - API :4000 error:', e.message); }

  try {
    const pRes = await fetch('http://localhost:8080/rest/admin/application-version');
    console.log('  - Proxy :8080 reachable (forwarding):', pRes.status === 200);
  } catch (e) { console.log('  - Proxy :8080 error:', e.message); }

  console.log('\n[5] Calling GET /health:');
  const healthRes = await fetch('http://localhost:4000/api/v1/health');
  const healthJson = await healthRes.json();
  console.log(JSON.stringify(healthJson, null, 2));

  // Cleanup
  targetProc.kill();
  apiProc.kill();
  proxyProc.kill();
  process.exit(0);
}

run();
